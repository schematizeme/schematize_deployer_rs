//! AUDITORIA — a trilha append-only de tudo que foi executado num host.
//! O quê: abre/fecha sessões, registra cada comando (veredito, exit, duração, transcript) e
//! lê o histórico. O transcript passa por [`crate::debugreport::scrub`] **no caminho de
//! escrita**, nunca na leitura.
//! Onde: `vps::exec` grava; `vps logs` e a tela de VPS da GUI leem.
//!
//! ## Por que redigir na ESCRITA e não na leitura
//! Redigir na leitura deixa o segredo em claro no disco: basta alguém abrir o `vps.db` com um
//! cliente SQLite qualquer, ou o arquivo vazar num backup, e a proteção some. Redigido na
//! escrita, o segredo nunca chega ao disco — e o custo de errar cai de "vazou" para "o log
//! ficou menos legível".
//!
//! ## Append-only
//! Este módulo **não expõe remoção**. `vps::registro::remover` apaga o HOST e deixa a trilha:
//! é justamente quando um host some que o histórico importa. Retenção, quando existir, será
//! rotina explícita e auditada — não efeito colateral de um clique na UI.

use super::db;
use super::politica::Veredito;
use rusqlite::{params, Connection};
use std::path::PathBuf;

/// Acima disto o transcript vai pra arquivo e o banco guarda só o caminho. Mantém a linha
/// pequena (a GUI lista centenas) e evita um `vps.db` de gigabytes.
pub const TRANSCRIPT_INLINE_MAX: usize = 16 * 1024;

/// Uma sessão aberta: o agrupador dos comandos de uma mesma "ida ao host".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sessao {
    /// Id no banco.
    pub id: i64,
    /// Alias do host.
    pub alias: String,
    /// Correlaciona esta sessão com os logs do servidor e do Grafana (piso 10/11).
    pub trace_id: String,
}

/// Uma linha do histórico, já redigida.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComandoRegistrado {
    pub id: i64,
    pub alias: String,
    pub trace_id: String,
    pub comando: String,
    pub veredito: String,
    pub exit_code: Option<i32>,
    pub duracao_ms: i64,
    pub ts: i64,
    /// Transcript redigido (vazio se foi pro arquivo — ver [`ComandoRegistrado::transcript_path`]).
    pub transcript: String,
    /// Caminho do transcript, quando grande demais pro banco.
    pub transcript_path: Option<String>,
}

/// Dir dos transcripts grandes (`~/.schematize/vps-logs/`).
pub fn transcripts_dir() -> PathBuf {
    crate::util::home_app_dir().join("vps-logs")
}

/// Identificador de correlação: 128 bits do CSPRNG do kernel, em hex.
///
/// **Onde:** [`abrir_sessao`]. Sem `Math.random`/timestamp como fonte de aleatoriedade
/// (piso 3) — mesmo sendo id de correlação e não segredo, não vale ter duas qualidades de
/// gerador no código pra alguém copiar a errada depois.
pub fn novo_trace_id() -> String {
    use std::io::Read;
    let mut b = [0u8; 16];
    // CSPRNG do kernel via /dev/urandom, lendo EXATAMENTE 16 bytes (`read_exact`) — um
    // `fs::read` aqui leria o device inteiro, que não termina nunca.
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut b).is_ok() {
            return b.iter().map(|x| format!("{x:02x}")).collect();
        }
    }
    // Fallback marcado: sem CSPRNG, o id diz que é degradado em vez de mentir.
    format!("nocsprng-{}-{}", std::process::id(), db::agora_secs())
}

/// Abre uma sessão para um host. `origem` diz quem pediu (`cli`, `gui`, `mcp`, `hook`).
///
/// **Onde:** `vps::exec::executar` (uma sessão por execução do CLI) e a GUI (uma por painel
/// aberto).
pub fn abrir_sessao(conn: &Connection, alias: &str, origem: &str) -> Result<Sessao, String> {
    super::registro::valid_alias(alias)?;
    let trace_id = novo_trace_id();
    conn.execute(
        "INSERT INTO sessoes (alias, trace_id, abriu_em, fechou_em, origem)
         VALUES (?1, ?2, ?3, NULL, ?4)",
        params![alias, trace_id, db::agora_secs(), origem],
    )
    .map_err(|e| format!("falha ao abrir sessão de auditoria: {e}"))?;
    Ok(Sessao { id: conn.last_insert_rowid(), alias: alias.to_string(), trace_id })
}

/// Fecha a sessão (carimba `fechou_em`). Best-effort por desenho: uma sessão que ficou aberta
/// porque o processo morreu ainda tem todos os comandos gravados — perder o carimbo de
/// fechamento é aceitável, perder o comando não seria.
pub fn fechar_sessao(conn: &Connection, s: &Sessao) {
    let _ = conn.execute(
        "UPDATE sessoes SET fechou_em = ?1 WHERE id = ?2 AND fechou_em IS NULL",
        params![db::agora_secs(), s.id],
    );
}

/// Registra um comando. **O transcript é redigido AQUI**, antes de qualquer escrita.
///
/// Transcript acima de [`TRANSCRIPT_INLINE_MAX`] vai pra arquivo (também redigido) e o banco
/// guarda o caminho. Devolve o id da linha.
///
/// **Onde:** `vps::exec::executar`, uma vez por comando — inclusive quando o veredito foi
/// `Deny` e nada rodou: a tentativa recusada é parte da trilha.
pub fn registrar_comando(
    conn: &Connection,
    s: &Sessao,
    comando: &str,
    veredito: &Veredito,
    exit_code: Option<i32>,
    duracao_ms: i64,
    transcript_bruto: &str,
) -> Result<i64, String> {
    // A ÚNICA porta de entrada do transcript no disco passa por aqui.
    let limpo = crate::debugreport::scrub(transcript_bruto);
    // O comando também: uma senha inline (`mysql -pSENHA`) é segredo como qualquer outro.
    let comando_limpo = crate::debugreport::scrub(comando);

    let (inline, caminho) = if limpo.len() > TRANSCRIPT_INLINE_MAX {
        let dir = transcripts_dir();
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("não consegui criar {}: {e}", dir.display()))?;
        db::restringir_dir(&dir);
        let nome = format!("{}-{}-{}.log", s.alias, s.trace_id, db::agora_secs());
        let p = dir.join(nome);
        // Sem seguir link: o transcript pode conter o que o comando remoto imprimiu, e um
        // link plantado aqui redirecionaria isso para um arquivo escolhido por outra pessoa.
        db::escrever_sem_seguir_link(&p, limpo.as_bytes())?;
        (String::new(), Some(p.to_string_lossy().into_owned()))
    } else {
        (limpo, None)
    };

    conn.execute(
        "INSERT INTO comandos (sessao_id, alias, trace_id, comando, veredito, exit_code,
                               duracao_ms, ts, transcript, transcript_path)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![
            s.id,
            s.alias,
            s.trace_id,
            comando_limpo,
            veredito.rotulo(),
            exit_code,
            duracao_ms,
            db::agora_secs(),
            inline,
            caminho,
        ],
    )
    .map_err(|e| format!("falha ao registrar o comando na auditoria: {e}"))?;
    Ok(conn.last_insert_rowid())
}

/// Últimos `limite` comandos de um host (mais recentes primeiro). `alias` vazio = todos.
///
/// **Onde:** `vps logs` e o painel de log da GUI.
pub fn listar_comandos(
    conn: &Connection,
    alias: &str,
    limite: usize,
) -> Result<Vec<ComandoRegistrado>, String> {
    let (sql, p): (&str, Vec<Box<dyn rusqlite::ToSql>>) = if alias.is_empty() {
        (
            "SELECT id, alias, trace_id, comando, veredito, exit_code, duracao_ms, ts,
                    transcript, transcript_path
               FROM comandos ORDER BY ts DESC, id DESC LIMIT ?1",
            vec![Box::new(limite as i64)],
        )
    } else {
        super::registro::valid_alias(alias)?;
        (
            "SELECT id, alias, trace_id, comando, veredito, exit_code, duracao_ms, ts,
                    transcript, transcript_path
               FROM comandos WHERE alias = ?1 ORDER BY ts DESC, id DESC LIMIT ?2",
            vec![Box::new(alias.to_string()), Box::new(limite as i64)],
        )
    };
    let mut stmt = conn.prepare(sql).map_err(|e| format!("falha ao preparar a consulta: {e}"))?;
    let refs: Vec<&dyn rusqlite::ToSql> = p.iter().map(|b| b.as_ref()).collect();
    let it = stmt
        .query_map(refs.as_slice(), |r| {
            Ok(ComandoRegistrado {
                id: r.get(0)?,
                alias: r.get(1)?,
                trace_id: r.get(2)?,
                comando: r.get(3)?,
                veredito: r.get(4)?,
                exit_code: r.get(5)?,
                duracao_ms: r.get(6)?,
                ts: r.get(7)?,
                transcript: r.get(8)?,
                transcript_path: r.get(9)?,
            })
        })
        .map_err(|e| format!("falha ao ler a auditoria: {e}"))?;
    let mut out = Vec::new();
    for r in it {
        match r {
            Ok(c) => out.push(c),
            // Linha ilegível não derruba a listagem (piso 10) — reporta e segue.
            Err(e) => eprintln!("aviso: linha de auditoria ilegível, ignorada: {e}"),
        }
    }
    Ok(out)
}

/// Quantos comandos há registrados para um host (`alias` vazio = todos).
///
/// **Onde:** o critério de sucesso 1 do plano (linhas de auditoria == comandos executados) e
/// o contador da GUI.
pub fn contar_comandos(conn: &Connection, alias: &str) -> Result<i64, String> {
    let n = if alias.is_empty() {
        conn.query_row("SELECT COUNT(*) FROM comandos", [], |r| r.get(0))
    } else {
        super::registro::valid_alias(alias)?;
        conn.query_row("SELECT COUNT(*) FROM comandos WHERE alias = ?1", params![alias], |r| {
            r.get(0)
        })
    };
    n.map_err(|e| format!("falha ao contar comandos: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vps::db_de_teste;
    use crate::vps::politica::Veredito;

    fn conn(nome: &str) -> Connection {
        db::open_at(&db_de_teste(nome)).unwrap()
    }

    #[test]
    fn transcript_e_redigido_no_caminho_de_escrita() {
        let c = conn("scrub");
        let s = abrir_sessao(&c, "srv", "teste").unwrap();
        // Output realista de um deploy que ecoou segredo por descuido.
        let sujo = "deploy ok\n\
                    export RESEND_API_KEY=re_AbCdEf0123456789\n\
                    Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.aaaa\n\
                    -----BEGIN OPENSSH PRIVATE KEY-----\n\
                    b3BlbnNzaC1rZXktdjEAAAAA\n\
                    -----END OPENSSH PRIVATE KEY-----\n\
                    fim";
        registrar_comando(&c, &s, "deploy", &Veredito::Allow, Some(0), 10, sujo).unwrap();

        let linha = &listar_comandos(&c, "srv", 1).unwrap()[0];
        let t = &linha.transcript;
        assert!(!t.contains("re_AbCdEf0123456789"), "token de API vazou: {t}");
        assert!(!t.contains("eyJhbGciOiJIUzI1NiJ9"), "JWT vazou: {t}");
        assert!(!t.contains("b3BlbnNzaC1rZXktdjEAAAAA"), "corpo de chave privada vazou: {t}");
        assert!(!t.contains("BEGIN OPENSSH PRIVATE KEY"), "bloco de chave privada vazou: {t}");
        assert!(
            t.contains("deploy ok") && t.contains("fim"),
            "a redação não pode comer o log útil"
        );
    }

    #[test]
    fn segredo_no_proprio_comando_tambem_e_redigido() {
        let c = conn("cmdscrub");
        let s = abrir_sessao(&c, "srv", "teste").unwrap();
        registrar_comando(
            &c,
            &s,
            "mysql -u root --password=sk-abc123def456ghi789",
            &Veredito::Allow,
            Some(0),
            1,
            "",
        )
        .unwrap();
        let linha = &listar_comandos(&c, "srv", 1).unwrap()[0];
        assert!(
            !linha.comando.contains("sk-abc123def456ghi789"),
            "senha no comando vazou: {}",
            linha.comando
        );
    }

    #[test]
    fn transcript_grande_vai_pro_arquivo_e_a_linha_fica_pequena() {
        let c = conn("grande");
        let s = abrir_sessao(&c, "srv", "teste").unwrap();
        let enorme = "x".repeat(5 * 1024 * 1024); // 5 MB
        registrar_comando(&c, &s, "build", &Veredito::Allow, Some(0), 1, &enorme).unwrap();

        let linha = &listar_comandos(&c, "srv", 1).unwrap()[0];
        assert!(linha.transcript.is_empty(), "o inline tem que ficar vazio");
        let p = linha.transcript_path.as_ref().expect("tem que ter caminho de arquivo");
        assert!(std::path::Path::new(p).is_file(), "o arquivo tem que existir");
        assert!(linha.comando.len() < 4096, "a linha do banco tem que ficar pequena");
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn contagem_de_auditoria_bate_com_os_comandos_executados() {
        // Critério de sucesso 1 do plano.
        let c = conn("contagem");
        let s = abrir_sessao(&c, "srv", "teste").unwrap();
        for i in 0..7 {
            registrar_comando(&c, &s, &format!("cmd-{i}"), &Veredito::Allow, Some(0), 1, "ok")
                .unwrap();
        }
        assert_eq!(contar_comandos(&c, "srv").unwrap(), 7);
        assert_eq!(contar_comandos(&c, "").unwrap(), 7);
        assert_eq!(listar_comandos(&c, "srv", 100).unwrap().len(), 7);
    }

    #[test]
    fn tentativa_recusada_tambem_entra_na_trilha() {
        // O que foi NEGADO é justamente o que mais importa auditar.
        let c = conn("negado");
        let s = abrir_sessao(&c, "srv", "teste").unwrap();
        registrar_comando(&c, &s, "rm -rf /", &Veredito::Deny("catastrófico".into()), None, 0, "")
            .unwrap();
        let l = &listar_comandos(&c, "srv", 1).unwrap()[0];
        assert_eq!(l.veredito, "deny");
        assert_eq!(l.exit_code, None, "nada rodou, então não há exit code");
        assert_eq!(contar_comandos(&c, "srv").unwrap(), 1);
    }

    #[test]
    fn remover_o_host_nao_apaga_a_trilha() {
        let c = conn("sobrevive");
        let mut p = crate::vps::registro::VpsProfile::novo("srv", "10.0.0.5", "d", "k");
        p.modo = crate::vps::registro::ModoPolitica::Livre;
        crate::vps::registro::salvar(&c, &p).unwrap();
        let s = abrir_sessao(&c, "srv", "teste").unwrap();
        registrar_comando(&c, &s, "uptime", &Veredito::Allow, Some(0), 1, "up").unwrap();

        assert!(crate::vps::registro::remover(&c, "srv").unwrap());
        assert_eq!(contar_comandos(&c, "srv").unwrap(), 1, "a trilha sobrevive ao host");
    }

    #[test]
    fn o_modulo_nao_tem_caminho_de_delete() {
        // Append-only por desenho: se alguém adicionar um DELETE aqui, este teste cai.
        let fonte = include_str!("auditoria.rs");
        let producao = fonte.split("#[cfg(test)]").next().unwrap_or("");
        assert!(producao.contains("pub fn registrar_comando"), "o corte pegou o arquivo errado");
        for proibido in ["DELETE FROM comandos", "DELETE FROM sessoes", "DROP TABLE"] {
            assert!(!producao.contains(proibido), "{proibido:?} não pode existir na auditoria");
        }
    }

    #[test]
    fn trace_id_e_do_csprng_e_unico() {
        let a = novo_trace_id();
        let b = novo_trace_id();
        assert_ne!(a, b);
        assert!(!a.starts_with("nocsprng-"), "o kernel tem /dev/urandom, não deveria degradar");
        assert_eq!(a.len(), 32, "128 bits em hex");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sessao_fecha_e_e_idempotente() {
        let c = conn("fechar");
        let s = abrir_sessao(&c, "srv", "teste").unwrap();
        fechar_sessao(&c, &s);
        fechar_sessao(&c, &s); // não pode explodir nem reabrir
        let f: Option<i64> = c
            .query_row("SELECT fechou_em FROM sessoes WHERE id = ?1", params![s.id], |r| r.get(0))
            .unwrap();
        assert!(f.is_some());
    }
}
