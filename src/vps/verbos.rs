//! CATÁLOGO DE VERBOS — o vocabulário que o agente tem permissão de falar num host.
//! O quê: `verbo -> comando real`, guardado por host, com o formato de texto que o shim lê no
//! servidor.
//! Onde: `vps verbs` (CLI), o modo `OpsVerbs` da `politica`, e o `bootstrap`, que sincroniza
//! o catálogo pro host junto com o shim.
//!
//! ## Um catálogo, dois lugares de aplicação
//!
//! O mesmo catálogo é aplicado onde der (ver [`super::capacidade::Fronteira`]):
//!
//! - com shim no host, quem recusa é o **sshd** — fronteira de verdade;
//! - sem shim, quem recusa é o **cliente** (modo `OpsVerbs`) — vale menos, mas o vocabulário,
//!   os nomes e a UX são **os mesmos**.
//!
//! Isso é deliberado: o dia em que um host ganhar `sudo`, o `bootstrap` empurra o catálogo
//! que já existia e a fronteira sobe de nível **sem ninguém reescrever nada**. E o agente não
//! precisa saber em qual host está — ele fala `deploy`, e a diferença é só onde o `deploy`
//! é conferido.
//!
//! ## E quando não existe `<projeto>_ops`?
//! Também acontece "às vezes". Por isso [`VERBOS_SUGERIDOS`] existe: um host novo nasce com
//! um catálogo mínimo plausível, que o usuário edita. Catálogo vazio **não** vira modo livre
//! disfarçado — vira `Deny` com a mensagem dizendo qual verbo criar.

use super::db;
use rusqlite::{params, Connection, OptionalExtension};

/// Um verbo: o nome que o agente usa e o comando que roda de verdade no host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verbo {
    pub nome: String,
    pub comando: String,
}

/// Catálogo inicial de um host novo — plausível, editável, e explicitamente um PALPITE.
///
/// **Onde:** `vps verbs --seed`. Existe porque nem todo projeto tem um `<projeto>_ops` pronto,
/// e obrigar o usuário a inventar o catálogo do zero antes de usar a ferramenta é a fricção
/// que faz ele desistir e voltar pro `ssh` cru.
pub const VERBOS_SUGERIDOS: &[(&str, &str)] = &[
    ("status", "systemctl status --no-pager"),
    ("logs", "journalctl --no-pager -n 200"),
    ("disco", "df -h"),
    ("uptime", "uptime"),
    ("ps", "ps aux --sort=-%mem"),
];

/// Nomes que o shim trata como pedido EMBUTIDO — um verbo com esses nomes nunca rodaria,
/// porque o embutido responde antes de o catálogo ser consultado.
///
/// Aceitar um verbo assim é armadilha silenciosa: o usuário define `schematize-probe`, o
/// bootstrap o instala, e ele simplesmente nunca executa. Achado no teste destrutivo.
pub const VERBOS_RESERVADOS: &[&str] = &["schematize-probe"];

/// Valida o nome de um verbo: `[a-z0-9][a-z0-9-]{0,31}`.
///
/// Restrito de propósito — o nome vira chave num arquivo de texto lido por `sh` no servidor;
/// espaço, aspas ou quebra de linha aqui viram injeção lá.
pub fn valid_verbo(nome: &str) -> Result<(), String> {
    let bad = || Err(format!("nome de verbo inválido: {nome:?} (use minúsculas, números e '-')"));
    if nome.is_empty() || nome.len() > 32 {
        return bad();
    }
    if !nome.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) {
        return bad();
    }
    if !nome.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return bad();
    }
    if VERBOS_RESERVADOS.contains(&nome) {
        return Err(format!(
            "{nome:?} é um nome reservado do `schematize-ops-shell` — um verbo com esse nome nunca seria executado, porque o shim responde ao pedido embutido antes de olhar o catálogo. Escolha outro nome"
        ));
    }
    Ok(())
}

/// Valida o comando de um verbo. Recusa vazio, quebra de linha e byte nulo.
///
/// A quebra de linha é o ponto: o catálogo no servidor é um arquivo linha-a-linha, e um
/// `\n` no comando acrescentaria um verbo que ninguém aprovou.
pub fn valid_comando(cmd: &str) -> Result<(), String> {
    if cmd.trim().is_empty() {
        return Err("comando do verbo não pode ser vazio".into());
    }
    if cmd.contains('\n') || cmd.contains('\r') || cmd.contains('\0') {
        return Err(
            "o comando do verbo não pode ter quebra de linha nem byte nulo — o catálogo do servidor é linha-a-linha, e isso acrescentaria um verbo não aprovado".into(),
        );
    }
    if cmd.contains('\t') {
        return Err("o comando do verbo não pode ter TAB (é o separador do catálogo)".into());
    }
    Ok(())
}

/// Define (ou redefine) um verbo para um host.
pub fn definir(conn: &Connection, alias: &str, nome: &str, comando: &str) -> Result<(), String> {
    super::registro::valid_alias(alias)?;
    valid_verbo(nome)?;
    valid_comando(comando)?;
    conn.execute(
        "INSERT INTO verbos (alias, verbo, comando, criado_em) VALUES (?1,?2,?3,?4)
         ON CONFLICT(alias, verbo) DO UPDATE SET comando = ?3",
        params![alias, nome, comando, db::agora_secs()],
    )
    .map_err(|e| format!("falha ao definir o verbo {nome:?}: {e}"))?;
    Ok(())
}

/// Remove um verbo. `false` se não existia.
pub fn remover(conn: &Connection, alias: &str, nome: &str) -> Result<bool, String> {
    super::registro::valid_alias(alias)?;
    valid_verbo(nome)?;
    let n = conn
        .execute("DELETE FROM verbos WHERE alias = ?1 AND verbo = ?2", params![alias, nome])
        .map_err(|e| format!("falha ao remover o verbo {nome:?}: {e}"))?;
    Ok(n > 0)
}

/// Catálogo de um host, em ordem alfabética.
pub fn listar(conn: &Connection, alias: &str) -> Result<Vec<Verbo>, String> {
    super::registro::valid_alias(alias)?;
    let mut stmt = conn
        .prepare("SELECT verbo, comando FROM verbos WHERE alias = ?1 ORDER BY verbo")
        .map_err(|e| format!("falha ao preparar a consulta de verbos: {e}"))?;
    let it = stmt
        .query_map(params![alias], |r| Ok(Verbo { nome: r.get(0)?, comando: r.get(1)? }))
        .map_err(|e| format!("falha ao listar verbos: {e}"))?;
    Ok(it.filter_map(Result::ok).collect())
}

/// Busca um verbo pelo nome.
pub fn buscar(conn: &Connection, alias: &str, nome: &str) -> Result<Option<Verbo>, String> {
    super::registro::valid_alias(alias)?;
    valid_verbo(nome)?;
    conn.query_row(
        "SELECT verbo, comando FROM verbos WHERE alias = ?1 AND verbo = ?2",
        params![alias, nome],
        |r| Ok(Verbo { nome: r.get(0)?, comando: r.get(1)? }),
    )
    .optional()
    .map_err(|e| format!("falha ao buscar o verbo {nome:?}: {e}"))
}

/// Semeia o catálogo de um host com os [`VERBOS_SUGERIDOS`], **sem sobrescrever** o que já
/// existe. Devolve quantos foram criados.
pub fn semear(conn: &Connection, alias: &str) -> Result<usize, String> {
    let ja = listar(conn, alias)?;
    let mut n = 0;
    for (nome, cmd) in VERBOS_SUGERIDOS {
        if ja.iter().any(|v| v.nome == *nome) {
            continue;
        }
        definir(conn, alias, nome, cmd)?;
        n += 1;
    }
    Ok(n)
}

/// Serializa o catálogo no formato que o shim lê: uma linha `verbo<TAB>comando`, comentários
/// com `#`. **Função pura.**
///
/// **Onde:** `bootstrap`, ao sincronizar o catálogo pro host; e os testes de contagem.
pub fn catalogo_texto(verbos: &[Verbo]) -> String {
    let mut s = String::from(
        "# catálogo do schematize-ops-shell — gerado, NÃO edite à mão no servidor\n\
         # formato: <verbo>\\t<comando>\n",
    );
    for v in verbos {
        s.push_str(&v.nome);
        s.push('\t');
        s.push_str(&v.comando);
        s.push('\n');
    }
    s
}

/// Lê o formato acima de volta. **Função pura** — é o espelho exato do que o shim faz em `sh`,
/// e é o que permite testar a regra do servidor sem servidor.
pub fn parse_catalogo(texto: &str) -> Vec<Verbo> {
    texto
        .lines()
        .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let (n, c) = l.split_once('\t')?;
            let (n, c) = (n.trim(), c.trim());
            (valid_verbo(n).is_ok() && valid_comando(c).is_ok())
                .then(|| Verbo { nome: n.to_string(), comando: c.to_string() })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vps::db_de_teste;

    fn conn(nome: &str) -> Connection {
        db::open_at(&db_de_teste(nome)).unwrap()
    }

    #[test]
    fn crud_de_verbo() {
        let c = conn("verbos");
        definir(&c, "srv", "deploy", "/srv/app/deploy.sh").unwrap();
        definir(&c, "srv", "status", "systemctl status app").unwrap();
        assert_eq!(listar(&c, "srv").unwrap().len(), 2);
        assert_eq!(buscar(&c, "srv", "deploy").unwrap().unwrap().comando, "/srv/app/deploy.sh");
        // redefinir substitui, não duplica.
        definir(&c, "srv", "deploy", "/srv/app/deploy2.sh").unwrap();
        assert_eq!(listar(&c, "srv").unwrap().len(), 2);
        assert_eq!(buscar(&c, "srv", "deploy").unwrap().unwrap().comando, "/srv/app/deploy2.sh");
        assert!(remover(&c, "srv", "deploy").unwrap());
        assert!(!remover(&c, "srv", "deploy").unwrap());
    }

    #[test]
    fn semear_nao_sobrescreve_o_que_o_usuario_definiu() {
        let c = conn("semear");
        definir(&c, "srv", "status", "MEU comando").unwrap();
        let n = semear(&c, "srv").unwrap();
        assert_eq!(n, VERBOS_SUGERIDOS.len() - 1, "o `status` já existia");
        assert_eq!(buscar(&c, "srv", "status").unwrap().unwrap().comando, "MEU comando");
        // semear de novo não cria nada.
        assert_eq!(semear(&c, "srv").unwrap(), 0);
    }

    #[test]
    fn nome_de_verbo_e_restrito() {
        for ok in ["deploy", "roll-back", "v2", "a"] {
            assert!(valid_verbo(ok).is_ok(), "{ok:?}");
        }
        for bad in [
            "",
            "Deploy",
            "de ploy",
            "de\tploy",
            "de\nploy",
            "-x",
            "deploy!",
            "açao",
            "schematize-probe",
            &"x".repeat(33),
        ] {
            assert!(valid_verbo(bad).is_err(), "{bad:?} deveria ser recusado");
        }
    }

    #[test]
    fn comando_com_quebra_de_linha_acrescentaria_verbo_nao_aprovado() {
        // O ataque: `definir("x", "cmd\nroot\t/bin/sh")` viraria DUAS linhas no catálogo do
        // servidor, e a segunda seria um verbo que ninguém aprovou.
        assert!(valid_comando("deploy.sh\nroot\t/bin/sh").is_err());
        assert!(valid_comando("deploy.sh\r\nx").is_err());
        assert!(valid_comando("deploy\tsh").is_err(), "TAB é o separador");
        assert!(valid_comando("deploy\0").is_err());
        assert!(valid_comando("").is_err());
        assert!(valid_comando("/srv/deploy.sh --prod").is_ok());
    }

    #[test]
    fn round_trip_do_catalogo_preserva_a_contagem() {
        // A prova que o plano pede: o que sai é exatamente o que entra.
        let v = vec![
            Verbo { nome: "deploy".into(), comando: "/srv/deploy.sh".into() },
            Verbo { nome: "status".into(), comando: "systemctl status app".into() },
            Verbo { nome: "roll-back".into(), comando: "/srv/rollback.sh --last".into() },
        ];
        let texto = catalogo_texto(&v);
        let volta = parse_catalogo(&texto);
        assert_eq!(volta, v, "round-trip tem que ser fiel");
        assert_eq!(volta.len(), v.len(), "nº de verbos no texto == nº no catálogo");
    }

    #[test]
    fn parse_ignora_lixo_em_vez_de_aceitar_verbo_invalido() {
        let texto = "# comentário\n\
                     deploy\t/srv/deploy.sh\n\
                     \n\
                     SEM-TAB-NENHUM\n\
                     MAIUSCULO\tcmd\n\
                     ok2\tcmd valido\n";
        let v = parse_catalogo(texto);
        assert_eq!(v.len(), 2, "só as linhas válidas entram: {v:?}");
        assert_eq!(v[0].nome, "deploy");
        assert_eq!(v[1].nome, "ok2");
    }

    #[test]
    fn catalogo_vazio_gera_texto_sem_verbo_nenhum() {
        assert_eq!(parse_catalogo(&catalogo_texto(&[])).len(), 0);
    }
}
