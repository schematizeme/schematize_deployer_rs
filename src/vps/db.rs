//! DB LOCAL do gestor de VPS (SQLite) — hosts registrados e a trilha de auditoria.
//! O quê: abre/cria `~/.schematize/vps.db` (override por `SCHEMATIZE_VPS_DB`, usado nos
//! testes) e garante o schema. Três tabelas: `hosts` (o registro), `sessoes` (uma abertura
//! de conexão) e `comandos` (cada execução, com exit/duração e o transcript já redigido).
//! Onde: consumido por `vps::registro` (hosts) e `vps::auditoria` (sessoes/comandos).
//!
//! Segue o padrão do `overdevdb::open` (mesma convenção de HOME, `CREATE TABLE IF NOT
//! EXISTS`, idempotente) — com WAL ligado, porque aqui a GUI lê o log ao vivo enquanto o
//! CLI escreve.
//!
//! **Append-only por desenho:** este módulo não expõe `DELETE`. A retenção (quando
//! existir) é uma rotina explícita e auditada, não um efeito colateral da UI.

use crate::util::home_app_dir;
use rusqlite::Connection;
use std::fs;
use std::path::{Path, PathBuf};

/// A conexão do banco de VPS, com nome próprio.
///
/// **Onde:** assinatura de tudo neste módulo e consumidores externos (a GUI). Existe pra que
/// quem usa a lib não precise declarar `rusqlite` como dependência só pra nomear um tipo —
/// o backend do banco é detalhe nosso, não contrato.
pub type Conn = rusqlite::Connection;

/// Caminho do DB. Respeita `SCHEMATIZE_VPS_DB` (testes); senão `~/.schematize/vps.db`.
///
/// **Onde:** todo acesso ao banco passa por [`open`], que chama esta função — não há
/// segundo lugar que decida o caminho.
pub fn db_path() -> PathBuf {
    if let Some(p) = std::env::var_os("SCHEMATIZE_VPS_DB") {
        return PathBuf::from(p);
    }
    home_app_dir().join("vps.db")
}

/// Abre a conexão, criando o diretório e o schema se preciso. Idempotente: chamar N vezes
/// é igual a chamar uma.
///
/// **Onde:** `registro` e `auditoria` chamam a cada operação (conexão SQLite é barata e
/// evita guardar estado global mutável entre CLI e GUI).
pub fn open() -> Result<Connection, String> {
    open_at(&db_path())
}

/// Igual a [`open`], mas num caminho explícito.
///
/// **Onde:** os testes (cada um no seu arquivo, sem env global — variável de ambiente é
/// estado de processo e os testes de Rust rodam em paralelo) e quem quiser um DB alternativo.
pub fn open_at(path: &Path) -> Result<Connection, String> {
    if let Some(d) = path.parent() {
        fs::create_dir_all(d).map_err(|e| format!("não consegui criar {}: {e}", d.display()))?;
        restringir_dir(d);
    }
    let conn = Connection::open(path)
        .map_err(|e| format!("não consegui abrir {}: {e}", path.display()))?;
    // WAL: a GUI segue o log enquanto o CLI escreve. Best-effort — um SQLite sem WAL
    // (filesystem de rede, por exemplo) continua funcionando, só com mais contenção.
    let _ = conn.pragma_update(None, "journal_mode", "WAL");
    // O banco guarda a trilha inteira (host, usuário, comando, transcript). 600, não o 644
    // que o umask dá — achado no teste destrutivo de higiene de permissões.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        for sufixo in ["-wal", "-shm"] {
            let lado = std::path::PathBuf::from(format!("{}{sufixo}", path.display()));
            let _ = fs::set_permissions(&lado, fs::Permissions::from_mode(0o600));
        }
    }
    migrar(&conn)?;
    Ok(conn)
}

/// Cria o schema. Separado de [`open`] pra ser testável e pra deixar explícito que toda
/// evolução de schema entra AQUI, com `IF NOT EXISTS` (nunca um `DROP`).
fn migrar(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS hosts (
            alias       TEXT PRIMARY KEY,
            host        TEXT NOT NULL,
            port        INTEGER NOT NULL DEFAULT 22,
            usuario     TEXT NOT NULL,
            key_name    TEXT NOT NULL,
            jump        TEXT,
            ambiente    TEXT NOT NULL,
            fingerprint TEXT,
            modo        TEXT NOT NULL,
            extra_opts  TEXT NOT NULL DEFAULT '',
            shim        INTEGER NOT NULL DEFAULT 0,
            criado_em   INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS verbos (
            alias     TEXT NOT NULL,
            verbo     TEXT NOT NULL,
            comando   TEXT NOT NULL,
            criado_em INTEGER NOT NULL,
            PRIMARY KEY (alias, verbo)
         );
         CREATE TABLE IF NOT EXISTS sessoes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            alias      TEXT NOT NULL,
            trace_id   TEXT NOT NULL,
            abriu_em   INTEGER NOT NULL,
            fechou_em  INTEGER,
            origem     TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS comandos (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            sessao_id   INTEGER NOT NULL,
            alias       TEXT NOT NULL,
            trace_id    TEXT NOT NULL,
            comando     TEXT NOT NULL,
            veredito    TEXT NOT NULL,
            exit_code   INTEGER,
            duracao_ms  INTEGER NOT NULL,
            ts          INTEGER NOT NULL,
            transcript  TEXT NOT NULL,
            transcript_path TEXT
         );
         CREATE INDEX IF NOT EXISTS idx_comandos_alias ON comandos(alias, ts);
         CREATE INDEX IF NOT EXISTS idx_sessoes_alias  ON sessoes(alias, abriu_em);",
    )
    .map_err(|e| format!("falha ao criar o schema do vps.db: {e}"))?;
    coluna_se_faltar(conn, "hosts", "fronteira", "TEXT NOT NULL DEFAULT 'sem'")?;
    coluna_se_faltar(conn, "hosts", "sondado_em", "INTEGER NOT NULL DEFAULT 0")?;
    Ok(())
}

/// Acrescenta uma coluna se ela ainda não existir. Idempotente.
///
/// **Onde:** [`migrar`]. `CREATE TABLE IF NOT EXISTS` não altera tabela que já existe — quem
/// já tinha um `vps.db` da versão anterior ficaria sem as colunas novas e todo `SELECT`
/// quebraria. Isto é a migração expand-only: só acrescenta, nunca dropa nem renomeia.
fn coluna_se_faltar(
    conn: &Connection,
    tabela: &str,
    coluna: &str,
    tipo: &str,
) -> Result<(), String> {
    // DDL é a ÚNICA exceção ao "SQL sempre parametrizado" do piso 2, e por um motivo técnico:
    // SQLite não aceita `?` no lugar de nome de tabela ou coluna. Como não dá pra parametrizar,
    // a defesa é blindar o identificador — assim nem um chamador futuro consegue injetar.
    //
    // Hoje os três argumentos são literais do próprio [`migrar`], mas a garantia não pode
    // depender disso continuar verdade: o teste de conformidade cobra esta checagem.
    let identificador_ok = |s: &str| {
        !s.is_empty()
            && s.len() <= 64
            && s.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    if !identificador_ok(tabela) || !identificador_ok(coluna) {
        return Err(format!("identificador inválido no schema: {tabela:?}.{coluna:?}"));
    }
    // O TIPO também: só o vocabulário fechado que este schema usa.
    const TIPOS: &[&str] = &["TEXT NOT NULL DEFAULT \'sem\'", "INTEGER NOT NULL DEFAULT 0"];
    if !TIPOS.contains(&tipo) {
        return Err(format!("tipo de coluna fora do vocabulário do schema: {tipo:?}"));
    }
    let existe: bool = conn
        .prepare(&format!("PRAGMA table_info({tabela})"))
        .and_then(|mut st| {
            let it = st.query_map([], |r| r.get::<_, String>(1))?;
            Ok(it.filter_map(Result::ok).any(|c| c == coluna))
        })
        .map_err(|e| format!("falha ao inspecionar {tabela}: {e}"))?;
    if existe {
        return Ok(());
    }
    conn.execute(&format!("ALTER TABLE {tabela} ADD COLUMN {coluna} {tipo}"), [])
        .map_err(|e| format!("falha ao acrescentar {tabela}.{coluna}: {e}"))?;
    Ok(())
}

/// Grava um arquivo **recusando-se a seguir symlink**, com modo 600.
///
/// O teste destrutivo mostrou o problema: com `~/.schematize/known_hosts/<alias>` apontando
/// para outro arquivo, `confiar()` escrevia ATRAVÉS do link e destruía o alvo. Um `fs::write`
/// comum segue link por definição — e os arquivos deste módulo (host keys, transcripts) são
/// justamente os que não podem ser redirecionados por ninguém.
///
/// `O_NOFOLLOW` faz o próprio kernel recusar; onde ele não existe, a checagem por
/// `symlink_metadata` cobre o caso comum.
///
/// **Onde:** `conexao::confiar` e `auditoria::registrar_comando`.
pub fn escrever_sem_seguir_link(caminho: &std::path::Path, conteudo: &[u8]) -> Result<(), String> {
    use std::io::Write;
    // Um symlink já existente é recusa imediata — não se sobrescreve o que aponta pra fora.
    if let Ok(md) = std::fs::symlink_metadata(caminho) {
        if md.file_type().is_symlink() {
            return Err(format!(
                "{} é um link simbólico — recuso escrever através dele. Apague o link e tente de novo",
                caminho.display()
            ));
        }
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(libc_o_nofollow());
    }
    let mut f = opts
        .open(caminho)
        .map_err(|e| format!("não consegui gravar {}: {e}", caminho.display()))?;
    f.write_all(conteudo).map_err(|e| format!("não consegui gravar {}: {e}", caminho.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(caminho, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// `O_NOFOLLOW` sem trazer a crate `libc` (o valor é estável na ABI de cada plataforma).
#[cfg(unix)]
fn libc_o_nofollow() -> i32 {
    #[cfg(target_os = "linux")]
    {
        0o400000
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        0x0100
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    {
        0
    }
}

/// Restringe um diretório a 700 (best-effort).
///
/// **Onde:** todo dir que este módulo cria. Antes nasciam com 775 pelo umask: o `vps.db`, os
/// transcripts e as host keys ficavam legíveis por qualquer usuário local — e o banco guarda a
/// trilha inteira do que o agente rodou.
pub fn restringir_dir(dir: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Segundos desde a época. Local (não vale importar crate de data só pra isto) e alinhado
/// ao que `overdevdb` já faz.
///
/// **Onde:** carimbo de `criado_em`, `abriu_em`, `ts`.
pub fn agora_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abrir_duas_vezes_e_idempotente() {
        let p = crate::vps::db_de_teste("idem");
        let a = open_at(&p).expect("primeira abertura");
        drop(a);
        let b = open_at(&p).expect("segunda abertura — schema já existe, não pode falhar");
        drop(b);
    }

    #[test]
    fn schema_cria_as_tres_tabelas() {
        let p = crate::vps::db_de_teste("schema");
        let conn = open_at(&p).unwrap();
        let mut achadas: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            )
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        achadas.sort();
        assert_eq!(achadas, vec!["comandos", "hosts", "sessoes", "verbos"]);
    }

    #[test]
    fn ddl_recusa_identificador_e_tipo_fora_do_vocabulario() {
        // DDL não pode ser parametrizado (SQLite não aceita `?` em identificador), então a
        // defesa é a blindagem — e ela precisa de teste, senão vira comentário otimista.
        let p = crate::vps::db_de_teste("ddl");
        let c = open_at(&p).unwrap();
        for (t, col) in [
            ("hosts; DROP TABLE hosts;--", "x"),
            ("hosts", "x TEXT); DROP TABLE hosts;--"),
            ("", "x"),
            ("hosts", ""),
            ("1hosts", "x"),
            ("hosts", "a-b"),
        ] {
            assert!(
                coluna_se_faltar(&c, t, col, "INTEGER NOT NULL DEFAULT 0").is_err(),
                "{t:?}.{col:?}"
            );
        }
        assert!(
            coluna_se_faltar(&c, "hosts", "nova", "DROP TABLE hosts").is_err(),
            "tipo fora do vocabulário"
        );
        // O caminho legítimo continua funcionando.
        assert!(coluna_se_faltar(&c, "hosts", "outra_col", "INTEGER NOT NULL DEFAULT 0").is_ok());
    }

    #[test]
    fn migracao_de_db_antigo_acrescenta_as_colunas_novas() {
        // Simula um vps.db da versão anterior (sem `fronteira`/`sondado_em`) e prova que
        // abrir com a versão nova o migra em vez de quebrar.
        let p = crate::vps::db_de_teste("migracao");
        {
            let c = Connection::open(&p).unwrap();
            c.execute_batch(
                "CREATE TABLE hosts (alias TEXT PRIMARY KEY, host TEXT NOT NULL, port INTEGER,
                    usuario TEXT, key_name TEXT, jump TEXT, ambiente TEXT, fingerprint TEXT,
                    modo TEXT, extra_opts TEXT, shim INTEGER, criado_em INTEGER);
                 INSERT INTO hosts VALUES ('velho','10.0.0.9',22,'d','k',NULL,'prd',NULL,'readonly','',0,1);",
            )
            .unwrap();
        }
        let c = open_at(&p).expect("abrir um DB antigo tem que MIGRAR, não falhar");
        let f: String = c
            .query_row("SELECT fronteira FROM hosts WHERE alias='velho'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(f, "sem", "linha existente ganha o default mais restritivo");
        // Migrar duas vezes não pode explodir.
        drop(c);
        open_at(&p).expect("migração tem que ser idempotente");
    }

    #[test]
    fn caminho_default_fica_sob_o_dir_do_app() {
        // Sem override, o DB mora ao lado do overdev.db — mesma convenção de HOME.
        std::env::remove_var("SCHEMATIZE_VPS_DB");
        assert!(db_path().ends_with("vps.db"));
    }
}
