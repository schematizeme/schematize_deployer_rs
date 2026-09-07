//! vps — acesso remoto MEDIADO: o agente executa deploy por verbos auditados, sem nunca
//! ver uma chave privada e sem conseguir abrir shell livre.
//!
//! O quê: registro de hosts (`registro`), montagem determinística dos argumentos do `ssh`
//! (`conexao`), execução com captura (`exec`), auditoria append-only e redigida
//! (`auditoria`), política de comando do cliente (`politica`) e o hook `PreToolUse` que
//! barra SSH cru no Bash do agente (`hook`).
//! Onde: CLI `schematize vps <sub>`; a GUI consome a mesma lib; o hook é chamado pelo
//! Claude Code a cada tool use.
//!
//! ## A fronteira NÃO está aqui (ADR-0005)
//! A `politica` deste módulo roda no CLIENTE e é **UX, não segurança**: ela pega acidente
//! (`rm -rf /`, `curl | sh`) e dá erro cedo e legível. Ela **não** segura ataque — qualquer
//! binário legítimo que abra shell (`git -c alias.x='!sh'`, `find -exec`, `vim -c ':!sh'`)
//! a contorna. A fronteira real é o **forced command** no `authorized_keys` do servidor
//! (`restrict,command="schematize-ops-shell"`), que é Fase 2.
//! Enquanto um host não tiver o shim, ele roda em modo degradado e a UI o marca.
//!
//! ## Pisos que este módulo carrega
//! - a chave privada nunca é lida, impressa nem logada — só referenciada por caminho (`-i`);
//! - transcript passa por [`crate::debugreport::redacao::scrub`] no caminho de ESCRITA;
//! - auditoria é append-only: não existe caminho de código que apague linha;
//! - `Ambiente::Prd` exige confirmação humana **sempre**, sem `--force`/`--skip-policy`;
//! - falha fechada: ambiente/modo desconhecido assume o MAIS restritivo;
//! - host inacessível nunca derruba o app (piso 10) — vira erro na linha, não panic.

pub mod analise;
pub mod auditoria;
pub mod bootstrap;
pub mod capacidade;
/// O catálogo do que nunca pode rodar — extraído do [`politica`], que é quem o consulta.
pub mod catastrofico;
pub mod conexao;
pub mod db;
pub mod exec;
pub mod hook;
pub mod politica;
pub mod registro;
pub mod verbos;

pub use analise::*;
pub use auditoria::*;
pub use capacidade::*;
pub use conexao::*;
pub use exec::*;
pub use politica::*;

pub use registro::*;

/// Caminho de um DB temporário EXCLUSIVO de um teste (nome + pid + contador).
///
/// **Onde:** só nos `#[cfg(test)]` deste módulo. Existe pra que nenhum teste dependa de
/// variável de ambiente — env é estado de processo, e os testes de Rust rodam em paralelo:
/// dois testes trocando `SCHEMATIZE_VPS_DB` um do outro é flaky na certa.
#[cfg(test)]
pub(crate) fn db_de_teste(nome: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let p =
        std::env::temp_dir().join(format!("schematize-vps-t-{nome}-{}-{n}.db", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}
