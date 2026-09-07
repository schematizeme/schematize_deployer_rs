//! **schematize deployer** — o app de operar servidor: chaves SSH, VPS e a porta auditada
//! que o agente enxerga.
//!
//! **O quê:** biblioteca compartilhada pelo binário `deployer` (CLI) e, adiante, pela GUI.
//! Três bounded contexts, cada um dono do seu domínio:
//!
//! - [`sshkeys`] — gerar, IMPORTAR, listar, exportar e usar chaves; a privada nunca é lida.
//! - [`vps`] — registro de hosts, política, auditoria e execução remota mediada (ADR-0005).
//! - [`mcp`] — as tools tipadas que o agente enxerga, e só elas.
//!
//! **Onde:** saiu do `schematize_cli_rs` por decisão do [ADR-0010]. Lá eram 28 de 128
//! comandos de um domínio que nada tem a ver com skills e overdev — piso 6 violado por
//! acréscimo, um comando de cada vez.
//!
//! ## A razão de segurança, dita sem eufemismo
//!
//! O motivo de existir separado **não é** organização: é que a credencial de deploy não deve
//! ficar ao alcance do agente. Mas separar o processo, sozinho, **não isola nada** — mesmo
//! usuário do sistema, mesmo `~/.ssh`, e o agente tem `Bash`. O isolamento de verdade vem do
//! cofre cifrado (fase 3 do plano); até ele existir, esta separação entrega **arquitetura, e
//! não segurança**. Está escrito aqui para ninguém ler o contrário.
//!
//! [ADR-0010]: ../../schematize_app_archive/decisoes/ADR-0010-deployer-app-separado.md

pub mod mcp;
pub mod nucleo;
pub mod sshkeys;
pub mod vps;

// Os módulos movidos chamam `crate::util::…`, `crate::settings::…` etc. Estes aliases
// mantêm o código IDÊNTICO ao que era no schematize — o corte é `/eng-refactor`, e
// reescrever 8.600 linhas de chamada seria mudança de comportamento disfarçada de mudança
// de caminho. Quando o Deployer tiver identidade própria, os aliases saem num passo só.
pub use nucleo::config;
pub use nucleo::i18n;
pub use nucleo::settings;
pub use nucleo::util;

// `debugreport` e `agentrun` são módulos do schematize dos quais os três contextos usam
// EXATAMENTE duas coisas cada: a redação de segredo em log, e a resolução de binário +
// abertura de terminal. Trazer os módulos inteiros arrastaria o relatório de diagnóstico e o
// lançador do `claude` — coisas que o Deployer não tem.
//
// Estes aliases mantêm o nome de chamada e apontam para o núcleo. NÃO são para durar: são a
// prova de que a fase 1 moveu sem reescrever. Saem num passo próprio, junto com a renomeação
// para a identidade do Deployer — e só depois de a rede de testes estar verde aqui.
pub mod debugreport {
    pub use crate::nucleo::redacao;
    pub use crate::nucleo::redacao::*;
}
pub mod agentrun {
    pub use crate::nucleo::bin::{
        abrir_comando_no_terminal, binary_in_path, nomes_de_executavel_em, resolve_bin,
    };
}
