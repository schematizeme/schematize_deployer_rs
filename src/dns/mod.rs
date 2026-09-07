//! DNS — gestão de zonas e registros da Cloudflare, com a credencial no cofre.
//!
//! **O quê:** [`api`] fala com a Cloudflare (transporte injetável, para ser testável sem
//! rede); [`politica`] decide o que passa sem perguntar; [`operacoes`] junta os dois e é o
//! que a CLI chama; [`credencial`] tira o token do cofre.
//!
//! **Onde:** `deployer dns <sub>`.
//!
//! ## O que este módulo entrega de segurança — e o que não
//!
//! O token de API da Cloudflare é uma credencial de **infraestrutura de produção**: com ele
//! se apaga um domínio do ar. Guardá-lo num `.env`, num `~/.cloudflare`, ou passá-lo por
//! variável de ambiente para um agente é o mesmo erro que o ADR-0005 já nomeou com chave SSH.
//!
//! **Resolvido:** o token não está no contexto do agente, não está em arquivo em claro que um
//! `cat` alcance, não passa por `argv` (o cliente HTTP é em processo, e é por isso que não se
//! usa `curl`), e não aparece em mensagem de erro — mesmo quando a Cloudflare o ecoa de volta.
//!
//! **Não resolvido, e não dá para resolver em UID compartilhado:** durante uma sessão
//! destravada, um processo do mesmo usuário alcança o que o processo destravado tem. Está
//! escrito aqui pelo mesmo motivo que está no README do cofre — a armadilha do ADR-0004 é a
//! defesa que dá confiança sem dar garantia.
//!
//! **O que de fato segura contra acidente:** a [`politica`], que exige confirmação explícita
//! para o que não tem undo — apex, tipos que reconfiguram a zona, e toda remoção.

pub mod api;
pub mod credencial;
pub mod operacoes;
pub mod politica;
