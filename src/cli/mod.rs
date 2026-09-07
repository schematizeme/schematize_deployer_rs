//! A camada de CLI: traduz argumentos do clap em chamadas da lib e imprime o resultado.
//!
//! **Onde:** `main.rs` despacha para cá. Nenhuma regra de domínio mora nesta camada — ela é
//! fina de propósito, para que a GUI e o MCP tenham exatamente o mesmo comportamento.

pub(crate) mod args;
pub(crate) mod cofre;
pub(crate) mod mcp;
pub(crate) mod ssh;
pub(crate) mod vps;
