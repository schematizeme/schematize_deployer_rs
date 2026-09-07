//! NÚCLEO — a infraestrutura que o Deployer precisa para andar sozinho.
//!
//! **O quê:** caminhos e `$HOME` ([`util`]), execução de processo ([`util::run`]), permissões
//! de arquivo, redação de segredo em log ([`redacao`]), resolução de binário fora do `$PATH`
//! ([`bin`]) e as entradas deste app no `settings.json` do Claude Code ([`settings`]).
//!
//! **Onde:** consumido por `sshkeys`, `vps` e `mcp`. É a única coisa que eles usam de fora do
//! próprio domínio.
//!
//! ## Por que é uma cópia do que existe no `schematize_cli_rs`
//!
//! O ADR-0010 decidiu que o Deployer **abre e funciona sozinho**. Depender do crate do
//! schematize para chamar `home()` amarraria os dois apps e mataria essa propriedade — o
//! Deployer não instalaria sem o schematize, que é o oposto do pedido.
//!
//! A alternativa seria um quinto repositório só com estas ~600 linhas de infraestrutura. Sai
//! mais caro que a cópia: mais um repo para versionar, testar, lançar e pinar, e o piso 11
//! ainda cobra um `<projeto>_ops` que este workspace não tem.
//!
//! **O que NÃO está aqui, e é o ponto:** nada de domínio. O piso 6 veta `commons` de
//! DOMÍNIO, e isto é plataforma — `home()`, `run()`, `chmod`. Se um dia entrar aqui algo que
//! saiba o que é uma skill, um host ou uma chave, o corte foi feito errado.

pub mod bin;
pub mod config;
pub mod i18n;
pub mod redacao;
pub mod settings;
pub mod util;
