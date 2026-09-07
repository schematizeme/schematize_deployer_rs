//! COFRE — o segredo do Deployer em repouso, ilegível para quem tem o disco.
//!
//! **O quê:** [`cripto`] é a criptografia pura (Argon2id + XChaCha20-Poly1305);
//! [`arquivo`] põe e tira do disco com escrita atômica.
//!
//! **Onde:** é a **fase 3** do ADR-0010 — a única que entrega o objetivo que motivou separar
//! o Deployer. As fases anteriores entregaram arquitetura; esta entrega a barreira.
//!
//! ## Contra quem este cofre defende, e contra quem NÃO defende
//!
//! **Defende contra quem tem o arquivo:** um agente com `Bash` que faz `cat`, um backup que
//! vazou, um disco roubado. Para todos eles o cofre é ruído — sem a passphrase não há o que
//! ler, e o Argon2id torna adivinhá-la caro.
//!
//! **NÃO defende contra quem está no processo destravado.** Enquanto o cofre está aberto, a
//! chave existe em memória; quem tiver `ptrace` no processo, ou executar código dentro dele,
//! alcança. Isso não é conserto pendente — é o limite de qualquer cofre de desktop, e está
//! escrito aqui para que ninguém suponha o contrário. O que reduz essa janela é o auto-lock,
//! não uma promessa.

pub mod arquivo;
pub mod cripto;
