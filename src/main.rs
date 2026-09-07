//! **deployer** — o binário de linha de comando do schematize Deployer.
//!
//! **O quê:** despacha `deployer ssh|vps|mcp <sub>` e traduz o erro num código de saída.
//!
//! **Onde:** ponto de entrada. Instalado sozinho, ou pelo schematize quando os dois convivem
//! (ADR-0010).
//!
//! ## Por que o erro sai por `Result` e não por `panic`
//!
//! Este binário é chamado por três bocas: a pessoa no terminal, a GUI, e o **schematize pela
//! ponte de subprocesso**. As três leem o **código de saída** — a ponte, em especial, decide
//! por ele. Um `panic` daria 101 para tudo e apagaria a diferença entre "host não existe" e
//! "o banco está corrompido".

mod cli;

use clap::Parser;
use cli::args::{Cli, Cmd};

/// **O quê:** devolve o `SIGPIPE` ao comportamento padrão do Unix.
///
/// **Onde:** primeira linha do [`main`].
///
/// **Por que é preciso:** o runtime do Rust põe `SIGPIPE` em `SIG_IGN`. Com isso, escrever
/// num pipe fechado deixa de matar o processo silenciosamente (como faz todo utilitário
/// Unix) e passa a devolver `EPIPE` — que o `println!` transforma em **panic**. O resultado
/// é que `deployer vps list | head -2` termina com um despejo de panic em vez de simplesmente
/// terminar.
///
/// `cmd | head` é uso corriqueiro, não exótico: §37.48 — quebrar por invocação não prevista é
/// bug do software, não erro de quem digitou.
///
/// **Segurança:** `unsafe` porque `signal` é FFI. É a chamada padrão para isto, feita antes
/// de qualquer thread existir, e não toca em estado do programa.
#[cfg(unix)]
fn restaurar_sigpipe() {
    // SAFETY: chamada única, antes de qualquer thread, restaurando o handler padrão do SO.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn restaurar_sigpipe() {}

fn main() {
    restaurar_sigpipe();
    let cli = Cli::parse();
    let r = match cli.cmd {
        Cmd::Ssh { sub } => cli::ssh::ssh_cmd(sub),
        Cmd::Vps { sub } => cli::vps::vps_cmd(sub),
        Cmd::Mcp { sub } => cli::mcp::mcp_cmd(sub),
        Cmd::Cofre { sub } => cli::cofre::cofre_cmd(sub),
    };
    if let Err(e) = r {
        eprintln!("erro: {e}");
        std::process::exit(1);
    }
}
