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

fn main() {
    let cli = Cli::parse();
    let r = match cli.cmd {
        Cmd::Ssh { sub } => cli::ssh::ssh_cmd(sub),
        Cmd::Vps { sub } => cli::vps::vps_cmd(sub),
        Cmd::Mcp { sub } => cli::mcp::mcp_cmd(sub),
    };
    if let Err(e) = r {
        eprintln!("erro: {e}");
        std::process::exit(1);
    }
}
