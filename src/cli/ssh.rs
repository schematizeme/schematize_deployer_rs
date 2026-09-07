//! Subcomandos de CHAVES SSH, mais a confirmação interativa que eles usam.

use crate::cli::args::*;
use deployer::i18n::{t, tf};
use deployer::sshkeys;
use std::io::Write;
use std::io::{self, BufRead};

/// Confirmação interativa (y/N). Falha fechada: erro/EOF/qualquer coisa ≠ sim = não.
pub(crate) fn confirm(prompt: &str) -> bool {
    print!("{prompt} ");
    let _ = io::stdout().flush();
    let mut line = String::new();
    if io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_lowercase().as_str(), "y" | "yes" | "s" | "sim")
}

/// `schematize ssh <sub>` — gestão de chaves SSH. Nunca imprime a chave privada.
pub(crate) fn ssh_cmd(sub: SshCmd) -> Result<(), String> {
    match sub {
        SshCmd::Gen { name, rsa, comment, github, agent, force } => {
            let kind = if rsa { sshkeys::KeyKind::Rsa4096 } else { sshkeys::KeyKind::Ed25519 };
            let info = sshkeys::generate(&name, kind, comment.as_deref(), None, force)?;
            println!("{}", tf("ssh.generated", &[("name", &info.name), ("kind", &info.kind)]));
            println!("{}", tf("ssh.fingerprint", &[("fp", &info.fingerprint)]));
            // Prova de entropia: nível de segurança + linha do ssh-keygen -l (bits + tipo).
            println!("entropia: {}", sshkeys::entropy_note(kind));
            if let Ok(proof) = sshkeys::proof_line(&name) {
                println!("prova (ssh-keygen -l): {proof}");
            }
            if agent {
                if sshkeys::add_to_agent(&name) {
                    println!("{}", t("ssh.agent_ok"));
                } else {
                    println!("{}", t("ssh.agent_fail"));
                }
            }
            if github {
                match sshkeys::add_to_github(&name) {
                    Ok(()) => println!("{}", tf("ssh.github_ok", &[("name", &name)])),
                    Err(e) => eprintln!("{}", tf("err.prefix", &[("e", &e)])),
                }
            }
            Ok(())
        }
        SshCmd::Import { file, name, passphrase, comment, force } => {
            let origem = std::path::Path::new(&file);
            // Sem --name, herda o nome do arquivo de origem: `~/backup/deploy` vira `deploy`.
            // É o que a pessoa espera, e evita obrigá-la a repetir o nome que já digitou.
            let nome = match name {
                Some(n) => n,
                None => {
                    origem.file_stem().and_then(|s| s.to_str()).map(str::to_string).ok_or_else(
                        || format!("não consegui deduzir o nome de {file} — use --name"),
                    )?
                }
            };
            let info =
                sshkeys::import(origem, &nome, passphrase.as_deref(), comment.as_deref(), force)?;
            println!("{}", tf("ssh.imported", &[("name", &info.name), ("kind", &info.kind)]));
            println!("{}", tf("ssh.fingerprint", &[("fp", &info.fingerprint)]));
            // A prova vem do ssh-keygen -l sobre o que FICOU em ~/.ssh, não do que a gente
            // acha que copiou: é o que distingue "importei" de "importei certo".
            if let Ok(proof) = sshkeys::proof_line(&info.name) {
                println!("prova (ssh-keygen -l): {proof}");
            }
            Ok(())
        }
        SshCmd::List => {
            let keys = sshkeys::list();
            if keys.is_empty() {
                println!("{}", t("ssh.list_empty"));
                return Ok(());
            }
            println!("{}", t("ssh.list_header"));
            for k in keys {
                println!("  {:<20} {:<8} {}  {}", k.name, k.kind, k.fingerprint, k.comment);
            }
            Ok(())
        }
        SshCmd::Export { name, copy, bitwarden, out } => {
            // --bitwarden: exporta pro cofre/arquivo (NUNCA imprime a privada).
            if bitwarden {
                let out_path = out.as_deref().map(std::path::Path::new);
                let msg = sshkeys::export_bitwarden(&name, out_path)?;
                println!("{msg}");
                return Ok(());
            }
            let pubkey = sshkeys::export_public(&name)?;
            println!("{pubkey}");
            if copy {
                if sshkeys::copy_to_clipboard(&pubkey) {
                    println!("{}", t("ssh.copied"));
                } else {
                    eprintln!("{}", t("ssh.copy_fail"));
                }
            }
            Ok(())
        }
        SshCmd::Run { name, target, command } => {
            // Deploy sem chave inline: usa a privada gerenciada só via `-i` (nunca a imprime).
            let code = sshkeys::run_ssh(&name, &target, &command)?;
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
        SshCmd::Authorize { name, target } => {
            sshkeys::authorize(&name, &target)?;
            println!("chave pública '{name}' instalada em {target}:~/.ssh/authorized_keys");
            println!("teste o acesso: schematize ssh run {name} {target} -- 'echo ok'");
            Ok(())
        }
        SshCmd::Rm { name } => {
            sshkeys::valid_name(&name)?;
            if !confirm(&tf("ssh.confirm_rm", &[("name", &name)])) {
                println!("{}", t("ssh.aborted"));
                return Ok(());
            }
            sshkeys::remove(&name)?;
            println!("{}", tf("ssh.removed", &[("name", &name)]));
            Ok(())
        }
        SshCmd::Github { name } => {
            sshkeys::add_to_github(&name)?;
            println!("{}", tf("ssh.github_ok", &[("name", &name)]));
            Ok(())
        }
    }
}
