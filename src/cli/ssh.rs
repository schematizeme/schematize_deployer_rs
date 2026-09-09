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
            println!("{}", tf("cli.ssh.entropy", &[("note", &sshkeys::entropy_note(kind))]));
            if let Ok(proof) = sshkeys::proof_line(&name) {
                println!("{}", tf("cli.ssh.proof", &[("proof", &proof)]));
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
        SshCmd::Import { file, paste, name, passphrase, comment, force } => {
            // Colagem e arquivo são caminhos IRMÃOS: os dois desembocam no mesmo
            // `gravar_e_validar` (temporário em 600, validação pelo ssh-keygen, rename
            // atômico). O que muda é só de onde vêm os bytes.
            //
            // `--paste` explícito vence; sem arquivo e sem flag, colar é a única leitura
            // possível do pedido — negar ali seria pedir uma flag para dizer o óbvio.
            let info = match file {
                Some(f) if !paste => {
                    let origem = std::path::Path::new(&f);
                    // Sem --name, herda o nome do arquivo: `~/backup/deploy` vira `deploy`. É
                    // o que a pessoa espera, e não a obriga a repetir o nome que já digitou.
                    let nome = match name {
                        Some(n) => n,
                        None => origem
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .map(str::to_string)
                            .ok_or_else(|| {
                                format!("não consegui deduzir o nome de {f} — use --name")
                            })?,
                    };
                    sshkeys::import(
                        origem,
                        &nome,
                        passphrase.as_deref(),
                        comment.as_deref(),
                        force,
                    )?
                }
                _ => {
                    // Colando não há arquivo de onde herdar o nome, então ele é pedido.
                    let nome = name.ok_or(
                        "colando a chave eu não tenho de onde tirar o nome — use --name <nome>",
                    )?;
                    let texto = ler_chave_colada()?;
                    sshkeys::import_texto(
                        &texto,
                        &nome,
                        passphrase.as_deref(),
                        comment.as_deref(),
                        force,
                    )?
                }
            };
            println!("{}", tf("ssh.imported", &[("name", &info.name), ("kind", &info.kind)]));
            println!("{}", tf("ssh.fingerprint", &[("fp", &info.fingerprint)]));
            // A prova vem do ssh-keygen -l sobre o que FICOU em ~/.ssh, não do que a gente
            // acha que copiou: é o que distingue "importei" de "importei certo".
            if let Ok(proof) = sshkeys::proof_line(&info.name) {
                println!("{}", tf("cli.ssh.proof", &[("proof", &proof)]));
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
            println!("{}", tf("cli.ssh.installed", &[("name", &name), ("target", &target)]));
            println!("{}", tf("cli.ssh.test_access", &[("name", &name), ("target", &target)]));
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

/// **O quê:** lê a chave privada COLADA da entrada padrão, até o fim.
///
/// **Onde:** `ssh import --paste`.
///
/// ## Por que stdin, e não um argumento
///
/// Uma chave privada passada como `--private "-----BEGIN…"` fica no histórico do shell, aparece
/// no `ps` para qualquer usuário da máquina e entra no log de quem audita comando. Por stdin
/// não deixa nenhum desses rastros.
///
/// **Não ecoa nem confirma o conteúdo.** Imprimir de volta o que foi colado poria a chave
/// privada no scrollback do terminal — que é gravado, copiado e às vezes compartilhado num
/// print. A confirmação que a pessoa recebe é o fingerprint da chave já importada, e ele é
/// público.
///
/// **Sem tty a leitura continua valendo:** é assim que `… | schematize-deployer ssh import
/// --paste --name k` funciona, e é o caminho que a janela usa.
fn ler_chave_colada() -> Result<String, String> {
    use std::io::{IsTerminal, Read};
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        eprintln!("{}", t("ssh.paste_prompt"));
        eprintln!("{}", t("ssh.paste_hint"));
    }
    let mut buf = String::new();
    stdin.lock().read_to_string(&mut buf).map_err(|e| format!("não consegui ler a chave: {e}"))?;
    if buf.trim().is_empty() {
        return Err("não veio nada pela entrada — cole a chave e termine com Ctrl-D".into());
    }
    Ok(buf)
}
