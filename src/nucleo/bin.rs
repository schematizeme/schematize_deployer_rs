//! NÚCLEO — achar binário fora do `$PATH` e abrir terminal do sistema.
//!
//! **O quê:** [`resolve_bin`] resolve o caminho ABSOLUTO de um executável varrendo o `$PATH`
//! e depois diretórios de fallback; [`abrir_comando_no_terminal`] lança um comando num
//! emulador de terminal, desacoplado deste processo.
//!
//! **Onde:** `vps::exec` (`resolve_bin("ssh")`) e `vps::conexao::abrir_no_terminal` (o botão
//! "Abrir no terminal").
//!
//! ## Por que este arquivo é uma cópia, e não uma dependência
//!
//! No `schematize_cli_rs` isto vive em `agentrun/lancador.rs`, junto do lançador do
//! **agente** (`claude`) — que o Deployer não tem e não quer ter. Depender daquele crate
//! amarraria o Deployer ao schematize e mataria a razão dele existir: **abrir e funcionar
//! sozinho** (ADR-0010).
//!
//! A duplicação é deliberada e pequena: são ~80 linhas de infraestrutura de plataforma,
//! estáveis (a última mudança foi acrescentar o OpenSSH do Windows). O piso 6 veta
//! `commons` **de domínio**; isto é infraestrutura, e a alternativa — um quinto repo só para
//! `resolve_bin` — sairia mais cara que a cópia.
//!
//! **Se divergir, o certo é este lado:** o `resolve_bin` do schematize existe para achar o
//! `claude`; aqui ele existe para achar o `ssh`, que é o caminho quente do produto.

use std::path::{Path, PathBuf};

/// Emuladores de terminal tentados, em ordem de preferência.
const TERMINAIS: [&str; 7] = [
    "konsole",
    "gnome-terminal",
    "xfce4-terminal",
    "x-terminal-emulator",
    "alacritty",
    "kitty",
    "xterm",
];

/// **O quê:** diretórios onde ferramenta de usuário cai, mas que o `$PATH` de um processo
/// aberto pelo LANÇADOR DO DESKTOP não inclui — o desktop não lê `~/.profile`/`~/.bashrc`.
///
/// **Onde:** [`resolve_bin`]. É o que faz o app achar o `ssh` mesmo aberto pelo menu de apps.
fn fallback_bin_dirs() -> Vec<PathBuf> {
    // `nucleo::util::home()` e não `env HOME`: no Windows a variável é outra, e a resolução
    // certa mora num lugar só.
    let h = super::util::home();
    let mut dirs = vec![h.join(".local/bin"), h.join(".claude/local"), h.join(".cargo/bin")];
    #[cfg(windows)]
    {
        // O OpenSSH do Windows vem aqui desde o Windows 10 1803, e NÃO está no PATH de todo
        // perfil — sem este fallback, o `vps exec` falha em máquina recém-instalada.
        if let Some(sysroot) = std::env::var_os("SystemRoot") {
            let sr = PathBuf::from(sysroot);
            dirs.push(sr.join("System32").join("OpenSSH"));
            dirs.push(sr.join("SysNative").join("OpenSSH"));
        }
        for pf in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
            if let Some(d) = std::env::var_os(pf) {
                dirs.push(PathBuf::from(d).join("OpenSSH"));
            }
        }
    }
    dirs.push(PathBuf::from("/usr/local/bin"));
    dirs.push(PathBuf::from("/usr/bin"));
    dirs.push(PathBuf::from("/opt/homebrew/bin"));
    dirs.push(PathBuf::from("/usr/local/opt/openssh/bin"));
    dirs
}

/// **O quê:** a REGRA de quais nomes de arquivo um executável pode ter, com a plataforma
/// como PARÂMETRO em vez de `#[cfg]`.
///
/// **Onde:** [`nomes_de_executavel`] em produção, e os testes com os dois valores.
///
/// **Por que a plataforma é argumento:** a versão original era `#[cfg(windows)]`, então no
/// Linux o corpo nem compilava e **nenhum teste o alcançava** — o mutation testing flagrou
/// que desligar a correção do Windows não quebrava teste nenhum. `cfg` deve escolher DADO,
/// não esconder LÓGICA.
pub fn nomes_de_executavel_em(bin: &str, windows: bool) -> Vec<String> {
    if !windows {
        return vec![bin.to_string()];
    }
    // Já veio com extensão: respeita o que o chamador pediu.
    if bin.contains('.') {
        return vec![bin.to_string()];
    }
    let mut v = vec![bin.to_string()];
    for ext in [".exe", ".cmd", ".bat", ".com"] {
        v.push(format!("{bin}{ext}"));
    }
    v
}

/// **O quê:** os nomes que `bin` pode ter NESTE sistema. **Onde:** [`resolve_bin`].
fn nomes_de_executavel(bin: &str) -> Vec<String> {
    nomes_de_executavel_em(bin, cfg!(windows))
}

/// **O quê:** caminho ABSOLUTO de `bin` — primeiro no `$PATH`, depois nos de fallback.
/// `None` se não achar em lugar nenhum.
///
/// **Onde:** `vps::exec` (o `ssh` de todo `vps exec`) e [`binary_in_path`].
pub fn resolve_bin(bin: &str) -> Option<PathBuf> {
    for dir in std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .chain(fallback_bin_dirs())
    {
        for nome in nomes_de_executavel(bin) {
            let p = dir.join(&nome);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

/// **O quê:** `true` se `bin` existe no `$PATH` ou nos fallbacks — checagem barata para dar
/// erro claro antes de tentar spawnar algo inexistente. **Onde:** [`spawn_no_terminal`].
pub fn binary_in_path(bin: &str) -> bool {
    resolve_bin(bin).is_some()
}

/// **O quê:** abre um COMANDO arbitrário num terminal do sistema, desacoplado deste processo.
///
/// **Onde:** `vps::conexao::abrir_no_terminal`.
///
/// Envolve o comando num script temporário porque é isso que [`spawn_no_terminal`] sabe
/// lançar em todos os emuladores — cada um recebe comando de um jeito, e o script normaliza.
pub fn abrir_comando_no_terminal(comando: &str) -> Result<String, String> {
    let dir = super::util::home_app_dir().join("run");
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("não consegui criar {}: {e}", dir.display()))?;
    let script = dir.join(format!("term-{}.sh", std::process::id()));
    // `exec` no fim: o shell do wrapper some e o terminal fica com o processo de verdade,
    // então fechar a janela encerra a sessão em vez de deixar um ssh órfão.
    std::fs::write(&script, format!("#!/bin/sh\nexec {comando}\n"))
        .map_err(|e| format!("não consegui gravar {}: {e}", script.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700));
    }
    spawn_no_terminal(&script)
}

/// **O quê:** lança `script` no primeiro emulador de terminal disponível, em grupo de
/// processos próprio. **Saída:** o nome do terminal usado. **Efeitos:** cria processo.
fn spawn_no_terminal(script: &Path) -> Result<String, String> {
    let term = TERMINAIS.iter().find(|t| binary_in_path(t)).ok_or_else(|| {
        "nenhum terminal encontrado (konsole/gnome-terminal/xterm/…).".to_string()
    })?;
    let mut cmd = std::process::Command::new(term);
    match *term {
        // esses usam `--` pra separar o comando a executar
        "gnome-terminal" | "xfce4-terminal" => {
            cmd.arg("--").arg("bash").arg(script);
        }
        _ => {
            cmd.arg("-e").arg("bash").arg(script);
        }
    }
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0); // desacopla do app: sobrevive se o app fechar
    }
    cmd.spawn().map_err(|e| format!("abrir terminal `{term}`: {e}"))?;
    Ok((*term).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A regra do Windows é verificável no Linux porque a plataforma é ARGUMENTO. Era
    /// `#[cfg(windows)]` e por isso nenhum teste a alcançava.
    #[test]
    fn nomes_de_executavel_cobre_pathext_no_windows() {
        assert_eq!(nomes_de_executavel_em("ssh", false), vec!["ssh"]);
        let w = nomes_de_executavel_em("ssh", true);
        assert!(w.contains(&"ssh.exe".to_string()), "sem .exe o vps exec não acha o ssh: {w:?}");
        assert_eq!(w[0], "ssh", "o nome nu vem primeiro");
        // Já veio com extensão: respeita, não empilha.
        assert_eq!(nomes_de_executavel_em("ssh.exe", true), vec!["ssh.exe"]);
    }

    /// `resolve_bin` devolve caminho ABSOLUTO e existente — ou `None`, nunca um palpite.
    #[test]
    fn resolve_bin_da_absoluto_ou_nada() {
        match resolve_bin("sh") {
            Some(p) => {
                assert!(p.is_absolute(), "tem de ser absoluto: {}", p.display());
                assert!(p.is_file());
            }
            None => panic!("`sh` tem de existir em qualquer unix"),
        }
        assert!(resolve_bin("binario-que-nao-existe-em-lugar-nenhum-42").is_none());
    }
}
