//! USO da chave: exportar a pública, copiar pro clipboard, somar ao agente, ao
//! GitHub, e rodar/autorizar ssh num alvo.

use super::*;

/// Devolve o conteúdo da chave PÚBLICA (pra colar no GitHub/servidor). Só a pública.
pub fn export_public(name: &str) -> Result<String, String> {
    let pub_p = public_path(name)?;
    let body = fs::read_to_string(&pub_p)
        .map_err(|_| format!("chave pública '{name}' não encontrada em ~/.ssh"))?;
    Ok(body.trim().to_string())
}

/// Copia um texto pro clipboard via `wl-copy` (Wayland) ou `xclip` (X11). Best-effort:
/// devolve true se algum copiador existia e rodou. Usado só com a PÚBLICA.
pub fn copy_to_clipboard(text: &str) -> bool {
    use std::io::Write;
    use std::process::{Command, Stdio};
    for (bin, args) in [("wl-copy", &[][..]), ("xclip", &["-selection", "clipboard"][..])] {
        let child = Command::new(bin)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        if let Ok(mut c) = child {
            if let Some(mut stdin) = c.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            if c.wait().map(|s| s.success()).unwrap_or(false) {
                return true;
            }
        }
    }
    false
}

/// Adiciona a chave ao `ssh-agent` (`ssh-add`). Best-effort: devolve true se rodou ok.
pub fn add_to_agent(name: &str) -> bool {
    let priv_p = match private_path(name) {
        Ok(p) => p,
        Err(_) => return false,
    };
    if !priv_p.exists() {
        return false;
    }
    util::run("ssh-add", &[&priv_p.to_string_lossy()]).is_ok()
}

/// Adiciona a chave PÚBLICA à conta do GitHub do usuário via `gh ssh-key add`.
/// Exige `gh` instalado e autenticado (erro claro caso contrário).
pub fn add_to_github(name: &str) -> Result<(), String> {
    let pub_p = public_path(name)?;
    if !pub_p.exists() {
        return Err(format!("chave pública '{name}' não encontrada em ~/.ssh"));
    }
    // Checa autenticação do gh antes de tentar (mensagem clara se faltar).
    if util::run("gh", &["auth", "status"]).is_err() {
        return Err("gh não está autenticado (ou não instalado) — rode `gh auth login` primeiro"
            .to_string());
    }
    util::run("gh", &["ssh-key", "add", &pub_p.to_string_lossy(), "--title", name])
        .map(|_| ())
        .map_err(|e| format!("gh ssh-key add falhou: {e}"))
}

/// Valida um alvo `user@host` (ou `host`) do ssh. Falha fechada: não-vazio, sem espaço e
/// SEM começar por `-` (senão o ssh interpretaria como opção — injeção de flag).
pub(crate) fn valid_target(target: &str) -> Result<(), String> {
    let t = target.trim();
    if t.is_empty() || t.starts_with('-') || t.chars().any(|c| c.is_whitespace()) {
        return Err(format!("alvo ssh inválido: {target:?} (use user@host)"));
    }
    Ok(())
}

/// Roda `ssh -i <privada gerenciada> <alvo> [comando...]` HERDANDO o terminal (stdin/out/err).
/// Sem comando → sessão interativa. A chave é referenciada só pelo CAMINHO (`-i`): o conteúdo da
/// privada NUNCA é lido nem impresso. `IdentitiesOnly=yes` força usar só a nossa chave.
/// Retorna o exit code do ssh (128+sinal se morto por sinal).
///
/// **`StrictHostKeyChecking=yes`, não `accept-new`.** Este é o caminho de DEPLOY: aceitar host
/// novo sem perguntar (TOFU cego) significa que a primeira conexão — justamente a que
/// estabelece a confiança — aceita qualquer um que atenda no endereço. Host desconhecido agora
/// falha com mensagem que ensina como confiar. Ver ADR-0005 e `vps::conexao`.
pub fn run_ssh(name: &str, target: &str, args: &[String]) -> Result<i32, String> {
    use std::process::Command;
    let key = key_path(name)?;
    if !key.exists() {
        return Err(format!(
            "chave privada '{name}' não encontrada em ~/.ssh — gere com `schematize ssh gen {name}`"
        ));
    }
    valid_target(target)?;
    let mut cmd = Command::new("ssh");
    cmd.arg("-i")
        .arg(&key)
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg("StrictHostKeyChecking=yes")
        .arg(target);
    // `--` não vai: o ssh já trata tudo após o alvo como o comando remoto.
    for a in args {
        cmd.arg(a);
    }
    let status = cmd.status().map_err(|e| format!("falha ao executar ssh: {e}"))?;
    // Exit 255 é do PRÓPRIO ssh (não do comando remoto) — e o motivo mais comum, agora que
    // o TOFU cego saiu, é host ainda não conhecido. Erro acionável em vez de "saiu 255".
    if status.code() == Some(255) {
        eprintln!(
            "dica: se o host é novo, a chave dele ainda não está no ~/.ssh/known_hosts. Confira a \n\
             fingerprint com `ssh-keyscan {target} | ssh-keygen -lf -` e, se conferir, registre o host \n\
             em `schematize vps add` + `schematize vps trust` — que pina a chave e audita o acesso."
        );
    }
    // code() é None quando morto por sinal — reporta 128+sinal (convenção shell) ou 1.
    Ok(status.code().unwrap_or(1))
}

/// Instala a chave PÚBLICA no `~/.ssh/authorized_keys` do host remoto (bootstrap de acesso).
/// Requer que você JÁ tenha acesso ao host (outra chave/senha/agent). Usa `ssh-copy-id -i <pub>`
/// se existir (melhor: lida com prompt de senha), senão faz append por ssh (pública via stdin).
/// Só a PÚBLICA é enviada — a privada nunca sai.
///
/// **O `accept-new` fica só neste atalho de compatibilidade.** Esta assinatura é a de PRIMEIRO
/// CONTATO usada pelo `schematize ssh authorize`, que não tem registro de host onde pinar nada.
///
/// **O gestor de VPS NÃO passa por aqui.** O `schematize vps authorize` faz o TOFU explícito —
/// colhe a host key, mostra a fingerprint, pede o aceite, grava o `known_hosts` do perfil — e
/// só então chama [`authorize_com_opcoes`] com `StrictHostKeyChecking=yes`. Ou seja: no caminho
/// que o agente usa, não existe TOFU cego em momento nenhum, nem no bootstrap.
pub fn authorize(name: &str, target: &str) -> Result<(), String> {
    authorize_com_opcoes(name, target, &["StrictHostKeyChecking=accept-new".to_string()])
}

/// Como [`authorize`], mas com as opções `-o` do `ssh` escolhidas pelo chamador.
///
/// **Existe para tirar o `accept-new` do caminho do gestor de VPS.** O `vps authorize` pina a
/// host key ANTES (mostrando a fingerprint para o humano conferir) e passa
/// `StrictHostKeyChecking=yes` mais o `known_hosts` do perfil — assim o bootstrap de acesso
/// deixa de ter TOFU cego, sem que o `schematize ssh authorize` (que não tem registro de host
/// para pinar) precise mudar.
///
/// **Onde:** [`authorize`] (compat, com `accept-new`) e `cli::vps::autorizar` (pinado).
pub fn authorize_com_opcoes(name: &str, target: &str, opcoes: &[String]) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let pub_p = public_path(name)?;
    if !pub_p.exists() {
        return Err(format!("chave pública '{name}' não encontrada em ~/.ssh"));
    }
    valid_target(target)?;

    // Caminho feliz: ssh-copy-id (herda o terminal pra pedir senha de bootstrap se preciso).
    if in_path("ssh-copy-id") {
        let mut cmd = Command::new("ssh-copy-id");
        cmd.arg("-i").arg(&pub_p);
        for o in opcoes {
            cmd.arg("-o").arg(o);
        }
        let status =
            cmd.arg(target).status().map_err(|e| format!("falha ao executar ssh-copy-id: {e}"))?;
        return if status.success() {
            Ok(())
        } else {
            Err(format!("ssh-copy-id falhou (exit {})", status.code().unwrap_or(-1)))
        };
    }

    // Fallback: append remoto por ssh, com a pública entrando pelo stdin (umask 077).
    let pubkey =
        fs::read_to_string(&pub_p).map_err(|e| format!("não consegui ler a pública: {e}"))?;
    let remote = "umask 077; mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys";
    let mut ssh = Command::new("ssh");
    for o in opcoes {
        ssh.arg("-o").arg(o);
    }
    let mut child = ssh
        .arg(target)
        .arg(remote)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("falha ao executar ssh: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(pubkey.trim_end().as_bytes())
            .and_then(|_| stdin.write_all(b"\n"))
            .map_err(|e| format!("falha ao enviar a pública: {e}"))?;
    }
    let status = child.wait().map_err(|e| format!("ssh não finalizou: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("append remoto falhou (exit {})", status.code().unwrap_or(-1)))
    }
}

/// `true` se um binário está no PATH (via `which`). Best-effort.
pub(crate) fn in_path(bin: &str) -> bool {
    std::process::Command::new("which")
        .arg(bin)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Roda um comando alimentando `input` pelo stdin e capturando o stdout. Usado pelo fluxo do `bw`
/// (`bw encode`). Erro traz o stderr. A privada passa por aqui só rumo ao `bw` (nunca é impressa).
pub(crate) fn run_with_stdin(cmd: &str, args: &[&str], input: &str) -> Result<String, String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("falha ao executar {cmd}: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input.as_bytes())
            .map_err(|e| format!("falha ao escrever no stdin de {cmd}: {e}"))?;
    }
    let out = child.wait_with_output().map_err(|e| format!("{cmd} não finalizou: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!("{cmd} falhou: {}", String::from_utf8_lossy(&out.stderr).trim()))
    }
}
