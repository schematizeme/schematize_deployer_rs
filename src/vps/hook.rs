//! HOOK `PreToolUse` — barra o SSH cru e a leitura de chave privada no Bash do agente.
//! O quê: [`guard`] lê o evento do Claude Code no stdin e imprime o veredito; o miolo é a
//! função pura [`avaliar_tool_use`].
//! Onde: registrado em `settings.json` por `schematize vps hooks --on`, disparado pelo Claude
//! Code a cada tool use.
//!
//! ## Por que este arquivo é o que resolve a dor
//! O `vps::politica` e a auditoria só valem se o agente USAR a porta certa. Nada o obrigava:
//! ele tem `Bash`, e `Bash` tem `ssh`. Este hook fecha as duas rotas conhecidas de vazamento
//! — o agente **colar** uma chave e o agente **ler** `~/.ssh/id_*` — e empurra todo acesso
//! remoto para `schematize vps exec`, que audita.
//!
//! ## Falha ABERTA, de propósito
//! Ao contrário da política (deny-by-default), um hook que não entende a entrada **libera**.
//! A razão é o §37.48: um hook que trava por um JSON inesperado quebra TODA tool use do
//! usuário, inclusive as que nada têm a ver com SSH. O hook é uma rede contra acidente, não
//! a fronteira — a fronteira é o forced command no servidor (ADR-0005).

use serde_json::Value;

/// Cabeçalhos de bloco de chave privada. Qualquer um deles em qualquer campo de qualquer tool
/// é recusa imediata: significa que uma privada entrou no contexto do agente.
const CABECALHOS_DE_CHAVE: &[&str] = &[
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "PuTTY-User-Key-File-",
];

/// Binários de acesso remoto que o agente não roda direto. `ssh-keygen`/`ssh-add` ficam de
/// fora de propósito: não conectam em lugar nenhum e são justamente o que o `sshkeys` usa.
const BINARIOS_BARRADOS: &[(&str, &str)] = &[
    ("ssh", "abre sessão remota sem auditoria"),
    ("scp", "copia arquivo pra máquina remota sem auditoria"),
    ("sftp", "abre transferência remota sem auditoria"),
    ("ssh-copy-id", "instala chave em host remoto sem registro"),
    ("sshpass", "passa senha de SSH em linha de comando — a senha vaza no log e no ps"),
    ("autossh", "abre sessão remota sem auditoria"),
    ("dbclient", "cliente SSH alternativo, mesma rota"),
    ("plink", "cliente SSH alternativo, mesma rota"),
];

/// Separadores de comando: cada pedaço tem seu próprio "primeiro token".
/// Sem isto, `uptime; ssh root@host` passaria por só olhar o começo da linha.
const SEPARADORES: &[char] = &[';', '&', '|', '\n', '\r'];

/// Mensagem de recusa — **acionável e sem culpa** (§37.48). Diz o que fazer, não o que a
/// pessoa (ou o agente) fez de errado.
fn como_fazer_certo(motivo: &str) -> String {
    format!(
        "Acesso remoto direto está desligado neste projeto ({motivo}).\n\
         \n\
         Use a porta auditada, que faz a mesma coisa e grava o log:\n\
           schematize vps list                      — os hosts registrados\n\
           schematize vps exec <alias> -- <comando> — roda e audita\n\
           schematize vps logs <alias>              — o que já rodou\n\
         \n\
         Host ainda não registrado? `schematize vps add <alias> --host <ip> --user <user> --key <chave>`, \
         depois `schematize vps trust <alias>` pra confiar na host key.\n\
         A chave privada nunca precisa entrar nesta conversa: o `vps` a referencia por caminho."
    )
}

/// Primeiro token de cada segmento do comando, em minúsculo e sem caminho.
///
/// **Onde:** [`comando_barrado`]. Extrai `ssh` de `/usr/bin/ssh`, de `uptime && ssh x` e de
/// `env FOO=1 ssh x`.
pub fn binarios_invocados(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    for seg in cmd.split(SEPARADORES) {
        let mut toks = seg.split_whitespace().peekable();
        // Pula atribuições de env (`FOO=bar cmd`) e prefixos comuns.
        while let Some(t) = toks.peek() {
            let t = *t;
            // Atribuição de env (`FOO=bar cmd`) OU prefixo que só embrulha o binário real:
            // nos dois casos o token é descartado e o binário está mais adiante.
            let atribuicao = t.contains('=') && !t.starts_with('-');
            let prefixo =
                matches!(t, "env" | "sudo" | "nohup" | "time" | "exec" | "command" | "nice");
            if atribuicao || prefixo {
                toks.next();
            } else {
                break;
            }
        }
        if let Some(t) = toks.next() {
            // Tira aspas e barras invertidas de DENTRO do token, não só das pontas:
            // `\ssh`, `'ssh'`, `"ssh"` e `s"s"h` são todos o binário `ssh` para o shell,
            // e um filtro que compara o token cru deixa os quatro passarem. Achado no
            // pentest (P5) com `\ssh root@host`.
            let limpo: String =
                t.chars().filter(|c| !matches!(c, '"' | '\'' | '\\' | '(')).collect();
            let base = limpo.rsplit('/').next().unwrap_or(&limpo);
            if !base.is_empty() {
                out.push(base.to_ascii_lowercase());
            }
        }
    }
    out
}

/// O comando invoca um binário de acesso remoto direto? Devolve o motivo.
///
/// Não barra `schematize vps ...` nem `schematize ssh ...`: essas SÃO a porta certa.
pub fn comando_barrado(cmd: &str) -> Option<&'static str> {
    for bin in binarios_invocados(cmd) {
        if let Some((_, motivo)) = BINARIOS_BARRADOS.iter().find(|(b, _)| *b == bin) {
            return Some(motivo);
        }
    }
    // `rsync -e ssh` é um ssh disfarçado de cópia.
    let n = cmd.to_ascii_lowercase();
    if binarios_invocados(cmd).iter().any(|b| b == "rsync")
        && (n.contains("-e ssh") || n.contains("--rsh"))
    {
        return Some("rsync sobre SSH é sessão remota sem auditoria");
    }
    None
}

/// O caminho aponta pra uma chave privada?
///
/// **Onde:** a checagem de leitura, tanto pelo `Bash` (`cat ~/.ssh/id_ed25519`) quanto pelas
/// tools de arquivo (`Read`, `Edit`).
pub fn caminho_de_chave_privada(caminho: &str) -> bool {
    let c = caminho.to_ascii_lowercase();
    let nome = c.rsplit('/').next().unwrap_or(&c);
    // `.pub` é PÚBLICA — pode ler à vontade; é justamente o que se cola no servidor.
    if nome.ends_with(".pub") {
        return false;
    }
    if nome.ends_with(".pem") || nome.ends_with(".key") || nome.ends_with(".ppk") {
        return true;
    }
    if c.contains("/.ssh/") || c.starts_with("~/.ssh") || c.starts_with(".ssh/") {
        // Dentro de ~/.ssh, os arquivos de infra são lidos à vontade; o resto é chave.
        return !matches!(
            nome,
            "config" | "known_hosts" | "known_hosts.old" | "authorized_keys" | "environment"
        );
    }
    nome.starts_with("id_") && !nome.ends_with(".pub")
}

/// Um comando de shell está lendo uma chave privada?
pub fn comando_le_chave_privada(cmd: &str) -> bool {
    const LEITORES: &[&str] = &[
        "cat", "head", "tail", "less", "more", "bat", "xxd", "od", "base64", "strings", "cp",
        "openssl", "gpg", "curl", "nc", "tee", "awk", "sed", "grep",
    ];
    let bins = binarios_invocados(cmd);
    if !bins.iter().any(|b| LEITORES.contains(&b.as_str())) {
        return false;
    }
    cmd.split_whitespace().any(caminho_de_chave_privada)
}

/// **O miolo, puro.** Dado o nome da tool e o input dela, devolve `Some(motivo)` pra negar ou
/// `None` pra liberar.
///
/// **Onde:** [`guard`] em produção e os testes. Puro pra que a regra seja exercitável sem
/// simular o Claude Code.
pub fn avaliar_tool_use(tool_name: &str, input: &Value) -> Option<String> {
    // 1) Chave privada em QUALQUER campo de QUALQUER tool — inclusive um cole do usuário
    //    dentro de um Write, ou uma env var num Bash.
    let bruto = input.to_string();
    if let Some(h) = CABECALHOS_DE_CHAVE.iter().find(|h| bruto.contains(**h)) {
        return Some(format!(
            "Bloqueado: uma CHAVE PRIVADA ({h}) apareceu no input da tool `{tool_name}`.\n\
             \n\
             Chave privada não precisa entrar no contexto do agente em nenhuma hipótese. O `schematize` \
             já guarda a chave em ~/.ssh e a referencia por caminho:\n\
               schematize ssh list                      — as chaves gerenciadas\n\
               schematize vps exec <alias> -- <comando> — usa a chave sem lê-la\n\
             \n\
             Se esta chave veio de um cole: ela agora está no histórico desta conversa. Considere \
             rotacioná-la."
        ));
    }

    match tool_name {
        "Bash" | "BashOutput" => {
            let cmd = input.get("command").and_then(Value::as_str).unwrap_or("");
            if let Some(motivo) = comando_barrado(cmd) {
                return Some(como_fazer_certo(motivo));
            }
            if comando_le_chave_privada(cmd) {
                return Some(como_fazer_certo("o comando lê uma chave privada"));
            }
            None
        }
        "Read" | "Edit" | "Write" | "NotebookEdit" => {
            let caminho = input
                .get("file_path")
                .or_else(|| input.get("notebook_path"))
                .and_then(Value::as_str)
                .unwrap_or("");
            if !caminho.is_empty() && caminho_de_chave_privada(caminho) {
                return Some(como_fazer_certo("o arquivo é uma chave privada"));
            }
            None
        }
        // Tool desconhecida: a checagem de chave privada acima já rodou; o resto libera.
        _ => None,
    }
}

/// O hook em si: lê o evento no stdin, decide, imprime o veredito e sai 0.
///
/// **Onde:** `schematize vps guard`, registrado como `PreToolUse` no `settings.json`.
/// **Falha aberta:** stdin ilegível ou JSON inesperado = libera (ver o doc do módulo).
pub fn guard() {
    use std::io::Read;
    let mut buf = String::new();
    if std::io::stdin().read_to_string(&mut buf).is_err() {
        return; // libera
    }
    let Ok(v) = serde_json::from_str::<Value>(&buf) else {
        return; // libera
    };
    let tool = v.get("tool_name").and_then(Value::as_str).unwrap_or("");
    let input = v.get("tool_input").cloned().unwrap_or(Value::Null);
    if let Some(motivo) = avaliar_tool_use(tool, &input) {
        println!("{}", veredito_de_negacao(&motivo));
    }
}

/// Monta o JSON de negação no formato que o Claude Code espera.
///
/// **Onde:** [`guard`] e os testes — que asseram a FORMA do veredito sem rodar o hook.
pub fn veredito_de_negacao(motivo: &str) -> Value {
    serde_json::json!({
        "decision": "block",
        "reason": motivo,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": motivo
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bash(cmd: &str) -> Option<String> {
        avaliar_tool_use("Bash", &json!({ "command": cmd }))
    }

    #[test]
    fn ssh_cru_e_seus_primos_sao_barrados() {
        for cmd in [
            "ssh root@10.0.0.5",
            "ssh -i ~/.ssh/id_ed25519 deploy@host 'systemctl restart app'",
            "/usr/bin/ssh root@host",
            "scp arquivo.tar root@host:/srv/",
            "sftp deploy@host",
            "ssh-copy-id -i k.pub root@host",
            "sshpass -p senha ssh root@host",
            "rsync -avz -e ssh ./ root@host:/srv/",
            "autossh -M 0 root@host",
            "plink -ssh root@host",
        ] {
            let v = bash(cmd);
            assert!(v.is_some(), "{cmd:?} deveria ser barrado");
            assert!(
                v.unwrap().contains("schematize vps exec"),
                "a mensagem tem que ensinar a porta certa"
            );
        }
    }

    #[test]
    fn encadeamento_nao_esconde_o_ssh() {
        // Só olhar o começo da linha deixaria estes passarem.
        for cmd in [
            "uptime; ssh root@host",
            "cd /srv && ssh root@host",
            "echo oi || ssh root@host",
            "true\nssh root@host",
            "env FOO=1 ssh root@host",
            "sudo ssh root@host",
            "nohup ssh root@host",
        ] {
            assert!(bash(cmd).is_some(), "{cmd:?} deveria ser barrado");
        }
    }

    #[test]
    fn leitura_de_chave_privada_e_barrada_no_bash() {
        for cmd in [
            "cat ~/.ssh/id_ed25519",
            "head -5 /home/tom/.ssh/id_rsa",
            "base64 ~/.ssh/id_ed25519",
            "xxd ~/.ssh/deploy.pem",
            "cp ~/.ssh/id_ed25519 /tmp/x",
            "openssl rsa -in servidor.key -text",
        ] {
            assert!(bash(cmd).is_some(), "{cmd:?} deveria ser barrado");
        }
    }

    #[test]
    fn tool_de_arquivo_tambem_e_barrada() {
        assert!(
            avaliar_tool_use("Read", &json!({"file_path": "/home/tom/.ssh/id_ed25519"})).is_some()
        );
        assert!(avaliar_tool_use("Edit", &json!({"file_path": "~/.ssh/id_rsa"})).is_some());
        assert!(
            avaliar_tool_use("Read", &json!({"file_path": "/srv/certs/servidor.pem"})).is_some()
        );
    }

    #[test]
    fn chave_privada_em_qualquer_campo_de_qualquer_tool_e_barrada() {
        let chave =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNz\n-----END OPENSSH PRIVATE KEY-----";
        // Um Write com a chave no conteúdo.
        let v = avaliar_tool_use("Write", &json!({"file_path": "/tmp/k", "content": chave}));
        assert!(v.is_some(), "chave no conteúdo de um Write");
        assert!(v.unwrap().contains("rotacioná-la"), "a mensagem tem que avisar do risco");
        // Uma tool arbitrária, campo arbitrário.
        assert!(avaliar_tool_use("QualquerCoisa", &json!({"x": {"y": chave}})).is_some());
        // Formato PuTTY e RSA clássico.
        assert!(avaliar_tool_use(
            "Bash",
            &json!({"command": format!("echo '{}'", "-----BEGIN RSA PRIVATE KEY-----")})
        )
        .is_some());
        assert!(avaliar_tool_use(
            "Write",
            &json!({"content": "PuTTY-User-Key-File-3: ssh-ed25519"})
        )
        .is_some());
    }

    #[test]
    fn a_porta_certa_nao_pode_ser_barrada() {
        // Caso negativo — sem isto, um hook que nega tudo passaria no CI.
        for cmd in [
            "schematize vps exec srv-01 -- systemctl status app",
            "schematize vps list",
            "schematize ssh list",
            "schematize ssh gen deploy",
            "ssh-keygen -t ed25519 -f ~/.ssh/nova",
            "ssh-add ~/.ssh/id_ed25519",
            "cat ~/.ssh/id_ed25519.pub",
            "cat ~/.ssh/config",
            "cat ~/.ssh/known_hosts",
            "cat ~/.ssh/authorized_keys",
            "git status",
            "cargo test",
            "grep -r ssh src/",
            "echo 'ssh é o assunto do texto'",
        ] {
            assert_eq!(bash(cmd), None, "{cmd:?} NÃO pode ser barrado");
        }
        assert_eq!(
            avaliar_tool_use("Read", &json!({"file_path": "/home/tom/.ssh/id_ed25519.pub"})),
            None,
            "a chave PÚBLICA é pra ser lida"
        );
    }

    #[test]
    fn veredito_tem_a_forma_que_o_claude_code_espera() {
        let v = veredito_de_negacao("motivo qualquer");
        assert_eq!(v["decision"], "block");
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(v["hookSpecificOutput"]["permissionDecisionReason"], "motivo qualquer");
    }

    #[test]
    fn mensagem_e_acionavel_e_sem_culpa() {
        let m = bash("ssh root@host").unwrap();
        assert!(m.contains("schematize vps exec"), "diz o comando certo");
        assert!(m.contains("vps add"), "diz o que fazer se o host não existe");
        for culpa in ["você errou", "voce errou", "não faça", "proibido para você"] {
            assert!(!m.to_lowercase().contains(culpa), "sem culpa: {m}");
        }
    }

    #[test]
    fn entrada_inesperada_libera_falha_aberta() {
        // Um hook que trava por JSON estranho quebra TODA tool use do usuário (§37.48).
        assert_eq!(avaliar_tool_use("Bash", &Value::Null), None);
        assert_eq!(avaliar_tool_use("Bash", &json!({})), None);
        assert_eq!(avaliar_tool_use("", &json!({"command": 42})), None);
        assert_eq!(avaliar_tool_use("Read", &json!({"file_path": ""})), None);
    }

    #[test]
    fn binarios_invocados_extrai_o_que_importa() {
        assert_eq!(binarios_invocados("ssh x"), vec!["ssh"]);
        assert_eq!(binarios_invocados("/usr/bin/ssh x"), vec!["ssh"]);
        assert_eq!(binarios_invocados("a; b | c && d"), vec!["a", "b", "c", "d"]);
        assert_eq!(binarios_invocados("FOO=1 BAR=2 ssh x"), vec!["ssh"]);
        // Disfarces de quoting — todos são `ssh` para o shell (pentest P5).
        for disfarce in [r"\ssh x", "'ssh' x", "\"ssh\" x", "s\"s\"h x", "s''sh x"] {
            assert_eq!(binarios_invocados(disfarce), vec!["ssh"], "{disfarce:?}");
        }
        assert_eq!(binarios_invocados(""), Vec::<String>::new());
    }
}
