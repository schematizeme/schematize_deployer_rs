//! A superfície da CLI do Deployer: `deployer ssh|vps|mcp <sub>`.
//!
//! **O quê:** a árvore de comandos do clap. Só a definição — nenhuma regra mora aqui.
//!
//! **Onde:** raiz consumida por `main.rs`; os despachos vivem em `cli/{ssh,vps,mcp}.rs`.
//!
//! ## Por que os enums vieram sem uma vírgula de diferença
//!
//! O corte do ADR-0010 é `/eng-refactor`: **comportamento idêntico**. Mudar a superfície na
//! mesma passada em que se muda o repositório tornaria impossível saber se uma regressão veio
//! do movimento ou da mudança. Os nomes de subcomando, flags e obrigatoriedades são os
//! mesmos que estavam em `schematize ssh|vps|mcp` — só o binário na frente mudou.
//!
//! O `tests/superficie-cli.txt` daqui congela isso, exatamente como o do schematize congela o
//! dele. Quando a superfície for evoluir, evolui com o snapshot reprovando primeiro.

use clap::{Parser, Subcommand};

/// `deployer` — chaves SSH, VPS e a porta auditada que o agente enxerga.
#[derive(Parser)]
#[command(
    name = "deployer",
    version,
    about = "schematize deployer — chaves SSH, VPS e acesso remoto auditado",
    long_about = "Opera servidor com credencial fora do alcance do agente.\n\
                  Funciona sozinho; integra-se ao schematize quando os dois convivem."
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) cmd: Cmd,
}

#[derive(Subcommand)]
pub(crate) enum Cmd {
    /// SSH keys: generate, import, list, export and manage keys in ~/.ssh (never leaks the private key).
    Ssh {
        #[command(subcommand)]
        sub: SshCmd,
    },
    /// VPS: host registry + AUDITED remote execution (the agent never sees the key).
    Vps {
        #[command(subcommand)]
        sub: VpsCmd,
    },
    /// MCP: exposes the VPS manager to the agent as typed tools.
    Mcp {
        #[command(subcommand)]
        sub: McpCmd,
    },
    /// Cofre: o segredo em repouso, ilegível para quem tem o disco (ADR-0010).
    Cofre {
        #[command(subcommand)]
        sub: CofreCmd,
    },
    /// DNS: gere zonas e registros da Cloudflare, com o token guardado no cofre.
    Dns {
        #[command(subcommand)]
        sub: DnsCmd,
    },
    /// Visão geral: o que está configurado e o que dá para fazer. É o que o ícone abre.
    Painel {
        /// Espera uma tecla no fim. O lançador do desktop usa isto — sem ele o terminal
        /// fecharia no mesmo instante e o clique pareceria não ter feito nada.
        #[arg(long)]
        aguardar: bool,
    },
    /// Ícone e entrada no menu de aplicativos — para abrir o app sem o schematize.
    Desktop {
        /// Instala (padrão se nenhuma flag vier).
        #[arg(long)]
        instalar: bool,
        /// Remove a entrada do menu.
        #[arg(long)]
        remover: bool,
    },
}

/// Gestão de DNS na Cloudflare.
///
/// O token NUNCA vem por argumento: `ps` mostra argv para qualquer processo do usuário, e o
/// histórico do shell o guarda. Ele entra uma vez, pelo terminal, e vai para o cofre.
#[derive(Subcommand)]
pub(crate) enum DnsCmd {
    /// Guarda o token de API da Cloudflare no cofre (pedido pelo terminal, sem eco).
    Auth {
        /// Só diz SE há token guardado — nunca qual é.
        #[arg(long)]
        status: bool,
        /// Remove o token do cofre.
        #[arg(long)]
        remover: bool,
    },
    /// Lista as zonas (domínios) da conta.
    Zones,
    /// Lista os registros de uma zona.
    List {
        /// Nome da zona (ex.: exemplo.com) ou o id de 32 hex.
        zona: String,
        /// Só deste tipo (A, CNAME, TXT…).
        #[arg(long)]
        tipo: Option<String>,
    },
    /// Cria um registro.
    Add {
        zona: String,
        /// A, AAAA, CNAME, TXT, MX…
        tipo: String,
        /// Nome do registro (`@` para o apex).
        nome: String,
        /// Para onde aponta (IP, host, texto…).
        conteudo: String,
        /// TTL em segundos: 1 = automático, ou 60..86400.
        #[arg(long, default_value_t = 1)]
        ttl: i64,
        /// Passa pelo proxy da Cloudflare (só A, AAAA e CNAME).
        #[arg(long)]
        proxied: bool,
        /// Confirma o que a política exigiria confirmar. NÃO destrava o proibido.
        #[arg(long)]
        yes: bool,
    },
    /// Altera um registro existente, achado por nome.
    Update {
        zona: String,
        nome: String,
        /// Novo conteúdo.
        conteudo: String,
        /// Desambigua quando o nome casa com mais de um registro.
        #[arg(long)]
        tipo: Option<String>,
        #[arg(long)]
        ttl: Option<i64>,
        #[arg(long)]
        proxied: Option<bool>,
        #[arg(long)]
        yes: bool,
    },
    /// Remove um registro. SEMPRE pede confirmação (ou `--yes`).
    Rm {
        zona: String,
        nome: String,
        #[arg(long)]
        tipo: Option<String>,
        #[arg(long)]
        yes: bool,
    },
}

/// O cofre cifrado. A passphrase NUNCA vem por argumento — `ps` a mostraria para qualquer
/// processo da máquina, incluindo o agente que este cofre existe para manter longe do segredo.
#[derive(Subcommand)]
pub(crate) enum CofreCmd {
    /// Cria o cofre. A passphrase é pedida no terminal, sem eco, e confirmada.
    Init,
    /// Mostra onde o cofre está, a permissão do arquivo e a força do KDF com que foi criado.
    Status,
    /// Troca a passphrase. Regrava com salt, nonce e custo de KDF novos.
    TrocarSenha,
}

#[derive(Subcommand)]
pub(crate) enum SshCmd {
    /// Generate a key pair (ed25519 by default; --rsa = rsa 4096) into ~/.ssh/<name>.
    Gen {
        name: String,
        /// Use RSA 4096 instead of the recommended ed25519.
        #[arg(long)]
        rsa: bool,
        /// Comment embedded in the key (default: schematize:<user>@<host>).
        #[arg(long)]
        comment: Option<String>,
        /// Also add the public key to your GitHub account (gh must be authenticated).
        #[arg(long)]
        github: bool,
        /// Also load the key into the ssh-agent (ssh-add).
        #[arg(long)]
        agent: bool,
        /// Overwrite an existing key with the same name.
        #[arg(long)]
        force: bool,
    },
    /// Import an EXISTING key pair into ~/.ssh/<name> (another machine, a backup, a vault).
    /// Derives the public key from the private one; the private key is copied byte for byte
    /// and keeps its passphrase. Use --passphrase if the key is encrypted.
    Import {
        /// Path to the PRIVATE key file (not the .pub).
        file: String,
        /// Name it will have in ~/.ssh (default: the source file name).
        #[arg(long)]
        name: Option<String>,
        /// Passphrase, if the key is encrypted. Only used to read the key; it stays encrypted.
        #[arg(long)]
        passphrase: Option<String>,
        /// Override the comment embedded in the public key.
        #[arg(long)]
        comment: Option<String>,
        /// Overwrite an existing key with the same name.
        #[arg(long)]
        force: bool,
    },
    /// List keys in ~/.ssh (name, type, fingerprint, comment). Never reads the private key.
    List,
    /// Print the PUBLIC key (paste it on GitHub/servers); --copy sends it to the clipboard.
    /// With --bitwarden, export the key to Bitwarden instead (item in the vault if `bw` is
    /// unlocked, else a mode-600 import JSON) — the PRIVATE key never hits stdout.
    Export {
        name: String,
        #[arg(long)]
        copy: bool,
        /// Export to Bitwarden (vault item via `bw`, or a mode-600 import JSON as fallback).
        #[arg(long)]
        bitwarden: bool,
        /// Import-JSON output path (only with --bitwarden fallback). Default ~/.schematize/bw-import-<name>.json.
        #[arg(long)]
        out: Option<String>,
    },
    /// Deploy WITHOUT pasting the key: `ssh -i <managed key> user@host [-- <remote cmd...>]`.
    /// Inherits the terminal, never prints the private key. No command = interactive session.
    /// Ex.: schematize ssh run deploy root@host -- 'cd /srv/app && git pull && ./deploy.sh'
    Run {
        name: String,
        target: String,
        /// Remote command to run (everything after `--`). Empty = interactive shell.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Install the PUBLIC key into the remote host's ~/.ssh/authorized_keys (bootstrap access).
    /// Requires you already have access to the host (another key/agent/password).
    Authorize { name: String, target: String },
    /// Remove a key pair (private + public) with confirmation.
    Rm { name: String },
    /// Add an existing PUBLIC key to your GitHub account (gh must be authenticated).
    Github { name: String },
}

/// Gestão de VPS — o "Termius embutido": hosts registrados, execução auditada e a política.
#[derive(Subcommand)]
pub(crate) enum VpsCmd {
    /// Registra um host. Nasce em `prd` + `readonly` (o mais restritivo) — ajuste com `policy`.
    Add {
        /// Nome curto do host (letras, números, '.', '_' ou '-').
        alias: String,
        #[arg(long)]
        host: String,
        #[arg(long)]
        user: String,
        /// Nome da chave gerenciada em ~/.ssh (veja `schematize ssh list`).
        #[arg(long)]
        key: String,
        #[arg(long, default_value_t = 22)]
        port: u16,
        /// Ambiente: dev | hml | prd. Qualquer outra coisa vira `prd` (falha fechada).
        #[arg(long, default_value = "prd")]
        env: String,
        /// ProxyJump explícito (`user@bastion`) — o ~/.ssh/config NÃO é lido.
        #[arg(long)]
        jump: Option<String>,
    },
    /// Lista os hosts registrados, com ambiente, modo e se têm fronteira server-side.
    List,
    /// Mostra a fingerprint da host key e, com --sim, passa a confiar nela (fim do TOFU cego).
    Trust {
        alias: String,
        /// Confia sem novo prompt (use depois de conferir a fingerprint).
        #[arg(long)]
        sim: bool,
    },
    /// Roda um comando no host, com política e auditoria.
    /// Ex.: schematize vps exec srv-01 -- systemctl status app
    Exec {
        alias: String,
        /// Confirma um veredito `Confirm` (produção, encadeamento). NÃO atropela um `Deny`.
        #[arg(long)]
        confirmar: bool,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        comando: Vec<String>,
    },
    /// Mostra o que já rodou (alias vazio = todos os hosts).
    Logs {
        #[arg(default_value = "")]
        alias: String,
        #[arg(long, default_value_t = 20)]
        n: usize,
        /// Mostra o transcript completo de cada linha.
        #[arg(long)]
        transcript: bool,
    },
    /// Ajusta a política de um host: modo e ambiente.
    Policy {
        alias: String,
        /// readonly | opsverbs | livre. Desconhecido vira `readonly` (falha fechada).
        #[arg(long)]
        modo: Option<String>,
        /// dev | hml | prd. Desconhecido vira `prd` (falha fechada).
        #[arg(long)]
        env: Option<String>,
    },
    /// Instala a chave PÚBLICA do perfil no authorized_keys do host (bootstrap de acesso).
    Authorize { alias: String },
    /// Pergunta ao host que nível de fronteira ele aguenta (somente leitura, nada é instalado).
    Probe { alias: String },
    /// Instala a MELHOR fronteira que o host aguentar (com sudo: shim do sistema; sem sudo:
    /// shim no home; host gerenciado: explica por que não dá e segue com a política do cliente).
    Bootstrap { alias: String },
    /// Catálogo de verbos do host — o vocabulário que o agente pode falar.
    Verbs {
        alias: String,
        /// Cria/atualiza um verbo (use junto com --cmd).
        #[arg(long)]
        add: Option<String>,
        /// O comando real que o verbo dispara no host.
        #[arg(long)]
        cmd: Option<String>,
        /// Remove um verbo.
        #[arg(long)]
        rm: Option<String>,
        /// Semeia um catálogo inicial plausível, sem sobrescrever o que já existe.
        #[arg(long)]
        seed: bool,
    },
    /// Remove um host do registro. A trilha de auditoria dele PERMANECE.
    Rm { alias: String },
    /// Liga/desliga o hook que barra SSH cru e leitura de chave privada no agente.
    Hooks {
        #[arg(long)]
        on: bool,
        #[arg(long)]
        off: bool,
    },
    /// (hook PreToolUse) veredito sobre uma tool use — lê o evento no stdin.
    #[command(hide = true)]
    Guard,
}

/// Servidor MCP — a porta CERTA do acesso remoto, com nome e schema que o agente entende.
#[derive(Subcommand)]
pub(crate) enum McpCmd {
    /// Roda o servidor (stdio, JSON-RPC). É o que o Claude Code invoca; raramente à mão.
    Serve,
    /// Registra o servidor no `.mcp.json` do projeto e libera as tools no settings.json.
    Install {
        /// Só mostra o que seria gravado, sem tocar em arquivo.
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove o servidor do `.mcp.json` e as permissões do settings.json.
    Uninstall,
    /// Mostra o estado: servidor registrado? tools liberadas?
    Status,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// Serializa a ÁRVORE INTEIRA de comandos num texto determinístico.
    ///
    /// **O quê:** para cada comando e subcomando, em ordem alfabética — o caminho, os
    /// aliases, se é oculto, e cada argumento com nome longo/curto, se é obrigatório, se
    /// recebe valor e qual o default. Nada de texto de ajuda: descrição muda com revisão de
    /// prosa e não é contrato; o que a pessoa DIGITA é.
    ///
    /// **Onde:** [`superficie_da_cli_nao_mudou`], contra um snapshot commitado.
    fn superficie(c: &clap::Command, caminho: &str, out: &mut Vec<String>) {
        let nome = if caminho.is_empty() {
            c.get_name().to_string()
        } else {
            format!("{caminho} {}", c.get_name())
        };
        let mut aliases: Vec<_> = c.get_all_aliases().collect();
        aliases.sort_unstable();
        out.push(format!(
            "CMD {nome}{}{}",
            if aliases.is_empty() {
                String::new()
            } else {
                format!(" aliases=[{}]", aliases.join(","))
            },
            if c.is_hide_set() { " (oculto)" } else { "" }
        ));
        // `SOBRE` é a descrição — vai pro arquivo (é dela que o índice de funcionalidades
        // se alimenta) mas FICA DE FORA da comparação: prosa muda em revisão de texto e não
        // é contrato. Quem quebra script é a linha `CMD`/`ARG`, não o `about`.
        if let Some(sobre) = c.get_about() {
            let t = sobre.to_string();
            out.push(format!("  SOBRE {}", t.lines().next().unwrap_or("").trim()));
        }

        let mut args: Vec<String> = c
            .get_arguments()
            .map(|a| {
                let longo = a.get_long().map(|l| format!("--{l}")).unwrap_or_default();
                let curto = a.get_short().map(|s| format!(" -{s}")).unwrap_or_default();
                let val = if a.get_num_args().map(|n| n.takes_values()).unwrap_or(false) {
                    " <valor>"
                } else {
                    ""
                };
                let obrig = if a.is_required_set() { " OBRIGATORIO" } else { "" };
                format!("  ARG {:<20} {longo}{curto}{val}{obrig}", a.get_id().to_string())
            })
            .collect();
        args.sort();
        out.extend(args);

        let mut subs: Vec<&clap::Command> = c.get_subcommands().collect();
        subs.sort_by_key(|s| s.get_name());
        for s in subs {
            superficie(s, &nome, out);
        }
    }

    /// A superfície da CLI é CONTRATO com quem escreveu script, hook e documentação.
    ///
    /// **Onde:** roda a cada `cargo test`, e existe pra que refatorar este módulo seja
    /// seguro — o `args.rs` passou de 780 linhas e precisou ser partido em submódulos por
    /// domínio, e sem esta prova o corte seria confiança, não verificação.
    ///
    /// **Se este teste falhar** e a mudança for INTENCIONAL (comando novo, flag nova),
    /// regenere com `DEPLOYER_REGRAVA_SUPERFICIE=1 cargo test superficie_da_cli` e leia o
    /// diff **linha por linha** antes de commitar: cada linha some é um script de alguém
    /// quebrando. Se foi acidente de refatoração, o teste acabou de fazer o trabalho dele.
    #[test]
    fn superficie_da_cli_nao_mudou() {
        let mut linhas = Vec::new();
        superficie(&Cli::command(), "", &mut linhas);
        let atual = linhas.join("\n") + "\n";

        let snap = std::path::Path::new("tests/superficie-cli.txt");
        if std::env::var_os("DEPLOYER_REGRAVA_SUPERFICIE").is_some() {
            std::fs::write(snap, &atual).expect("gravar o snapshot");
            return;
        }
        let esperado = std::fs::read_to_string(snap).expect(
            "tests/superficie-cli.txt ausente — gere com \
             DEPLOYER_REGRAVA_SUPERFICIE=1 cargo test superficie_da_cli",
        );
        // A ASSERÇÃO é só sobre o contrato: `CMD` e `ARG`. As linhas `SOBRE` viajam no
        // arquivo pra alimentar o índice de funcionalidades, e mudam livremente com revisão
        // de prosa — descrição não quebra o script de ninguém.
        let contrato = |t: &str| -> Vec<String> {
            t.lines().filter(|l| !l.trim_start().starts_with("SOBRE ")).map(String::from).collect()
        };
        if contrato(&atual) == contrato(&esperado) {
            // Só a prosa mudou: regrava sem reprovar.
            if atual != esperado {
                std::fs::write(snap, &atual).expect("regravar a prosa do snapshot");
            }
            return;
        }
        // Diff legível: a primeira divergência é o que a pessoa precisa ver.
        let (a, e) = (contrato(&atual), contrato(&esperado));
        let sumiram: Vec<_> = e.iter().filter(|l| !a.contains(l)).collect();
        let surgiram: Vec<_> = a.iter().filter(|l| !e.contains(l)).collect();
        panic!(
            "a superfície da CLI MUDOU.\n\nsumiram ({}) — cada uma é um script de alguém \
             quebrando:\n  {}\n\nsurgiram ({}):\n  {}\n\nSe foi intencional: \
             DEPLOYER_REGRAVA_SUPERFICIE=1 cargo test superficie_da_cli",
            sumiram.len(),
            sumiram.iter().map(|s| s.to_string()).collect::<Vec<_>>().join("\n  "),
            surgiram.len(),
            surgiram.iter().map(|s| s.to_string()).collect::<Vec<_>>().join("\n  "),
        );
    }
}
