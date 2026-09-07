//! CONEXÃO — montagem determinística dos argumentos do `ssh` e o pinning da host key.
//! O quê: [`ssh_args`] (função PURA, testável sem rede) e o fluxo de confiança explícita
//! numa host key ([`descobrir_host_key`] → [`confiar`]).
//! Onde: `vps::exec` (execução), `vps trust` (CLI) e o botão de confiar da GUI.
//!
//! ## Duas decisões que moram aqui
//!
//! **1. `-F none` — o `~/.ssh/config` do usuário NÃO entra** (ADR-0006, emenda 1). Medido no
//! spike U0c: `IdentityFile` é multi-valorado e ACUMULA, então um `IdentityFile` no config do
//! usuário para um `Host` que case seria oferecido junto com a nossa chave — e `IdentitiesOnly
//! =yes` não impede (ele restringe às chaves *declaradas*, e a do config está declarada).
//! A auditoria afirma qual chave foi usada; com o config no meio, essa afirmação poderia ser
//! falsa. Log de auditoria que pode mentir é pior que log nenhum. O perfil é a fonte única.
//!
//! **2. Sem TOFU cego.** O `sshkeys::run_ssh` original usa `StrictHostKeyChecking=accept-new`,
//! que aceita host novo sem perguntar. Aqui é `=yes` contra um `known_hosts` POR PERFIL, e um
//! host só entra nele por ato explícito ([`confiar`]) depois de o humano ver a fingerprint.
//! Host não confiado devolve `Err`, nunca conecta "só desta vez".

use super::registro::VpsProfile;
use crate::sshkeys;
use crate::util::home_app_dir;
use std::fmt;
use std::path::PathBuf;

/// Erros de conexão que sabemos nomear. O resto do stderr do `ssh` é preservado em
/// [`ErroSsh::Outro`] — nada é engolido (piso 4).
///
/// Implementado à mão (sem `thiserror`) porque este crate mantém a árvore de dependências
/// mínima de propósito; o valor buscado é o erro TIPADO, e 20 linhas de `Display` entregam
/// isso sem crate nova.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErroSsh {
    /// Autenticação recusada — chave errada, não autorizada, ou usuário errado.
    PermissaoNegada,
    /// A host key não bate com a pinada: ou o servidor mudou, ou é outro servidor.
    HostKeyMudou,
    /// O host não confiado ainda — falta rodar o fluxo de [`confiar`].
    HostKeyNaoConfiada,
    /// Ninguém atendeu na porta.
    ConexaoRecusada,
    /// Nome não resolveu.
    HostDesconhecido,
    /// Estourou o tempo.
    Timeout,
    /// Qualquer outra falha, com o stderr preservado na íntegra.
    Outro(String),
}

impl fmt::Display for ErroSsh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErroSsh::PermissaoNegada => write!(
                f,
                "autenticação recusada pelo host — confira o usuário e se a PÚBLICA desta chave está no authorized_keys (use `schematize vps authorize <alias>`)"
            ),
            ErroSsh::HostKeyMudou => write!(
                f,
                "a host key MUDOU em relação à pinada. Ou o servidor foi reinstalado, ou você não está falando com ele. Verifique antes de re-confiar com `schematize vps trust <alias>`"
            ),
            ErroSsh::HostKeyNaoConfiada => write!(
                f,
                "host ainda não confiado — rode `schematize vps trust <alias>` para ver a fingerprint e confiar explicitamente"
            ),
            ErroSsh::ConexaoRecusada => write!(f, "conexão recusada — o sshd está no ar nessa porta?"),
            ErroSsh::HostDesconhecido => write!(f, "não consegui resolver o endereço do host"),
            ErroSsh::Timeout => write!(f, "tempo esgotado ao conectar"),
            ErroSsh::Outro(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for ErroSsh {}

/// Classifica o stderr do `ssh` num [`ErroSsh`]. O que não casa vira `Outro` com o texto
/// ORIGINAL — nunca um `Outro("erro desconhecido")` que perde a informação.
///
/// **Onde:** `vps::exec`, ao converter uma execução que terminou com exit != 0 e sem output.
pub fn classificar_erro(stderr: &str) -> ErroSsh {
    let s = stderr.to_ascii_lowercase();
    if s.contains("permission denied") || s.contains("too many authentication failures") {
        ErroSsh::PermissaoNegada
    } else if s.contains("host key verification failed")
        || s.contains("remote host identification has changed")
    {
        ErroSsh::HostKeyMudou
    } else if s.contains("no matching host key")
        || s.contains("not known") && s.contains("host key")
    {
        ErroSsh::HostKeyNaoConfiada
    } else if s.contains("connection refused") {
        ErroSsh::ConexaoRecusada
    } else if s.contains("could not resolve hostname") || s.contains("name or service not known") {
        ErroSsh::HostDesconhecido
    } else if s.contains("timed out") || s.contains("connection timed out") {
        ErroSsh::Timeout
    } else {
        ErroSsh::Outro(stderr.trim().to_string())
    }
}

/// Dir dos `known_hosts` por perfil (`~/.schematize/known_hosts/`).
///
/// **Onde:** [`known_hosts_path`]. Um arquivo POR ALIAS, e não um global: assim confiar num
/// host não afeta nenhum outro, e apagar o perfil não mexe na confiança dos vizinhos.
pub fn known_hosts_dir() -> PathBuf {
    home_app_dir().join("known_hosts")
}

/// Arquivo de `known_hosts` deste alias. Valida o alias antes (nunca vira caminho).
pub fn known_hosts_path(alias: &str) -> Result<PathBuf, String> {
    super::registro::valid_alias(alias)?;
    Ok(known_hosts_dir().join(alias))
}

/// O host já foi explicitamente confiado? Exige as DUAS pontas: a fingerprint gravada no
/// registro e o `known_hosts` no disco. Se uma sumir, o host volta a "não confiado" — é o
/// estado honesto, e o erro diz como resolver.
///
/// **Onde:** [`ssh_args`], e a GUI pra decidir se mostra o botão "confiar".
pub fn esta_confiado(p: &VpsProfile) -> bool {
    let Some(fp) = &p.fingerprint else {
        return false;
    };
    if fp.trim().is_empty() {
        return false;
    }
    known_hosts_path(&p.alias).map(|k| k.is_file()).unwrap_or(false)
}

/// Monta os argumentos do `ssh` para um perfil. **Função pura** — não toca a rede, não lê a
/// chave, e é o único lugar que decide a forma da linha de comando.
///
/// `comando` vazio = sessão interativa; não-vazio = comando remoto (tudo depois do alvo é
/// tratado como comando pelo próprio `ssh`, então não vai `--`).
///
/// **Onde:** `vps::exec::executar` e os testes. **Erros:** host não confiado, alias/perfil
/// inválido, ou chave ausente em `~/.ssh`.
pub fn ssh_args(p: &VpsProfile, comando: &[String]) -> Result<Vec<String>, String> {
    super::registro::valid_alias(&p.alias)?;
    super::registro::valid_host(&p.host)?;
    let chave = sshkeys::key_path(&p.key_name)?;
    if !esta_confiado(p) {
        return Err(ErroSsh::HostKeyNaoConfiada.to_string());
    }
    let known = known_hosts_path(&p.alias)?;
    Ok(ssh_args_puro(p, &chave, &known, comando))
}

/// O miolo de [`ssh_args`]: dados o perfil e os dois caminhos já resolvidos, devolve a linha
/// de comando. **Pura de verdade** — nenhum acesso a disco, rede ou `$HOME`.
///
/// **Onde:** [`ssh_args`] em produção, e os testes deste módulo, que precisam exercitar a
/// FORMA dos argumentos (o `-F none`, o `=yes`, a ordem) sem depender de haver chave em
/// `~/.ssh` nem `known_hosts` gravado na máquina do CI.
pub fn ssh_args_puro(
    p: &VpsProfile,
    chave: &std::path::Path,
    known: &std::path::Path,
    comando: &[String],
) -> Vec<String> {
    let mut a: Vec<String> = Vec::new();
    // `-F none`: nada do ~/.ssh/config do usuário entra (ver o doc do módulo).
    a.push("-F".into());
    a.push("none".into());
    a.push("-i".into());
    a.push(chave.to_string_lossy().into_owned());
    // Só a nossa chave é oferecida — com `-F none` a lista tem exatamente uma entrada.
    a.push("-o".into());
    a.push("IdentitiesOnly=yes".into());
    // Pinning: nada de accept-new. Host fora deste known_hosts é recusado pelo próprio ssh.
    a.push("-o".into());
    a.push("StrictHostKeyChecking=yes".into());
    a.push("-o".into());
    a.push(format!("UserKnownHostsFile={}", known.to_string_lossy()));
    // Sem prompt de senha: se a chave não serve, falha na hora em vez de pendurar um agente
    // esperando input que nunca vem.
    a.push("-o".into());
    a.push("BatchMode=yes".into());
    a.push("-o".into());
    a.push("ConnectTimeout=15".into());
    a.push("-p".into());
    a.push(p.port.to_string());
    a.push("-l".into());
    a.push(p.usuario.clone());
    if let Some(j) = &p.jump {
        a.push("-J".into());
        a.push(j.clone());
    }
    for o in &p.extra_opts {
        a.push("-o".into());
        a.push(o.clone());
    }
    a.push(p.host.clone());
    a.extend(comando.iter().cloned());
    a
}

/// Abre uma sessão INTERATIVA no terminal do sistema, com o perfil já aplicado.
///
/// **Onde:** o botão "Abrir no terminal" da GUI e `schematize vps shell`. É o caminho do
/// HUMANO: sessão interativa não passa pela política nem pela auditoria de comando (não há
/// comando pra auditar), e por isso **não** é oferecida ao agente — a sessão fica registrada
/// como abertura, e o que a pessoa digita lá é responsabilidade dela.
///
/// **Erros:** host não confiado, ou nenhum terminal encontrado na máquina.
pub fn abrir_no_terminal(p: &VpsProfile) -> Result<(), String> {
    let args = ssh_args(p, &[])?;
    // Cada argumento entre aspas simples: caminho com espaço (comum no Windows/macOS) não
    // pode virar dois argumentos ao passar pela linha de comando do terminal.
    let linha = std::iter::once("ssh".to_string())
        .chain(args.into_iter().map(|a| format!("'{}'", a.replace('\'', "'\\''"))))
        .collect::<Vec<_>>()
        .join(" ");
    crate::agentrun::abrir_comando_no_terminal(&linha).map(|_| ())
}

/// Uma host key candidata, colhida do servidor mas AINDA NÃO confiada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyCandidata {
    /// Linhas no formato `known_hosts`, como vieram do `ssh-keyscan`.
    pub linhas: String,
    /// Fingerprint SHA256 legível, pro humano comparar com o que o provedor informou.
    pub fingerprint: String,
}

/// Colhe a host key do servidor via `ssh-keyscan`. **Não confia em nada** — só devolve o
/// candidato pro humano conferir.
///
/// **Onde:** `vps trust` (CLI) e o botão "confiar" da GUI, sempre com a fingerprint exibida
/// antes do aceite. É o passo que troca o TOFU cego por TOFU explícito.
pub fn descobrir_host_key(p: &VpsProfile) -> Result<HostKeyCandidata, String> {
    super::registro::valid_host(&p.host)?;
    let porta = p.port.to_string();
    let linhas = crate::util::run("ssh-keyscan", &["-T", "10", "-p", &porta, &p.host])
        .map_err(|e| format!("ssh-keyscan falhou em {}:{}: {e}", p.host, p.port))?;
    let linhas: String = linhas
        .lines()
        .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    if linhas.trim().is_empty() {
        return Err(format!("nenhuma host key veio de {}:{}", p.host, p.port));
    }
    let fingerprint = fingerprint_de(&linhas)?;
    Ok(HostKeyCandidata { linhas, fingerprint })
}

/// Calcula a fingerprint legível de um bloco `known_hosts`, via `ssh-keygen -lf -`.
///
/// **Onde:** [`descobrir_host_key`], e nos testes com um bloco fixo.
fn fingerprint_de(linhas: &str) -> Result<String, String> {
    let out = sshkeys::run_with_stdin("ssh-keygen", &["-lf", "-"], linhas)?;
    let fps: Vec<String> =
        out.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
    if fps.is_empty() {
        return Err("ssh-keygen não devolveu fingerprint".into());
    }
    Ok(fps.join("\n"))
}

/// Confia numa host key: grava o `known_hosts` do perfil (600) e a fingerprint no registro.
/// **Só deve ser chamada depois de o humano ver e aceitar a fingerprint.**
///
/// **Onde:** `vps trust`, após a confirmação. **Efeitos:** escreve em
/// `~/.schematize/known_hosts/<alias>` e atualiza a linha do host.
pub fn confiar(
    conn: &rusqlite::Connection,
    p: &mut VpsProfile,
    c: &HostKeyCandidata,
) -> Result<(), String> {
    let path = known_hosts_path(&p.alias)?;
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)
            .map_err(|e| format!("não consegui criar {}: {e}", d.display()))?;
        crate::vps::db::restringir_dir(d);
    }
    crate::vps::db::escrever_sem_seguir_link(
        &path,
        format!("{}\n", c.linhas.trim_end()).as_bytes(),
    )?;
    p.fingerprint = Some(c.fingerprint.clone());
    super::registro::salvar(conn, p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vps::registro::{Ambiente, VpsProfile};
    use std::path::Path;

    /// Perfil de exemplo pros testes da função pura.
    fn perfil() -> VpsProfile {
        VpsProfile::novo("srv-01", "10.0.0.5", "deploy", "id_ed25519")
    }

    /// Os args montados pelo caminho puro, com caminhos fixos (sem tocar em $HOME).
    fn args_de(p: &VpsProfile, cmd: &[String]) -> Vec<String> {
        ssh_args_puro(p, Path::new("/k/priv"), Path::new("/kh/srv-01"), cmd)
    }

    /// Valor que segue a flag `flag` (ex.: `-p` -> "2222"), procurando o par exato.
    fn valor_de(a: &[String], flag: &str) -> Option<String> {
        a.iter().position(|x| x == flag).and_then(|i| a.get(i + 1)).cloned()
    }

    #[test]
    fn args_carregam_f_none_o_perfil_e_a_fonte_unica() {
        // O achado do spike U0c: sem `-F none`, um IdentityFile no ~/.ssh/config do usuário
        // ACUMULA com o nosso e o log de auditoria passa a poder mentir.
        let a = args_de(&perfil(), &[]);
        assert_eq!(
            valor_de(&a, "-F").as_deref(),
            Some("none"),
            "o config do usuário não pode entrar"
        );
    }

    #[test]
    fn args_pinam_a_host_key_e_nunca_usam_accept_new() {
        let a = args_de(&perfil(), &[]);
        assert!(a.contains(&"StrictHostKeyChecking=yes".to_string()));
        assert!(
            !a.iter().any(|x| x.contains("accept-new")),
            "TOFU cego é justamente o que este módulo existe pra eliminar"
        );
        assert!(a.contains(&"UserKnownHostsFile=/kh/srv-01".to_string()), "known_hosts POR PERFIL");
        assert!(a.contains(&"IdentitiesOnly=yes".to_string()));
        assert_eq!(
            valor_de(&a, "-i").as_deref(),
            Some("/k/priv"),
            "a chave entra por CAMINHO, nunca por conteúdo"
        );
    }

    #[test]
    fn args_nao_penduram_esperando_senha() {
        // BatchMode: sem isto, uma chave errada deixa o agente esperando um prompt eterno.
        let a = args_de(&perfil(), &[]);
        assert!(a.contains(&"BatchMode=yes".to_string()));
        assert!(a.iter().any(|x| x.starts_with("ConnectTimeout=")));
    }

    #[test]
    fn porta_usuario_jump_e_extras_saem_do_perfil() {
        let mut p = perfil();
        p.port = 2222;
        p.usuario = "ops".into();
        p.jump = Some("bastion@borda.example".into());
        p.extra_opts = vec!["ServerAliveInterval=30".into()];
        let a = args_de(&p, &[]);
        assert_eq!(valor_de(&a, "-p").as_deref(), Some("2222"));
        assert_eq!(valor_de(&a, "-l").as_deref(), Some("ops"));
        assert_eq!(valor_de(&a, "-J").as_deref(), Some("bastion@borda.example"));
        assert!(a.contains(&"ServerAliveInterval=30".to_string()));
    }

    #[test]
    fn comando_remoto_vem_depois_do_alvo_e_sem_separador() {
        // O ssh já trata tudo depois do alvo como comando remoto: um `--` viraria argumento.
        let cmd = vec!["systemctl".to_string(), "status".to_string(), "app".to_string()];
        let a = args_de(&perfil(), &cmd);
        let i = a.iter().position(|x| x == "10.0.0.5").expect("o alvo tem que estar lá");
        assert_eq!(&a[i + 1..], &cmd[..], "o comando vem logo após o alvo");
        assert!(!a.contains(&"--".to_string()));
    }

    #[test]
    fn sem_comando_e_sessao_interativa() {
        let a = args_de(&perfil(), &[]);
        assert_eq!(a.last().map(String::as_str), Some("10.0.0.5"), "nada depois do alvo");
    }

    #[test]
    fn a_linha_do_terminal_escapa_aspas_no_caminho() {
        // Um caminho com aspas simples (raro, mas legítimo em macOS/Windows) fecharia o
        // quoting e o resto viraria argumento — ou comando — do shell do terminal.
        let escapado = "/home/o'brien/.ssh/k".replace('\'', "'\\''");
        assert_eq!(escapado, "/home/o'\\''brien/.ssh/k");
        // Envolvido em aspas simples, o shell reconstrói o literal original.
        let saida = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("printf %s '{escapado}'"))
            .output()
            .expect("sh");
        assert_eq!(String::from_utf8_lossy(&saida.stdout), "/home/o'brien/.ssh/k");
    }

    #[test]
    fn host_nao_confiado_nao_conecta_nem_uma_vez() {
        let p = VpsProfile::novo("novo", "10.0.0.5", "deploy", "k");
        assert!(!esta_confiado(&p));
        let e = ssh_args(&p, &[]).unwrap_err();
        assert!(e.contains("não confiado"), "erro precisa ensinar o caminho: {e}");
    }

    #[test]
    fn fingerprint_sem_known_hosts_no_disco_nao_conta_como_confiado() {
        let mut p = VpsProfile::novo("meio", "10.0.0.5", "deploy", "k");
        p.fingerprint = Some("256 SHA256:abc".into());
        // Sem o arquivo no disco, a confiança está pela metade — e meia confiança é não-confiança.
        assert!(!esta_confiado(&p));
    }

    #[test]
    fn fingerprint_vazia_nao_conta_como_confiado() {
        let mut p = VpsProfile::novo("vazio", "10.0.0.5", "deploy", "k");
        p.fingerprint = Some("   ".into());
        assert!(!esta_confiado(&p));
    }

    #[test]
    fn prd_sem_fingerprint_e_erro() {
        let mut p = VpsProfile::novo("prod", "10.0.0.5", "deploy", "k");
        p.ambiente = Ambiente::Prd;
        p.fingerprint = None;
        assert!(ssh_args(&p, &[]).is_err(), "produção sem pinning não pode conectar");
    }

    #[test]
    fn classificar_erro_cobre_os_casos_conhecidos_e_preserva_o_resto() {
        assert_eq!(classificar_erro("Permission denied (publickey)."), ErroSsh::PermissaoNegada);
        assert_eq!(classificar_erro("Host key verification failed."), ErroSsh::HostKeyMudou);
        assert_eq!(
            classificar_erro("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!"),
            ErroSsh::HostKeyMudou
        );
        assert_eq!(
            classificar_erro("ssh: connect to host x port 22: Connection refused"),
            ErroSsh::ConexaoRecusada
        );
        assert_eq!(
            classificar_erro("ssh: Could not resolve hostname x"),
            ErroSsh::HostDesconhecido
        );
        assert_eq!(
            classificar_erro("ssh: connect to host x port 22: Connection timed out"),
            ErroSsh::Timeout
        );
        // O que não casa é PRESERVADO na íntegra — nada de "erro desconhecido".
        let estranho = "kex_exchange_identification: read: Connection reset by peer";
        assert_eq!(classificar_erro(estranho), ErroSsh::Outro(estranho.to_string()));
    }

    #[test]
    fn mensagens_de_erro_sao_acionaveis_e_sem_culpa() {
        // §37.48: a mensagem diz o que FAZER, não que o usuário errou.
        assert!(ErroSsh::HostKeyNaoConfiada.to_string().contains("vps trust"));
        assert!(ErroSsh::PermissaoNegada.to_string().contains("vps authorize"));
        for e in [ErroSsh::PermissaoNegada, ErroSsh::HostKeyMudou, ErroSsh::HostKeyNaoConfiada] {
            let m = e.to_string();
            assert!(!m.to_lowercase().contains("você errou"), "sem culpa: {m}");
            assert!(m.len() > 20, "mensagem precisa ensinar algo: {m}");
        }
    }
}
