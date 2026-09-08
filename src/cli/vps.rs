//! Subcomandos do gestor de VPS (`schematize vps <sub>`).
//! O quê: traduz os argumentos do clap em chamadas da lib `deployer::vps` e imprime o
//! resultado. Nenhuma regra mora aqui — política, auditoria e conexão são da lib, pra que a
//! GUI e o MCP tenham exatamente o mesmo comportamento.
//! Onde: despachado por `main.rs` (`Cmd::Vps`).

use crate::cli::args::*;
use crate::cli::ssh::confirm;
use deployer::nucleo::i18n::{t, tf};
use deployer::vps;

/// Despacha `schematize vps <sub>`.
///
/// **Onde:** `main.rs`. **Erros:** propagados como `String` e impressos pelo `main`.
pub(crate) fn vps_cmd(sub: VpsCmd) -> Result<(), String> {
    match sub {
        // O guard não abre banco nem valida nada: é o hook, roda a cada tool use do agente e
        // precisa ser barato. Fica antes de tudo por isso.
        VpsCmd::Guard => {
            vps::hook::guard();
            Ok(())
        }
        VpsCmd::Hooks { on, off } => hooks(on, off),
        VpsCmd::Add { alias, host, user, key, port, env, jump } => {
            let conn = vps::db::open()?;
            let mut p = vps::VpsProfile::novo(&alias, &host, &user, &key);
            p.port = port;
            p.ambiente = vps::Ambiente::from_raw(&env);
            p.jump = jump;
            vps::salvar(&conn, &p)?;
            println!(
                "{}",
                tf(
                    "cli.vps.registered",
                    &[
                        ("alias", &format!("{alias:?}")),
                        ("env", p.ambiente.as_str()),
                        ("host", &p.host),
                        ("port", &p.port.to_string())
                    ]
                )
            );
            println!("{}", tf("cli.vps.mode_set", &[("mode", p.modo.as_str()), ("alias", &alias)]));
            println!("{}", tf("cli.vps.next_trust", &[("alias", &alias)]));
            Ok(())
        }
        VpsCmd::List => listar(),
        VpsCmd::Trust { alias, sim } => confiar(&alias, sim),
        VpsCmd::Exec { alias, confirmar, comando } => executar(&alias, confirmar, &comando),
        VpsCmd::Logs { alias, n, transcript } => logs(&alias, n, transcript),
        VpsCmd::Policy { alias, modo, env } => politica(&alias, modo, env),
        VpsCmd::Authorize { alias } => autorizar(&alias),
        VpsCmd::Probe { alias } => sondar(&alias),
        VpsCmd::Bootstrap { alias } => bootstrap(&alias),
        VpsCmd::Verbs { alias, add, cmd, rm, seed } => verbos(&alias, add, cmd, rm, seed),
        VpsCmd::Rm { alias } => remover(&alias),
    }
}

/// Liga/desliga o hook `PreToolUse`. Sem flag, só mostra o estado.
fn hooks(on: bool, off: bool) -> Result<(), String> {
    if on && off {
        return Err("--on e --off ao mesmo tempo; escolha um".into());
    }
    let exe = deployer::util::self_exe();
    if on {
        deployer::settings::enable_vps(&exe)?;
        println!("{}", t("cli.vps.hook_on"));
    } else if off {
        deployer::settings::disable_vps()?;
        println!("{}", t("cli.vps.hook_off"));
    } else {
        let estado = if deployer::settings::vps_hook_enabled() { "ligado" } else { "desligado" };
        println!("{}", tf("cli.vps.hook_state", &[("state", estado)]));
        println!("{}", t("cli.vps.hook_usage"));
    }
    Ok(())
}

/// Lista os hosts, marcando os que rodam SEM fronteira server-side.
fn listar() -> Result<(), String> {
    let conn = vps::db::open()?;
    let hosts = vps::listar(&conn)?;
    if hosts.is_empty() {
        println!("{}", t("cli.vps.no_hosts"));
        return Ok(());
    }
    println!(
        "{:<18} {:<24} {:<5} {:<9} {:<8} FRONTEIRA",
        "ALIAS", "DESTINO", "ENV", "MODO", "HOSTKEY"
    );
    for h in &hosts {
        let destino = format!("{}@{}:{}", h.usuario, h.host, h.port);
        let hostkey = if vps::esta_confiado(h) { "pinada" } else { "NÃO" };
        // Cada host mostra o nível que de fato tem — não um sim/não que esconde a diferença.
        println!(
            "{:<18} {:<24} {:<5} {:<9} {:<8} {}",
            h.alias,
            destino,
            h.ambiente.as_str(),
            h.modo.as_str(),
            hostkey,
            h.fronteira.rotulo()
        );
    }
    let sem = hosts.iter().filter(|h| !h.fronteira.e_server_side()).count();
    let nunca_sondado = hosts.iter().filter(|h| h.sondado_em == 0).count();
    if sem > 0 {
        println!(
            "\n{sem} host(s) sem fronteira no servidor — {}",
            vps::Fronteira::Sem.explicacao()
        );
        println!(
            "tente subir de nível com `schematize vps bootstrap <alias>` (ele descobre o que dá)."
        );
    }
    if nunca_sondado > 0 {
        println!("{}", tf("cli.vps.never_probed", &[("count", &nunca_sondado.to_string())]));
    }
    Ok(())
}

/// Mostra a fingerprint e, com aceite, passa a confiar na host key.
fn confiar(alias: &str, sim: bool) -> Result<(), String> {
    let conn = vps::db::open()?;
    let mut p = vps::buscar(&conn, alias)?.ok_or_else(|| host_ausente(alias))?;
    let c = vps::descobrir_host_key(&p)?;
    println!(
        "{}",
        tf(
            "cli.vps.host_key",
            &[("host", &p.host), ("port", &p.port.to_string()), ("fp", &c.fingerprint)]
        )
    );
    if let Some(atual) = &p.fingerprint {
        if atual.trim() != c.fingerprint.trim() {
            println!("\n{}", tf("cli.vps.fingerprint_changed", &[("current", atual)]));
            println!("{}", t("cli.vps.fingerprint_changed_why"));
        }
    }
    if !sim && !confirm("\nconfere com o que o provedor informou? confiar nesta chave? [y/N]") {
        println!("{}", t("cli.vps.unchanged_untrusted"));
        return Ok(());
    }
    vps::confiar(&conn, &mut p, &c)?;
    println!("{}", tf("cli.vps.pinned_ready", &[("alias", alias)]));
    Ok(())
}

/// Roda um comando no host.
fn executar(alias: &str, confirmar: bool, comando: &[String]) -> Result<(), String> {
    if comando.is_empty() {
        return Err(format!(
            "faltou o comando. Ex.: schematize vps exec {alias} -- systemctl status app"
        ));
    }
    let conn = vps::db::open()?;
    let p = vps::buscar(&conn, alias)?.ok_or_else(|| host_ausente(alias))?;
    let cmd = comando.join(" ");
    let confirmacao =
        if confirmar { vps::Confirmacao::HumanoConfirmou } else { vps::Confirmacao::Ausente };
    let out = vps::executar(&conn, &p, &cmd, "cli", confirmacao)?;
    print!("{}", out.stdout);
    if !out.stderr.trim().is_empty() {
        eprint!("{}", out.stderr);
    }
    if let Some(e) = &out.erro {
        return Err(e.to_string());
    }
    match out.exit_code {
        Some(0) => Ok(()),
        Some(c) => Err(format!("o comando remoto saiu com {c} ({} ms)", out.duracao_ms)),
        None => Err("o ssh foi morto por sinal".into()),
    }
}

/// Mostra a trilha de auditoria.
fn logs(alias: &str, n: usize, transcript: bool) -> Result<(), String> {
    let conn = vps::db::open()?;
    let linhas = vps::listar_comandos(&conn, alias, n)?;
    if linhas.is_empty() {
        println!("{}", t("cli.vps.nothing_logged"));
        return Ok(());
    }
    for l in &linhas {
        let exit = l.exit_code.map(|c| c.to_string()).unwrap_or_else(|| "-".into());
        println!(
            "[{}] {:<12} {:<8} exit={:<4} {:>6}ms  {}",
            l.ts, l.alias, l.veredito, exit, l.duracao_ms, l.comando
        );
        if transcript {
            if let Some(p) = &l.transcript_path {
                println!("{}", tf("cli.vps.big_transcript", &[("path", p)]));
            } else if !l.transcript.trim().is_empty() {
                for linha in l.transcript.lines() {
                    println!("    {linha}");
                }
            }
        }
    }
    println!("\n{}", tf("cli.vps.trail_lines", &[("count", &linhas.len().to_string())]));
    Ok(())
}

/// Ajusta modo e/ou ambiente de um host.
fn politica(alias: &str, modo: Option<String>, env: Option<String>) -> Result<(), String> {
    let conn = vps::db::open()?;
    let mut p = vps::buscar(&conn, alias)?.ok_or_else(|| host_ausente(alias))?;
    if modo.is_none() && env.is_none() {
        println!(
            "{}",
            tf(
                "cli.vps.policy_line",
                &[("alias", alias), ("mode", p.modo.as_str()), ("env", p.ambiente.as_str())]
            )
        );
        return Ok(());
    }
    if let Some(m) = &modo {
        p.modo = vps::ModoPolitica::from_raw(m);
    }
    if let Some(e) = &env {
        p.ambiente = vps::Ambiente::from_raw(e);
    }
    vps::salvar(&conn, &p)?;
    println!(
        "{}",
        tf(
            "cli.vps.policy_line",
            &[("alias", alias), ("mode", p.modo.as_str()), ("env", p.ambiente.as_str())]
        )
    );
    if p.ambiente == vps::Ambiente::Prd {
        println!("{}", t("cli.vps.prod_confirms"));
    }
    Ok(())
}

/// Instala a pública do perfil no host (reusa o `sshkeys::authorize`, que já existe).
fn autorizar(alias: &str) -> Result<(), String> {
    let conn = vps::db::open()?;
    let mut p = vps::buscar(&conn, alias)?.ok_or_else(|| host_ausente(alias))?;

    // TOFU EXPLÍCITO ANTES DO BOOTSTRAP DE ACESSO.
    //
    // A instalação da chave é a PRIMEIRA conexão com o host, e é justamente a que estabelece a
    // confiança — aceitar qualquer um que atenda no endereço aqui é o pior momento possível.
    // Pinando antes, o `ssh-copy-id` roda com `StrictHostKeyChecking=yes` e o `accept-new`
    // some do caminho do gestor de VPS.
    if !vps::esta_confiado(&p) {
        let c = vps::descobrir_host_key(&p)?;
        println!(
            "{}",
            tf(
                "cli.vps.host_key",
                &[("host", &p.host), ("port", &p.port.to_string()), ("fp", &c.fingerprint)]
            )
        );
        if !confirm("\nconfere com o que o provedor informou? confiar nesta chave? [y/N]") {
            return Err("bootstrap cancelado — sem confiar na host key não dá pra instalar a chave com segurança".into());
        }
        vps::confiar(&conn, &mut p, &c)?;
        println!("{}", t("cli.vps.pinned"));
    }

    let known = vps::known_hosts_path(alias)?;
    let opcoes = vec![
        "StrictHostKeyChecking=yes".to_string(),
        format!("UserKnownHostsFile={}", known.to_string_lossy()),
        format!("Port={}", p.port),
    ];
    let alvo = format!("{}@{}", p.usuario, p.host);
    deployer::sshkeys::authorize_com_opcoes(&p.key_name, &alvo, &opcoes)?;
    println!(
        "chave pública de {:?} instalada em {alvo} (host key pinada, sem TOFU cego)",
        p.key_name
    );
    println!("{}", tf("cli.vps.no_forced_command", &[("alias", alias)]));
    Ok(())
}

/// Remove um host (com confirmação). A trilha permanece.
fn remover(alias: &str) -> Result<(), String> {
    let conn = vps::db::open()?;
    if vps::buscar(&conn, alias)?.is_none() {
        return Err(host_ausente(alias));
    }
    if !confirm(&format!("remover o host {alias:?} do registro? (a auditoria permanece) [y/N]")) {
        println!("{}", t("cli.vps.unchanged"));
        return Ok(());
    }
    vps::remover(&conn, alias)?;
    println!("{}", tf("cli.vps.removed", &[("alias", &format!("{alias:?}")), ("plain", alias)]));
    Ok(())
}

/// Sonda o host: o que ele aguenta hoje, sem instalar nada.
fn sondar(alias: &str) -> Result<(), String> {
    let conn = vps::db::open()?;
    let mut p = vps::buscar(&conn, alias)?.ok_or_else(|| host_ausente(alias))?;
    let s = vps::sondar(&conn, &p)?;
    println!("{}", tf("cli.vps.cap_host", &[("alias", alias)]));
    println!("{}", tf("cli.vps.cap_installed", &[("value", s.instalada.rotulo())]));
    println!("{}", tf("cli.vps.cap_possible", &[("value", s.possivel.rotulo())]));
    println!(
        "{}",
        tf(
            "cli.vps.cap_sudo",
            &[("value", &t(if s.sudo_sem_senha { "common.yes" } else { "common.no" }))]
        )
    );
    println!(
        "{}",
        tf(
            "cli.vps.cap_authkeys",
            &[("value", &t(if s.pode_escrever_authkeys { "common.yes" } else { "common.no" }))]
        )
    );
    for n in &s.notas {
        println!("· {n}");
    }
    println!("\n{}", s.possivel.explicacao());
    if s.pode_melhorar() {
        println!("\n{}", tf("cli.vps.can_level_up", &[("alias", alias)]));
    }
    // A sondagem é informação: registra mesmo quando o usuário só perguntou.
    p.fronteira = s.instalada;
    p.sondado_em = vps::db::agora_secs();
    vps::salvar(&conn, &p)?;
    Ok(())
}

/// Instala a melhor fronteira possível no host.
fn bootstrap(alias: &str) -> Result<(), String> {
    let conn = vps::db::open()?;
    let mut p = vps::buscar(&conn, alias)?.ok_or_else(|| host_ausente(alias))?;
    // A execução interna não passa pelo gate de produção (é o app, não o agente) — então o
    // gate de prd para o bootstrap mora AQUI, onde há um humano no terminal. Bootstrap
    // escreve no servidor: em produção isso não acontece sem alguém dizer sim.
    if p.ambiente == vps::Ambiente::Prd
        && !confirm(&format!(
            "{alias:?} é PRODUÇÃO. O bootstrap escreve no host (shim, catálogo e authorized_keys). Continuar? [y/N]"
        ))
    {
        println!("{}", t("cli.vps.unchanged"));
        return Ok(());
    }
    let r = vps::bootstrap::instalar(&conn, &mut p)?;
    for n in &r.notas {
        println!("· {n}");
    }
    println!();
    if r.melhorou() {
        println!(
            "{}",
            tf("cli.vps.boundary_moved", &[("from", r.antes.rotulo()), ("to", r.depois.rotulo())])
        );
    } else {
        println!("{}", tf("cli.vps.boundary_same", &[("value", r.depois.rotulo())]));
    }
    if r.verbos > 0 {
        println!("{}", tf("cli.vps.verbs_synced", &[("count", &r.verbos.to_string())]));
    }
    println!("\n{}", r.depois.explicacao());
    if r.depois.e_server_side() {
        println!("\n{}", tf("cli.vps.hint_opsverbs", &[("alias", alias)]));
    }
    Ok(())
}

/// Gerencia o catálogo de verbos do host.
fn verbos(
    alias: &str,
    add: Option<String>,
    cmd: Option<String>,
    rm: Option<String>,
    seed: bool,
) -> Result<(), String> {
    let conn = vps::db::open()?;
    if vps::buscar(&conn, alias)?.is_none() {
        return Err(host_ausente(alias));
    }
    if let Some(nome) = &add {
        let c = cmd
            .as_deref()
            .ok_or("--add precisa do --cmd com o comando real que o verbo dispara")?;
        vps::verbos::definir(&conn, alias, nome, c)?;
        println!("{}", tf("cli.vps.verb_set", &[("name", &format!("{nome:?}"))]));
    }
    if let Some(nome) = &rm {
        if vps::verbos::remover(&conn, alias, nome)? {
            println!("{}", tf("cli.vps.verb_removed", &[("name", &format!("{nome:?}"))]));
        } else {
            println!("{}", tf("cli.vps.verb_absent", &[("name", &format!("{nome:?}"))]));
        }
    }
    if seed {
        let n = vps::verbos::semear(&conn, alias)?;
        println!("{}", tf("cli.vps.verbs_seeded", &[("count", &n.to_string())]));
    }
    let lista = vps::verbos::listar(&conn, alias)?;
    if lista.is_empty() {
        println!("{}", tf("cli.vps.catalog_empty", &[("alias", &format!("{alias:?}"))]));
        println!(
            "semeie um inicial com `schematize vps verbs {alias} --seed`, ou crie um a um com"
        );
        println!("{}", tf("cli.vps.catalog_hint", &[("alias", alias)]));
        return Ok(());
    }
    println!(
        "{}",
        tf(
            "cli.vps.catalog_header",
            &[("alias", &format!("{alias:?}")), ("count", &lista.len().to_string())]
        )
    );
    for v in &lista {
        println!("  {:<16} {}", v.nome, v.comando);
    }
    if add.is_some() || rm.is_some() || seed {
        println!("\n{}", tf("cli.vps.push_catalog", &[("alias", alias)]));
    }
    Ok(())
}

/// Mensagem de host inexistente — acionável (§37.48): diz como listar e como criar.
fn host_ausente(alias: &str) -> String {
    format!(
        "não achei o host {alias:?}. Veja os registrados com `schematize vps list`, ou registre com \
         `schematize vps add {alias} --host <ip> --user <user> --key <chave>`"
    )
}
