//! Subcomandos do servidor MCP (`schematize mcp <sub>`).
//! O quê: roda o servidor, e registra/remove/inspeciona ele no `.mcp.json` do projeto e no
//! `settings.json` do Claude Code.
//! Onde: despachado por `main.rs` (`Cmd::Mcp`).

use crate::cli::args::*;
use deployer::mcp;
use deployer::nucleo::i18n::{t, tf};
use serde_json::{json, Value};
use std::path::PathBuf;

/// Despacha `schematize mcp <sub>`.
pub(crate) fn mcp_cmd(sub: McpCmd) -> Result<(), String> {
    match sub {
        // NADA pode ser impresso aqui além do protocolo: stdout é o canal do JSON-RPC.
        McpCmd::Serve => {
            mcp::servir();
            Ok(())
        }
        McpCmd::Install { dry_run } => instalar(dry_run),
        McpCmd::Uninstall => desinstalar(),
        McpCmd::Status => estado(),
    }
}

/// `.mcp.json` do projeto corrente (o formato que o Claude Code lê por projeto).
fn caminho_mcp_json() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join(".mcp.json")
}

/// Lê um JSON de objeto, ou objeto vazio se não existir/for inválido.
///
/// Arquivo alheio malformado é entrada hostil: corrige o nó e segue, nunca panica.
fn ler_json(p: &PathBuf) -> Value {
    match std::fs::read_to_string(p) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_else(|_| json!({})),
        Err(_) => json!({}),
    }
}

/// Registra o servidor e libera as tools.
fn instalar(dry_run: bool) -> Result<(), String> {
    let exe = deployer::util::self_exe();
    let bloco = mcp::bloco_mcp_json(&exe);
    let perms = mcp::nomes_de_permissao();
    let alvo = caminho_mcp_json();

    if dry_run {
        println!("{}", tf("cli.mcp.would_write", &[("path", &alvo.display().to_string())]));
        println!("{}", serde_json::to_string_pretty(&bloco).unwrap_or_default());
        println!("\n{}", t("cli.mcp.would_allow"));
        for p in &perms {
            println!("  {p}");
        }
        return Ok(());
    }

    // .mcp.json — PRESERVA os outros servidores do projeto.
    let mut raiz = ler_json(&alvo);
    if !raiz.is_object() {
        raiz = json!({});
    }
    {
        let Some(obj) = raiz.as_object_mut() else {
            return Err(format!("{} não é um objeto JSON", alvo.display()));
        };
        let servers = obj.entry("mcpServers").or_insert_with(|| json!({}));
        if !servers.is_object() {
            *servers = json!({});
        }
        if let (Some(s), Some(novo)) = (servers.as_object_mut(), bloco["mcpServers"].as_object()) {
            for (k, v) in novo {
                s.insert(k.clone(), v.clone());
            }
        }
    }
    std::fs::write(&alvo, serde_json::to_string_pretty(&raiz).unwrap_or_default())
        .map_err(|e| format!("não consegui gravar {}: {e}", alvo.display()))?;
    println!("{}", tf("cli.mcp.registered", &[("path", &alvo.display().to_string())]));

    let n = deployer::settings::permitir_tools(&perms)?;
    println!("{}", tf("cli.mcp.allowed", &[("count", &n.to_string())]));
    println!("\n{}", t("cli.mcp.next_session"));
    for p in &perms {
        println!("  {p}");
    }
    println!("\n{}", t("cli.mcp.hint_hooks"));
    Ok(())
}

/// Remove o servidor e as permissões.
fn desinstalar() -> Result<(), String> {
    let alvo = caminho_mcp_json();
    let mut raiz = ler_json(&alvo);
    let mut removeu = false;
    if let Some(s) = raiz.get_mut("mcpServers").and_then(|s| s.as_object_mut()) {
        removeu = s.remove(deployer::mcp::protocolo::NOME_DO_SERVIDOR).is_some();
    }
    if removeu {
        std::fs::write(&alvo, serde_json::to_string_pretty(&raiz).unwrap_or_default())
            .map_err(|e| format!("não consegui gravar {}: {e}", alvo.display()))?;
        println!("{}", tf("cli.mcp.removed", &[("path", &alvo.display().to_string())]));
    } else {
        println!("{}", tf("cli.mcp.was_absent", &[("path", &alvo.display().to_string())]));
    }
    let n = deployer::settings::remover_tools(&mcp::nomes_de_permissao())?;
    println!("{}", tf("cli.mcp.perms_removed", &[("count", &n.to_string())]));
    Ok(())
}

/// Mostra o estado do registro.
fn estado() -> Result<(), String> {
    let alvo = caminho_mcp_json();
    let raiz = ler_json(&alvo);
    let registrado = raiz
        .get("mcpServers")
        .and_then(|s| s.get(deployer::mcp::protocolo::NOME_DO_SERVIDOR))
        .is_some();
    println!("{}", tf("cli.mcp.file", &[("path", &alvo.display().to_string())]));
    println!(
        "{}",
        tf(
            "cli.mcp.is_registered",
            &[("value", &t(if registrado { "common.yes" } else { "common.no" }))]
        )
    );
    let perms = mcp::nomes_de_permissao();
    let liberadas = deployer::settings::tools_permitidas(&perms);
    println!(
        "{}",
        tf(
            "cli.mcp.allowed_count",
            &[("allowed", &liberadas.to_string()), ("total", &perms.len().to_string())]
        )
    );
    if !registrado || liberadas < perms.len() {
        println!("\n{}", t("cli.mcp.run_install"));
    }
    Ok(())
}
