//! Subcomandos do servidor MCP (`schematize mcp <sub>`).
//! O quê: roda o servidor, e registra/remove/inspeciona ele no `.mcp.json` do projeto e no
//! `settings.json` do Claude Code.
//! Onde: despachado por `main.rs` (`Cmd::Mcp`).

use crate::cli::args::*;
use deployer::mcp;
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
        println!("gravaria em {}:", alvo.display());
        println!("{}", serde_json::to_string_pretty(&bloco).unwrap_or_default());
        println!("\ne liberaria em permissions.allow do settings.json:");
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
    println!("servidor registrado em {}", alvo.display());

    let n = deployer::settings::permitir_tools(&perms)?;
    println!("{n} permissão(ões) de tool liberada(s) no settings.json.");
    println!("\nas tools ficam disponíveis pro agente na PRÓXIMA sessão do Claude Code:");
    for p in &perms {
        println!("  {p}");
    }
    println!("\ndica: `schematize vps hooks --on` fecha a porta errada (ssh cru) enquanto esta abre a certa.");
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
        println!("servidor removido de {}", alvo.display());
    } else {
        println!("o servidor não estava registrado em {}", alvo.display());
    }
    let n = deployer::settings::remover_tools(&mcp::nomes_de_permissao())?;
    println!("{n} permissão(ões) removida(s) do settings.json.");
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
    println!("arquivo   : {}", alvo.display());
    println!("registrado: {}", if registrado { "sim" } else { "não" });
    let perms = mcp::nomes_de_permissao();
    let liberadas = deployer::settings::tools_permitidas(&perms);
    println!("permitidas: {}/{} tools", liberadas, perms.len());
    if !registrado || liberadas < perms.len() {
        println!("\nrode `schematize mcp install` (ou `--dry-run` pra só ver o que mudaria).");
    }
    Ok(())
}
