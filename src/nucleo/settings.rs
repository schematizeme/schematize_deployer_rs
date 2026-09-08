//! NÚCLEO — as entradas do Deployer no `settings.json` do Claude Code.
//!
//! **O quê:** liga/desliga o hook `PreToolUse` do gestor de VPS e registra/remove as tools do
//! MCP em `permissions.allow`.
//!
//! **Onde:** `deployer vps hooks --on|--off` e `deployer mcp install|uninstall`.
//!
//! ## Por que este arquivo existe, sendo que o schematize tem um igual
//!
//! Não é cópia por preguiça: é a **fronteira de posse**. O `settings.json` é um arquivo só,
//! compartilhado, e cada app registra **as próprias** entradas — o schematize registra os
//! hooks do overdev (`Stop`, `overdev guard`), o Deployer registra os dele (`vps guard`) e as
//! tools de MCP. Nenhum dos dois mexe no que é do outro, e nenhum mexe em hook de terceiro.
//!
//! É por isso que [`disable_vps`] filtra por `"vps guard"` em vez de limpar o array: um
//! `PreToolUse` inteiro apagado levaria junto o `overdev guard` do vizinho.
//!
//! ## Nada aqui pode dar `panic`
//!
//! O `settings.json` é de QUEM USA. Um `"hooks": "x"` (string onde se espera objeto) já fez o
//! CLI panicar. Arquivo alheio malformado é **entrada hostil** como qualquer outra: o nó
//! errado é corrigido e a execução segue. E o `permissions.allow` do usuário costuma ter
//! dezenas de entradas construídas ao longo de meses — perder isso seria imperdoável, então
//! toda escrita é aditiva e preserva o resto.

use serde_json::{json, Value};
use std::fs;

/// **O quê:** um grupo de hooks contém um comando com este trecho?
/// **Onde:** [`disable_vps`] e [`vps_hook_enabled`] — é o que distingue o hook DESTE app.
fn group_has(group: &Value, needle: &str) -> bool {
    group.get("hooks").and_then(|h| h.as_array()).is_some_and(|arr| {
        arr.iter()
            .any(|h| h.get("command").and_then(|c| c.as_str()).is_some_and(|c| c.contains(needle)))
    })
}

/// **O quê:** lê o `settings.json` como objeto — ou objeto vazio se não existir/for inválido.
/// **Onde:** toda função pública deste módulo.
fn load() -> Value {
    match fs::read_to_string(super::util::settings_path()) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_else(|_| json!({})),
        Err(_) => json!({}),
    }
}

/// **O quê:** grava o `settings.json`, criando o diretório se preciso.
fn save(v: &Value) -> Result<(), String> {
    let p = super::util::settings_path();
    if let Some(dir) = p.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let body = serde_json::to_string_pretty(v).map_err(|e| e.to_string())?;
    fs::write(&p, body).map_err(|e| e.to_string())
}

/// **O quê:** garante que `hooks[event]` (array) tenha `group`, se ainda não houver `needle`.
/// Corrige nós de tipo errado em vez de panicar.
fn ensure_group(root: &mut Value, event: &str, needle: &str, group: Value) {
    let Some(raiz) = root.as_object_mut() else {
        return;
    };
    let hooks = raiz.entry("hooks").or_insert_with(|| json!({}));
    if !hooks.is_object() {
        *hooks = json!({});
    }
    let Some(hooks) = hooks.as_object_mut() else {
        return;
    };
    let ev = hooks.entry(event).or_insert_with(|| json!([]));
    if !ev.is_array() {
        *ev = json!([]);
    }
    let Some(arr) = ev.as_array_mut() else { return };
    if arr.iter().any(|g| group_has(g, needle)) {
        return;
    }
    arr.push(group);
}

/// **O quê:** o comando que o hook grava — o binário DESTE app, com o subcomando.
fn hook_cmd(exe: &str, sub: &str) -> String {
    format!("{exe} {sub}")
}

/// **O quê:** liga o hook do gestor de VPS — `PreToolUse` em TODAS as tools, barrando SSH cru
/// e leitura de chave privada (ver `vps::hook`).
///
/// **Onde:** `deployer vps hooks --on`.
///
/// O matcher é `"*"` porque a checagem de chave privada precisa ver o input de **qualquer**
/// tool: um `Write` com a chave no conteúdo vaza igual a um `Bash`.
pub fn enable_vps(exe: &str) -> Result<(), String> {
    let mut root = load();
    if !root.is_object() {
        root = json!({});
    }
    let cmd = hook_cmd(exe, "vps guard");
    ensure_group(
        &mut root,
        "PreToolUse",
        "vps guard",
        json!({ "matcher": "*", "hooks": [ { "type": "command", "command": cmd } ] }),
    );
    save(&root)
}

/// **O quê:** remove o hook do gestor de VPS — e **só** ele.
/// **Onde:** `deployer vps hooks --off`. Ver a nota de posse no topo do módulo.
pub fn disable_vps() -> Result<(), String> {
    let mut root = load();
    if let Some(arr) =
        root.get_mut("hooks").and_then(|h| h.get_mut("PreToolUse")).and_then(|a| a.as_array_mut())
    {
        arr.retain(|g| !group_has(g, "vps guard"));
    }
    save(&root)
}

/// **O quê:** acrescenta nomes de tool ao `permissions.allow`, sem duplicar e sem remover
/// nada. Devolve quantos entraram. **Onde:** `deployer mcp install`.
pub fn permitir_tools(nomes: &[String]) -> Result<usize, String> {
    let mut root = load();
    if !root.is_object() {
        root = json!({});
    }
    let Some(raiz) = root.as_object_mut() else {
        return Ok(0);
    };
    let perms = raiz.entry("permissions").or_insert_with(|| json!({}));
    if !perms.is_object() {
        *perms = json!({});
    }
    let Some(perms) = perms.as_object_mut() else {
        return Ok(0);
    };
    let allow = perms.entry("allow").or_insert_with(|| json!([]));
    if !allow.is_array() {
        *allow = json!([]);
    }
    let Some(arr) = allow.as_array_mut() else {
        return Ok(0);
    };
    let mut n = 0;
    for nome in nomes {
        if !arr.iter().any(|v| v.as_str() == Some(nome.as_str())) {
            arr.push(json!(nome));
            n += 1;
        }
    }
    save(&root)?;
    Ok(n)
}

/// **O quê:** remove nomes de tool do `permissions.allow`. Devolve quantos saíram.
/// **Onde:** `deployer mcp uninstall`.
pub fn remover_tools(nomes: &[String]) -> Result<usize, String> {
    let mut root = load();
    let Some(arr) =
        root.get_mut("permissions").and_then(|p| p.get_mut("allow")).and_then(|a| a.as_array_mut())
    else {
        return Ok(0);
    };
    let antes = arr.len();
    arr.retain(|v| !v.as_str().is_some_and(|s| nomes.iter().any(|n| n == s)));
    let n = antes - arr.len();
    save(&root)?;
    Ok(n)
}

/// **O quê:** quantos dos `nomes` já estão em `permissions.allow`.
/// **Onde:** `deployer mcp status`.
pub fn tools_permitidas(nomes: &[String]) -> usize {
    let root = load();
    let Some(arr) = root.get("permissions").and_then(|p| p.get("allow")).and_then(|a| a.as_array())
    else {
        return 0;
    };
    nomes.iter().filter(|n| arr.iter().any(|v| v.as_str() == Some(n.as_str()))).count()
}

/// **O quê:** o hook do gestor de VPS está registrado?
/// **Onde:** `deployer vps hooks` (sem flag, mostra o estado) e o `doctor`.
pub fn vps_hook_enabled() -> bool {
    load()
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|a| a.as_array())
        .is_some_and(|arr| arr.iter().any(|g| group_has(g, "vps guard")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A regra de posse: desligar o hook DESTE app não pode levar junto o do vizinho.
    /// É o teste que impede a regressão mais cara possível neste arquivo — apagar
    /// configuração alheia.
    #[test]
    fn desligar_o_vps_preserva_hook_de_terceiro() {
        let mut root = json!({
            "hooks": { "PreToolUse": [
                { "matcher": "*",               "hooks": [{ "type": "command", "command": "/x/schematize-deployer vps guard" }] },
                { "matcher": "AskUserQuestion", "hooks": [{ "type": "command", "command": "/x/schematize overdev guard" }] },
                { "matcher": "*",               "hooks": [{ "type": "command", "command": "/algum/hook/alheio" }] }
            ]}
        });
        if let Some(arr) = root
            .get_mut("hooks")
            .and_then(|h| h.get_mut("PreToolUse"))
            .and_then(|a| a.as_array_mut())
        {
            arr.retain(|g| !group_has(g, "vps guard"));
        }
        let arr = root["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 2, "só o grupo do vps podia sair");
        let txt = serde_json::to_string(arr).unwrap();
        assert!(txt.contains("overdev guard"), "levou o hook do schematize junto");
        assert!(txt.contains("/algum/hook/alheio"), "levou hook de terceiro junto");
        assert!(!txt.contains("vps guard"));
    }

    /// `settings.json` malformado é entrada hostil: corrige o nó, não panica.
    #[test]
    fn no_de_tipo_errado_e_corrigido_sem_panicar() {
        let mut root = json!({ "hooks": "isto deveria ser um objeto" });
        ensure_group(&mut root, "PreToolUse", "vps guard", json!({ "matcher": "*" }));
        assert!(root["hooks"].is_object(), "o nó errado tinha de ser corrigido");
        assert_eq!(root["hooks"]["PreToolUse"].as_array().map(|a| a.len()), Some(1));
    }

    /// Registrar duas vezes não duplica — o instalador roda a cada atualização.
    #[test]
    fn registrar_duas_vezes_nao_duplica() {
        let mut root = json!({});
        for _ in 0..2 {
            ensure_group(
                &mut root,
                "PreToolUse",
                "vps guard",
                json!({ "matcher": "*", "hooks": [{ "type": "command", "command": "d vps guard" }] }),
            );
        }
        assert_eq!(root["hooks"]["PreToolUse"].as_array().map(|a| a.len()), Some(1));
    }
}
