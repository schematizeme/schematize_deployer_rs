//! Export pro Bitwarden — a cópia de segurança da chave privada num cofre, em vez
//! de um arquivo solto no disco.

use super::*;

/// O `bw` está no PATH e DESTRAVADO? (`bw status` traz `"status":"unlocked"`.) Só então
/// criamos item direto no cofre; caso contrário caímos no arquivo de import.
pub(crate) fn bw_unlocked() -> bool {
    if !in_path("bw") {
        return false;
    }
    match util::run("bw", &["status"]) {
        Ok(s) => s.contains("\"status\":\"unlocked\""),
        Err(_) => false,
    }
}

/// Monta o corpo (notas) legível do item — inclui a privada. NUNCA é impresso em stdout;
/// só entra no item do cofre / arquivo de import.
pub(crate) fn bw_notes(
    name: &str,
    kind: &str,
    fingerprint: &str,
    pubkey: &str,
    privkey: &str,
) -> String {
    format!(
        "Chave SSH gerenciada pelo schematize\n\
         nome: {name}\n\
         tipo: {kind}\n\
         fingerprint: {fingerprint}\n\n\
         --- CHAVE PÚBLICA ---\n{pubkey}\n\n\
         --- CHAVE PRIVADA (secreta) ---\n{privkey}\n"
    )
}

/// JSON de UM item de cofre (secure note, type 2) pro `bw encode | bw create item`.
/// Campos: public_key + fingerprint (visíveis) e private_key (oculto, type 1).
pub(crate) fn bw_item_json(
    name: &str,
    notes: &str,
    pubkey: &str,
    fingerprint: &str,
    privkey: &str,
) -> String {
    let item = serde_json::json!({
        "type": 2,
        "name": format!("SSH schematize:{name}"),
        "notes": notes,
        "secureNote": { "type": 0 },
        "fields": [
            { "name": "public_key",  "value": pubkey,      "type": 0 },
            { "name": "fingerprint", "value": fingerprint, "type": 0 },
            { "name": "private_key", "value": privkey,     "type": 1 }
        ]
    });
    item.to_string()
}

/// JSON no formato de IMPORT do Bitwarden (`{items:[...]}`) — o fallback quando o `bw` não está
/// destravado. Mesma modelagem do item (secure note com os campos), envelopado em `items`.
pub(crate) fn bw_import_json(
    name: &str,
    notes: &str,
    pubkey: &str,
    fingerprint: &str,
    privkey: &str,
) -> String {
    let doc = serde_json::json!({
        "items": [ serde_json::from_str::<serde_json::Value>(
            &bw_item_json(name, notes, pubkey, fingerprint, privkey)
        ).unwrap_or(serde_json::Value::Null) ]
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into())
}

/// Caminho default do arquivo de import (`~/.schematize/bw-import-<name>.json`).
pub(crate) fn bw_import_path(name: &str) -> PathBuf {
    util::home_app_dir().join(format!("bw-import-{name}.json"))
}

/// Exporta a chave `name` pro Bitwarden. Se o `bw` estiver destravado, cria um item (secure note)
/// no cofre com nome/tipo/fingerprint/pública/PRIVADA. Senão, grava um JSON no formato de import
/// (default `~/.schematize/bw-import-<name>.json`, mode 600) e instrui a importar. A privada é lida
/// do arquivo e SÓ vai pro cofre/arquivo — NUNCA pro stdout/log. Retorna uma mensagem do que ocorreu.
pub fn export_bitwarden(name: &str, out: Option<&Path>) -> Result<String, String> {
    valid_name(name)?;
    let info = read_info(name)?;
    let priv_p = private_path(name)?;
    if !priv_p.exists() {
        return Err(format!("chave privada '{name}' não encontrada em ~/.ssh"));
    }
    let privkey = fs::read_to_string(&priv_p)
        .map_err(|e| format!("não consegui ler a privada de '{name}': {e}"))?;
    let privkey = privkey.trim_end().to_string();
    let pubkey = export_public(name)?;
    let notes = bw_notes(name, &info.kind, &info.fingerprint, &pubkey, &privkey);

    // Caminho feliz: cofre destravado → cria o item direto (bw encode | bw create item).
    if bw_unlocked() {
        let item_json = bw_item_json(name, &notes, &pubkey, &info.fingerprint, &privkey);
        let encoded = run_with_stdin("bw", &["encode"], &item_json)?;
        // `bw create item` lê o base64 pelo stdin.
        match run_with_stdin("bw", &["create", "item"], encoded.trim()) {
            Ok(_) => {
                return Ok(format!(
                    "item 'SSH schematize:{name}' criado no seu cofre Bitwarden \
                     (pública + fingerprint + privada oculta). A privada não foi impressa."
                ));
            }
            // Falhou no cofre: não perde a exportação — cai no arquivo de import.
            Err(e) => {
                eprintln!("(aviso: bw create item falhou: {e} — gerando arquivo de import)");
            }
        }
    }

    // Fallback: arquivo de import (mode 600).
    let target = match out {
        Some(p) => p.to_path_buf(),
        None => bw_import_path(name),
    };
    if let Some(dir) = target.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("falha ao criar {}: {e}", dir.display()))?;
        crate::util::definir_modo(dir, 0o700);
    }
    let body = bw_import_json(name, &notes, &pubkey, &info.fingerprint, &privkey);
    fs::write(&target, body).map_err(|e| format!("falha ao gravar {}: {e}", target.display()))?;
    crate::util::definir_modo(&target, 0o600);
    Ok(format!(
        "arquivo de import do Bitwarden gravado (mode 600) em {}\n\
         importe em: Bitwarden → Tools → Import data → formato 'Bitwarden (json)'.\n\
         Apague o arquivo depois de importar (ele contém a chave privada).",
        target.display()
    ))
}
