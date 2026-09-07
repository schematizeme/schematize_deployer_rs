//! sshkeys — gestão de chaves SSH da máquina do usuário (gerar/IMPORTAR/listar/exportar/remover).
//! O quê: envolve o `ssh-keygen` (via `util`) pra agilizar setup de GitHub/servidores;
//! guarda o par em `~/.ssh/<name>` (privada 600) e `~/.ssh/<name>.pub` (644).
//! Onde: lógica COMPARTILHADA (o CLI usa via `schematize ssh`; a GUI consumirá depois).
//!
//! SEGURANÇA (piso, deny-by-default):
//! - a chave PRIVADA nunca é lida, impressa, copiada nem exportada — só a PÚBLICA sai;
//! - nome validado por allow-list (sem `/`, sem `..`, sem `~`) pra não escapar de `~/.ssh`;
//! - permissões forçadas: privada 600, pública 644, diretório `~/.ssh` 700;
//! - passphrase repassada ao `ssh-keygen` sem ecoar (nunca vai pra log/stdout);
//! - não sobrescreve chave existente sem `force` explícito.

use crate::util;
use std::fs;
use std::path::{Path, PathBuf};

// Submódulos (piso da casa: <=750 linhas, uma unidade lógica por arquivo).
mod bitwarden;
mod chaves;
mod entropia;
mod importar;
mod uso;
pub use bitwarden::*;
pub use chaves::*;
pub use entropia::*;
pub use importar::*;
pub use uso::*;

// ------------------------------------------------------------------------------------------------
// ENTROPIA — piso de segurança na geração.
// ------------------------------------------------------------------------------------------------

// ------------------------------------------------------------------------------------------------
// DEPLOY sem chave inline — usar a chave gerenciada pra logar/rodar comando remoto, e instalar a
// PÚBLICA no host. A privada NUNCA vai pra stdout/log: só é referenciada pelo caminho (`ssh -i`).
// ------------------------------------------------------------------------------------------------

// ------------------------------------------------------------------------------------------------
// EXPORT pro Bitwarden — via CLI `bw` (se destravado) OU arquivo de IMPORT (fallback).
// A chave PRIVADA só vai pro cofre/arquivo (mode 600) — NUNCA pro stdout/log.
// ------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_keykind_rol_e_default() {
        assert_eq!(KeyKind::parse("ed25519").unwrap(), KeyKind::Ed25519);
        assert_eq!(KeyKind::parse("ED").unwrap(), KeyKind::Ed25519);
        assert_eq!(KeyKind::parse("").unwrap(), KeyKind::Ed25519); // default
        assert_eq!(KeyKind::parse("rsa").unwrap(), KeyKind::Rsa4096);
        assert_eq!(KeyKind::parse("rsa4096").unwrap(), KeyKind::Rsa4096);
        assert!(KeyKind::parse("dsa").is_err()); // deny-by-default
        assert!(KeyKind::parse("ecdsa").is_err());
    }

    #[test]
    fn nome_invalido_e_recusado_deny_by_default() {
        // Válidos.
        assert!(valid_name("github").is_ok());
        assert!(valid_name("id_ed25519").is_ok());
        assert!(valid_name("srv-01.prod").is_ok());
        // Inválidos — nada que escape de ~/.ssh.
        assert!(valid_name("").is_err());
        assert!(valid_name("../evil").is_err());
        assert!(valid_name("a/b").is_err());
        assert!(valid_name("a\\b").is_err());
        assert!(valid_name(".hidden").is_err()); // não começa por alfanumérico
        assert!(valid_name("-flag").is_err());
        assert!(valid_name("foo..bar").is_err());
        assert!(valid_name("nome com espaco").is_err());
        assert!(valid_name(&"x".repeat(65)).is_err()); // longo demais
    }

    #[test]
    fn keygen_args_ed25519_nao_tem_bits() {
        let a = keygen_args(KeyKind::Ed25519, "/home/u/.ssh/k", "c@h", "");
        assert!(a.contains(&"-t".to_string()));
        assert!(a.contains(&"ed25519".to_string()));
        assert!(!a.contains(&"-b".to_string()), "ed25519 não usa -b");
        // -f aponta pro caminho da privada e -C traz o comentário.
        let fi = a.iter().position(|s| s == "-f").unwrap();
        assert_eq!(a[fi + 1], "/home/u/.ssh/k");
        let ci = a.iter().position(|s| s == "-C").unwrap();
        assert_eq!(a[ci + 1], "c@h");
        // -N presente (passphrase vazia = sem senha).
        let ni = a.iter().position(|s| s == "-N").unwrap();
        assert_eq!(a[ni + 1], "");
    }

    #[test]
    fn keygen_args_rsa_tem_bits_4096_e_passphrase() {
        let a = keygen_args(KeyKind::Rsa4096, "/home/u/.ssh/k", "c", "s3cr3t");
        let bi = a.iter().position(|s| s == "-b").expect("rsa usa -b");
        assert_eq!(a[bi + 1], "4096");
        assert!(a.contains(&"rsa".to_string()));
        let ni = a.iter().position(|s| s == "-N").unwrap();
        assert_eq!(a[ni + 1], "s3cr3t"); // passphrase repassada via -N
    }

    #[test]
    fn parse_de_linha_publica() {
        let ed = "ssh-ed25519 AAAAC3NzaC1lZDI1 schematize:lucas@box";
        assert_eq!(kind_from_publine(ed), "ED25519");
        assert_eq!(comment_from_publine(ed), "schematize:lucas@box");
        let rsa = "ssh-rsa AAAAB3Nza comentario com espacos";
        assert_eq!(kind_from_publine(rsa), "RSA");
        assert_eq!(comment_from_publine(rsa), "comentario com espacos");
        // Sem comentário.
        let semc = "ssh-ed25519 AAAAC3NzaC1lZDI1";
        assert_eq!(comment_from_publine(semc), "");
    }

    #[test]
    fn comentario_padrao_tem_prefixo_schematize() {
        let c = default_comment();
        assert!(c.starts_with("schematize:"), "comentário: {c}");
        assert!(c.contains('@'));
    }

    #[test]
    fn entropia_ed25519_sempre_ok_rsa_no_piso() {
        // ed25519 é aceito e a nota cita 256/128 bits.
        assert!(validate_entropy(KeyKind::Ed25519).is_ok());
        let n = entropy_note(KeyKind::Ed25519);
        assert!(n.contains("256"));
        assert!(n.contains("128"));
        // RSA do rol é 4096 (>= piso) → aceito; a nota cita 4096.
        assert!(validate_entropy(KeyKind::Rsa4096).is_ok());
        assert!(entropy_note(KeyKind::Rsa4096).contains("4096"));
        assert_eq!(RSA_MIN_BITS, 4096);
    }

    #[test]
    fn alvo_ssh_valido_recusa_injecao_de_flag() {
        assert!(valid_target("root@host").is_ok());
        assert!(valid_target("host.local").is_ok());
        assert!(valid_target("deploy@10.0.0.1").is_ok());
        // Falha fechada: vazio, começando por '-' (flag), ou com espaço.
        assert!(valid_target("").is_err());
        assert!(valid_target("-oProxyCommand=evil").is_err());
        assert!(valid_target("user@host extra").is_err());
    }

    #[test]
    fn key_path_valida_nome_e_fica_em_ssh() {
        let p = key_path("deploy").expect("nome válido");
        assert!(p.ends_with("deploy"));
        assert!(p.to_string_lossy().contains(".ssh"));
        // Nome que escaparia de ~/.ssh é recusado.
        assert!(key_path("../evil").is_err());
    }

    #[test]
    fn bw_item_json_tem_secure_note_e_campos() {
        let notes = bw_notes("deploy", "ED25519", "SHA256:abc", "ssh-ed25519 AAA c", "PRIV");
        let j = bw_item_json("deploy", &notes, "ssh-ed25519 AAA c", "SHA256:abc", "PRIV");
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["type"], 2); // secure note
        assert_eq!(v["secureNote"]["type"], 0);
        assert_eq!(v["name"], "SSH schematize:deploy");
        // Campos: public_key/fingerprint visíveis, private_key oculto (type 1).
        let fields = v["fields"].as_array().unwrap();
        assert!(fields.iter().any(|f| f["name"] == "public_key" && f["type"] == 0));
        assert!(fields.iter().any(|f| f["name"] == "fingerprint" && f["type"] == 0));
        assert!(fields.iter().any(|f| f["name"] == "private_key" && f["type"] == 1));
        // A privada está presente no item (vai pro cofre), mas o notes também a carrega.
        assert!(notes.contains("PRIV"));
    }

    #[test]
    fn bw_import_json_envelopa_em_items() {
        let notes = bw_notes("k", "RSA", "SHA256:z", "ssh-rsa AAA", "PRIV");
        let j = bw_import_json("k", &notes, "ssh-rsa AAA", "SHA256:z", "PRIV");
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        let items = v["items"].as_array().expect("items é array");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["type"], 2);
        assert_eq!(items[0]["name"], "SSH schematize:k");
    }
}
