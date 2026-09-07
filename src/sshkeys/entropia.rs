//! Piso CRIPTOGRÁFICO da casa: tamanho mínimo de RSA e a prova de que a chave
//! gerada atende (nada de chave fraca passar calada).

use super::*;

/// Bits mínimos aceitos para RSA (deny-by-default: nada abaixo disso).
pub const RSA_MIN_BITS: u32 = 4096;

/// Nota (legível) sobre o NÍVEL de entropia/segurança de um tipo de chave — pra mostrar como
/// prova ao usuário. Toda geração usa o CSPRNG do `ssh-keygen` (getrandom do kernel).
pub fn entropy_note(kind: KeyKind) -> String {
    match kind {
        KeyKind::Ed25519 =>
            "ed25519 (Curve25519): chave de 256 bits do CSPRNG do ssh-keygen (getrandom do kernel), \
             ~128 bits de segurança efetiva — o padrão recomendado da casa."
                .to_string(),
        KeyKind::Rsa4096 => format!(
            "RSA {RSA_MIN_BITS} bits do CSPRNG do ssh-keygen, ~140+ bits de segurança efetiva — \
             só para hosts/dispositivos legados que ainda não falam ed25519."
        ),
    }
}

/// Valida o PISO de entropia do pedido (falha fechada). ed25519 é sempre aceito (256-bit fixo,
/// CSPRNG); RSA só com bits >= `RSA_MIN_BITS`. Chamado por `generate` antes de invocar o ssh-keygen.
pub fn validate_entropy(kind: KeyKind) -> Result<(), String> {
    match kind {
        KeyKind::Ed25519 => Ok(()),
        KeyKind::Rsa4096 => {
            let bits = kind.bits().unwrap_or(0);
            if bits < RSA_MIN_BITS {
                Err(format!(
                    "RSA com {bits} bits é fraco — o piso da casa é {RSA_MIN_BITS} bits \
                     (prefira ed25519, o default)"
                ))
            } else {
                Ok(())
            }
        }
    }
}

/// Linha de PROVA da chave: `ssh-keygen -l -f <pub>` → "bits SHA256:… comentário (TIPO)".
/// Mostra bits + fingerprint + tipo de uma vez (o usuário confere a força visualmente).
/// Best-effort: erro claro se a pública some ou o ssh-keygen falha.
pub fn proof_line(name: &str) -> Result<String, String> {
    let pub_p = public_path(name)?;
    if !pub_p.exists() {
        return Err(format!("chave pública '{name}' não encontrada em ~/.ssh"));
    }
    util::run("ssh-keygen", &["-l", "-f", &pub_p.to_string_lossy()])
        .map(|s| s.trim().to_string())
        .map_err(|e| format!("ssh-keygen -l falhou: {e}"))
}
