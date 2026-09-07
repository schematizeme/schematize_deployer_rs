//! DNS — de onde vem o token da Cloudflare.
//!
//! **O quê:** guarda e lê o token no cofre, sob uma chave conhecida.
//!
//! **Onde:** `cli::dns`, no começo de toda operação.
//!
//! **Por que é um arquivo separado de três funções:** é a fronteira entre "o segredo" e "o
//! que se faz com ele". Enquanto ela for um lugar só, dá para afirmar — e testar — que não
//! existe outro caminho pelo qual o token entra no processo.

use crate::cofre::segredos::{self, Segredos};

/// A chave do token dentro do cofre.
pub const CHAVE: &str = "cloudflare.token";

/// **O quê:** guarda o token no cofre, preservando os outros segredos.
///
/// **Onde:** `deployer dns auth`.
///
/// **Devolve** `true` se substituiu um token que já existia — a CLI diz isso ao usuário, para
/// que trocar a credencial sem querer não passe calado.
pub fn guardar(passphrase: &str, token: &str) -> Result<bool, String> {
    let t = token.trim();
    if t.is_empty() {
        return Err("o token não pode ser vazio".into());
    }
    // Carrega o mapa inteiro e devolve o mapa inteiro: gravar só esta chave apagaria as
    // outras. É a mesma família de erro do `unwrap_or_default()` que já destruiu arquivo de
    // usuário nesta casa.
    let mut s = segredos::carregar(passphrase)?;
    let substituiu = s.set(CHAVE, t);
    segredos::salvar(passphrase, &s)?;
    Ok(substituiu)
}

/// **O quê:** lê o token do cofre.
///
/// **Onde:** toda operação de DNS. A mensagem de ausência diz o comando que resolve — sem
/// ela, quem nunca configurou recebe "chave não encontrada" e não sabe o que fazer.
pub fn ler(passphrase: &str) -> Result<String, String> {
    let s = segredos::carregar(passphrase)?;
    s.get(CHAVE).map(str::to_string).ok_or_else(|| {
        "não há token da Cloudflare no cofre. Guarde um com `deployer dns auth`".to_string()
    })
}

/// **O quê:** remove o token do cofre. **Onde:** `deployer dns auth --remover`.
pub fn remover(passphrase: &str) -> Result<bool, String> {
    let mut s = segredos::carregar(passphrase)?;
    let tinha = s.remove(CHAVE);
    segredos::salvar(passphrase, &s)?;
    Ok(tinha)
}

/// **O quê:** o cofre tem token da Cloudflare? Sem revelar qual.
/// **Onde:** `deployer dns auth --status`.
pub fn existe(s: &Segredos) -> bool {
    s.get(CHAVE).is_some()
}
