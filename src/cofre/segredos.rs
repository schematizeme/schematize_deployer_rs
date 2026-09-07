//! COFRE — os segredos como MAPA, e não como um blob solto.
//!
//! **O quê:** uma camada tipada sobre [`super::arquivo`]: ler, gravar e remover segredos por
//! chave, dentro do mesmo arquivo cifrado.
//!
//! **Onde:** `dns` (o token da Cloudflare) e todo consumidor futuro. O cofre em si não sabe o
//! que guarda; este arquivo é quem dá forma.
//!
//! ## Por que um mapa, e não um arquivo por segredo
//!
//! Um arquivo por segredo multiplicaria salt, nonce e — pior — **derivações de Argon2id**: a
//! 64 MiB cada, destravar cinco segredos custaria cinco vezes o tempo e a memória. Com um
//! mapa, uma derivação abre tudo.
//!
//! O preço é que **todo segredo compartilha a mesma passphrase**, e é um preço consciente:
//! quem quer separação de fato quer cofres separados, não chaves separadas no mesmo arquivo.
//!
//! ## O que NUNCA aparece aqui
//!
//! Nenhuma função deste módulo imprime, loga ou devolve o segredo em erro. [`ler`] devolve o
//! valor para o chamador e nada mais; um `Debug` derivado no mapa vazaria tudo num
//! `dbg!` distraído, e por isso [`Segredos`] não deriva `Debug`.

use std::collections::BTreeMap;
use zeroize::Zeroize;

/// O mapa de segredos, como vive DENTRO do cofre.
///
/// **Sem `Debug` de propósito:** um `dbg!(segredos)` ou um `{:?}` num log despejaria todos os
/// tokens de uma vez. O tipo não oferece essa corda.
#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct Segredos {
    /// `chave -> valor`. `BTreeMap` e não `HashMap`: a serialização fica **determinística**,
    /// então o mesmo conteúdo produz o mesmo texto antes de cifrar — o que torna possível
    /// afirmar em teste que nada mudou além do que se quis mudar.
    #[serde(flatten)]
    itens: BTreeMap<String, String>,
}

impl Drop for Segredos {
    /// Zera os valores ao sair de escopo. O `String` do serde não é `Zeroize` sozinho, e sem
    /// isto os tokens sobreviveriam no heap liberado — indo parar em core dump e em swap.
    fn drop(&mut self) {
        for v in self.itens.values_mut() {
            v.zeroize();
        }
    }
}

impl Segredos {
    /// **O quê:** o valor de `chave`, se houver. **Onde:** `dns::credencial`.
    pub fn get(&self, chave: &str) -> Option<&str> {
        self.itens.get(chave).map(String::as_str)
    }

    /// **O quê:** define (ou substitui) um segredo. Devolve `true` se substituiu.
    pub fn set(&mut self, chave: &str, valor: &str) -> bool {
        self.itens.insert(chave.to_string(), valor.to_string()).is_some()
    }

    /// **O quê:** remove um segredo. Devolve `true` se existia.
    pub fn remove(&mut self, chave: &str) -> bool {
        if let Some(mut v) = self.itens.remove(chave) {
            v.zeroize(); // o removido também some da memória
            true
        } else {
            false
        }
    }

    /// **O quê:** as CHAVES guardadas — nunca os valores.
    ///
    /// **Onde:** `deployer cofre status` e `dns status`, para mostrar *o que* está guardado
    /// sem mostrar o quê. É a única listagem que este módulo oferece, e a limitação é o ponto.
    pub fn chaves(&self) -> Vec<&str> {
        self.itens.keys().map(String::as_str).collect()
    }

    /// **O quê:** quantos segredos há.
    pub fn len(&self) -> usize {
        self.itens.len()
    }

    /// **O quê:** está vazio?
    pub fn is_empty(&self) -> bool {
        self.itens.is_empty()
    }
}

/// **O quê:** abre o cofre e devolve o mapa de segredos.
///
/// **Onde:** todo consumidor. Um cofre recém-criado guarda `{}`, então o caminho normal é
/// desserializar um objeto vazio — não um erro.
pub fn carregar(passphrase: &str) -> Result<Segredos, String> {
    let claro = super::arquivo::abrir(passphrase)?;
    if claro.is_empty() {
        return Ok(Segredos::default());
    }
    serde_json::from_slice(&claro).map_err(|e| {
        // Não ecoa o conteúdo: ele é o segredo. Só o formato.
        format!("o cofre abriu mas o conteúdo não é um mapa de segredos válido ({e})")
    })
}

/// **O quê:** grava o mapa de volta no cofre, re-selando com salt e nonce novos.
///
/// **Onde:** todo consumidor que escreve. Ver [`super::arquivo::gravar`]: a escrita é atômica,
/// então uma falha no meio preserva o cofre anterior inteiro.
pub fn salvar(passphrase: &str, s: &Segredos) -> Result<(), String> {
    let mut json =
        serde_json::to_vec(s).map_err(|e| format!("não consegui serializar os segredos: {e}"))?;
    let r = super::arquivo::gravar(passphrase, &json);
    json.zeroize(); // o buffer em claro não sobrevive à função
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_remove() {
        let mut s = Segredos::default();
        assert!(s.is_empty());
        assert!(!s.set("cloudflare.token", "abc123"), "primeira vez não substitui");
        assert_eq!(s.get("cloudflare.token"), Some("abc123"));
        assert!(s.set("cloudflare.token", "novo"), "segunda vez substitui");
        assert_eq!(s.get("cloudflare.token"), Some("novo"));
        assert!(s.remove("cloudflare.token"));
        assert!(!s.remove("cloudflare.token"), "remover o que não existe é false");
        assert_eq!(s.get("cloudflare.token"), None);
    }

    /// **A listagem mostra CHAVES, nunca valores.** É o que permite um `status` útil sem
    /// transformar o comando de diagnóstico num despejo de credenciais.
    #[test]
    fn listar_nao_expoe_valores() {
        let mut s = Segredos::default();
        s.set("cloudflare.token", "SEGREDO-QUE-NAO-PODE-VAZAR");
        s.set("outro.token", "TAMBEM-NAO");
        let ch = s.chaves();
        assert_eq!(ch, vec!["cloudflare.token", "outro.token"], "ordenadas (BTreeMap)");
        let txt = format!("{ch:?}");
        assert!(!txt.contains("SEGREDO"), "a listagem vazou um valor: {txt}");
        assert!(!txt.contains("NAO"), "a listagem vazou um valor: {txt}");
    }

    /// A serialização é determinística — mesmo conteúdo, mesmo texto. Sem isso não dá para
    /// afirmar em teste que uma gravação mudou só o que devia.
    #[test]
    fn serializacao_e_deterministica() {
        let mut a = Segredos::default();
        a.set("z", "1");
        a.set("a", "2");
        let mut b = Segredos::default();
        b.set("a", "2");
        b.set("z", "1"); // inserido em ordem diferente
        assert_eq!(serde_json::to_string(&a).unwrap(), serde_json::to_string(&b).unwrap());
    }

    /// Ida e volta pelo JSON, que é o que vai cifrado pro disco.
    #[test]
    fn ida_e_volta_pelo_json() {
        let mut s = Segredos::default();
        s.set("cloudflare.token", "tok-123");
        let j = serde_json::to_vec(&s).unwrap();
        let volta: Segredos = serde_json::from_slice(&j).unwrap();
        assert_eq!(volta.get("cloudflare.token"), Some("tok-123"));
        assert_eq!(volta.len(), 1);
    }

    /// Cofre recém-criado guarda `{}` — desserializar isso é o caminho NORMAL, não erro.
    #[test]
    fn cofre_novo_desserializa_vazio() {
        let s: Segredos = serde_json::from_slice(b"{}").unwrap();
        assert!(s.is_empty());
    }
}
