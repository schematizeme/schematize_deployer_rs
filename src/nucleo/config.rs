//! NÚCLEO — a configuração do Deployer, e a primeira peça de integração de ecossistema.
//!
//! **O quê:** guarda a preferência de idioma do Deployer, e a **herda** do schematize quando
//! o usuário já escolheu uma lá.
//!
//! **Onde:** [`crate::nucleo::i18n`], na resolução do idioma ativo.
//!
//! ## Duas regras que este arquivo existe para cumprir
//!
//! **1. Estado próprio em arquivo próprio.** O Deployer grava só em `deployer.json`. O
//! `config.json` do schematize carrega coisas que este app não conhece — `dev_dirs`,
//! `projects`, `recent_projects`. Um `load()` numa struct que não tem esses campos, seguido
//! de `save()`, **apaga** todos eles: é a mesma família do `unwrap_or_default()` que já
//! destruiu `.bashrc` e `~/.ssh/config` de gente nesta casa. A defesa aqui não é lembrar de
//! não fazer isso — é **não ter** a escrita.
//!
//! **2. Ler o vizinho é integração; escrever nele é invasão.** Se o schematize está
//! instalado e a pessoa escolheu português lá, o Deployer abre em português sem perguntar de
//! novo. Se o schematize não existe, o arquivo não existe, e cai no default — degradação
//! graciosa (piso 10), não erro.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuração PRÓPRIA do Deployer. Deliberadamente mínima: cada campo aqui é um campo que
/// alguém tem de manter, migrar e traduzir.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    /// Idioma escolhido no Deployer. `None` = herdar do schematize, ou cair no default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
}

/// **O quê:** caminho do config DESTE app.
/// **Onde:** [`load`] e [`save`].
pub fn config_path() -> PathBuf {
    super::util::dados_dir().join("deployer.json")
}

/// **O quê:** caminho do config do SCHEMATIZE — lido, nunca escrito.
/// **Onde:** [`lang_herdada`].
fn config_do_schematize() -> PathBuf {
    super::util::config_path()
}

/// **O quê:** lê o config do Deployer. Arquivo ausente ou inválido devolve o default —
/// configuração corrompida não pode impedir o app de abrir.
pub fn load() -> Config {
    std::fs::read_to_string(config_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// **O quê:** grava o config do Deployer. **Onde:** [`set_lang`].
pub fn save(c: &Config) -> Result<(), String> {
    let p = config_path();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let body = serde_json::to_string_pretty(c).map_err(|e| e.to_string())?;
    std::fs::write(&p, body).map_err(|e| e.to_string())
}

/// **O quê:** define o idioma do Deployer. Escreve **só** no `deployer.json`.
pub fn set_lang(code: &str) -> Result<(), String> {
    let mut c = load();
    c.lang = Some(code.to_string());
    save(&c)
}

/// **O quê:** o idioma que o schematize tem configurado, se houver.
///
/// **Onde:** [`lang_efetiva`]. Lê o JSON como `Value` e pega **um** campo: assim um
/// `config.json` com campos que este app não conhece não vira erro nem perda.
pub fn lang_herdada() -> Option<String> {
    let txt = std::fs::read_to_string(config_do_schematize()).ok()?;
    let v: serde_json::Value = serde_json::from_str(&txt).ok()?;
    v.get("lang")?.as_str().map(str::to_string)
}

/// **O quê:** o idioma que vale AGORA — o do Deployer, senão o herdado do schematize,
/// senão `None` (o chamador aplica o default).
///
/// **Onde:** [`crate::nucleo::i18n`].
pub fn lang_efetiva() -> Option<String> {
    load().lang.or_else(lang_herdada)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A precedência: escolha explícita no Deployer vence a herdada.
    #[test]
    fn escolha_propria_vence_a_herdada() {
        let c = Config { lang: Some("ja".into()) };
        assert_eq!(c.lang.clone().or_else(|| Some("pt".into())), Some("ja".into()));
        let vazio = Config { lang: None };
        assert_eq!(vazio.lang.or_else(|| Some("pt".into())), Some("pt".into()));
    }

    /// O config do Deployer NÃO serializa campo ausente — é o que garante que o arquivo
    /// dele nunca ganhe chaves que ele não entende.
    #[test]
    fn config_vazio_nao_grava_lang_nula() {
        let s = serde_json::to_string(&Config::default()).unwrap();
        assert_eq!(s, "{}", "`lang: null` no arquivo confundiria a herança: {s}");
    }

    /// Config corrompido não impede o app de abrir.
    #[test]
    fn json_invalido_cai_no_default_sem_panicar() {
        let r: Result<Config, _> = serde_json::from_str("{ isto nao e json");
        assert!(r.is_err());
        assert!(r.unwrap_or_default().lang.is_none());
    }

    /// **A regra que este arquivo existe para cumprir:** a leitura do config do vizinho
    /// extrai UM campo e ignora o resto — nunca desserializa numa struct que perderia os
    /// outros. Se alguém trocar isto por `serde_json::from_str::<Config>`, os `dev_dirs` e
    /// `projects` do usuário somem no primeiro `save`.
    #[test]
    fn heranca_le_um_campo_e_preserva_o_resto() {
        let vizinho = r#"{"lang":"de","dev_dirs":["/a","/b"],"projects":["/p"]}"#;
        let v: serde_json::Value = serde_json::from_str(vizinho).unwrap();
        assert_eq!(v.get("lang").and_then(|l| l.as_str()), Some("de"));
        // O que importa: os campos alheios continuam lá, intocados.
        assert_eq!(v["dev_dirs"].as_array().map(|a| a.len()), Some(2));
        assert!(v.get("projects").is_some());
    }
}
