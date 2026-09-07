//! i18n — catálogo de strings multi-idioma da UI (CLI + GUI).
//! O quê: resolve o idioma ativo (config → env → fallback en) e traduz chaves.
//! Onde: `t()`/`tf()` usados por main/gui/agent/doctor/status/news/upgrade.
//! Os JSONs por idioma vivem em `src/i18n/<code>.json` e são embutidos no binário.

use super::config;
use std::collections::HashMap;
use std::sync::RwLock;

/// Idiomas suportados: (código, nome nativo, JSON embutido).
/// Adicionar idioma = um `.json` + uma linha aqui.
pub const LANGS: &[(&str, &str, &str)] = &[
    ("en", "English", include_str!("i18n/en.json")),
    ("es", "Español", include_str!("i18n/es.json")),
    ("it", "Italiano", include_str!("i18n/it.json")),
    ("fr", "Français", include_str!("i18n/fr.json")),
    ("de", "Deutsch", include_str!("i18n/de.json")),
    ("pt", "Português", include_str!("i18n/pt.json")),
    ("ja", "日本語", include_str!("i18n/ja.json")),
    ("zh", "中文", include_str!("i18n/zh.json")),
    ("ru", "Русский", include_str!("i18n/ru.json")),
    ("ar", "العربية", include_str!("i18n/ar.json")),
    ("hi", "हिन्दी", include_str!("i18n/hi.json")),
    ("ko", "한국어", include_str!("i18n/ko.json")),
    ("tr", "Türkçe", include_str!("i18n/tr.json")),
    ("vi", "Tiếng Việt", include_str!("i18n/vi.json")),
    ("id", "Bahasa Indonesia", include_str!("i18n/id.json")),
    ("pl", "Polski", include_str!("i18n/pl.json")),
    ("nl", "Nederlands", include_str!("i18n/nl.json")),
    ("th", "ไทย", include_str!("i18n/th.json")),
    ("fa", "فارسی", include_str!("i18n/fa.json")),
    ("bn", "বাংলা", include_str!("i18n/bn.json")),
];

/// Idiomas escritos da direita para a esquerda (RTL). A direção é da UI, não do JSON.
pub fn is_rtl(code: &str) -> bool {
    matches!(code, "ar" | "fa")
}

/// Idioma ativo já parseado (mapa do idioma + mapa en para fallback).
struct Active {
    code: String,
    map: HashMap<String, String>,
    en: HashMap<String, String>,
}

static ACTIVE: RwLock<Option<Active>> = RwLock::new(None);

/// True se o código é um idioma que suportamos.
pub fn is_supported(code: &str) -> bool {
    LANGS.iter().any(|(c, _, _)| *c == code)
}

/// Nome nativo do idioma, se suportado.
pub fn name_of(code: &str) -> Option<&'static str> {
    LANGS.iter().find(|(c, _, _)| *c == code).map(|(_, n, _)| *n)
}

/// JSON embutido de um código (ou en como fallback).
fn json_of(code: &str) -> &'static str {
    LANGS.iter().find(|(c, _, _)| *c == code).map(|(_, _, j)| *j).unwrap_or(LANGS[0].2)
}

fn parse(code: &str) -> HashMap<String, String> {
    serde_json::from_str(json_of(code)).unwrap_or_default()
}

/// Normaliza um valor de env tipo "pt_BR.UTF-8" → "pt" (se suportado).
fn from_env_value(v: &str) -> Option<String> {
    let two: String = v.chars().take_while(|c| c.is_ascii_alphabetic()).collect();
    let two = two.to_lowercase();
    if two.len() >= 2 {
        let code = &two[..2];
        if is_supported(code) {
            return Some(code.to_string());
        }
    }
    None
}

/// Resolve o idioma ativo: config.json → $SCHEMATIZE_LANG → $LANG/$LC_* → en.
pub fn resolve_code() -> String {
    // `lang_efetiva`: o idioma do Deployer, ou — se ele não tem — o que o usuário já
    // escolheu no schematize. Herdar é integração; o Deployer nunca ESCREVE no config do
    // vizinho (ver `nucleo::config`). Sem o schematize instalado isto é `None` e a cadeia
    // segue para o ambiente, em vez de falhar.
    if let Some(c) = config::lang_efetiva() {
        if is_supported(&c) {
            return c;
        }
    }
    for var in ["DEPLOYER_LANG", "SCHEMATIZE_LANG", "LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(v) = std::env::var(var) {
            if let Some(c) = from_env_value(&v) {
                return c;
            }
        }
    }
    "en".to_string()
}

/// Garante o idioma ativo carregado (idempotente).
fn ensure() {
    {
        if ACTIVE.read().unwrap().is_some() {
            return;
        }
    }
    let code = resolve_code();
    let a = Active { map: parse(&code), en: parse("en"), code };
    *ACTIVE.write().unwrap() = Some(a);
}

/// Troca o idioma ativo em runtime (GUI) e persiste na config.
pub fn set_lang(code: &str) -> Result<(), String> {
    if !is_supported(code) {
        return Err(format!("idioma não suportado: {code}"));
    }
    config::set_lang(code)?;
    let a = Active { map: parse(code), en: parse("en"), code: code.to_string() };
    *ACTIVE.write().unwrap() = Some(a);
    Ok(())
}

/// Código do idioma ativo.
pub fn current_code() -> String {
    ensure();
    ACTIVE.read().unwrap().as_ref().map(|a| a.code.clone()).unwrap_or_else(|| "en".into())
}

/// Traduz uma chave. Fallback: idioma ativo → en → a própria chave.
pub fn t(key: &str) -> String {
    ensure();
    let g = ACTIVE.read().unwrap();
    let a = g.as_ref().unwrap();
    a.map.get(key).or_else(|| a.en.get(key)).cloned().unwrap_or_else(|| key.to_string())
}

/// Traduz e substitui placeholders `{nome}` pelos valores dados.
pub fn tf(key: &str, args: &[(&str, &str)]) -> String {
    let mut s = t(key);
    for (k, v) in args {
        s = s.replace(&format!("{{{k}}}"), v);
    }
    s
}

#[cfg(test)]
mod tests_paridade {
    use std::collections::BTreeSet;

    /// Lê os pares `"chave": "valor"` de um JSON de locale sem depender de crate externa
    /// no teste — basta o suficiente pra conferir chaves e placeholders.
    fn pares(bruto: &str) -> Vec<(String, String)> {
        serde_json::from_str::<std::collections::BTreeMap<String, String>>(bruto)
            .expect("locale tem que ser JSON válido")
            .into_iter()
            .collect()
    }

    fn locales() -> Vec<(String, String)> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/nucleo/i18n");
        let mut v: Vec<(String, String)> = std::fs::read_dir(dir)
            .expect("src/nucleo/i18n existe")
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .map(|e| {
                let nome = e.path().file_stem().unwrap().to_string_lossy().to_string();
                (nome, std::fs::read_to_string(e.path()).expect("locale legível"))
            })
            .collect();
        v.sort();
        v
    }

    /// Os placeholders `{assim}` de uma string, ordenados.
    fn placeholders(s: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let b = s.as_bytes();
        let mut i = 0;
        while let Some(ini) = b[i..].iter().position(|c| *c == b'{').map(|p| p + i) {
            match b[ini..].iter().position(|c| *c == b'}').map(|p| p + ini) {
                Some(fim) => {
                    out.insert(s[ini..=fim].to_string());
                    i = fim + 1;
                }
                None => break,
            }
        }
        out
    }

    /// O QUE: todo locale tem EXATAMENTE as chaves do `pt.json`.
    ///
    /// POR QUE é teste e não script: a paridade só era conferida por um `gate.sh` que
    /// apontava pra um workspace morto — na prática, ninguém checava. 18 dos 20 locales
    /// ficaram sem 12 chaves `env.*` e o buraco só apareceu por acaso. Gate que não roda
    /// não é gate.
    #[test]
    fn todos_os_locales_tem_as_mesmas_chaves() {
        let todos = locales();
        let pt = todos.iter().find(|(n, _)| n == "pt").expect("pt.json existe");
        let base: BTreeSet<String> = pares(&pt.1).into_iter().map(|(k, _)| k).collect();

        for (nome, bruto) in &todos {
            let k: BTreeSet<String> = pares(bruto).into_iter().map(|(k, _)| k).collect();
            let faltam: Vec<_> = base.difference(&k).collect();
            let sobram: Vec<_> = k.difference(&base).collect();
            assert!(
                faltam.is_empty() && sobram.is_empty(),
                "{nome}.json fora de paridade — faltam {faltam:?}, sobram {sobram:?}"
            );
        }
    }

    /// O QUE: cada tradução carrega os MESMOS placeholders do original.
    ///
    /// POR QUE: `{tool}` traduzido ou perdido não quebra a compilação — quebra em runtime,
    /// na cara do usuário, mostrando `{tool}` cru ou uma frase sem o dado. É o erro mais
    /// fácil de cometer traduzindo e o mais difícil de ver revisando.
    #[test]
    fn traducoes_preservam_os_placeholders() {
        let todos = locales();
        let pt: std::collections::BTreeMap<String, String> =
            pares(&todos.iter().find(|(n, _)| n == "pt").unwrap().1).into_iter().collect();

        for (nome, bruto) in &todos {
            for (k, v) in pares(bruto) {
                let Some(orig) = pt.get(&k) else { continue };
                assert_eq!(
                    placeholders(orig),
                    placeholders(&v),
                    "{nome}.json / {k}: placeholders divergem do pt"
                );
            }
        }
    }
}
