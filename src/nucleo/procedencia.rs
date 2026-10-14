//! De qual commit este binário foi construído.
//!
//! **O quê:** casca fina sobre `schematize_plataforma::procedencia` (a decisão pura — `rotulo`,
//! `sha_valido`, `sujo_de` — e seus testes moram na lib). Aqui ficam só os NOMES das variáveis
//! que o `build.rs` deste repo emite.
//!
//! **Onde:** [`rotulo_versao`] alimenta o `--version` do clap (`cli/args.rs`).

use schematize_plataforma::procedencia::sha_valido;

/// O SHA colhido no build. Vazio quando não havia git (tarball, export, sem `git`).
const SHA: &str = env!("SCHEMATIZE_GIT_SHA");

/// **O quê:** o rótulo de versão deste binário, pronto para o `--version` (`&'static str`: o
/// clap exige `Str`).
///
/// **Onde:** `cli/args.rs`, no `#[command(version = ...)]`.
pub fn rotulo_versao() -> &'static str {
    schematize_plataforma::rotulo_versao!("SCHEMATIZE_GIT_SHA", "SCHEMATIZE_GIT_DIRTY")
}

/// **O quê:** o SHA deste build, ou `None` quando não há.
///
/// **Onde:** o `doctor`/guard que compara o binário instalado com o HEAD do repo.
pub fn sha() -> Option<&'static str> {
    sha_valido(SHA)
}

#[cfg(test)]
mod tests {
    use super::*;
    use schematize_plataforma::procedencia::sujo_de;

    /// O valor real deste build é um dos dois estados — nunca uma terceira coisa.
    #[test]
    fn o_build_de_verdade_produz_um_dos_dois_estados() {
        let r = rotulo_versao();
        assert!(r.starts_with(env!("CARGO_PKG_VERSION")), "{r}");
        assert!(
            r.ends_with(')') && r.contains(" ("),
            "o rótulo sempre traz a procedência entre parênteses: {r}"
        );
        assert_eq!(
            r.contains("-sujo)"),
            sujo_de(env!("SCHEMATIZE_GIT_DIRTY")) && sha().is_some(),
            "a marca `-sujo` tem de refletir o build: {r}"
        );
        match sha() {
            Some(s) => assert!(r.contains(s), "o SHA de {s} tem de aparecer em {r}"),
            None => assert!(r.contains("fonte sem git"), "{r}"),
        }
    }
}
