//! De qual commit este binário foi construído — e a decisão de como dizer isso.
//!
//! ## Onde
//!
//! [`rotulo_versao`] alimenta o `--version` do clap (`cli/args.rs`). O `build.rs` colhe o SHA;
//! aqui está a única decisão, e ela é pura para poder ser vista falhando.

/// O SHA colhido no build. Vazio quando não havia git (tarball, export, sem `git`).
const SHA: &str = env!("SCHEMATIZE_GIT_SHA");

/// **O quê:** `"0.2.1 (b9fcc65abcde)"`, ou `"0.2.1 (fonte sem git)"` quando o SHA não veio.
///
/// **Onde:** [`rotulo_versao`], e os testes — que afirmam as duas formas sem depender de o
/// repo de quem roda a suíte ter git.
///
/// **Por que nunca esconder o caso vazio:** um `--version` que mostra só o número quando não
/// sabe o commit é indistinguível de um binário antigo que nunca soube. Dizer "fonte sem git"
/// informa o que aconteceu, e quem lê sabe que não pode comparar SHA com o repo.
///
/// **Por que SHA malformado conta como ausente:** se um dia o `build.rs` emitir lixo (um erro
/// de git em stdout, por exemplo), mostrar o lixo como se fosse procedência é pior que dizer
/// que não sabe — alguém compararia com o HEAD e concluiria "defasado" sobre um build novo.
pub fn rotulo(versao: &str, sha: &str) -> String {
    let limpo = sha.trim();
    let valido = (7..=40).contains(&limpo.len()) && limpo.chars().all(|c| c.is_ascii_hexdigit());
    if valido {
        format!("{versao} ({limpo})")
    } else {
        format!("{versao} (fonte sem git)")
    }
}

/// **O quê:** o rótulo de versão deste binário, pronto para o `--version`.
///
/// **Onde:** `cli/args.rs`, no `#[command(version = ...)]`.
///
/// **Devolve `&'static str` e não `String` porque o clap exige `Str`, que só converte de
/// `&'static str`.** O `OnceLock` é o que dá o `'static` sem vazar memória a cada chamada e
/// sem transformar a decisão em `const` — ela não pode ser `const`, porque escolher entre o
/// SHA e "fonte sem git" exige olhar o conteúdo da string.
pub fn rotulo_versao() -> &'static str {
    static R: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    R.get_or_init(|| rotulo(env!("CARGO_PKG_VERSION"), SHA)).as_str()
}

/// **O quê:** o SHA deste build, ou `None` quando não há.
///
/// **Onde:** o `doctor`/guard que compara o binário instalado com o HEAD do repo.
pub fn sha() -> Option<&'static str> {
    let s = SHA.trim();
    ((7..=40).contains(&s.len()) && s.chars().all(|c| c.is_ascii_hexdigit())).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA de verdade entra no rótulo como veio.
    #[test]
    fn sha_valido_aparece_no_rotulo() {
        assert_eq!(rotulo("0.2.1", "b9fcc65abcde"), "0.2.1 (b9fcc65abcde)");
        assert_eq!(rotulo("1.0.0", "abcdef0"), "1.0.0 (abcdef0)", "7 dígitos é o mínimo aceito");
    }

    /// **O caso do tarball:** sem git, o build NÃO falha e a versão diz o que houve.
    #[test]
    fn sem_git_o_rotulo_diz_que_nao_sabe_em_vez_de_omitir() {
        assert_eq!(rotulo("0.2.1", ""), "0.2.1 (fonte sem git)");
        assert_eq!(rotulo("0.2.1", "   "), "0.2.1 (fonte sem git)");
    }

    /// Lixo NÃO passa por procedência — senão alguém compara com o HEAD e tira conclusão.
    #[test]
    fn sha_malformado_conta_como_ausente() {
        for ruim in ["fatal:", "nao-hex-aqui", "abc", "zzzzzzzzz", "b9fcc65 extra"] {
            assert_eq!(
                rotulo("0.2.1", ruim),
                "0.2.1 (fonte sem git)",
                "{ruim:?} não é SHA e não pode virar procedência"
            );
        }
    }

    /// O valor real deste build é um dos dois estados — nunca uma terceira coisa.
    #[test]
    fn o_build_de_verdade_produz_um_dos_dois_estados() {
        let r = rotulo_versao();
        assert!(r.starts_with(env!("CARGO_PKG_VERSION")), "{r}");
        assert!(
            r.ends_with(')') && r.contains(" ("),
            "o rótulo sempre traz a procedência entre parênteses: {r}"
        );
        match sha() {
            Some(s) => assert!(r.contains(s), "o SHA de {s} tem de aparecer em {r}"),
            None => assert!(r.contains("fonte sem git"), "{r}"),
        }
    }
}
