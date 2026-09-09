//! O seletor de chave SSH — listar em vez de mandar digitar.
//!
//! **O quê:** mostra as chaves gerenciadas em `~/.ssh`, deixa escolher pelo número, e oferece
//! gerar ou importar uma nova ali mesmo.
//!
//! **Onde:** `vps add` sem `--key`, e qualquer lugar que precise de uma chave.
//!
//! ## Por que existe
//!
//! O `vps add` exigia `--key <caminho>` digitado à mão — sobre uma máquina onde o app **já
//! sabe** listar as chaves, com nome, tipo e fingerprint. Pedir para a pessoa digitar um
//! caminho que o programa tem na mão é a mesma classe de erro do `.NET` que mandava adicionar
//! o repo da Microsoft manualmente: devolver ao usuário um trabalho que a ferramenta tem os
//! dados para fazer.
//!
//! E é pior que incômodo: caminho digitado erra silenciosamente. Um `~/.ssh/deploy` que não
//! existe entrava no banco do mesmo jeito, e a falha só aparecia na primeira conexão — longe,
//! no tempo e na tela, de onde foi causada.

use crate::i18n::t;
use crate::sshkeys::{self, KeyInfo};
use std::io::{BufRead, IsTerminal, Write};

/// O que a pessoa escolheu na lista.
#[derive(Debug, PartialEq, Eq)]
pub enum Escolha {
    /// Uma chave existente, pelo nome.
    Chave(String),
    /// Gerar um par novo.
    Gerar,
    /// Importar uma chave que já existe (arquivo ou colagem).
    Importar,
    /// Nada — a pessoa desistiu.
    Cancelou,
}

/// **O quê:** interpreta o que foi digitado no menu. PURA.
///
/// **Onde:** [`escolher`]. Separada porque é a regra, e regra sem teste é onde um índice fora
/// da lista vira `panic` na frente do usuário.
///
/// Aceita o NÚMERO da linha, o NOME da chave (quem já sabe qual quer não precisa contar), e as
/// letras `g`/`i`. Vazio ou lixo é `Cancelou` — falha fechada: na dúvida, não escolhe por
/// ninguém.
pub fn interpretar(entrada: &str, chaves: &[String]) -> Escolha {
    let e = entrada.trim();
    if e.is_empty() {
        return Escolha::Cancelou;
    }
    match e.to_lowercase().as_str() {
        "g" | "gerar" | "new" | "n" => return Escolha::Gerar,
        "i" | "importar" | "import" => return Escolha::Importar,
        _ => {}
    }
    if let Ok(n) = e.parse::<usize>() {
        // 1-based: a lista é mostrada a humano, e humano conta do 1.
        return match n.checked_sub(1).and_then(|i| chaves.get(i)) {
            Some(nome) => Escolha::Chave(nome.clone()),
            None => Escolha::Cancelou,
        };
    }
    if chaves.iter().any(|c| c == e) {
        return Escolha::Chave(e.to_string());
    }
    Escolha::Cancelou
}

/// **O quê:** o texto do menu. PURA — é o que permite testar o que a pessoa vê sem um tty.
///
/// **Onde:** [`escolher`].
///
/// **O fingerprint vai junto do nome** porque é o que permite conferir que é A chave certa
/// quando há duas com nomes parecidos — e fingerprint é público, não vaza nada.
pub fn render_menu(chaves: &[KeyInfo]) -> String {
    let mut s = format!("{}\n", t("vps.pick_title"));
    for (i, k) in chaves.iter().enumerate() {
        s.push_str(&format!("  {:>2}) {:<16} {:<8} {}\n", i + 1, k.name, k.kind, k.fingerprint));
    }
    s.push_str(&format!("   {}\n", t("vps.pick_generate")));
    s.push_str(&format!("   {}\n", t("vps.pick_import")));
    s.push_str(&format!("{} ", t("vps.pick_prompt")));
    s
}

/// **O quê:** imprime a lista e lê a escolha.
///
/// **Onde:** [`resolver`], quando não veio `--key`.
///
/// **Sem tty devolve `Cancelou`** em vez de pendurar: num script ou num pipe não há quem
/// responda, e travar ali seria um processo parado para sempre sem dizer por quê.
pub fn escolher(chaves: &[KeyInfo]) -> Escolha {
    if !std::io::stdin().is_terminal() {
        return Escolha::Cancelou;
    }
    print!("{}", render_menu(chaves));
    let _ = std::io::stdout().flush();
    let mut linha = String::new();
    if std::io::stdin().lock().read_line(&mut linha).is_err() {
        return Escolha::Cancelou;
    }
    let nomes: Vec<String> = chaves.iter().map(|k| k.name.clone()).collect();
    interpretar(&linha, &nomes)
}

/// **O quê:** devolve o nome da chave a usar — do `--key` quando veio, do menu quando não.
///
/// **Onde:** `vps add`.
///
/// **`--key` continua valendo, e é o caminho de script.** O menu só aparece na ausência dele:
/// quem automatiza não pode ser interrompido por uma pergunta.
///
/// **Um `--key` que não existe NÃO é aceito.** Antes entrava no banco e falhava na primeira
/// conexão — longe, no tempo e na tela, de onde foi causado. Agora a lista das que existem é
/// mostrada junto do erro, porque "não achei" sem dizer o que há é meio diagnóstico.
pub fn resolver(key: Option<String>) -> Result<String, String> {
    let chaves = sshkeys::list();
    if let Some(k) = key {
        let nome =
            std::path::Path::new(&k).file_stem().and_then(|s| s.to_str()).unwrap_or(&k).to_string();
        if chaves.iter().any(|c| c.name == nome) {
            return Ok(nome);
        }
        let disponiveis: Vec<&str> = chaves.iter().map(|c| c.name.as_str()).collect();
        return Err(if disponiveis.is_empty() {
            format!(
                "não achei a chave `{k}` em ~/.ssh, e não há nenhuma gerenciada.\n  \
                 Crie uma com: schematize-deployer ssh gen <nome>\n  \
                 Ou importe a que você já tem: schematize-deployer ssh import --paste --name <nome>"
            )
        } else {
            format!(
                "não achei a chave `{k}` em ~/.ssh.\n  As que existem: {}\n  \
                 Ou omita --key para escolher da lista.",
                disponiveis.join(", ")
            )
        });
    }
    if chaves.is_empty() {
        return Err("não há chave nenhuma em ~/.ssh.\n  \
                    Crie uma com: schematize-deployer ssh gen <nome>\n  \
                    Ou importe a que você já tem (do Bitwarden, por exemplo): \
                    schematize-deployer ssh import --paste --name <nome>"
            .to_string());
    }
    match escolher(&chaves) {
        Escolha::Chave(n) => Ok(n),
        Escolha::Gerar => Err("escolha `gerar`: rode `schematize-deployer ssh gen <nome>` e \
                               repita o `vps add`."
            .to_string()),
        Escolha::Importar => Err("escolha `importar`: rode `schematize-deployer ssh import \
                                  --paste --name <nome>` (cola a chave) e repita o `vps add`."
            .to_string()),
        Escolha::Cancelou => Err("nenhuma chave escolhida — nada foi registrado.".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ks() -> Vec<String> {
        ["deploy", "github", "prod"].iter().map(|s| s.to_string()).collect()
    }

    /// Número escolhe a linha, contando do 1 — que é como humano lê lista.
    #[test]
    fn numero_escolhe_a_linha_contando_do_um() {
        assert_eq!(interpretar("1", &ks()), Escolha::Chave("deploy".into()));
        assert_eq!(interpretar("3", &ks()), Escolha::Chave("prod".into()));
    }

    /// Número fora da lista NÃO vira `panic` nem escolhe a última: vira cancelamento. É o
    /// caminho que um `0` ou um `99` digitado por engano toma.
    #[test]
    fn numero_fora_da_lista_cancela_em_vez_de_estourar() {
        assert_eq!(interpretar("0", &ks()), Escolha::Cancelou);
        assert_eq!(interpretar("4", &ks()), Escolha::Cancelou);
        assert_eq!(interpretar("999999999999999999999", &ks()), Escolha::Cancelou);
    }

    /// Quem já sabe o nome não precisa contar linha.
    #[test]
    fn nome_tambem_escolhe() {
        assert_eq!(interpretar("github", &ks()), Escolha::Chave("github".into()));
        assert_eq!(interpretar("  prod  ", &ks()), Escolha::Chave("prod".into()));
    }

    /// Nome que não está na lista não é aceito de contrabando — senão um typo viraria um
    /// perfil apontando para chave inexistente, que é o bug que este módulo existe pra matar.
    #[test]
    fn nome_desconhecido_nao_passa() {
        assert_eq!(interpretar("nao-existe", &ks()), Escolha::Cancelou);
    }

    /// O menu MOSTRA o que a pessoa precisa para escolher: número, nome, tipo e fingerprint —
    /// mais as duas saídas (gerar/importar). Sem o fingerprint, duas chaves de nome parecido
    /// ficam indistinguíveis, que é justamente quando errar dói.
    #[test]
    fn o_menu_mostra_numero_nome_e_fingerprint() {
        let chaves = sshkeys::list();
        if chaves.is_empty() {
            return;
        }
        let m = render_menu(&chaves);
        for (i, k) in chaves.iter().enumerate() {
            assert!(m.contains(&format!("{})", i + 1)), "faltou o número {}: {m}", i + 1);
            assert!(m.contains(&k.name), "faltou o nome `{}`: {m}", k.name);
            assert!(m.contains(&k.fingerprint), "faltou o fingerprint de `{}`", k.name);
        }
        // As duas saídas têm de estar visíveis: sem elas, quem não tem a chave certa fica sem
        // caminho e conclui que precisa sair do programa para resolver.
        assert!(m.contains("g)"), "faltou a opção de gerar: {m}");
        assert!(m.contains("i)"), "faltou a opção de importar: {m}");
    }

    /// As letras de atalho, e o vazio como cancelamento (falha fechada).
    #[test]
    fn atalhos_e_vazio() {
        assert_eq!(interpretar("g", &ks()), Escolha::Gerar);
        assert_eq!(interpretar("I", &ks()), Escolha::Importar);
        assert_eq!(interpretar("", &ks()), Escolha::Cancelou);
        assert_eq!(interpretar("   \n", &ks()), Escolha::Cancelou);
    }

    /// `--key ~/.ssh/deploy` e `--key deploy` são a mesma coisa: o caminho é reduzido ao NOME
    /// antes da busca, porque é assim que a pessoa tem a chave na cabeça. Sem isso, quem
    /// copiasse o caminho do `ssh list` levaria "não achei" sobre uma chave que existe.
    #[test]
    fn caminho_e_nome_apontam_para_a_mesma_chave() {
        let Some(k) = sshkeys::list().into_iter().next() else {
            return; // máquina sem chave: nada a comparar, e inventar uma seria testar a fixture
        };
        let por_nome = resolver(Some(k.name.clone())).expect("o nome tem de resolver");
        let por_caminho = resolver(Some(format!("/qualquer/lugar/{}", k.name)))
            .expect("o caminho tem de resolver para o mesmo nome");
        assert_eq!(por_nome, por_caminho);
        assert_eq!(por_nome, k.name);
    }

    /// Chave inexistente é recusada ANTES de virar perfil, e o erro LISTA as que existem —
    /// "não achei" sem dizer o que há é meio diagnóstico.
    #[test]
    fn chave_inexistente_e_recusada_e_o_erro_lista_as_reais() {
        let e = resolver(Some("nao-existe-mesmo-xyz".into())).unwrap_err();
        assert!(e.contains("não achei"), "{e}");
        for k in sshkeys::list() {
            assert!(e.contains(&k.name), "o erro tem de listar `{}`: {e}", k.name);
        }
    }
}
