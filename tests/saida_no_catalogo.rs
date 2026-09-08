//! A saída de usuário do Deployer passa pelo CATÁLOGO, não por `println!` cru.
//!
//! # Por que este teste existe
//!
//! O ADR-0014 (D8) resolveu uma inconsistência real: os COMANDOS deste app foram traduzidos
//! para inglês quando ele virou app próprio, e a SAÍDA ficou em português. Um `--help` que
//! promete inglês e um relatório que entrega português é a metade estranha do meio caminho —
//! quem não lê português vê a interface prometer o que o conteúdo não cumpre.
//!
//! **Aqui a saída vai para `en` + `pt` apenas**, e a ausência dos outros dezoito é DECLARADA
//! em `nucleo::i18n::SO_EN_E_PT` — não escondida copiando inglês para dentro de `ja.json`.
//!
//! Consertar uma vez é fácil; **manter consertado é o que precisa de gate**. Uma linha nova
//! escrita direto em `println!("...")` volta a criar o problema, não quebra compilação nenhuma
//! e não aparece em revisão de diff grande.
//!
//! # O que ele NÃO cobra
//!
//! Formatação pura (`"{}"`, `"  {}"`, separadores, números) e a saída de DADO que vem do
//! sistema (nome de unidade, caminho, versão) não são texto de interface e não se traduzem.
//! O critério é: **tem letra de palavra e não é só marcador de formatação**.

use std::path::Path;

/// Os arquivos que falam com o usuário. A camada `cli` é a fronteira de saída deste app.
const FALANTES: &[&str] = &[
    "src/cli/vps.rs",
    "src/cli/ssh.rs",
    "src/cli/painel.rs",
    "src/cli/dns.rs",
    "src/cli/mcp.rs",
    "src/cli/cofre.rs",
];

/// **O quê:** a linha imprime PROSA fora do catálogo?
///
/// **Onde:** o varredor abaixo. Separada porque a regra é o teste — e uma regra enterrada num
/// laço com IO não é revisável.
fn e_prosa_crua(linha: &str) -> bool {
    let l = linha.trim();
    if l.starts_with("//") || !l.contains("println!") && !l.contains("print!") {
        return false;
    }
    // Extrai o literal do primeiro argumento, se houver.
    let Some(ini) = l.find('"') else { return false };
    let Some(fim) = l[ini + 1..].find('"').map(|p| p + ini + 1) else { return false };
    let literal = &l[ini + 1..fim];

    // Tira TODO placeholder, inclusive os NOMEADOS (`{custo}`, `{marca}`) — não só o `{}`.
    // Foi o que este varredor errou na primeira escrita: ele reprovou
    // `println!("  {custo}  {}{marca}", …)`, que é pura formatação, porque só limpava o `{}`
    // vazio e as letras de dentro dos nomeados sobravam contando como prosa.
    let mut sem_formato = String::new();
    let mut dentro = false;
    for c in literal.chars() {
        match c {
            '{' => dentro = true,
            '}' => dentro = false,
            _ if !dentro => sem_formato.push(c),
            _ => {}
        }
    }
    let sem_formato = sem_formato.replace("\\n", "");
    // Duas letras seguidas é palavra; um `s` ou um `%` solto, não.
    sem_formato.chars().filter(|c| c.is_alphabetic()).count() >= 2
}

/// **A regra, e o self-check dela.** Um varredor que nunca viu prosa é um varredor que pode
/// estar com o filtro invertido e ninguém saberia.
#[test]
fn o_varredor_distingue_prosa_de_formatacao() {
    // PROSA — tem de ser pega.
    assert!(e_prosa_crua(r#"    println!("MACHINE");"#));
    assert!(e_prosa_crua(r#"println!("  RAM      : {}", gib(m.ram_bytes));"#));
    assert!(e_prosa_crua(r#"println!("nothing to revert");"#));

    // FORMATAÇÃO — não é texto de interface.
    assert!(!e_prosa_crua(r#"    println!("{}", t("diag.machine_header"));"#));
    assert!(!e_prosa_crua(r#"    println!();"#));
    assert!(!e_prosa_crua(r#"    println!("  {}", c.nome);"#));
    // Placeholders NOMEADOS também são formatação — foi o falso positivo desta primeira
    // escrita, e por isso ele vive aqui como caso.
    assert!(!e_prosa_crua(r#"    println!("  {custo}  {}{marca}", s.unidade);"#));
    assert!(!e_prosa_crua(r#"    println!("  {}", t(&motivo));"#));
    assert!(!e_prosa_crua(r#"    // println!("MACHINE");"#));
}

/// **O QUE ELE TRAVA:** nenhuma linha de saída da camada `cli` escreve prosa direto.
///
/// Se este teste ficar vermelho, a correção é mover a frase para `src/nucleo/i18n/en.json` e
/// `pt.json` e imprimir `t("chave")` — não é acrescentar o arquivo a uma exceção.
#[test]
fn a_saida_de_usuario_passa_pelo_catalogo() {
    let raiz = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut cruas: Vec<String> = Vec::new();

    for arquivo in FALANTES {
        let caminho = raiz.join(arquivo);
        let src = std::fs::read_to_string(&caminho)
            .unwrap_or_else(|e| panic!("{}: {e}", caminho.display()));
        for (n, linha) in src.lines().enumerate() {
            if e_prosa_crua(linha) {
                cruas.push(format!("{arquivo}:{} — {}", n + 1, linha.trim()));
            }
        }
    }

    assert!(
        cruas.is_empty(),
        "saída de usuário FORA do catálogo i18n ({} linha(s)) — o relatório volta a sair \
         num idioma e a interface em outro:\n  {}",
        cruas.len(),
        cruas.join("\n  ")
    );
}

/// Toda chave usada no código EXISTE no catálogo.
///
/// **Por que importa:** chave ausente não quebra compilação — ela cai no fallback e imprime a
/// própria chave. `diag.gpu_header` na tela é feio e é bug óbvio; o problema é que ninguém
/// revisando um diff grande percebe a chave errada ANTES de ela chegar na tela.
#[test]
fn toda_chave_usada_existe_no_catalogo() {
    let raiz = Path::new(env!("CARGO_MANIFEST_DIR"));
    let en: std::collections::BTreeMap<String, String> = serde_json::from_str(
        &std::fs::read_to_string(raiz.join("src/nucleo/i18n/en.json")).expect("en.json"),
    )
    .expect("en.json é JSON válido");

    let mut faltando = Vec::new();
    for arquivo in FALANTES.iter() {
        let src = std::fs::read_to_string(raiz.join(arquivo)).expect(arquivo);
        // Só o código de PRODUÇÃO: os testes de dentro do arquivo citam prefixos de chave nas
        // asserções (`chave.starts_with("svc.")`), e o varredor os leria como chave.
        let src = src.split("#[cfg(test)]").next().unwrap_or(&src);
        // `t("x")` e `tf("x", …)`, e as chaves guardadas nas tabelas (`"svc.…"`, `"box.…"`).
        for cap in src.split('"').skip(1).step_by(2) {
            let e_chave = cap.starts_with("cli.") || cap.starts_with("common.");
            if e_chave && !en.contains_key(cap) {
                faltando.push(format!("{arquivo}: {cap}"));
            }
        }
    }
    assert!(faltando.is_empty(), "chave usada e AUSENTE do en.json:\n  {}", faltando.join("\n  "));
}
