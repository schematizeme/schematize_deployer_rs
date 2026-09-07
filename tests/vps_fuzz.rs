//! O QUE: fuzzing dirigido por INVARIANTES. Gera entrada aleatória (incluindo lixo binário,
//! unicode e strings enormes) e afirma propriedades que têm de valer para TODA entrada.
//!
//! POR QUE EXISTE: os testes de exemplo cobrem os casos que alguém imaginou. Estes cobrem os
//! que ninguém imaginou — e é lá que mora o bug que derruba o app na mão do usuário. O piso
//! da casa pede property-based no domínio crítico; isto é property-based sem trazer `proptest`
//! (o crate mantém a árvore de deps mínima), com um PRNG determinístico para que uma falha
//! seja reproduzível pela seed.
//!
//! DE ONDE VEM: nada externo. PRA ONDE VAI: nada — só asserção.

use deployer::vps::{
    self,
    politica::Veredito,
    registro::{Ambiente, ModoPolitica, VpsProfile},
};

/// PRNG determinístico (xorshift64*). Nada de `rand`: uma falha aqui precisa ser reproduzível
/// pela seed impressa, e um gerador do sistema tornaria isso impossível.
struct Rng(u64);
impl Rng {
    fn novo(seed: u64) -> Self {
        Rng(seed | 1)
    }
    fn proximo(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn ate(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.proximo() % n as u64) as usize
        }
    }
}

/// Alfabeto deliberadamente hostil: metacaracteres, unicode confuso, controle e byte nulo
/// misturados a caracteres normais.
const ALFABETO: &[char] = &[
    'a', 'b', 'z', 'A', 'Z', '0', '9', ' ', '\t', '\n', '\r', '\0', ';', '&', '|', '`', '$', '(',
    ')', '>', '<', '\'', '"', '\\', '/', '-', '.', '_', '=', '*', '\u{0440}', '\u{202e}',
    '\u{200b}', '\u{FEFF}', 'ç', 'é', '中', '🙂', '\u{1}', '\u{7f}',
];

fn palavra(r: &mut Rng, max: usize) -> String {
    let n = r.ate(max);
    (0..n).map(|_| ALFABETO[r.ate(ALFABETO.len())]).collect()
}

fn perfil(r: &mut Rng) -> VpsProfile {
    let mut p = VpsProfile::novo("srv", "10.0.0.1", "u", "k");
    p.modo = match r.ate(3) {
        0 => ModoPolitica::ReadOnly,
        1 => ModoPolitica::OpsVerbs,
        _ => ModoPolitica::Livre,
    };
    p.ambiente = match r.ate(3) {
        0 => Ambiente::Dev,
        1 => Ambiente::Hml,
        _ => Ambiente::Prd,
    };
    p
}

/// INVARIANTES da política. Valem para toda entrada, sem exceção.
#[test]
fn fuzz_politica_mantem_as_invariantes() {
    for seed in 1..=4000u64 {
        let mut r = Rng::novo(seed);
        let p = perfil(&mut r);
        let cmd = palavra(&mut r, 60);
        let v = vps::politica::avaliar(&p, &cmd);

        // 1. Byte nulo NUNCA passa — em modo nenhum, ambiente nenhum.
        if cmd.contains('\0') {
            assert!(matches!(v, Veredito::Deny(_)), "seed {seed}: byte nulo passou em {cmd:?}");
        }
        // 2. Comando vazio (ou só espaço) NUNCA é Allow.
        if cmd.trim().is_empty() {
            assert!(matches!(v, Veredito::Deny(_)), "seed {seed}: vazio virou {v:?}");
        }
        // 3. Produção NUNCA devolve Allow — sempre Confirm ou Deny.
        if p.ambiente == Ambiente::Prd {
            assert_ne!(v, Veredito::Allow, "seed {seed}: prd liberou {cmd:?}");
        }
        // 4. Modo restrito + metacaractere de shell = sempre Deny.
        if p.modo != ModoPolitica::Livre && cmd.chars().any(|c| ";&|`$><\n\r".contains(c)) {
            assert!(matches!(v, Veredito::Deny(_)), "seed {seed}: metacaractere passou em {cmd:?}");
        }
        // 5. Não-ASCII nunca é Allow (ataque ao gate humano).
        if !cmd.chars().all(|c| c.is_ascii_graphic() || c == ' ') && !cmd.trim().is_empty() {
            assert_ne!(v, Veredito::Allow, "seed {seed}: não-ASCII liberado em {cmd:?}");
        }
        // 6. Todo Deny/Confirm carrega motivo não-vazio (mensagem que ensina — §37.48).
        if let Some(m) = v.motivo() {
            assert!(!m.trim().is_empty(), "seed {seed}: veredito sem motivo");
        }
        // 7. Determinismo: a mesma entrada dá sempre o mesmo veredito.
        assert_eq!(v, vps::politica::avaliar(&p, &cmd), "seed {seed}: política não-determinística");
    }
}

/// INVARIANTES da validação de entrada do registro.
#[test]
fn fuzz_validacao_nunca_aceita_o_que_escapa() {
    for seed in 1..=4000u64 {
        let mut r = Rng::novo(seed);
        let alias = palavra(&mut r, 40);
        let ok = vps::registro::valid_alias(&alias).is_ok();
        if ok {
            // Um alias aceito é SEGURO por construção: vira nome de arquivo e nada mais.
            assert!(!alias.is_empty() && alias.len() <= 64, "seed {seed}: {alias:?}");
            assert!(
                alias.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')),
                "seed {seed}: caractere fora do allow-list em {alias:?}"
            );
            assert!(!alias.contains(".."), "seed {seed}: travessia em {alias:?}");
            assert!(
                alias.chars().next().is_some_and(|c| c.is_ascii_alphanumeric()),
                "seed {seed}: não começa por alfanumérico: {alias:?}"
            );
            // E o caminho derivado dele fica DENTRO do dir de known_hosts.
            let kh = vps::known_hosts_path(&alias).expect("alias válido tem caminho");
            assert_eq!(
                kh.parent(),
                Some(vps::known_hosts_dir().as_path()),
                "seed {seed}: {alias:?} escapou do dir"
            );
        }
        // Opções: aceito => tem `=`, sem espaço, e a chave está na allowlist.
        let opcao = palavra(&mut r, 30);
        if vps::registro::valid_opcao(&opcao).is_ok() {
            assert!(opcao.contains('='), "seed {seed}: opção sem `=`: {opcao:?}");
            assert!(!opcao.chars().any(char::is_whitespace), "seed {seed}: {opcao:?}");
            let chave = opcao.split('=').next().unwrap().to_ascii_lowercase();
            assert!(!chave.contains("command"), "seed {seed}: opção que executa: {opcao:?}");
        }
        // Host: aceito => não começa por `-` (injeção de flag) e não tem espaço.
        let host = palavra(&mut r, 30);
        if vps::registro::valid_host(&host).is_ok() {
            assert!(!host.trim().starts_with('-'), "seed {seed}: flag como host: {host:?}");
            assert!(!host.chars().any(char::is_whitespace), "seed {seed}: {host:?}");
        }
    }
}

/// INVARIANTES do hook: nunca entra em pânico, e a porta certa nunca é barrada.
#[test]
fn fuzz_hook_nunca_panica_e_nunca_barra_a_porta_certa() {
    use deployer::vps::hook::avaliar_tool_use;
    use serde_json::json;
    for seed in 1..=3000u64 {
        let mut r = Rng::novo(seed);
        let cmd = palavra(&mut r, 60);
        let tool = ["Bash", "Read", "Edit", "Write", "Glob", ""][r.ate(6)];
        // Não pode panicar com nada.
        let _ = avaliar_tool_use(tool, &json!({ "command": cmd, "file_path": cmd }));
        // Se barrou, o motivo ENSINA o caminho certo.
        if let Some(m) = avaliar_tool_use("Bash", &json!({ "command": cmd })) {
            assert!(m.contains("schematize"), "seed {seed}: recusa sem caminho: {m}");
        }
    }
    // A porta certa NUNCA é barrada, com qualquer sufixo hostil grudado.
    for seed in 1..=500u64 {
        let mut r = Rng::novo(seed);
        let sufixo: String =
            palavra(&mut r, 20).chars().filter(|c| c.is_ascii_alphanumeric()).collect();
        let cmd = format!("schematize vps exec srv -- uptime{sufixo}");
        assert_eq!(
            avaliar_tool_use("Bash", &json!({ "command": cmd })),
            None,
            "seed {seed}: a porta certa foi barrada: {cmd:?}"
        );
    }
}

/// INVARIANTES da redação: nunca cresce sem limite, é idempotente, e nunca deixa passar
/// um bloco de chave privada.
#[test]
fn fuzz_redacao_e_idempotente_e_nunca_vaza_chave() {
    use deployer::debugreport::scrub;
    for seed in 1..=3000u64 {
        let mut r = Rng::novo(seed);
        let texto = palavra(&mut r, 200);
        let uma = scrub(&texto);
        assert_eq!(scrub(&uma), uma, "seed {seed}: redação não é idempotente");
        // Nunca explode de tamanho (um substituidor mal feito pode multiplicar).
        assert!(uma.len() <= texto.len() * 4 + 64, "seed {seed}: saída inchou");

        // Com um bloco de chave privada em QUALQUER posição, o miolo some.
        let com_chave = format!(
            "{texto}\n-----BEGIN OPENSSH PRIVATE KEY-----\nSEGREDOxyz123\n-----END OPENSSH PRIVATE KEY-----\n{texto}"
        );
        assert!(!scrub(&com_chave).contains("SEGREDOxyz123"), "seed {seed}: chave privada vazou");
    }
}

/// INVARIANTES do protocolo MCP: toda requisição com `id` responde, e nunca com os dois campos.
#[test]
fn fuzz_mcp_sempre_responde_e_nunca_panica() {
    use deployer::mcp::{protocolo, tools};
    use serde_json::{json, Value};
    let schema = tools::schema();
    for seed in 1..=3000u64 {
        let mut r = Rng::novo(seed);
        let metodo = ["initialize", "tools/list", "tools/call", "ping", "", &palavra(&mut r, 20)]
            [r.ate(6)]
        .to_string();
        let nome = palavra(&mut r, 20);
        let msg = json!({
            "jsonrpc": if r.ate(4) == 0 { "1.0" } else { "2.0" },
            "id": match r.ate(4) { 0 => json!(r.ate(1000)), 1 => json!(palavra(&mut r, 10)), 2 => Value::Null, _ => json!(seed) },
            "method": metodo,
            "params": { "name": nome, "arguments": { "alias": palavra(&mut r, 30), "n": r.ate(100000) as i64 } }
        });
        let resp = protocolo::responder(&msg, &schema, |_, _| Ok("ok".into()));
        let resp = resp.expect("requisição com id sempre responde");
        assert_eq!(resp["jsonrpc"], "2.0", "seed {seed}");
        assert!(resp.get("id").is_some(), "seed {seed}: id não ecoado");
        let tem_erro = resp.get("error").is_some();
        let tem_result = resp.get("result").is_some();
        assert!(tem_erro ^ tem_result, "seed {seed}: erro e result juntos (ou nenhum)");
    }
}

/// INVARIANTE do catálogo: o que passa na validação sobrevive ao round-trip do formato.
#[test]
fn fuzz_catalogo_round_trip() {
    use deployer::vps::verbos::{
        catalogo_texto, parse_catalogo, valid_comando, valid_verbo, Verbo,
    };
    for seed in 1..=3000u64 {
        let mut r = Rng::novo(seed);
        let nome = palavra(&mut r, 20);
        let comando = palavra(&mut r, 40);
        if valid_verbo(&nome).is_err() || valid_comando(&comando).is_err() {
            continue;
        }
        let v = vec![Verbo { nome: nome.clone(), comando: comando.clone() }];
        let volta = parse_catalogo(&catalogo_texto(&v));
        assert_eq!(volta, v, "seed {seed}: round-trip perdeu {nome:?} -> {comando:?}");
        // E o texto gerado nunca cria uma LINHA a mais (seria um verbo não aprovado).
        let linhas = catalogo_texto(&v)
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .count();
        assert_eq!(linhas, 1, "seed {seed}: o catálogo ganhou linha");
    }
}

// ===========================================================================================
// CAMADA 3/4 do Q.A. de 2026-09-01 — fuzzing adversarial dos validadores que NASCERAM depois
// deste arquivo, e invariantes que valem para TODOS eles de uma vez.
//
// O que estas asserções pegam e as anteriores não: a família inteira de validadores é tratada
// como UM contrato ("nenhum aceita algo que vire argumento, caminho ou comando"), em vez de
// cada um com o seu teste de exemplos. Validador novo que entre na família sem respeitar o
// contrato cai aqui.
// ===========================================================================================

/// Corpus adversarial compartilhado. Cresce; não encolhe.
fn corpus_hostil() -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for s in [
        "",
        " ",
        "\t",
        "\n",
        "\r\n",
        "\0",
        "a\0b",
        // quebra de citação — o vetor do `$HOME` do host
        "x'; id; echo '",
        "x\"; id; \"",
        "x`id`",
        "x$(id)",
        "x${IFS}id",
        // encadeamento e redirecionamento
        "a;b",
        "a&&b",
        "a||b",
        "a|b",
        "a>b",
        "a<b",
        "a&",
        "a\nb",
        // caminho
        "../etc/passwd",
        "..\\..\\win",
        "/abs",
        "./rel",
        "a/b",
        "a//b",
        "~/x",
        "$HOME/x",
        // flag
        "-x",
        "--flag",
        "-o",
        "-D",
        "-",
        "--",
        // unicode e homóglifo
        "café",
        "𝓪",
        "а",
        "\u{202e}txt",
        "a\u{200b}b",
        "ｆｕｌｌ",
        // limites
        "0",
        "-1",
        "٩",
        "１２３",
    ] {
        v.push(s.to_string());
    }
    // Comprimento: 1, no teto, e muito além.
    for n in [1usize, 64, 65, 256, 257, 4096, 100_000] {
        v.push("a".repeat(n));
        v.push(format!("/{}", "a".repeat(n)));
    }
    // Bytes altos válidos em UTF-8 mas fora de ASCII.
    v.push("\u{1F600}".repeat(50));
    v
}

/// **Invariante da família:** nenhum validador entra em pânico, com nada.
///
/// **Por que importa:** todos rodam sobre entrada que veio de fora — perfil vindo do banco,
/// `$HOME` vindo do host, opção vinda do usuário. Pânico num validador é o app morrendo no
/// exato ponto que existe pra proteger.
#[test]
fn nenhum_validador_panica_com_entrada_hostil() {
    for s in corpus_hostil() {
        let _ = deployer::vps::registro::valid_alias(&s);
        let _ = deployer::vps::registro::valid_host(&s);
        let _ = deployer::vps::registro::valid_opcao(&s);
        let _ = deployer::vps::registro::valid_home_remoto(&s);
        let _ = deployer::sshkeys::valid_name(&s);
        let _ = deployer::vps::registro::resumir(&s);
    }
}

/// **Invariante da família:** o que é ACEITO nunca contém metacaractere de shell, separador
/// de argumento, byte nulo, quebra de linha, nem começa por `-`.
///
/// **Por que como propriedade e não como lista de exemplos:** cada validador tem hoje o seu
/// teste com os venenos que alguém lembrou. Esta versão afirma a regra sobre o corpus
/// inteiro de uma vez — e vale automaticamente para qualquer entrada nova no corpus.
///
/// `valid_opcao` fica de fora do "não pode ter `=`" porque a forma dele **é** `Chave=valor`;
/// o resto do contrato vale igual.
#[test]
fn o_que_passa_nunca_carrega_metacaractere() {
    const PROIBIDOS: &[char] =
        &[';', '&', '|', '`', '$', '>', '<', '\n', '\r', '\0', '\'', '"', '(', ')', ' ', '\t'];

    for s in corpus_hostil() {
        for (nome, aceito) in [
            ("valid_alias", deployer::vps::registro::valid_alias(&s).is_ok()),
            ("valid_host", deployer::vps::registro::valid_host(&s).is_ok()),
            ("valid_opcao", deployer::vps::registro::valid_opcao(&s).is_ok()),
            ("valid_home_remoto", deployer::vps::registro::valid_home_remoto(&s).is_ok()),
            ("sshkeys::valid_name", deployer::sshkeys::valid_name(&s).is_ok()),
        ] {
            if !aceito {
                continue;
            }
            for c in PROIBIDOS {
                assert!(
                    !s.contains(*c),
                    "{nome} ACEITOU {s:?}, que contém {c:?} — isso vira argumento, caminho \
                     ou comando no outro lado"
                );
            }
            assert!(
                !s.starts_with('-'),
                "{nome} ACEITOU {s:?}, que começa por `-` e o `ssh` leria como flag"
            );
            assert!(
                s.len() <= 256,
                "{nome} ACEITOU {} bytes — sem teto, a mensagem de erro vira amplificação",
                s.len()
            );
        }
    }
}

/// **Invariante:** `resumir` limita a saída, e nunca cresce a entrada.
///
/// **Por que:** ele existe porque `alias inválido: {alias:?}` com 300 MB devolvia uma
/// mensagem de 300 MB — validação virando amplificação. A propriedade é "a saída é curta",
/// não "a saída é 120 caracteres em tal caso".
#[test]
fn resumir_nunca_amplifica() {
    for s in corpus_hostil() {
        let r = deployer::vps::registro::resumir(&s);
        assert!(
            r.chars().count() <= 200,
            "resumir devolveu {} caracteres para uma entrada de {}",
            r.chars().count(),
            s.chars().count()
        );
    }
}
