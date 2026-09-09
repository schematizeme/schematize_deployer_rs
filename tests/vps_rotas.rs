//! O QUE: enumera TODA rota exposta (subcomando de CLI e tool de MCP) e prova que cada uma
//! existe de ponta a ponta: declarada, despachada, e alcançável de verdade.
//!
//! POR QUE EXISTE: o piso `simulated` da casa — 100% das rotas acessíveis a quem deve, e
//! **rota fantasma ou morta quebra o run**. Um subcomando declarado no `clap` mas sem braço no
//! `match`, ou uma tool no schema do MCP sem tratamento no dispatch, é uma promessa que o
//! usuário (ou o agente) descobre quebrada em produção. A verificação é por CONTAGEM: o
//! número de rotas declaradas tem que bater com o de rotas tratadas.
//!
//! DE ONDE VEM: o próprio código-fonte + o binário. PRA ONDE VAI: só asserção.

use std::path::PathBuf;
use std::process::Command;

fn binario() -> PathBuf {
    let mut p = std::env::current_exe().expect("current_exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    // `CARGO_BIN_EXE_…` e nao um nome montado a mao: o Cargo garante o caminho do binario
    // DESTE alvo, e um rename passa a ser problema do Cargo em vez de virar teste procurando
    // arquivo que nao existe mais.
    //
    // Foi exatamente isso que aconteceu: o binario virou `schematize-deployer` (ADR-0012) e
    // estes testes seguiram procurando `deployer`. Passavam na maquina de quem desenvolve,
    // porque havia um binario ANTIGO sobrando no target, e reprovaram no CI, que compila do
    // zero. Um teste que depende do lixo do seu proprio target nao esta testando o codigo.
    let _ = p;
    PathBuf::from(env!("CARGO_BIN_EXE_schematize-deployer"))
}

/// Variantes declaradas de um `enum` do `clap`, lidas do fonte.
///
/// **Onde:** os dois testes de rota abaixo.
///
/// **Por que PROCURA o enum em vez de receber o arquivo:** a versão anterior recebia
/// `"src/cli/args.rs"` fixo, e quebrou no dia em que aquele arquivo virou o diretório
/// `src/cli/args/` (780 linhas, acima do teto da casa). O teste falhou por saber DEMAIS
/// sobre a arrumação do código — não sobre o comportamento dele. Procurando pela
/// declaração, o próximo corte não o derruba, e o erro que sobra é o erro de verdade:
/// "este enum não existe em lugar nenhum".
fn variantes(nome_do_enum: &str) -> Vec<String> {
    /// Todo `.rs` sob `raiz`, recursivo.
    fn fontes(raiz: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(dir) = std::fs::read_dir(raiz) else {
            return;
        };
        for e in dir.flatten() {
            let p = e.path();
            if p.is_dir() {
                fontes(&p, out);
            } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }
    let mut arquivos = Vec::new();
    fontes(std::path::Path::new("src"), &mut arquivos);
    arquivos.sort();

    let agulha = format!("pub(crate) enum {nome_do_enum} {{");
    let achados: Vec<(std::path::PathBuf, String)> = arquivos
        .iter()
        .filter_map(|p| {
            let src = std::fs::read_to_string(p).ok()?;
            src.contains(&agulha).then(|| (p.clone(), src))
        })
        .collect();
    assert_eq!(
        achados.len(),
        1,
        "`{nome_do_enum}` tinha que estar declarado em UM arquivo, e está em {}: {:?}",
        achados.len(),
        achados.iter().map(|(p, _)| p.display().to_string()).collect::<Vec<_>>()
    );
    let src = &achados[0].1;
    let ini = src.find(&agulha).expect("enum declarado");
    let corpo = &src[ini..];
    let fim = corpo.find("\n}").expect("fim do enum");
    corpo[..fim]
        .lines()
        .filter_map(|l| {
            let t = l.trim();
            // Variante = linha que começa com maiúscula e termina em `,`, `{` ou `(`.
            let primeiro = t.chars().next()?;
            if !primeiro.is_ascii_uppercase() {
                return None;
            }
            let nome: String = t.chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
            (!nome.is_empty()).then_some(nome)
        })
        .collect()
}

/// Toda variante declarada tem braço no `match` — nenhuma rota fantasma.
#[test]
fn toda_rota_declarada_e_despachada() {
    for (nome, arq_dispatch) in [("VpsCmd", "src/cli/vps.rs"), ("McpCmd", "src/cli/mcp.rs")] {
        let vs = variantes(nome);
        assert!(
            vs.len() >= 4,
            "{nome}: só {} variantes lidas — o parser do teste quebrou",
            vs.len()
        );
        let dispatch = std::fs::read_to_string(arq_dispatch).expect("dispatch");
        let mut sem_braco = Vec::new();
        for v in &vs {
            if !dispatch.contains(&format!("{nome}::{v}")) {
                sem_braco.push(v.clone());
            }
        }
        assert!(
            sem_braco.is_empty(),
            "{nome}: rota declarada sem despacho (fantasma): {sem_braco:?}"
        );
        println!("{nome}: {} rotas, todas despachadas", vs.len());
    }
}

/// Toda rota do CLI responde de verdade — `--help` do subcomando sai 0 e descreve algo.
#[test]
fn toda_rota_do_cli_e_alcancavel() {
    let vs = variantes("VpsCmd");
    let db = std::env::temp_dir().join(format!("schematize-rotas-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&db);
    let mut mortas = Vec::new();
    for v in &vs {
        // `Guard` é o hook: não tem --help útil (lê stdin), então é exercitado à parte.
        if v == "Guard" {
            continue;
        }
        let sub = kebab(v);
        let out = Command::new(binario())
            .args(["vps", &sub, "--help"])
            .env("SCHEMATIZE_VPS_DB", &db)
            .output()
            .expect("binário");
        let texto = String::from_utf8_lossy(&out.stdout);
        if !out.status.success() || texto.trim().is_empty() {
            mortas.push(sub);
        }
    }
    assert!(mortas.is_empty(), "rotas declaradas mas MORTAS (o --help não responde): {mortas:?}");

    // O `Guard` responde ao contrato dele: JSON no stdin, e sai 0 sempre (falha aberta).
    let mut filho = Command::new(binario())
        .args(["vps", "guard"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    {
        use std::io::Write;
        let mut e = filho.stdin.take().unwrap();
        writeln!(e, r#"{{"tool_name":"Bash","tool_input":{{"command":"ssh root@h"}}}}"#).unwrap();
    }
    let saida = filho.wait_with_output().expect("guard");
    assert!(saida.status.success(), "o hook tem que sair 0 sempre");
    let texto = String::from_utf8_lossy(&saida.stdout);
    assert!(texto.contains("\"deny\""), "o hook não barrou ssh cru: {texto}");
    let _ = std::fs::remove_file(&db);
}

/// `Xyz` -> `xyz`; `ListAssets` -> `list-assets`.
fn kebab(v: &str) -> String {
    let mut s = String::new();
    for (i, c) in v.chars().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            s.push('-');
        }
        s.push(c.to_ascii_lowercase());
    }
    s
}

/// Toda tool do schema MCP é tratada no dispatch, e nenhuma sobra no dispatch sem schema.
#[test]
fn as_tools_do_mcp_batem_dos_dois_lados() {
    use deployer::mcp::tools;
    let schema = tools::schema();
    let nomes: Vec<String> = schema
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();

    let fonte = std::fs::read_to_string("src/mcp/tools.rs").expect("fonte");
    let dispatch = fonte.split("pub fn executar").nth(1).expect("a função de dispatch");

    // 1. Toda tool declarada tem braço.
    for n in &nomes {
        assert!(dispatch.contains(&format!("\"{n}\"")), "tool {n:?} no schema mas sem despacho");
    }
    // 2. Todo braço do dispatch está no schema — nenhuma tool oculta, não documentada.
    for linha in dispatch.lines() {
        let t = linha.trim();
        if let Some(resto) = t.strip_prefix("\"vps_") {
            if let Some(fim) = resto.find('"') {
                let nome = format!("vps_{}", &resto[..fim]);
                assert!(
                    nomes.contains(&nome),
                    "tool {nome:?} despachada mas NÃO declarada no schema"
                );
            }
        }
    }
    // 3. Contagem: o que o agente vê é exatamente o que existe.
    assert_eq!(nomes.len(), 5, "o número de tools mudou — atualize o ADR e a doc");
    println!("MCP: {} tools, schema e dispatch em paridade", nomes.len());
}

/// Toda tool responde a uma chamada real, mesmo sem host registrado — nenhuma explode.
#[test]
fn toda_tool_do_mcp_responde_de_verdade() {
    use serde_json::json;
    let db = std::env::temp_dir().join(format!("schematize-rotas-mcp-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&db);

    let mut linhas = Vec::new();
    for (i, (tool, args)) in [
        ("vps_list", json!({})),
        ("vps_open", json!({"alias":"nao-existe"})),
        ("vps_exec", json!({"alias":"nao-existe","comando":"uptime"})),
        ("vps_tail", json!({"alias":"","n":5})),
        ("vps_close", json!({"alias":"nao-existe"})),
    ]
    .iter()
    .enumerate()
    {
        linhas.push(
            json!({"jsonrpc":"2.0","id":i+1,"method":"tools/call",
                           "params":{"name":tool,"arguments":args}})
            .to_string(),
        );
    }

    let mut filho = Command::new(binario())
        .args(["mcp", "serve"])
        .env("SCHEMATIZE_VPS_DB", &db)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    {
        use std::io::Write;
        let mut e = filho.stdin.take().unwrap();
        for l in &linhas {
            writeln!(e, "{l}").unwrap();
        }
    }
    let out = filho.wait_with_output().expect("mcp");
    let respostas: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("json"))
        .collect();

    assert_eq!(respostas.len(), 5, "nem toda tool respondeu: {respostas:?}");
    for (i, r) in respostas.iter().enumerate() {
        let c = r["result"]["content"][0]["text"].as_str().unwrap_or("");
        assert!(!c.trim().is_empty(), "tool {i} respondeu vazio: {r}");
    }
    let _ = std::fs::remove_file(&db);
}
