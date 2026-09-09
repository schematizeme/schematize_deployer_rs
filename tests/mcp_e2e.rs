//! O QUE: prova que o servidor MCP fala o protocolo de verdade — alimentando o BINÁRIO por
//! stdin, como o Claude Code faz, e conferindo cada resposta.
//!
//! POR QUE EXISTE: os testes de unidade exercitam `protocolo::responder` com tools de mentira.
//! Isso não prova que o laço de stdio funciona, que o handshake completo passa, nem que uma
//! notificação no meio não desalinha o canal. Aqui é o processo real.
//!
//! DE ONDE VEM: `SCHEMATIZE_VPS_DB` num temporário. PRA ONDE VAI: só esse temporário.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

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

fn db(nome: &str) -> PathBuf {
    std::env::temp_dir().join(format!("schematize-mcp-{nome}-{}.db", std::process::id()))
}

/// Manda as linhas pro `mcp serve` e devolve as respostas parseadas.
fn conversar(db: &PathBuf, linhas: &[&str]) -> Vec<serde_json::Value> {
    let mut filho = Command::new(binario())
        .args(["mcp", "serve"])
        .env("SCHEMATIZE_VPS_DB", db)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("o binário precisa estar compilado");
    {
        let mut e = filho.stdin.take().expect("stdin");
        for l in linhas {
            writeln!(e, "{l}").expect("escrever");
        }
    } // fecha o stdin -> o servidor termina o laço
    let out = filho.wait_with_output().expect("esperar o servidor");
    assert!(out.status.success(), "o servidor não pode sair com erro: {:?}", out.status);
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str(l).unwrap_or_else(|e| panic!("resposta não é JSON: {l} ({e})"))
        })
        .collect()
}

#[test]
fn handshake_completo_como_o_claude_code_faz() {
    let db = db("handshake");
    let _ = std::fs::remove_file(&db);
    let r = conversar(
        &db,
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        ],
    );

    // A notificação NÃO pode gerar resposta — se gerasse, o canal desalinharia.
    assert_eq!(r.len(), 2, "esperava 2 respostas (a notificação não responde): {r:?}");
    assert_eq!(r[0]["id"], 1);
    assert_eq!(r[0]["result"]["serverInfo"]["name"], "schematize-vps");
    assert_eq!(r[1]["id"], 2);
    let nomes: Vec<&str> = r[1]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(nomes, ["vps_list", "vps_open", "vps_exec", "vps_tail", "vps_close"]);
    let _ = std::fs::remove_file(&db);
}

#[test]
fn linha_malformada_nao_derruba_o_servidor() {
    // Um servidor MCP que morre na primeira linha estranha derruba a sessão do usuário.
    let db = db("malformada");
    let r = conversar(
        &db,
        &[
            "isto não é json",
            "{\"incompleto\": ",
            "[]",
            r#"{"jsonrpc":"2.0","id":9,"method":"initialize"}"#,
        ],
    );
    // As três primeiras viram erro; a quarta ainda é atendida — o laço sobreviveu.
    let ultima = r.last().expect("o servidor tem que ter respondido à linha válida");
    assert_eq!(ultima["id"], 9);
    assert_eq!(ultima["result"]["serverInfo"]["name"], "schematize-vps");
    let _ = std::fs::remove_file(&db);
}

#[test]
fn a_politica_vale_pelo_mcp_igual_ao_cli() {
    // O MCP é outra PORTA para a mesma lógica — não uma segunda lógica.
    let db = db("politica");
    let _ = std::fs::remove_file(&db);
    // Registra um host livre em hml pelo próprio binário.
    let add = Command::new(binario())
        .args([
            "vps",
            "add",
            "srv",
            "--host",
            "10.0.0.5",
            "--user",
            "d",
            "--key",
            "id_ed25519",
            "--env",
            "hml",
        ])
        .env("SCHEMATIZE_VPS_DB", &db)
        .output()
        .expect("add");
    assert!(add.status.success());
    let pol = Command::new(binario())
        .args(["vps", "policy", "srv", "--modo", "livre"])
        .env("SCHEMATIZE_VPS_DB", &db)
        .output()
        .expect("policy");
    assert!(pol.status.success());

    let r = conversar(
        &db,
        &[
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vps_list","arguments":{}}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vps_exec","arguments":{"alias":"srv","comando":"rm -rf /"}}}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"vps_open","arguments":{"alias":"nao-existe"}}}"#,
        ],
    );

    // vps_list responde e já avisa que a host key não está pinada.
    let texto = r[0]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(texto.contains("srv"), "{texto}");
    assert!(
        texto.contains("NÃO CONFIADA"),
        "o agente precisa saber por que nada vai funcionar: {texto}"
    );

    // O comando catastrófico é RECUSADO — e chega como resultado legível, não erro opaco.
    assert_eq!(r[1]["result"]["isError"], true);
    let motivo = r[1]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(motivo.contains("recusado pela política"), "{motivo}");

    // Host inexistente ENSINA o próximo passo em vez de só falhar.
    assert_eq!(r[2]["result"]["isError"], true);
    let m = r[2]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(m.contains("vps_list"), "{m}");
    let _ = std::fs::remove_file(&db);
}

#[test]
fn o_agente_nao_consegue_se_autoconfirmar_em_producao() {
    // O invariante que sustenta o gate de produção inteiro: não há argumento, campo extra ou
    // combinação que faça o agente responder à pergunta que é do humano.
    let db = db("autoconfirma");
    let _ = std::fs::remove_file(&db);
    for args in [
        &[
            "vps",
            "add",
            "prod",
            "--host",
            "10.0.0.9",
            "--user",
            "d",
            "--key",
            "id_ed25519",
            "--env",
            "prd",
        ][..],
        &["vps", "policy", "prod", "--modo", "livre"][..],
    ] {
        let o = Command::new(binario())
            .args(args)
            .env("SCHEMATIZE_VPS_DB", &db)
            .output()
            .expect("setup");
        assert!(o.status.success(), "setup falhou: {args:?}");
    }

    let tentativas = [
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vps_exec","arguments":{"alias":"prod","comando":"uptime"}}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vps_exec","arguments":{"alias":"prod","comando":"uptime","confirmar":true}}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"vps_exec","arguments":{"alias":"prod","comando":"uptime","force":true,"yes":true,"skip_policy":true}}}"#,
    ];
    let r = conversar(&db, &tentativas);
    for (i, resp) in r.iter().enumerate() {
        assert_eq!(resp["result"]["isError"], true, "tentativa {i} não podia passar: {resp}");
        let t = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            t.contains("confirmação humana"),
            "tentativa {i}: produção tem que exigir humano, veio: {t}"
        );
    }
    let _ = std::fs::remove_file(&db);
}
