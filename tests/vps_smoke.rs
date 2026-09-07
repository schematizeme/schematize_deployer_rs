//! O QUE: smoke ponta a ponta do `schematize vps` — roda o BINÁRIO de verdade e assere o
//! CONTEÚDO da saída (shape), não só o exit code.
//!
//! POR QUE EXISTE: o piso da casa manda o smoke asserir conteúdo, ter assertion NEGATIVA e
//! trazer um self-check que força uma falha conhecida. Smoke que só olha "exit 0" está cego:
//! um binário que imprime nada, ou que imprime um erro e sai 0, passaria.
//!
//! DE ONDE VEM: `SCHEMATIZE_VPS_DB` aponta pra um arquivo temporário exclusivo desta suíte —
//! o teste nunca toca o `~/.schematize/vps.db` de quem roda.
//! PRA ONDE VAI: escreve só nesse temporário, e o apaga no fim.

use std::path::PathBuf;
use std::process::Command;

/// Caminho do binário compilado, ao lado do executável de teste.
fn binario() -> PathBuf {
    let mut p = std::env::current_exe().expect("current_exe");
    p.pop(); // deps/
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("deployer")
}

/// DB temporário exclusivo de UM teste. O `nome` importa: os testes desta suíte rodam em
/// paralelo, e sem ele os dois cairiam no mesmo arquivo (mesmo pid) — um apagando o DB do
/// outro no meio do caminho.
fn db_temporario(nome: &str) -> PathBuf {
    std::env::temp_dir().join(format!("schematize-vps-smoke-{nome}-{}.db", std::process::id()))
}

/// Roda `schematize vps <args>` contra o DB temporário. Devolve `(stdout+stderr, sucesso)`.
fn vps(db: &PathBuf, args: &[&str]) -> (String, bool) {
    let out = Command::new(binario())
        .arg("vps")
        .args(args)
        .env("SCHEMATIZE_VPS_DB", db)
        .output()
        .expect("o binário `schematize` precisa estar compilado (cargo build)");
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (s, out.status.success())
}

#[test]
fn smoke_do_gestor_de_vps() {
    let db = db_temporario("fluxo");
    let _ = std::fs::remove_file(&db);

    // --- 1. o help enumera os subcomandos prometidos (contagem, não amostragem) ----------
    let (help, ok) = vps(&db, &["--help"]);
    assert!(ok, "vps --help tem que sair 0:\n{help}");
    for sub in ["add", "list", "trust", "exec", "logs", "policy", "authorize", "rm", "hooks"] {
        assert!(help.contains(sub), "`{sub}` sumiu do help:\n{help}");
    }

    // --- 2. registro: o host nasce no default MAIS RESTRITIVO ---------------------------
    let (add, ok) = vps(
        &db,
        &[
            "add",
            "srv-01",
            "--host",
            "10.0.0.5",
            "--user",
            "deploy",
            "--key",
            "id_ed25519",
            "--env",
            "hml",
        ],
    );
    assert!(ok, "add falhou:\n{add}");
    assert!(add.contains("readonly"), "o host tem que nascer readonly:\n{add}");
    assert!(add.contains("vps trust"), "o add tem que ensinar o próximo passo:\n{add}");

    let (list, ok) = vps(&db, &["list"]);
    assert!(ok, "list falhou:\n{list}");
    assert!(
        list.contains("srv-01") && list.contains("deploy@10.0.0.5:22"),
        "shape da listagem:\n{list}"
    );
    // O aviso que o ADR-0005 exige: host sem shim não tem fronteira server-side.
    assert!(list.contains("SEM"), "host sem shim tem que aparecer marcado:\n{list}");

    // --- 3. host não confiado não conecta (fim do TOFU cego) -----------------------------
    let (r, ok) = vps(&db, &["exec", "srv-01", "--", "uptime"]);
    assert!(!ok, "host não confiado NÃO pode sair 0:\n{r}");
    assert!(
        r.contains("não confiado") && r.contains("vps trust"),
        "erro tem que ser acionável:\n{r}"
    );

    // --- 4. comando catastrófico é recusado antes de qualquer rede -----------------------
    let (r, ok) = vps(&db, &["exec", "srv-01", "--", "rm", "-rf", "/"]);
    assert!(!ok, "catastrófico NÃO pode sair 0:\n{r}");
    assert!(r.contains("recusado pela política"), "shape do erro de política:\n{r}");
    // ASSERTION NEGATIVA: a mensagem não pode ser a de host não confiado — a política vem ANTES.
    assert!(
        !r.contains("não confiado"),
        "a política tem que barrar antes de tentar conectar:\n{r}"
    );

    // --- 5. a tentativa recusada ENTRA na trilha ----------------------------------------
    let (logs, ok) = vps(&db, &["logs", "srv-01"]);
    assert!(ok, "logs falhou:\n{logs}");
    assert!(
        logs.contains("deny") && logs.contains("rm -rf /"),
        "a recusa tem que estar na trilha:\n{logs}"
    );
    assert!(logs.contains("append-only"), "o rodapé declara a natureza da trilha:\n{logs}");

    // --- 6. produção pede confirmação até pro comando mais inofensivo --------------------
    let (_, ok) = vps(&db, &["policy", "srv-01", "--env", "prd", "--modo", "livre"]);
    assert!(ok);
    let (r, ok) = vps(&db, &["exec", "srv-01", "--", "uptime"]);
    assert!(!ok, "prd sem confirmação NÃO pode sair 0:\n{r}");
    assert!(
        r.contains("confirmação humana") && r.contains("--confirmar"),
        "shape do gate de prd:\n{r}"
    );

    // --- 7. confirmar NÃO é --force: um Deny continua Deny -------------------------------
    let (r, ok) = vps(&db, &["exec", "srv-01", "--confirmar", "--", "rm", "-rf", "/"]);
    assert!(!ok, "confirmar não pode liberar catastrófico:\n{r}");
    assert!(r.contains("recusado pela política"), "{r}");

    // --- 8. host inexistente dá erro que ENSINA -----------------------------------------
    let (r, ok) = vps(&db, &["exec", "nao-existe", "--", "uptime"]);
    assert!(!ok);
    assert!(
        r.contains("vps list") && r.contains("vps add"),
        "erro tem que ensinar as duas saídas:\n{r}"
    );

    let _ = std::fs::remove_file(&db);
}

/// SELF-CHECK: força uma falha CONHECIDA e prova que o smoke a enxergaria.
///
/// Sem isto, um smoke que só faz `assert!(ok)` continuaria verde mesmo se o binário parasse
/// de imprimir qualquer coisa — e ninguém ficaria sabendo. Aqui a "falha conhecida" é um
/// subcomando que não existe: se o smoke não conseguir distinguir isso de um sucesso, ele
/// está cego e este teste cai.
#[test]
fn self_check_o_smoke_enxerga_falha() {
    let db = db_temporario("selfcheck");
    let (saida, ok) = vps(&db, &["subcomando-que-nao-existe"]);
    assert!(!ok, "um subcomando inexistente TEM que falhar — se saiu 0, o smoke está cego");
    assert!(
        saida.contains("error") || saida.contains("erro") || saida.contains("unrecognized"),
        "o smoke precisa conseguir LER a falha na saída, não só no exit code:\n{saida}"
    );

    // E o inverso: um caminho que sabidamente funciona TEM que ser visto como sucesso.
    let (saida, ok) = vps(&db, &["--help"]);
    assert!(
        ok && !saida.is_empty(),
        "o smoke precisa distinguir sucesso de falha, não negar sempre"
    );
    let _ = std::fs::remove_file(&db);
}
