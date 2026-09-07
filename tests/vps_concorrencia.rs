//! O QUE: prova que o banco aguenta CLI, GUI e servidor MCP mexendo nele ao mesmo tempo.
//!
//! POR QUE EXISTE: os três são PROCESSOS separados sobre o mesmo `~/.schematize/vps.db`, e é
//! o cenário normal — o usuário com a janela aberta, o agente executando por MCP, e um
//! `schematize vps logs` no terminal. Um `database is locked` aqui vira perda de linha de
//! auditoria, que é o único registro do que o agente fez.
//!
//! DE ONDE VEM: DB temporário. PRA ONDE VAI: só ele.

use std::path::PathBuf;
use std::process::Command;

fn binario() -> PathBuf {
    let mut p = std::env::current_exe().expect("current_exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("deployer")
}

fn db(nome: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("schematize-conc-{nome}-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

/// Roda `schematize vps <args>` contra `db`.
fn vps(db: &PathBuf, args: &[&str]) -> (String, bool) {
    let out = Command::new(binario())
        .arg("vps")
        .args(args)
        .env("SCHEMATIZE_VPS_DB", db)
        .output()
        .expect("binário compilado");
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (s, out.status.success())
}

/// N processos escrevendo ao mesmo tempo: nada pode ser perdido nem corromper o banco.
#[test]
fn escrita_concorrente_de_varios_processos_nao_perde_linha() {
    let db = db("escrita");
    let (_, ok) = vps(
        &db,
        &["add", "srv", "--host", "10.0.0.1", "--user", "d", "--key", "id_ed25519", "--env", "hml"],
    );
    assert!(ok, "setup");
    vps(&db, &["policy", "srv", "--modo", "livre"]);

    // 8 processos × 6 execuções. Cada uma FALHA (host não confiado) mas GRAVA na trilha —
    // que é exatamente o caminho que precisa sobreviver à concorrência.
    const PROCS: usize = 8;
    const CADA: usize = 6;
    let filhos: Vec<_> = (0..PROCS)
        .map(|i| {
            let db = db.clone();
            std::thread::spawn(move || {
                for j in 0..CADA {
                    let _ = vps(&db, &["exec", "srv", "--", &format!("comando-{i}-{j}")]);
                }
            })
        })
        .collect();
    for f in filhos {
        f.join().expect("thread");
    }

    // Toda linha tem que estar lá: perder auditoria por contenção é o pior desfecho possível.
    let (saida, ok) = vps(&db, &["logs", "srv", "--n", "500"]);
    assert!(ok, "listar falhou:\n{saida}");
    let linhas = saida.lines().filter(|l| l.contains("comando-")).count();
    assert_eq!(linhas, PROCS * CADA, "auditoria perdeu linha sob concorrência:\n{saida}");

    // E cada combinação exata aparece — não é só a contagem que bate.
    for i in 0..PROCS {
        for j in 0..CADA {
            let alvo = format!("comando-{i}-{j}");
            assert!(saida.contains(&alvo), "sumiu: {alvo}");
        }
    }
    let _ = std::fs::remove_file(&db);
}

/// Leitura enquanto se escreve: o `logs` (que a GUI roda em laço) não pode falhar nem
/// bloquear quem escreve.
#[test]
fn leitura_concorrente_nao_bloqueia_a_escrita() {
    let db = db("leitura");
    vps(
        &db,
        &["add", "srv", "--host", "10.0.0.1", "--user", "d", "--key", "id_ed25519", "--env", "hml"],
    );
    vps(&db, &["policy", "srv", "--modo", "livre"]);

    let db_w = db.clone();
    let escritor = std::thread::spawn(move || {
        for i in 0..25 {
            let _ = vps(&db_w, &["exec", "srv", "--", &format!("w{i}")]);
        }
    });
    let db_r = db.clone();
    let leitor = std::thread::spawn(move || {
        let mut falhas = 0;
        for _ in 0..40 {
            let (_, ok) = vps(&db_r, &["logs", "srv"]);
            if !ok {
                falhas += 1;
            }
        }
        falhas
    });
    escritor.join().expect("escritor");
    let falhas: i32 = leitor.join().expect("leitor");
    assert_eq!(falhas, 0, "{falhas} leituras falharam durante escrita concorrente");
    let _ = std::fs::remove_file(&db);
}

/// Registro concorrente do MESMO alias: o último vence, e nunca duplica.
#[test]
fn registro_concorrente_do_mesmo_alias_nao_duplica() {
    let db = db("upsert");
    let filhos: Vec<_> = (0..10)
        .map(|i| {
            let db = db.clone();
            std::thread::spawn(move || {
                let host = format!("10.0.0.{}", i + 1);
                vps(
                    &db,
                    &[
                        "add",
                        "mesmo",
                        "--host",
                        &host,
                        "--user",
                        "d",
                        "--key",
                        "id_ed25519",
                        "--env",
                        "hml",
                    ],
                );
            })
        })
        .collect();
    for f in filhos {
        f.join().expect("thread");
    }

    let (saida, ok) = vps(&db, &["list"]);
    assert!(ok, "{saida}");
    assert_eq!(
        saida.lines().filter(|l| l.contains("mesmo")).count(),
        1,
        "o alias duplicou sob concorrência:\n{saida}"
    );
    let _ = std::fs::remove_file(&db);
}

/// O banco sobrevive a um processo morto no meio de uma escrita (o usuário fecha a janela).
#[test]
fn banco_sobrevive_a_processo_morto_no_meio() {
    let db = db("morto");
    vps(
        &db,
        &["add", "srv", "--host", "10.0.0.1", "--user", "d", "--key", "id_ed25519", "--env", "hml"],
    );
    vps(&db, &["policy", "srv", "--modo", "livre"]);
    vps(&db, &["exec", "srv", "--", "antes"]);

    // Mata um processo enquanto ele trabalha.
    let mut filho = Command::new(binario())
        .args(["vps", "exec", "srv", "--", "durante"])
        .env("SCHEMATIZE_VPS_DB", &db)
        .spawn()
        .expect("spawn");
    let _ = filho.kill();
    let _ = filho.wait();

    // O banco continua utilizável e o que já estava gravado continua lá.
    let (saida, ok) = vps(&db, &["logs", "srv", "--n", "50"]);
    assert!(ok, "o banco ficou inutilizável após processo morto:\n{saida}");
    assert!(saida.contains("antes"), "perdeu o que já estava gravado:\n{saida}");
    let (_, ok) = vps(&db, &["exec", "srv", "--", "depois"]);
    let (saida, _) = vps(&db, &["logs", "srv", "--n", "50"]);
    assert!(saida.contains("depois"), "não dá mais pra escrever após processo morto:\n{saida}");
    let _ = ok;
    let _ = std::fs::remove_file(&db);
}
