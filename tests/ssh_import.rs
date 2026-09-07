//! O QUE: prova que `schematize ssh import` adota uma chave já existente sem desprotegê-la,
//! sem deixar rastro quando falha, e — o principal — **sem nunca pendurar**.
//!
//! POR QUE EXISTE: o gestor de chaves só sabia CRIAR (`gen`). Quem já tinha chave — de outra
//! máquina, de um backup, de um cofre — não conseguia trazê-la para a gestão do app, e a
//! única saída era copiar à mão e acertar permissão na unha.
//!
//! POR QUE RODA O BINÁRIO, E NÃO A LIB: `sshkeys` resolve `~/.ssh` via `util::home()`, que lê
//! `$HOME`. Mexer em `$HOME` dentro do teste é estado GLOBAL do processo, e os testes de Rust
//! rodam em paralelo — um roubaria o `$HOME` do outro. O próprio `util.rs` registra essa
//! armadilha. Subprocesso com `$HOME` próprio é o isolamento que de fato isola.
//!
//! DE ONDE VEM: chaves de mentira geradas na hora, em diretório temporário.
//! PRA ONDE VAI: só asserção — nenhum `~/.ssh` real é lido ou escrito.
//!
//! POR QUE SÓ EM UNIX: as asserções centrais são de PERMISSÃO (600/644), que não existem
//! fora do Unix, e o `definir_modo` é no-op nas outras plataformas. Não é teste escondido:
//! nas outras não há o que afirmar.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Quanto tempo um import pode levar antes de ser considerado **pendurado**.
/// Generoso de propósito: o que se quer pegar é o prompt de passphrase, que espera para
/// sempre — não lentidão de máquina carregada.
const LIMITE: Duration = Duration::from_secs(45);

/// **O quê:** sandbox exclusivo deste teste, com `$HOME` e diretório de origem próprios.
/// **Onde:** todo teste deste arquivo, uma vez cada.
fn sandbox(nome: &str) -> (PathBuf, PathBuf) {
    let base =
        std::env::temp_dir().join(format!("schematize-sshimp-{nome}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let (home, origem) = (base.join("home"), base.join("origem"));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&origem).unwrap();
    (home, origem)
}

/// **O quê:** gera um par de mentira em `dir/<nome>`, com ou sem passphrase.
/// **Onde:** as fixtures de cada teste. Falha ALTO se o `ssh-keygen` não existe — um gate
/// que não consegue verificar não diz VERDE (e sem `ssh-keygen` o próprio produto não roda).
fn chave_falsa(dir: &Path, nome: &str, passphrase: &str, comentario: &str) -> PathBuf {
    let p = dir.join(nome);
    let ok = Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-f",
            &p.to_string_lossy(),
            "-C",
            comentario,
            "-N",
            passphrase,
            "-q",
        ])
        .status()
        .unwrap_or_else(|e| {
            panic!("`ssh-keygen` é obrigatório para este teste (e para o produto): {e}")
        });
    assert!(ok.success(), "ssh-keygen falhou ao criar a fixture {nome}");
    p
}

/// **O quê:** roda `schematize ssh import …` com `$HOME` próprio e **prazo**. Devolve
/// (sucesso, stdout+stderr).
///
/// **Onde:** todo teste. O prazo é o que transforma "pendurou" — que sem isto viraria um CI
/// estourando por timeout, sem dizer por quê — numa falha que se explica sozinha.
fn importar(home: &Path, args: &[&str]) -> (bool, String) {
    let mut filho = Command::new(env!("CARGO_BIN_EXE_deployer"))
        .arg("ssh")
        .arg("import")
        .args(args)
        .env("HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("não consegui executar o binário do schematize");

    let inicio = Instant::now();
    loop {
        match filho.try_wait().expect("try_wait") {
            Some(_) => break,
            None if inicio.elapsed() > LIMITE => {
                let _ = filho.kill();
                let _ = filho.wait();
                panic!(
                    "`ssh import {args:?}` PENDUROU por mais de {}s — quase certamente um \
                     prompt de passphrase do ssh-keygen. É exatamente o que o `-P` sempre \
                     presente existe para impedir (ver sshkeys::importar::readpub_args).",
                    LIMITE.as_secs()
                );
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    let out = filho.wait_with_output().expect("wait_with_output");
    let mut txt = String::from_utf8_lossy(&out.stdout).into_owned();
    txt.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), txt)
}

/// **O quê:** permissão de um arquivo, em octal (ex.: 0o600).
fn modo(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap_or_else(|e| panic!("{}: {e}", p.display())).permissions().mode()
        & 0o777
}

/// **O quê:** o arquivo continua CIFRADO? (lê a pública com passphrase vazia; se der, não está)
fn esta_cifrada(p: &Path) -> bool {
    !Command::new("ssh-keygen")
        .args(["-y", "-P", "", "-f", &p.to_string_lossy()])
        .stdin(Stdio::null())
        .output()
        .expect("ssh-keygen")
        .status
        .success()
}

// ---------------------------------------------------------------------------
// O caso que motivou a funcionalidade.
// ---------------------------------------------------------------------------

/// Chave de backup com permissão ABERTA (644) — o caso mais comum, e o que o `ssh-keygen`
/// se recusa a ler no lugar (`bad permissions`). Tem de importar e sair em 600.
#[test]
fn importa_chave_com_permissao_aberta_e_aplica_o_piso() {
    let (home, origem) = sandbox("aberta");
    let k = chave_falsa(&origem, "deploy", "", "eu@antigo");
    std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o644)).unwrap();

    let (ok, saida) = importar(&home, &[&k.to_string_lossy()]);
    assert!(ok, "import falhou: {saida}");

    let priv_p = home.join(".ssh/deploy");
    let pub_p = home.join(".ssh/deploy.pub");
    assert!(priv_p.exists() && pub_p.exists(), "o par não apareceu em ~/.ssh: {saida}");
    assert_eq!(modo(&priv_p), 0o600, "a privada TEM de sair em 600");
    assert_eq!(modo(&pub_p), 0o644, "a pública sai em 644");

    // O comentário original é o que identifica a chave num authorized_keys alheio.
    let publica = std::fs::read_to_string(&pub_p).unwrap();
    assert!(publica.contains("eu@antigo"), "o comentário original se perdeu: {publica}");
    assert!(publica.starts_with("ssh-ed25519 "), "pública malformada: {publica}");
}

/// **Importar não pode desproteger.** A passphrase serve só para LER a chave; o arquivo é
/// copiado byte a byte e continua cifrado em `~/.ssh`.
#[test]
fn chave_cifrada_continua_cifrada_depois_de_importada() {
    let (home, origem) = sandbox("cifrada");
    let k = chave_falsa(&origem, "cofre", "s3nh4", "eu@cofre");

    let (ok, saida) = importar(&home, &[&k.to_string_lossy(), "--passphrase", "s3nh4"]);
    assert!(ok, "import com passphrase falhou: {saida}");

    let priv_p = home.join(".ssh/cofre");
    assert!(esta_cifrada(&priv_p), "a chave foi DESPROTEGIDA ao importar — nunca");
    assert_eq!(modo(&priv_p), 0o600);
}

/// A joia da coroa: chave cifrada **sem** `--passphrase` tem de falhar RÁPIDO e dizer o que
/// fazer. Sem o `-P` sempre presente, o `ssh-keygen` abre prompt e pendura — e fechar o
/// stdin não resolve, porque ele lê de `/dev/tty`. Se isto pendurar, o `importar` explode
/// com a explicação em vez de deixar o CI estourar mudo.
#[test]
fn cifrada_sem_passphrase_falha_rapido_e_ensina_o_proximo_passo() {
    let (home, origem) = sandbox("semsenha");
    let k = chave_falsa(&origem, "cofre", "s3nh4", "eu@cofre");

    let (ok, saida) = importar(&home, &[&k.to_string_lossy()]);
    assert!(!ok, "devia recusar sem a passphrase: {saida}");
    assert!(saida.contains("--passphrase"), "a mensagem tem de ensinar o passo: {saida}");
    assert!(!home.join(".ssh/cofre").exists(), "não pode deixar chave meio-importada");
}

// ---------------------------------------------------------------------------
// Enganos prováveis — a mensagem tem de dizer o próximo passo, nunca culpar.
// ---------------------------------------------------------------------------

/// Apontar para o `.pub` é o engano mais provável, e o OpenSSH responde `error in libcrypto`,
/// que não ajuda ninguém.
#[test]
fn apontar_para_o_pub_diz_para_apontar_para_a_privada() {
    let (home, origem) = sandbox("pub");
    let k = chave_falsa(&origem, "deploy", "", "c");
    let pubfile = format!("{}.pub", k.to_string_lossy());

    let (ok, saida) = importar(&home, &[&pubfile, "--name", "x"]);
    assert!(!ok, "não devia aceitar um .pub: {saida}");
    assert!(saida.contains("PÚBLICA"), "mensagem tem de nomear o engano: {saida}");
}

/// Arquivo que não é chave: diz os formatos aceitos e como converter o do PuTTY.
#[test]
fn arquivo_que_nao_e_chave_lista_os_formatos_aceitos() {
    let (home, origem) = sandbox("naochave");
    let lixo = origem.join("lixo.txt");
    std::fs::write(&lixo, "isto nao e uma chave\n").unwrap();

    let (ok, saida) = importar(&home, &[&lixo.to_string_lossy()]);
    assert!(!ok, "não devia aceitar lixo: {saida}");
    assert!(saida.contains("OpenSSH"), "tem de dizer o que aceita: {saida}");
}

/// Não sobrescreve chave existente em silêncio — e `--force` destrava.
#[test]
fn nao_sobrescreve_sem_force_e_sobrescreve_com_force() {
    let (home, origem) = sandbox("force");
    let k = chave_falsa(&origem, "deploy", "", "c");
    let arg = k.to_string_lossy().into_owned();

    let (ok1, s1) = importar(&home, &[&arg]);
    assert!(ok1, "1º import falhou: {s1}");

    let (ok2, s2) = importar(&home, &[&arg]);
    assert!(!ok2, "o 2º devia recusar: {s2}");
    assert!(s2.contains("--force"), "tem de ensinar a saída: {s2}");

    let (ok3, s3) = importar(&home, &[&arg, "--force"]);
    assert!(ok3, "--force devia destravar: {s3}");
}

/// Nome que escaparia de `~/.ssh` é recusado. O import não pode ser a porta dos fundos que o
/// `gen` já fechou.
#[test]
fn nome_que_escaparia_de_ssh_e_recusado() {
    let (home, origem) = sandbox("escape");
    let k = chave_falsa(&origem, "deploy", "", "c");
    let arg = k.to_string_lossy().into_owned();

    for mau in ["../evil", "a/b"] {
        let (ok, saida) = importar(&home, &[&arg, "--name", mau]);
        assert!(!ok, "nome {mau:?} devia ser recusado: {saida}");
    }
    // Nada escapou para fora de ~/.ssh.
    assert!(!home.join("evil").exists());
    assert!(!home.join(".ssh/../evil").exists());
}

/// Falha não pode deixar entulho: o temporário da importação some em todo caminho de erro.
#[test]
fn falha_nao_deixa_temporario_para_tras() {
    let (home, origem) = sandbox("entulho");
    let lixo = origem.join("lixo");
    std::fs::write(&lixo, "nao e chave\n").unwrap();

    let (ok, saida) = importar(&home, &[&lixo.to_string_lossy(), "--name", "k"]);
    assert!(!ok, "{saida}");

    let restos: Vec<_> = std::fs::read_dir(home.join(".ssh"))
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.contains("importando"))
                .collect()
        })
        .unwrap_or_default();
    assert!(restos.is_empty(), "sobrou temporário em ~/.ssh: {restos:?}");
}

/// SELF-CHECK: o arnês consegue REPROVAR? Um `importar()` que sempre devolvesse sucesso
/// deixaria todos os testes acima cegos — já aconteceu nesta casa (um helper de teste falso
/// fez dois testes de trava não afirmarem nada).
#[test]
fn o_arnes_consegue_ver_falha() {
    let (home, _) = sandbox("selfcheck");
    let (ok, saida) = importar(&home, &["/caminho/que/nao/existe/em/lugar/nenhum"]);
    assert!(!ok, "o arnês reportou SUCESSO para um arquivo inexistente — está cego");
    assert!(!saida.is_empty(), "o arnês não capturou a saída do processo");
}
