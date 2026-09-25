//! Grava no binário de qual COMMIT ele foi construído.
//!
//! ## Por que isto existe
//!
//! Em 2026-09-24 os três apps desta máquina estavam com binários de **2026-09-09**, e a
//! versão dos dois era a MESMA (`0.2.1`) — o número não foi bumpado entre os commits que
//! mudaram comportamento. O efeito: `schematize-market desktop --install` rodava, dizia `✓`,
//! e gravava a forma ANTIGA do `.desktop` (terminal) com a janela instalada ao lado. Levou
//! 15 dias para alguém notar, e o que impediu de notar foi não haver **nada** que
//! distinguisse os dois binários.
//!
//! Versão igual com comportamento diferente é um estado indetectável. O SHA resolve isso sem
//! depender de ninguém lembrar de bumpar número.
//!
//! ## O que ele emite, e o que NÃO faz
//!
//! `SCHEMATIZE_GIT_SHA` = a saída de `git rev-parse --short=12 HEAD`, ou **string vazia** em
//! qualquer falha. Vazio é um caso legítimo, não um erro: quem compila de tarball (o
//! `install.sh` faz isso), de um export, ou sem `git` instalado não tem commit nenhum para
//! informar. **Falhar o build por causa disso seria trocar um diagnóstico por um bloqueio.**
//!
//! A decisão sobre o que MOSTRAR quando está vazio não é aqui — é em `procedencia.rs`, função
//! pura, testável. Aqui só se colhe o dado bruto; um `build.rs` não tem teste.

use std::process::Command;

fn main() {
    // `--short=12`: 7 colide em repo grande, 40 não cabe numa linha de `--version`.
    let sha = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    println!("cargo:rustc-env=SCHEMATIZE_GIT_SHA={sha}");

    // Sem isto o valor congela no primeiro build e a versão passa a MENTIR — que é o bug que
    // este arquivo existe para matar. `.git/HEAD` muda a cada checkout/commit; o `refs/heads`
    // cobre o commit na mesma branch.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");
}
