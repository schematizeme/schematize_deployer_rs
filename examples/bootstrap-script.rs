//! Imprime o script de bootstrap que o `vps bootstrap` geraria, para o e2e contra sshd real.
//!
//! **O quê:** `cargo run --example bootstrap-script -- <home> <pubkey-do-agente> [nivel]`
//! escreve o script no stdout. Nada mais.
//!
//! **Onde:** `scripts/e2e-sshd.sh` (camada 10 do Q.A.), que o envia por `ssh` a um container
//! com sshd de verdade.
//!
//! **Por que um `example` e não um subcomando:** um subcomando novo mudaria a **superfície da
//! CLI**, que é contrato com quem escreveu script e hook (e o snapshot
//! `tests/superficie-cli.txt` reprovaria, com razão). Um `example` não entra no binário
//! publicado nem na árvore do clap.
//!
//! **Por que não copiar o script para dentro do shell de teste:** copiar é exatamente como o
//! teste e a produção divergem sem ninguém ver. O e2e tem de exercitar o script que o app
//! gera, não uma cópia que já foi verdade.

fn main() {
    let mut args = std::env::args().skip(1);
    let home = args.next().unwrap_or_else(|| "/home/deploy".into());
    // A PÚBLICA DO AGENTE — a chave que o `restrict,command=` vai prender ao shim. Tem de
    // ser a chave com que o e2e ataca depois; passar uma fixa faz o teste atacar por uma
    // linha SEM restrição e concluir que a fronteira não existe. (Foi o que aconteceu na
    // primeira execução — o harness estava errado, não o produto.)
    let chave = args.next().unwrap_or_else(|| "ssh-ed25519 AAAA e2e".into());
    let nivel = match args.next().as_deref() {
        Some("root") => deployer::vps::capacidade::Fronteira::OpsShellRoot,
        _ => deployer::vps::capacidade::Fronteira::OpsShellUsuario,
    };
    // O catálogo-semente do app, não uma lista inventada aqui — o e2e tem de exercitar o
    // que o `vps verbs --seed` de verdade instala.
    let catalogo: Vec<deployer::vps::verbos::Verbo> = deployer::vps::verbos::VERBOS_SUGERIDOS
        .iter()
        .map(|(n, c)| deployer::vps::verbos::Verbo {
            nome: (*n).to_string(),
            comando: (*c).to_string(),
        })
        .collect();
    match deployer::vps::bootstrap::script_de_instalacao(nivel, &catalogo, chave.trim(), &home) {
        Ok(s) => print!("{s}"),
        Err(e) => {
            eprintln!("erro: {e}");
            std::process::exit(1);
        }
    }
}
