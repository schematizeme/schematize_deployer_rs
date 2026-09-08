//! `deployer painel` — a visão geral, e o que o ícone do menu abre.
//!
//! **O quê:** diz o que está configurado e o que dá para fazer a seguir.
//!
//! **Onde:** `deployer painel`, e o `Exec=` do `.desktop`.
//!
//! **Por que existe:** clicar no ícone de uma CLI tem de mostrar ALGO. Sem este comando o
//! `.desktop` chamaria `deployer` puro, que imprime o help do clap e sai — um piscar de
//! terminal. §37.48: o software se adapta ao clique, em vez de exigir que a pessoa saiba que
//! isto é uma CLI.

use deployer::nucleo::i18n::{t, tf};
use deployer::{cofre, dns::credencial, nucleo::desktop};

pub(crate) fn painel_cmd(wait: bool) -> Result<(), String> {
    println!("{}", tf("cli.panel.title", &[("version", env!("CARGO_PKG_VERSION"))]));
    println!("{}", t("cli.panel.subtitle"));
    println!();

    // COFRE — a base de tudo o mais. Sem ele, os outros itens não têm o que dizer.
    let tem_cofre = cofre::arquivo::existe();
    let estado = t(if tem_cofre { "cli.panel.vault_created" } else { "cli.panel.vault_absent" });
    println!("{}", tf("cli.panel.vault", &[("state", &estado)]));
    if !tem_cofre {
        println!("{}", t("cli.panel.vault_start_here"));
    }

    // CHAVES — leitura pública, não precisa destravar nada.
    let chaves = deployer::sshkeys::list();
    println!("{}", tf("cli.panel.keys", &[("count", &chaves.len().to_string())]));
    if chaves.is_empty() {
        println!("{}", t("cli.panel.keys_hint"));
    }

    // DNS — só diz SE há token, e só quando o cofre existe. Nunca destrava para um painel:
    // pedir a passphrase para mostrar um resumo treinaria a pessoa a digitá-la à toa.
    if tem_cofre {
        println!("{}", t("cli.panel.dns"));
    }
    let _ = credencial::CHAVE; // a chave é conhecida; o valor nunca passa por aqui

    println!();
    println!("{}", t("cli.panel.what_you_can_do"));

    if !desktop::arquivo_desktop(&deployer::nucleo::util::home()).exists() {
        println!();
        println!("{}", t("cli.panel.not_in_menu"));
    }

    if wait {
        // O lançador do desktop fecha o terminal quando o processo sai. Sem esta pausa, o
        // clique no ícone seria um piscar.
        println!();
        print!("{} ", t("common.press_enter"));
        use std::io::Write;
        let _ = std::io::stdout().flush();
        let mut l = String::new();
        let _ = std::io::stdin().read_line(&mut l);
    }
    Ok(())
}

/// `deployer desktop` — põe (ou tira) o app do menu de aplicativos.
pub(crate) fn desktop_cmd(install: bool, remove: bool) -> Result<(), String> {
    if install && remove {
        return Err("`--install` and `--remove` are opposites — ask for one at a time".into());
    }
    let home = deployer::nucleo::util::home();
    if remove {
        let tinha = desktop::remover(&home)?;
        println!("{}", t(if tinha { "cli.desktop.removed" } else { "cli.desktop.was_absent" }));
        return Ok(());
    }
    // O caminho do PRÓPRIO executável: gravar um adivinhado faria o ícone abrir outra coisa
    // (ou nada) em quem instalou fora do lugar padrão.
    let bin = std::env::current_exe()
        .map_err(|e| format!("não descobri o caminho do próprio binário: {e}"))?;
    let p = desktop::instalar(&home, &bin)?;
    println!("{}", tf("cli.desktop.installed", &[("path", &p.display().to_string())]));
    println!("{}", t("cli.desktop.now_listed"));
    Ok(())
}
