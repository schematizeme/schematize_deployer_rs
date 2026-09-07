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

use deployer::{cofre, dns::credencial, nucleo::desktop};

pub(crate) fn painel_cmd(aguardar: bool) -> Result<(), String> {
    println!("schematize Deployer {}", env!("CARGO_PKG_VERSION"));
    println!("SSH, VPS e DNS — com a credencial fora do alcance do agente.");
    println!();

    // COFRE — a base de tudo o mais. Sem ele, os outros itens não têm o que dizer.
    let tem_cofre = cofre::arquivo::existe();
    println!("  cofre     : {}", if tem_cofre { "criado" } else { "NÃO criado" });
    if !tem_cofre {
        println!("              comece por aqui: deployer cofre init");
    }

    // CHAVES — leitura pública, não precisa destravar nada.
    let chaves = deployer::sshkeys::list();
    println!("  chaves SSH: {} em ~/.ssh", chaves.len());
    if chaves.is_empty() {
        println!("              gere uma: deployer ssh gen <nome>");
        println!("              ou adote a que já tem: deployer ssh import <arquivo>");
    }

    // DNS — só diz SE há token, e só quando o cofre existe. Nunca destrava para um painel:
    // pedir a passphrase para mostrar um resumo treinaria a pessoa a digitá-la à toa.
    if tem_cofre {
        println!("  DNS       : token da Cloudflare — use `deployer dns auth --status`");
    }
    let _ = credencial::CHAVE; // a chave é conhecida; o valor nunca passa por aqui

    println!();
    println!("O QUE DÁ PARA FAZER");
    println!("  deployer ssh list          chaves gerenciadas");
    println!("  deployer vps list          servidores registrados");
    println!("  deployer dns zones         domínios na Cloudflare");
    println!("  deployer --help            tudo");

    if !desktop::arquivo_desktop(&deployer::nucleo::util::home()).exists() {
        println!();
        println!("  (este app ainda não está no seu menu de aplicativos:");
        println!("   `deployer desktop --instalar` põe o ícone lá)");
    }

    if aguardar {
        // O lançador do desktop fecha o terminal quando o processo sai. Sem esta pausa, o
        // clique no ícone seria um piscar.
        println!();
        print!("Enter para fechar… ");
        use std::io::Write;
        let _ = std::io::stdout().flush();
        let mut l = String::new();
        let _ = std::io::stdin().read_line(&mut l);
    }
    Ok(())
}

/// `deployer desktop` — põe (ou tira) o app do menu de aplicativos.
pub(crate) fn desktop_cmd(instalar: bool, remover: bool) -> Result<(), String> {
    if instalar && remover {
        return Err("`--instalar` e `--remover` são opostos — peça um de cada vez".into());
    }
    let home = deployer::nucleo::util::home();
    if remover {
        let tinha = desktop::remover(&home)?;
        println!("{}", if tinha { "removido do menu." } else { "não estava no menu." });
        return Ok(());
    }
    // O caminho do PRÓPRIO executável: gravar um adivinhado faria o ícone abrir outra coisa
    // (ou nada) em quem instalou fora do lugar padrão.
    let bin = std::env::current_exe()
        .map_err(|e| format!("não descobri o caminho do próprio binário: {e}"))?;
    let p = desktop::instalar(&home, &bin)?;
    println!("instalado: {}", p.display());
    println!("O app agora aparece na lista de programas do sistema.");
    Ok(())
}
