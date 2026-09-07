//! NÚCLEO — a integração com o ambiente gráfico: ícone e entrada no menu de aplicativos.
//!
//! **O quê:** grava o `.desktop` e instala os ícones, para o app **aparecer na lista de
//! programas** e abrir sozinho — sem passar pelo schematize.
//!
//! **Onde:** `deployer desktop --instalar` / `--remover`, e o `install.sh` ao instalar o app.
//!
//! ## Por que o app instala a PRÓPRIA integração
//!
//! Se quem gravasse o `.desktop` do Deployer fosse o instalador do schematize, o Deployer
//! deixaria de ser instalável sozinho — e essa autonomia é a razão do ADR-0010. Quem instala
//! o binário direto do release, ou compila do fonte, tem de conseguir o ícone também.
//!
//! ## `Terminal=true`, e por que isso não é preguiça
//!
//! Este app é uma CLI. Um `.desktop` com `Terminal=false` abriria um processo sem janela que
//! termina no mesmo instante — o clique não faria **nada**, que é pior que não ter ícone.
//! Com `Terminal=true`, o ambiente gráfico abre um terminal e roda o comando ali.
//!
//! E o comando é `painel --aguardar`: sem o `--aguardar`, o terminal fecharia junto com o
//! processo e a pessoa veria um piscar. §37.48 — o software se adapta ao clique que a pessoa
//! deu, em vez de exigir que ela saiba que isto é uma CLI.

use std::path::{Path, PathBuf};

/// Nome do arquivo `.desktop` e do ícone. Um só lugar: se divergirem, o menu mostra um
/// quadrado cinza e ninguém liga a causa ao nome.
pub const ID: &str = "schematize-deployer";

/// **O quê:** o conteúdo do `.desktop`, exatamente como vai para o disco.
///
/// **Onde:** [`instalar`] e o teste. Função PURA — o formato é afirmável sem escrever em
/// `~/.local/share`.
///
/// **`Exec` com caminho ABSOLUTO:** o lançador do desktop dá **PATH mínimo** — não lê
/// `~/.bashrc` nem `~/.profile` —, então `Exec=deployer` falharia em achar o binário em
/// `~/.cargo/bin`. É a mesma armadilha que já quebrou o lançador do schematize.
pub fn render(bin: &Path, icone: &Path) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=schematize Deployer\n\
         GenericName=Chaves SSH, VPS e cofre\n\
         Comment=Opera servidor com a credencial fora do alcance do agente\n\
         Exec={} painel --aguardar\n\
         Icon={}\n\
         Terminal=true\n\
         Categories=Development;System;Security;\n\
         Keywords=ssh;vps;deploy;dns;cloudflare;cofre;chave;\n\
         StartupNotify=false\n",
        bin.display(),
        icone.display()
    )
}

/// **O quê:** onde os `.desktop` do usuário moram.
pub fn dir_apps(home: &Path) -> PathBuf {
    home.join(".local/share/applications")
}

/// **O quê:** o caminho do `.desktop` deste app.
pub fn arquivo_desktop(home: &Path) -> PathBuf {
    dir_apps(home).join(format!("{ID}.desktop"))
}

/// **O quê:** instala ícone + `.desktop`, e devolve o caminho do `.desktop`.
///
/// **Onde:** `deployer desktop --instalar` e o `install.sh`.
///
/// **`bin` é o caminho do próprio executável**, resolvido pelo chamador — gravar um caminho
/// adivinhado faria o ícone abrir outra coisa (ou nada) na máquina de quem instalou fora do
/// lugar padrão.
pub fn instalar(home: &Path, bin: &Path) -> Result<PathBuf, String> {
    // O ícone primeiro: um `.desktop` apontando para ícone inexistente vira quadrado cinza,
    // e a pessoa conclui que o app não instalou direito.
    let icone =
        super::icone::install_all(home).map_err(|e| format!("não consegui gerar o ícone: {e}"))?;
    let dir = dir_apps(home);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("não consegui criar {}: {e}", dir.display()))?;
    let p = arquivo_desktop(home);
    std::fs::write(&p, render(bin, &icone))
        .map_err(|e| format!("não consegui gravar {}: {e}", p.display()))?;
    // Best-effort: alguns ambientes só releem o menu depois disto. Falhar aqui não invalida
    // a instalação — no pior caso o ícone aparece no próximo login.
    let _ = std::process::Command::new("update-desktop-database").arg(&dir).status();
    Ok(p)
}

/// **O quê:** remove o `.desktop` deste app. Devolve `true` se havia um.
///
/// **Onde:** `deployer desktop --remover`. Os ícones ficam: são inertes, e apagá-los sem
/// necessidade mexeria numa árvore (`hicolor`) compartilhada com outros apps.
pub fn remover(home: &Path) -> Result<bool, String> {
    let p = arquivo_desktop(home);
    if !p.exists() {
        return Ok(false);
    }
    std::fs::remove_file(&p).map_err(|e| format!("não consegui remover {}: {e}", p.display()))?;
    let _ = std::process::Command::new("update-desktop-database").arg(dir_apps(home)).status();
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **O `Exec` tem de ser ABSOLUTO.** O lançador do desktop dá PATH mínimo — não lê
    /// `~/.bashrc` nem `~/.profile` —, então um `Exec=deployer` não acharia o binário em
    /// `~/.cargo/bin`. É a armadilha que já quebrou o lançador do schematize.
    #[test]
    fn o_exec_e_absoluto() {
        let t = render(Path::new("/home/u/.cargo/bin/deployer"), Path::new("/i/x.png"));
        let exec = t.lines().find(|l| l.starts_with("Exec=")).unwrap();
        assert!(exec.contains("/home/u/.cargo/bin/deployer"), "{exec}");
        assert!(!exec.starts_with("Exec=deployer"), "relativo depende do PATH do DE: {exec}");
    }

    /// **`Terminal=true` e `--aguardar`, juntos.** Sem o primeiro, o clique não abre janela
    /// nenhuma; sem o segundo, a janela fecha no mesmo instante. Um sem o outro é um ícone
    /// que parece quebrado.
    #[test]
    fn abre_em_terminal_e_nao_fecha_na_cara() {
        let t = render(Path::new("/b/deployer"), Path::new("/i/x.png"));
        assert!(t.contains("Terminal=true"), "CLI sem terminal não mostra nada");
        assert!(t.contains("--aguardar"), "sem isto o terminal fecha antes de a pessoa ler");
    }

    /// O `.desktop` tem os campos que o menu exige — sem eles a entrada é ignorada em
    /// silêncio, que é o modo de falha mais difícil de diagnosticar.
    #[test]
    fn tem_os_campos_obrigatorios() {
        let t = render(Path::new("/b/deployer"), Path::new("/i/x.png"));
        for campo in ["[Desktop Entry]", "Type=Application", "Name=", "Exec=", "Icon="] {
            assert!(t.contains(campo), "faltou {campo}:\n{t}");
        }
    }

    /// Instalar e remover deixa o diretório como estava.
    #[test]
    fn instalar_e_remover_volta_ao_estado_anterior() {
        let h = std::env::temp_dir().join(format!("dep-desk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&h);
        std::fs::create_dir_all(&h).unwrap();

        let p = instalar(&h, Path::new("/b/deployer")).unwrap();
        assert!(p.exists());
        let txt = std::fs::read_to_string(&p).unwrap();
        assert!(txt.contains("schematize Deployer"));
        // O ícone tem de existir: `.desktop` apontando para ícone ausente vira quadrado cinza.
        assert!(
            h.join(".local/share/icons/hicolor/256x256/apps/schematize-deployer.png").exists(),
            "o ícone não foi gerado — o menu mostraria um quadrado cinza"
        );

        assert!(remover(&h).unwrap());
        assert!(!p.exists());
        assert!(!remover(&h).unwrap(), "remover o que não existe é false, não erro");
        let _ = std::fs::remove_dir_all(&h);
    }
}
