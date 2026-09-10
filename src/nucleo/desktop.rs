//! NÚCLEO — a integração com o ambiente gráfico: ícone e entrada no menu de aplicativos.
//!
//! **O quê:** grava o `.desktop` e instala os ícones, para o app **aparecer na lista de
//! programas** e abrir sozinho — sem passar pelo schematize.
//!
//! **Onde:** `deployer desktop --install` / `--remover`, e o `install.sh` ao instalar o app.
//!
//! ## Por que o app instala a PRÓPRIA integração
//!
//! Se quem gravasse o `.desktop` do Deployer fosse o instalador do schematize, o Deployer
//! deixaria de ser instalável sozinho — e essa autonomia é a razão do ADR-0010. Quem instala
//! o binário direto do release, ou compila do fonte, tem de conseguir o ícone também.
//!
//! ## O ícone tem DUAS formas, e escolhe a melhor disponível
//!
//! **Com a janela instalada** (`schematize-deployer-gui`): `Exec=` aponta para ela e
//! `Terminal=false`. É o caso normal. O ícone executava `panel --wait` — abria um terminal,
//! imprimia um painel e esperava um Enter. **Ícone que só imprime é relatório com atalho, não
//! aplicativo.**
//!
//! **Sem a janela:** cai em `panel --wait` com `Terminal=true`, exatamente o que havia antes.
//! Um `.desktop` com `Terminal=false` apontando para uma CLI abriria um processo sem janela
//! que termina no mesmo instante — o clique não faria **nada**, que é pior que não ter ícone.
//! O `--wait` é o que impede o terminal de fechar junto com o processo e a pessoa ver um
//! piscar. §37.48 — o software se adapta ao clique que a pessoa deu.
//!
//! **Por que a escolha é feita ao GRAVAR, e não ao clicar.** Um `Exec=` que decidisse na hora
//! precisaria de `Terminal=` fixo, e nenhum dos dois valores serve aos dois caminhos: com
//! `false` o fallback em terminal não teria terminal; com `true` a janela abriria com um
//! terminal preto pendurado atrás. Quem grava sabe o que existe na máquina, e regrava a cada
//! `desktop --install`.

use std::path::{Path, PathBuf};

/// Nome do arquivo `.desktop` e do ícone. Um só lugar: se divergirem, o menu mostra um
/// quadrado cinza e ninguém liga a causa ao nome.
pub const ID: &str = "schematize-deployer";

/// Nome do executável da JANELA deste app.
///
/// Constante e não literal espalhado: nome de binário que não bate com o dono já deixou o
/// update de um app da casa morto por um release inteiro, e **nada dá erro** nesse caso.
pub const GUI_BIN: &str = "schematize-deployer-gui";

/// **O quê:** o caminho ABSOLUTO da janela deste app, ou `None` se ela não estiver instalada.
///
/// **Onde:** [`instalar`], para decidir entre as duas formas do `.desktop`.
///
/// **A ordem importa.** Primeiro ao lado do próprio binário: é onde o `install.sh` põe os
/// dois, e é o par que se atualiza junto. Só depois o `$PATH` e os fallbacks.
pub fn resolver_gui(bin_do_app: &Path) -> Option<PathBuf> {
    let nomes: &[&str] =
        if cfg!(windows) { &["schematize-deployer-gui.exe", GUI_BIN] } else { &[GUI_BIN] };
    if let Some(dir) = bin_do_app.parent() {
        for n in nomes {
            let c = dir.join(n);
            if c.is_file() {
                return Some(c);
            }
        }
    }
    super::bin::resolve_bin(GUI_BIN)
}

/// **O quê:** o conteúdo do `.desktop`, exatamente como vai para o disco. `gui` é o caminho da
/// janela quando ela existe; `None` produz a forma de terminal.
///
/// **Onde:** [`instalar_com_gui`] e os testes. Função PURA — as duas formas são afirmáveis sem
/// escrever em `~/.local/share` e sem ter janela nenhuma instalada.
///
/// **`Exec` com caminho ABSOLUTO nas duas formas:** o lançador do desktop dá **PATH mínimo** —
/// não lê `~/.bashrc` nem `~/.profile` —, então `Exec=schematize-deployer` falharia em achar o
/// binário em `~/.cargo/bin`. É a armadilha que já quebrou o lançador do schematize.
pub fn render(bin: &Path, icone: &Path, gui: Option<&Path>) -> String {
    // A janela não recebe `--wait`: ela fica aberta porque tem event loop. A CLI recebe, senão
    // o terminal fecha na cara de quem clicou.
    let (exec, terminal) = match gui {
        Some(g) => (format!("{}", g.display()), "false"),
        None => (format!("{} panel --wait", bin.display()), "true"),
    };
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=schematize Deployer\n\
         GenericName=Chaves SSH, hosts e cofre\n\
         Comment=Acesso remoto mediado: chaves, servidores e segredo em repouso\n\
         Exec={exec}\n\
         Icon={}\n\
         Terminal={terminal}\n\
         Categories=Development;System;Network;\n\
         Keywords=deploy;ssh;vps;servidor;server;chave;key;cofre;vault;\n\
         StartupNotify=false\n",
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
/// **Onde:** `deployer desktop --install` e o `install.sh`.
///
/// **`bin` é o caminho do próprio executável**, resolvido pelo chamador — gravar um caminho
/// adivinhado faria o ícone abrir outra coisa (ou nada) na máquina de quem instalou fora do
/// lugar padrão.
pub fn instalar(home: &Path, bin: &Path) -> Result<PathBuf, String> {
    instalar_com_gui(home, bin, resolver_gui(bin).as_deref())
}

/// **O quê:** o mesmo que [`instalar`], com a janela DADA em vez de procurada.
///
/// **Onde:** [`instalar`] em produção, e os testes — que precisam das duas formas sem depender
/// do que está instalado na máquina de quem roda a suíte. Teste que muda de resultado com o
/// ambiente não prova nem uma coisa nem outra.
pub fn instalar_com_gui(home: &Path, bin: &Path, gui: Option<&Path>) -> Result<PathBuf, String> {
    // O ícone primeiro: um `.desktop` apontando para ícone inexistente vira quadrado cinza,
    // e a pessoa conclui que o app não instalou direito.
    let icone =
        super::icone::install_all(home).map_err(|e| format!("não consegui gerar o ícone: {e}"))?;
    let dir = dir_apps(home);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("não consegui criar {}: {e}", dir.display()))?;
    let p = arquivo_desktop(home);
    std::fs::write(&p, render(bin, &icone, gui))
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

    /// A linha `Exec=` de um render, sem o prefixo.
    fn exec_de(t: &str) -> String {
        t.lines().find(|l| l.starts_with("Exec=")).expect("sem Exec= a entrada é ignorada")[5..]
            .to_string()
    }

    /// **O `Exec` tem de ser ABSOLUTO — nas DUAS formas.** O lançador do desktop dá PATH
    /// mínimo (não lê `~/.bashrc` nem `~/.profile`), então `Exec=schematize-deployer` não
    /// acharia o binário em `~/.cargo/bin`. É a armadilha que já quebrou o lançador do
    /// schematize, e ela vale igual para o caminho da janela.
    #[test]
    fn o_exec_e_absoluto_com_e_sem_janela() {
        let bin = Path::new("/home/u/.cargo/bin/schematize-deployer");
        let gui = Path::new("/home/u/.cargo/bin/schematize-deployer-gui");

        let sem = exec_de(&render(bin, Path::new("/i/x.png"), None));
        assert!(sem.starts_with("/home/u/.cargo/bin/schematize-deployer "), "{sem}");

        let com = exec_de(&render(bin, Path::new("/i/x.png"), Some(gui)));
        assert_eq!(com, "/home/u/.cargo/bin/schematize-deployer-gui", "{com}");
        assert!(!com.starts_with("schematize"), "relativo depende do PATH do DE: {com}");
    }

    /// **A JANELA é o caminho normal.** O ícone executava `panel --wait`: abria um terminal,
    /// imprimia um painel e esperava um Enter. Ícone que só imprime é relatório com atalho,
    /// não aplicativo. Com a janela instalada, `Terminal=false` — `true` aqui deixaria um
    /// terminal preto pendurado atrás.
    #[test]
    fn com_a_janela_instalada_o_icone_abre_a_janela() {
        let t = render(
            Path::new("/b/schematize-deployer"),
            Path::new("/i/x.png"),
            Some(Path::new("/b/schematize-deployer-gui")),
        );
        assert!(t.contains("Terminal=false"), "janela com Terminal=true abre terminal atrás");
        let exec = exec_de(&t);
        assert!(exec.ends_with("schematize-deployer-gui"), "{exec}");
        assert!(!exec.contains("panel"), "a janela não recebe subcomando: {exec}");
        assert!(!exec.contains("--wait"), "`--wait` é da CLI, e travaria a janela: {exec}");
    }

    /// **Sem a janela o ícone NÃO fica quebrado:** cai no `panel --wait` em terminal, que é
    /// exatamente o que havia antes (§37.48).
    #[test]
    fn sem_a_janela_cai_no_terminal_e_nao_fecha_na_cara() {
        let t = render(Path::new("/b/schematize-deployer"), Path::new("/i/x.png"), None);
        assert!(t.contains("Terminal=true"), "CLI sem terminal não mostra nada");
        assert!(t.contains("--wait"), "sem isto o terminal fecha antes de a pessoa ler");
        assert!(!t.contains("-gui"), "sem janela instalada não se aponta para janela nenhuma");
    }

    /// O `.desktop` tem os campos que o menu exige — **nas duas formas**.
    #[test]
    fn tem_os_campos_obrigatorios_nas_duas_formas() {
        let gui = PathBuf::from("/b/schematize-deployer-gui");
        for g in [None, Some(gui.as_path())] {
            let t = render(Path::new("/b/schematize-deployer"), Path::new("/i/x.png"), g);
            for campo in ["[Desktop Entry]", "Type=Application", "Name=", "Exec=", "Icon="] {
                assert!(t.contains(campo), "faltou {campo} (gui={g:?}):\n{t}");
            }
            assert!(
                t.contains("Terminal=true") || t.contains("Terminal=false"),
                "Terminal= tem de ter valor"
            );
        }
    }

    /// **A janela ao lado do binário ganha do `$PATH`.** É o par que o `install.sh` põe junto
    /// e que se atualiza junto.
    #[test]
    fn resolver_gui_prefere_a_janela_irma() {
        let h = std::env::temp_dir().join(format!("dep-gui-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&h);
        std::fs::create_dir_all(&h).unwrap();
        let bin = h.join("schematize-deployer");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();

        if let Some(p) = resolver_gui(&bin) {
            assert!(p.is_file(), "só devolve o que existe: {}", p.display());
            assert_ne!(p, h.join(GUI_BIN), "a irmã não foi criada ainda");
        }

        let irma = h.join(GUI_BIN);
        std::fs::write(&irma, b"#!/bin/sh\n").unwrap();
        assert_eq!(resolver_gui(&bin).expect("a irmã está ao lado"), irma);

        let _ = std::fs::remove_dir_all(&h);
    }

    /// Instalar e remover deixa o diretório como estava — e regravar TROCA a forma.
    #[test]
    fn instalar_e_remover_volta_ao_estado_anterior() {
        let h = std::env::temp_dir().join(format!("dep-desk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&h);
        std::fs::create_dir_all(&h).unwrap();

        // SEM janela: a forma de terminal, de ponta a ponta.
        let p = instalar_com_gui(&h, Path::new("/b/schematize-deployer"), None).unwrap();
        assert!(p.exists());
        let txt = std::fs::read_to_string(&p).unwrap();
        assert!(txt.contains("schematize Deployer"));
        assert!(txt.contains("Exec=/b/schematize-deployer panel --wait"), "{txt}");
        assert!(txt.contains("Terminal=true"), "{txt}");
        // O ícone tem de existir: `.desktop` apontando para ícone ausente vira quadrado cinza.
        assert!(
            h.join(".local/share/icons/hicolor/256x256/apps/schematize-deployer.png").exists(),
            "o ícone não foi gerado — o menu mostraria um quadrado cinza"
        );

        // COM janela: regravar troca a forma.
        let gui = PathBuf::from("/b/schematize-deployer-gui");
        let p2 = instalar_com_gui(&h, Path::new("/b/schematize-deployer"), Some(&gui)).unwrap();
        assert_eq!(p2, p, "é o mesmo arquivo, regravado");
        let txt = std::fs::read_to_string(&p).unwrap();
        assert!(txt.contains("Exec=/b/schematize-deployer-gui\n"), "{txt}");
        assert!(txt.contains("Terminal=false"), "{txt}");

        assert!(remover(&h).unwrap());
        assert!(!p.exists());
        assert!(!remover(&h).unwrap(), "remover o que não existe é false, não erro");
        let _ = std::fs::remove_dir_all(&h);
    }
}
