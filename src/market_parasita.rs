//! **market_parasita** — todo binário do ecossistema garante, ao iniciar, que o
//! `schematize-market` e o `schematize-market-gui` existem em `$HOME/.cargo/bin`.
//!
//! **O quê:** o "parasita" do contrato (2026-10-13): o gestor de atualizações viaja com qualquer
//! programa da casa que a pessoa instalar. Caminho rápido = 2 `stat`; só quando falta algo baixa
//! (uma vez por máquina) do release `latest` do `schematize_market_rs`.
//!
//! **Onde:** [`garantir`], chamada no início do `main` de cada binário (CLI e janela), depois do
//! parse de args e antes de qualquer janela. Não roda em `--version`/`--help`/`desktop`, nem sob
//! `SCHEMATIZE_DELEGADO_AO_MARKET=1`, `SCHEMATIZE_SEM_MARKET=1`, `CI` ou `cfg(test)`.
//!
//! **Piso 10/4:** nunca derruba o app e nunca engole erro — toda falha vira uma linha no stderr
//! e o app segue. As duas linhas ficam em pt fixas (são logs, não prosa de interface).

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

/// Os dois binários que o parasita garante, na ordem em que são instalados.
pub const NOMES: [&str; 2] = ["schematize-market", "schematize-market-gui"];

/// Idade a partir da qual um lock é considerado órfão (processo morto no meio da instalação).
const LOCK_ORFAO: Duration = Duration::from_secs(10 * 60);

/// Teto de espera do `--version` do binário baixado.
const VERSAO_TIMEOUT: Duration = Duration::from_secs(10);

/// Base dos assets do release `latest`.
const BASE_URL: &str =
    "https://github.com/schematizeme/schematize_market_rs/releases/latest/download";

/// Comando de recuperação mostrado na linha de falha.
const COMANDO_MANUAL: &str =
    "curl -fsSL https://raw.githubusercontent.com/schematizeme/schematize-cli/main/install.sh | bash";

/// Assinatura do downloader injetável: `(url, destino) -> Result`.
pub type Baixador<'a> = &'a dyn Fn(&str, &Path) -> Result<(), String>;

/// Resultado de uma tentativa de garantir os binários.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Resultado {
    /// Binários instalados nesta chamada.
    pub instalados: Vec<&'static str>,
    /// Binários que falharam, com a causa.
    pub falhas: Vec<(&'static str, String)>,
    /// Avisos que não são falha de binário (ex.: lock que não saiu).
    pub avisos: Vec<String>,
    /// Outro processo já cuida da instalação (lock recente).
    pub outro_cuida: bool,
}

/// **O quê:** nome do arquivo do binário na plataforma (`.exe` no Windows).
///
/// **Onde:** [`o_que_falta`] e a instalação.
pub fn nome_do_arquivo(nome: &str, os: &str) -> String {
    if os == "windows" {
        format!("{nome}.exe")
    } else {
        nome.to_string()
    }
}

/// **O quê:** quais dos dois binários não existem em `pasta` (decisão pura, 2 `stat`).
///
/// **Onde:** início de [`garantir_com`] — vazio = caminho rápido.
pub fn o_que_falta(pasta: &Path) -> Vec<&'static str> {
    let os = std::env::consts::OS;
    NOMES.iter().copied().filter(|n| !pasta.join(nome_do_arquivo(n, os)).is_file()).collect()
}

/// **O quê:** URL do asset de `nome` para `os`/`arch`, ou `None` se a plataforma não tem asset.
///
/// **Onde:** instalação de cada binário. Publicados: linux-x86_64, macos-x86_64, macos-arm64,
/// windows-x86_64.
pub fn url_do_asset(nome: &str, os: &str, arch: &str) -> Option<String> {
    let publicado = matches!(
        (os, arch),
        ("linux", "x86_64") | ("macos", "x86_64" | "arm64") | ("windows", "x86_64")
    );
    if !publicado {
        return None;
    }
    let ext = if os == "windows" { ".exe" } else { "" };
    Some(format!("{BASE_URL}/{nome}-{os}-{arch}{ext}"))
}

/// **O quê:** `(os, arch)` desta máquina na nomenclatura dos assets (`aarch64` vira `arm64`).
///
/// **Onde:** [`garantir`].
pub fn plataforma_atual() -> (&'static str, &'static str) {
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        outro => outro,
    };
    (std::env::consts::OS, arch)
}

/// **O quê:** o parasita deve ficar quieto? (`SCHEMATIZE_SEM_MARKET=1`, `CI` definida, ou
/// chamado pelo market com `SCHEMATIZE_DELEGADO_AO_MARKET=1`).
///
/// **Onde:** [`garantir_com`]; `get` é injetável para teste sem tocar o ambiente real.
pub fn deve_ficar_quieto(get: &dyn Fn(&str) -> Option<String>) -> bool {
    let um = |k: &str| get(k).as_deref() == Some("1");
    um("SCHEMATIZE_SEM_MARKET") || um("SCHEMATIZE_DELEGADO_AO_MARKET") || get("CI").is_some()
}

/// Resultado de tentar pegar o lock.
enum Lock {
    Meu,
    Ocupado,
}

/// **O quê:** pega o lock com `create_new`; órfão (>10 min) é removido e retomado.
///
/// **Onde:** [`garantir_com`], antes de baixar qualquer coisa.
fn pegar_lock(lock: &Path) -> Result<Lock, String> {
    if let Some(pai) = lock.parent() {
        fs::create_dir_all(pai).map_err(|e| format!("criar {}: {e}", pai.display()))?;
    }
    for _ in 0..2 {
        match fs::OpenOptions::new().write(true).create_new(true).open(lock) {
            Ok(_) => return Ok(Lock::Meu),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                let idade = fs::metadata(lock)
                    .and_then(|m| m.modified())
                    .map(|t| SystemTime::now().duration_since(t).unwrap_or(Duration::ZERO));
                match idade {
                    Ok(i) if i < LOCK_ORFAO => return Ok(Lock::Ocupado),
                    Ok(_) => fs::remove_file(lock)
                        .or_else(|e| if e.kind() == ErrorKind::NotFound { Ok(()) } else { Err(e) })
                        .map_err(|e| format!("remover lock órfão: {e}"))?,
                    Err(e) if e.kind() == ErrorKind::NotFound => {}
                    Err(e) => return Err(format!("ler lock: {e}")),
                }
            }
            Err(e) => return Err(format!("criar lock {}: {e}", lock.display())),
        }
    }
    Ok(Lock::Ocupado)
}

/// **O quê:** baixa `url` para `destino` com `curl -fsSL --max-time 30`.
///
/// **Onde:** downloader real, passado por [`garantir`] a [`garantir_com`].
pub fn baixar_com_curl(url: &str, destino: &Path) -> Result<(), String> {
    let saida = Command::new("curl")
        .args(["-fsSL", "--max-time", "30", "-o"])
        .arg(destino)
        .arg(url)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("curl indisponível: {e}"))?;
    if saida.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&saida.stderr);
    Err(format!("curl falhou ({}): {}", saida.status, err.trim()))
}

/// **O quê:** repete uma execução enquanto o kernel responde `ETXTBSY` ("Text file busy", errno 26).
///
/// **Onde:** a validação `--version` do binário recém-gravado (`<dst>.novo`), em [`executa_com_sucesso`].
///
/// **Por quê:** com outra thread fazendo `fork` em paralelo, o filho herda por instantes o
/// descritor de escrita do arquivo que acabou de ser gravado e o `exec` falha com 26. É transitório:
/// só em unix e só nesse errno repete (até 40 vezes, backoff de 5 a 25 ms); qualquer outro erro
/// sai na hora, com a causa.
fn repetir_em_etxtbsy<T>(mut f: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    const ETXTBSY: i32 = 26;
    let mut tentativa: u64 = 0;
    loop {
        match f() {
            Err(e) if cfg!(unix) && e.raw_os_error() == Some(ETXTBSY) && tentativa < 40 => {
                tentativa += 1;
                std::thread::sleep(std::time::Duration::from_millis(5 * tentativa.min(5)));
            }
            r => return r,
        }
    }
}

/// **O quê:** o binário baixado executa? Roda `<bin> --version` e exige saída 0 (teto 10 s).
///
/// **Onde:** [`instalar_um`], antes do `rename` para o destino.
fn executa_com_sucesso(bin: &Path) -> Result<(), String> {
    let mut filho = repetir_em_etxtbsy(|| {
        Command::new(bin)
            .arg("--version")
            .env("SCHEMATIZE_SEM_MARKET", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    })
    .map_err(|e| format!("o binário baixado não executa: {e}"))?;
    let inicio = Instant::now();
    loop {
        match filho.try_wait() {
            Ok(Some(st)) if st.success() => return Ok(()),
            Ok(Some(st)) => return Err(format!("`--version` saiu com {st}")),
            Ok(None) if inicio.elapsed() > VERSAO_TIMEOUT => {
                let _ = filho.kill();
                let _ = filho.wait();
                return Err("`--version` não terminou em 10 s".into());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(format!("esperar `--version`: {e}")),
        }
    }
}

/// **O quê:** `chmod +x` (unix); no-op nas outras plataformas.
///
/// **Onde:** [`instalar_um`].
#[cfg(unix)]
fn marcar_executavel(p: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(0o755)).map_err(|e| format!("chmod: {e}"))
}
#[cfg(not(unix))]
fn marcar_executavel(_: &Path) -> Result<(), String> {
    Ok(())
}

/// **O quê:** baixa → `chmod +x` → `--version` → `rename` de UM binário; qualquer falha remove
/// o `.novo` e deixa o destino intocado.
///
/// **Onde:** laço de [`garantir_com`].
fn instalar_um(
    nome: &str,
    pasta: &Path,
    (os, arch): (&str, &str),
    baixar: Baixador<'_>,
) -> Result<(), String> {
    let url = url_do_asset(nome, os, arch)
        .ok_or_else(|| format!("sem binário publicado para {os}-{arch}"))?;
    let dst = pasta.join(nome_do_arquivo(nome, os));
    let mut novo = dst.clone().into_os_string();
    novo.push(".novo");
    let novo = PathBuf::from(novo);
    let r = baixar(&url, &novo)
        .and_then(|()| marcar_executavel(&novo))
        .and_then(|()| executa_com_sucesso(&novo))
        .and_then(|()| fs::rename(&novo, &dst).map_err(|e| format!("rename: {e}")));
    match r {
        Ok(()) => Ok(()),
        Err(causa) => match fs::remove_file(&novo) {
            Ok(()) => Err(causa),
            Err(e) if e.kind() == ErrorKind::NotFound => Err(causa),
            Err(e) => Err(format!("{causa}; e não removi {}: {e}", novo.display())),
        },
    }
}

/// **O quê:** o miolo testável — decide, trava, instala o que falta e destrava.
///
/// **Onde:** [`garantir`] (com o ambiente real) e os testes (com tudo injetado).
pub fn garantir_com(
    get: &dyn Fn(&str) -> Option<String>,
    pasta: &Path,
    lock: &Path,
    plataforma: (&str, &str),
    baixar: Baixador<'_>,
) -> Resultado {
    let mut res = Resultado::default();
    if deve_ficar_quieto(get) {
        return res;
    }
    let falta = o_que_falta(pasta);
    if falta.is_empty() {
        return res;
    }
    match pegar_lock(lock) {
        Ok(Lock::Meu) => {}
        Ok(Lock::Ocupado) => {
            res.outro_cuida = true;
            return res;
        }
        Err(causa) => {
            res.falhas.push((falta[0], causa));
            return res;
        }
    }
    if let Err(e) = fs::create_dir_all(pasta) {
        res.falhas.push((falta[0], format!("criar {}: {e}", pasta.display())));
    } else {
        for nome in falta {
            match instalar_um(nome, pasta, plataforma, baixar) {
                Ok(()) => res.instalados.push(nome),
                Err(causa) => res.falhas.push((nome, causa)),
            }
        }
    }
    match fs::remove_file(lock) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => res.avisos.push(format!("não removi o lock {}: {e}", lock.display())),
    }
    res
}

/// **O quê:** as linhas de stderr que o contrato manda (sucesso, uma por falha, avisos).
///
/// **Onde:** [`garantir`]; pura para ser testada.
pub fn linhas(res: &Resultado, pasta: &Path) -> Vec<String> {
    let mut v = Vec::new();
    if !res.instalados.is_empty() {
        v.push(format!(
            "schematize: instalei o gestor de atualizações ({}) em {}",
            res.instalados.join(", "),
            pasta.display()
        ));
    }
    for (nome, causa) in &res.falhas {
        v.push(format!(
            "schematize: não consegui instalar o {nome} ({causa}) — o app segue normal; rode: {COMANDO_MANUAL}"
        ));
    }
    for a in &res.avisos {
        v.push(format!("schematize: aviso: {a}"));
    }
    v
}

/// **O quê:** garante os dois binários do market em `$HOME/.cargo/bin` e imprime o resultado.
///
/// **Onde:** primeira coisa do `main` de cada binário, depois do parse de args (e, nas janelas,
/// depois do `--version` e antes de abrir a janela). Em `cfg(test)` não faz nada.
pub fn garantir() {
    if cfg!(test) {
        return;
    }
    let get = |k: &str| std::env::var(k).ok();
    if deve_ficar_quieto(&get) {
        return;
    }
    let home = get("HOME").or_else(|| get("USERPROFILE")).filter(|h| !h.is_empty());
    let Some(home) = home else {
        eprintln!(
            "schematize: não consegui instalar o schematize-market (HOME indefinida) — o app segue normal; rode: {COMANDO_MANUAL}"
        );
        return;
    };
    let home = PathBuf::from(home);
    let pasta = home.join(".cargo").join("bin");
    let lock = home.join(".schematize").join("run").join("market-bootstrap.lock");
    let res = garantir_com(&get, &pasta, &lock, plataforma_atual(), &baixar_com_curl);
    for l in linhas(&res, &pasta) {
        eprintln!("{l}");
    }
}

#[cfg(test)]
mod testes {
    use super::*;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const LINUX: (&str, &str) = ("linux", "x86_64");

    /// Diretório novo e vazio dentro de `target/` do próprio repo (nada fora do workspace).
    fn tmp(nome: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join(format!(
            "tmp-market-parasita-{nome}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).expect("criar tmp");
        d
    }

    fn sem_env(_: &str) -> Option<String> {
        None
    }

    /// Downloader falso que grava um script que sai com `codigo`.
    fn baixa_script(codigo: i32) -> impl Fn(&str, &Path) -> Result<(), String> {
        move |_, dst| {
            fs::write(dst, format!("#!/bin/sh\nexit {codigo}\n")).map_err(|e| e.to_string())
        }
    }

    fn toca(pasta: &Path, nome: &str) {
        fs::create_dir_all(pasta).expect("mkdir");
        fs::write(pasta.join(nome), b"x").expect("write");
    }

    #[test]
    fn falta_os_dois_quando_a_pasta_esta_vazia() {
        let d = tmp("falta2");
        assert_eq!(o_que_falta(&d), vec!["schematize-market", "schematize-market-gui"]);
    }

    #[test]
    fn falta_so_um_e_nenhum() {
        let d = tmp("falta1");
        let os = std::env::consts::OS;
        toca(&d, &nome_do_arquivo("schematize-market", os));
        assert_eq!(o_que_falta(&d), vec!["schematize-market-gui"]);
        toca(&d, &nome_do_arquivo("schematize-market-gui", os));
        assert!(o_que_falta(&d).is_empty());
    }

    #[test]
    fn url_dos_quatro_alvos_publicados() {
        let b = "https://github.com/schematizeme/schematize_market_rs/releases/latest/download";
        let n = "schematize-market";
        assert_eq!(url_do_asset(n, "linux", "x86_64"), Some(format!("{b}/{n}-linux-x86_64")));
        assert_eq!(url_do_asset(n, "macos", "x86_64"), Some(format!("{b}/{n}-macos-x86_64")));
        assert_eq!(url_do_asset(n, "macos", "arm64"), Some(format!("{b}/{n}-macos-arm64")));
        assert_eq!(
            url_do_asset("schematize-market-gui", "windows", "x86_64"),
            Some(format!("{b}/schematize-market-gui-windows-x86_64.exe"))
        );
    }

    #[test]
    fn linux_arm64_nao_tem_asset() {
        assert_eq!(url_do_asset("schematize-market", "linux", "arm64"), None);
    }

    #[test]
    #[cfg(unix)]
    fn sucesso_renomeia_e_nao_deixa_novo() {
        let d = tmp("ok");
        let lock = d.join("run").join("l.lock");
        let pasta = d.join("bin");
        let r = garantir_com(&sem_env, &pasta, &lock, LINUX, &baixa_script(0));
        assert_eq!(r.instalados, vec!["schematize-market", "schematize-market-gui"]);
        assert!(r.falhas.is_empty(), "{:?}", r.falhas);
        assert!(o_que_falta(&pasta).is_empty());
        let sobras: Vec<_> = fs::read_dir(&pasta)
            .expect("ls")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".novo"))
            .collect();
        assert!(sobras.is_empty(), "sobrou .novo");
        assert!(!lock.exists(), "o lock tem de sair");
    }

    #[test]
    #[cfg(unix)]
    fn binario_que_nao_executa_remove_novo_e_nao_toca_o_destino() {
        let d = tmp("ruim");
        let pasta = d.join("bin");
        let lock = d.join("l.lock");
        let r = garantir_com(&sem_env, &pasta, &lock, LINUX, &baixa_script(3));
        assert!(r.instalados.is_empty());
        assert_eq!(r.falhas.len(), 2);
        assert!(r.falhas[0].1.contains("--version"), "{}", r.falhas[0].1);
        assert!(!pasta.join("schematize-market").exists(), "destino não pode nascer");
        assert!(!pasta.join("schematize-market.novo").exists(), ".novo tem de sumir");
    }

    #[test]
    fn falha_do_downloader_vira_falha_e_nao_panico() {
        let d = tmp("net");
        let baixa = |_: &str, _: &Path| Err("sem rede".to_string());
        let r = garantir_com(&sem_env, &d.join("bin"), &d.join("l.lock"), LINUX, &baixa);
        assert_eq!(r.falhas.len(), 2);
        let l = linhas(&r, &d);
        assert!(l[0].contains("não consegui instalar o schematize-market (sem rede)"), "{l:?}");
        assert!(l[0].contains("install.sh | bash"));
    }

    #[test]
    fn lock_recente_nao_faz_nada() {
        let d = tmp("lock");
        let lock = d.join("l.lock");
        fs::write(&lock, b"").expect("lock");
        let chamadas = Cell::new(0);
        let baixa = |_: &str, _: &Path| {
            chamadas.set(chamadas.get() + 1);
            Ok(())
        };
        let r = garantir_com(&sem_env, &d.join("bin"), &lock, LINUX, &baixa);
        assert!(r.outro_cuida);
        assert_eq!(chamadas.get(), 0);
        assert!(lock.exists(), "lock alheio não é removido");
    }

    #[test]
    #[cfg(unix)]
    fn lock_orfao_e_retomado() {
        let d = tmp("orfao");
        let lock = d.join("l.lock");
        let f = fs::File::create(&lock).expect("lock");
        f.set_modified(SystemTime::now() - Duration::from_secs(11 * 60)).expect("mtime");
        drop(f);
        let r = garantir_com(&sem_env, &d.join("bin"), &lock, LINUX, &baixa_script(0));
        assert!(!r.outro_cuida);
        assert_eq!(r.instalados.len(), 2);
    }

    #[test]
    fn opt_outs_nao_chamam_o_downloader() {
        for (k, v) in
            [("SCHEMATIZE_SEM_MARKET", "1"), ("SCHEMATIZE_DELEGADO_AO_MARKET", "1"), ("CI", "true")]
        {
            let d = tmp("optout");
            let chamadas = Cell::new(0);
            let baixa = |_: &str, _: &Path| {
                chamadas.set(chamadas.get() + 1);
                Ok(())
            };
            let get = |q: &str| (q == k).then(|| v.to_string());
            let r = garantir_com(&get, &d.join("bin"), &d.join("l.lock"), LINUX, &baixa);
            assert_eq!(chamadas.get(), 0, "{k} não calou o parasita");
            assert_eq!(r, Resultado::default());
        }
    }

    #[test]
    fn caminho_rapido_nao_baixa_nem_trava() {
        let d = tmp("rapido");
        let os = std::env::consts::OS;
        for n in NOMES {
            toca(&d.join("bin"), &nome_do_arquivo(n, os));
        }
        let baixa = |_: &str, _: &Path| Err("não devia baixar".to_string());
        let lock = d.join("run").join("l.lock");
        let r = garantir_com(&sem_env, &d.join("bin"), &lock, (os, "x86_64"), &baixa);
        assert_eq!(r, Resultado::default());
        assert!(!lock.exists());
    }

    #[test]
    fn linhas_de_sucesso_seguem_o_contrato() {
        let r = Resultado { instalados: vec!["schematize-market"], ..Resultado::default() };
        assert_eq!(
            linhas(&r, Path::new("/h/.cargo/bin")),
            vec!["schematize: instalei o gestor de atualizações (schematize-market) em /h/.cargo/bin"]
        );
    }
}
