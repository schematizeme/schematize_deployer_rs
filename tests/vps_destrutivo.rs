//! O QUE: os oito achados da rodada DESTRUTIVA, cada um fixado em regressão.
//!
//! POR QUE EXISTE: a rodada anterior de Q.A. e pentest passou 100% — e mesmo assim estes oito
//! estavam lá. Não porque os testes eram ruins, mas porque **todo teste anterior perguntava se
//! o sistema faz o que promete; nenhum tentava quebrá-lo de propósito**. Os dois piores
//! (denylist furada por reordenação de flag, e 300 MB de entrada virando 1,7 GB de RSS) só
//! aparecem quando a pergunta muda de "funciona?" para "como eu destruo isso?".
//!
//! DE ONDE VEM: nada externo. PRA ONDE VAI: só temporários, apagados no fim.

use deployer::vps::{
    self,
    politica::{avaliar, Veredito},
    registro::{Ambiente, ModoPolitica, VpsProfile},
};

fn perfil_permissivo() -> VpsProfile {
    let mut p = VpsProfile::novo("srv", "10.0.0.1", "u", "k");
    p.modo = ModoPolitica::Livre;
    p.ambiente = Ambiente::Hml;
    p
}

fn db(nome: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("schematize-destr-{nome}-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

/// **D1** — a denylist casava SUBSTRING, então bastava reordenar a flag para escapar.
#[test]
fn d1_denylist_nao_e_mais_burlavel_por_forma_de_escrita() {
    let p = perfil_permissivo();
    // Todos estes PASSAVAM antes. Nenhum é evasão sofisticada — `rm -r -f /` é gente digitando.
    let variantes = [
        "rm -r -f /",
        "rm -f -r /",
        "rm --recursive --force /",
        "rm --force --recursive /",
        "rm -R -f /",
        "rm -Rf /",
        r#"rm -rf "/""#,
        "rm -rf '/'",
        "rm -rf ~",
        "rm -rf /etc",
        "rm -rf /usr",
        "rm -rf /var",
        "sudo rm -r -f /",
        "/bin/rm -r -f /",
        "env X=1 rm -rf /",
        r#"dd if=/dev/zero of="/dev/sda""#,
        "dd if=/dev/zero of='/dev/sda'",
        "wipefs -a /dev/sda",
        "blkdiscard /dev/sda",
        "sgdisk -Z /dev/sda",
        "parted /dev/sda mklabel gpt",
        "shred -u /etc/passwd",
        "truncate -s 0 /etc/passwd",
        "chattr +i /etc",
        "setfacl -b -R /",
        "systemctl mask sshd",
        "systemctl stop ssh",
        "killall -9 sshd",
        "pkill sshd",
        "chown -R nobody /",
        "chmod -R 000 /",
        "mkfs.ext4 /dev/sda1",
        "userdel deploy",
        "passwd root",
    ];
    let mut escaparam = Vec::new();
    for c in variantes {
        if avaliar(&p, c) == Veredito::Allow {
            escaparam.push(c);
        }
    }
    assert!(escaparam.is_empty(), "escaparam da denylist: {escaparam:?}");
    assert!(variantes.len() >= 30, "a tabela precisa de >=30 variantes");
}

/// **D1-b** — o espelho: a denylist bloqueava trabalho legítimo de deploy.
///
/// `rm -rf /srv/app/build` contém `"rm -rf /"` como substring. Uma denylist que erra o perigo
/// E bloqueia o trabalho normal é o pior dos dois mundos — e é o que faz o usuário desligá-la.
#[test]
fn d1b_denylist_nao_bloqueia_deploy_legitimo() {
    let p = perfil_permissivo();
    let legitimos = [
        "rm -rf /srv/app/build",
        "rm -rf /var/cache/app/tmp",
        "rm -rf ./target",
        "rm -rf node_modules",
        "dd if=/dev/urandom of=/srv/app/seed bs=1M count=1",
        "chmod 640 /srv/app/.env",
        "chown deploy:deploy /srv/app",
        "truncate -s 0 /srv/app/log",
        "systemctl restart app",
        "systemctl status app",
        "journalctl -u app -n 100",
        "docker ps",
        "docker logs app",
        "git status",
        "df -h",
    ];
    let mut bloqueados = Vec::new();
    for c in legitimos {
        if avaliar(&p, c) != Veredito::Allow {
            bloqueados.push(format!("{c:?} -> {:?}", avaliar(&p, c)));
        }
    }
    assert!(bloqueados.is_empty(), "falso-positivo em comando legítimo: {bloqueados:?}");
}

/// **D2** — 300 MB de entrada viravam 1,7 GB de RSS, e a mensagem de erro ecoava tudo.
#[test]
fn d2_entrada_gigante_nao_derruba_nem_amplifica() {
    // O teto existe e é sóbrio. (Lido pra variável: `assert!` sobre `const` o clippy dobra
    // em tempo de compilação e acusa asserção constante.)
    let teto = deployer::mcp::MAX_LINHA;
    assert!(teto <= 4 * 1024 * 1024, "teto grande demais: {teto}");
    assert!(teto >= 64 * 1024, "teto pequeno demais pra uso legítimo: {teto}");

    // A mensagem de erro NUNCA cresce com a entrada — era amplificação de DoS.
    let enorme = "a".repeat(5 * 1024 * 1024);
    let e = vps::registro::valid_alias(&enorme).unwrap_err();
    assert!(e.len() < 600, "a mensagem de erro tem {} bytes — ecoa a entrada", e.len());
    assert!(e.contains("caracteres no total"), "a mensagem tem que dizer o tamanho real: {e}");

    let e = vps::registro::valid_host(&enorme).unwrap_err();
    assert!(e.len() < 600, "o erro de host ecoa a entrada: {} bytes", e.len());

    // `resumir` preserva o que é curto e corta o que é absurdo.
    assert_eq!(vps::registro::resumir("srv-01"), "srv-01");
    assert!(vps::registro::resumir(&enorme).len() < 300);
}

/// **D3** — `confiar()` escrevia ATRAVÉS de um symlink e destruía o alvo.
#[test]
fn d3_nao_escreve_atraves_de_symlink() {
    #[cfg(unix)]
    {
        let dir = std::env::temp_dir().join(format!("schematize-sym-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let alvo = dir.join("nao-me-toque.txt");
        std::fs::write(&alvo, "CONTEUDO ORIGINAL").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&alvo, &link).unwrap();

        let r = vps::db::escrever_sem_seguir_link(&link, b"INVASOR");
        assert!(r.is_err(), "escreveu através do link");
        assert!(r.unwrap_err().contains("link simbólico"), "o erro tem que explicar");
        assert_eq!(
            std::fs::read_to_string(&alvo).unwrap(),
            "CONTEUDO ORIGINAL",
            "o alvo foi destruído"
        );

        // E o caminho normal continua funcionando, com modo 600.
        let normal = dir.join("normal.txt");
        vps::db::escrever_sem_seguir_link(&normal, b"ok").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(&normal).unwrap().permissions().mode() & 0o777;
        assert_eq!(m, 0o600, "arquivo devia nascer 600, veio {m:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// **D4** — o script do bootstrap fazia read-modify-write sem trava.
#[test]
fn d4_bootstrap_concorrente_nao_duplica_nem_perde_chave() {
    use deployer::vps::{bootstrap::script_de_instalacao, capacidade::Fronteira, verbos::Verbo};
    let home = std::env::temp_dir().join(format!("schematize-conc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    let humana = "ssh-ed25519 AAAAHUMANA tom@notebook";
    let ci = "ssh-rsa AAAACI ci@github";
    std::fs::write(home.join(".ssh/authorized_keys"), format!("{humana}\n{ci}\n")).unwrap();

    let agente = "ssh-ed25519 AAAAAGENTE agente@schematize";
    let v = vec![Verbo { nome: "deploy".into(), comando: "echo ok".into() }];
    let script =
        script_de_instalacao(Fronteira::OpsShellUsuario, &v, agente, &home.to_string_lossy())
            .expect("$HOME de teste é válido");

    // Seis instalações simultâneas — antes deixavam SEIS linhas do agente.
    let filhos: Vec<_> = (0..6)
        .map(|_| {
            let (s, h) = (script.clone(), home.clone());
            std::thread::spawn(move || {
                let _ = std::process::Command::new("sh").arg("-c").arg(&s).env("HOME", &h).output();
            })
        })
        .collect();
    for f in filhos {
        f.join().unwrap();
    }

    let ak = std::fs::read_to_string(home.join(".ssh/authorized_keys")).unwrap();
    assert_eq!(
        ak.lines().filter(|l| l.contains(agente)).count(),
        1,
        "a linha do agente duplicou:\n{ak}"
    );
    assert!(ak.contains(humana), "o break-glass humano SUMIU sob concorrência:\n{ak}");
    assert!(ak.contains(ci), "a chave de CI sumiu:\n{ak}");
    assert_eq!(ak.lines().filter(|l| !l.trim().is_empty()).count(), 3, "linhas a mais:\n{ak}");
    // Nem trava nem temporário ficam para trás.
    assert!(!home.join(".ssh/.schematize-bootstrap.lock").exists(), "a trava ficou presa");
    let sobras: Vec<_> = std::fs::read_dir(home.join(".ssh"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("schematize."))
        .collect();
    assert!(sobras.is_empty(), "temporários órfãos: {sobras:?}");
    let _ = std::fs::remove_dir_all(&home);
}

/// **D5** — um verbo chamado `schematize-probe` nunca rodaria: o embutido do shim responde antes.
#[test]
fn d5_verbo_com_nome_reservado_e_recusado() {
    let c = vps::db::open_at(&db("d5")).unwrap();
    let e = vps::verbos::definir(&c, "srv", "schematize-probe", "echo x").unwrap_err();
    assert!(e.contains("reservado"), "o erro tem que explicar o porquê: {e}");
    assert!(e.contains("nunca seria executado"), "{e}");
    // Nome parecido continua livre.
    assert!(vps::verbos::definir(&c, "srv", "schematize-probe2", "echo x").is_ok());
    assert!(vps::verbos::definir(&c, "srv", "probe", "echo x").is_ok());
}

/// **D6** — porta 0 era aceita e produzia uma falha do `ssh` que não ajuda ninguém.
#[test]
fn d6_porta_zero_e_recusada() {
    let c = vps::db::open_at(&db("d6")).unwrap();
    let mut p = VpsProfile::novo("srv", "10.0.0.1", "u", "k");
    p.port = 0;
    let e = vps::salvar(&c, &p).unwrap_err();
    assert!(e.contains("porta inválida"), "{e}");
    for porta in [1u16, 22, 2222, 65535] {
        p.port = porta;
        assert!(vps::salvar(&c, &p).is_ok(), "porta {porta} é legítima");
    }
}

/// **D7** — o banco nascia 644 e os diretórios 775, legíveis por qualquer usuário local.
#[test]
fn d7_arquivos_nascem_restritos() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let caminho = db("d7");
        let c = vps::db::open_at(&caminho).unwrap();
        drop(c);
        let m = std::fs::metadata(&caminho).unwrap().permissions().mode() & 0o777;
        assert_eq!(m, 0o600, "o banco guarda a trilha inteira e nasceu {m:o}");

        let dir = std::env::temp_dir().join(format!("schematize-perm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        vps::db::restringir_dir(&dir);
        let m = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(m, 0o700, "o dir veio {m:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// **D12** — a saída do host era bufferizada sem teto: 7 GB de RSS em 25 segundos.
///
/// O host controla quanto imprime, e isto **não precisa de host malicioso**: um verbo `logs`
/// num journal grande derruba a máquina do usuário por acidente.
#[test]
fn d12_saida_do_host_tem_teto_de_memoria() {
    // O teto existe, é sóbrio, e há prazo máximo. (Ver a nota do `teto` em `d2_…`.)
    let teto = vps::exec::MAX_SAIDA;
    assert!(teto <= 32 * 1024 * 1024, "teto de saída grande demais: {teto}");
    assert!(teto >= 1024 * 1024, "teto pequeno demais pra log de deploy: {teto}");
    assert!(vps::exec::TIMEOUT.as_secs() >= 60, "prazo curto demais pra um deploy real");
    assert!(vps::exec::TIMEOUT.as_secs() <= 3600, "sem prazo, um jorro infinito trava pra sempre");

    // E o caminho de captura NÃO usa `.output()`, que é o que bufferizava sem limite.
    let fonte = std::fs::read_to_string("src/vps/exec.rs").unwrap();
    let producao = fonte.split("#[cfg(test)]").next().unwrap_or("");
    assert!(!producao.contains(".output()"), "voltou a usar `.output()`, que não tem teto");
    assert!(producao.contains("capturar_limitado"), "a captura limitada sumiu");
    // Descartar, não interromper: parar de ler encheria o pipe e travaria o comando remoto
    // no meio de um deploy.
    assert!(
        producao.contains("Descarta, não interrompe"),
        "a decisão de DRENAR em vez de parar precisa continuar documentada onde é tomada"
    );
}

/// **D10** — `resolve_bin` procurava `ssh`; no Windows o arquivo é `ssh.exe`.
///
/// A regra foi extraída para uma função com a plataforma como PARÂMETRO justamente porque o
/// mutation testing mostrou que, sendo `#[cfg(windows)]`, ela não podia ser testada em Linux —
/// desligar a correção não quebrava teste nenhum.
#[test]
fn d10_resolucao_de_executavel_conhece_o_windows() {
    use deployer::agentrun::nomes_de_executavel_em;

    // Unix: o nome é o nome.
    assert_eq!(nomes_de_executavel_em("ssh", false), vec!["ssh"]);
    assert_eq!(nomes_de_executavel_em("claude", false), vec!["claude"]);

    // Windows: tenta o nome cru e as extensões executáveis, nessa ordem.
    let w = nomes_de_executavel_em("ssh", true);
    assert!(w.contains(&"ssh.exe".to_string()), "sem `.exe` o vps exec não acha nada: {w:?}");
    assert_eq!(w[0], "ssh", "o nome cru vem primeiro");
    for ext in [".exe", ".cmd", ".bat", ".com"] {
        assert!(w.contains(&format!("ssh{ext}")), "faltou {ext}: {w:?}");
    }
    // Já com extensão: respeita o que foi pedido, sem inventar `ssh.exe.exe`.
    assert_eq!(nomes_de_executavel_em("ssh.exe", true), vec!["ssh.exe"]);
}

/// **D11** — `home()` fazia `expect` numa variável que o Windows não define.
#[test]
fn d11_home_resolve_em_qualquer_plataforma() {
    use deployer::util::resolver_home;
    use std::path::PathBuf;

    let s = |x: &str| Some(x.to_string());

    // Unix: `HOME` vence.
    assert_eq!(
        resolver_home(s("/home/tom"), s("/C/Users/tom"), None, None),
        PathBuf::from("/home/tom")
    );
    // Windows moderno: sem `HOME`, cai no `USERPROFILE`.
    assert_eq!(resolver_home(None, s(r"C:\Users\tom"), None, None), PathBuf::from(r"C:\Users\tom"));
    // Windows antigo / domínio: o par HOMEDRIVE + HOMEPATH, com a barra inicial descartada
    // (senão o `join` trataria como absoluto e comeria o drive).
    assert_eq!(
        resolver_home(None, None, s("C:"), s(r"\Users\tom")),
        PathBuf::from("C:").join(r"Users\tom")
    );
    // Nada declarado: degrada pro temporário em vez de PANICAR (era um `expect`, piso 4).
    let fallback = resolver_home(None, None, None, None);
    assert!(fallback.starts_with(std::env::temp_dir()), "{fallback:?}");
    // Valor vazio não conta como definido (o `home()` filtra antes de chamar).
    assert_eq!(resolver_home(None, s("/perfil"), None, None), PathBuf::from("/perfil"));
}
