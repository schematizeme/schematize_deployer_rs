//! O QUE: prova que o script que o `bootstrap` gera FUNCIONA de verdade — rodando ele num
//! `$HOME` de mentira e conferindo o resultado: shim executável, catálogo no lugar, linha
//! `restrict,command=` no authorized_keys, e o shim recusando o que deve recusar.
//!
//! POR QUE EXISTE: `script_de_instalacao` é uma função que devolve TEXTO. Testar o texto
//! (contém "restrict"? contém o caminho?) prova pouco — um script pode conter todas as
//! palavras certas e mesmo assim falhar no `sh`. Aqui o script é EXECUTADO, e o que se assere
//! é o estado do disco depois. É o mais perto de um host real que dá pra chegar sem um.
//!
//! DE ONDE VEM: um diretório temporário exclusivo. PRA ONDE VAI: só esse diretório, apagado no fim.

use deployer::vps::bootstrap::script_de_instalacao;
use deployer::vps::capacidade::Fronteira;
use deployer::vps::verbos::Verbo;
use std::path::PathBuf;
use std::process::Command;

/// Diretório-sandbox exclusivo deste teste, fazendo as vezes do `$HOME` do host.
fn sandbox(nome: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("schematize-boot-{nome}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("criar sandbox");
    d
}

fn catalogo() -> Vec<Verbo> {
    vec![
        Verbo { nome: "deploy".into(), comando: "echo DEPLOY-RODOU".into() },
        Verbo { nome: "status".into(), comando: "echo STATUS-OK".into() },
    ]
}

/// Roda o script no `sh`, com `$HOME` apontando pro sandbox.
fn rodar(script: &str, home: &PathBuf) -> (String, String, bool) {
    let out = Command::new("sh")
        .arg("-c")
        .arg(script)
        .env("HOME", home)
        .output()
        .expect("sh precisa existir");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.success(),
    )
}

#[test]
fn o_script_de_instalacao_realmente_instala() {
    let home = sandbox("instala");
    let pub_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA agente@schematize";
    let script = script_de_instalacao(
        Fronteira::OpsShellUsuario,
        &catalogo(),
        pub_key,
        &home.to_string_lossy(),
    )
    .expect("$HOME de teste é válido");

    let (out, err, ok) = rodar(&script, &home);
    assert!(ok, "o script tem que rodar limpo.\nstdout: {out}\nstderr: {err}");
    assert!(out.contains("SCHEMATIZE_BOOTSTRAP_OK"), "faltou a confirmação:\n{out}");

    // --- o shim ficou executável ---------------------------------------------------------
    let shim = home.join(".schematize/ops-shell");
    assert!(shim.is_file(), "shim não foi criado em {}", shim.display());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(&shim).unwrap().permissions().mode();
        assert_eq!(m & 0o111, 0o111, "o shim precisa ser executável (modo {m:o})");
    }

    // --- o catálogo foi inteiro, com a contagem certa -------------------------------------
    let cat = std::fs::read_to_string(home.join(".schematize/catalogo")).expect("catálogo");
    let verbos_no_arquivo =
        cat.lines().filter(|l| !l.trim_start().starts_with('#') && l.contains('\t')).count();
    assert_eq!(verbos_no_arquivo, catalogo().len(), "nº de verbos no host == nº no catálogo");

    // --- a linha do authorized_keys aponta pro caminho LITERAL ----------------------------
    let ak = std::fs::read_to_string(home.join(".ssh/authorized_keys")).expect("authorized_keys");
    assert!(ak.contains("restrict,command="), "faltou o forced command:\n{ak}");
    assert!(ak.contains(&shim.to_string_lossy().to_string()), "caminho tem que ser literal:\n{ak}");
    assert!(!ak.contains("$HOME"), "o command= não pode depender de expansão do shell:\n{ak}");
    assert!(ak.contains(pub_key), "a chave pública tem que estar na linha:\n{ak}");

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn o_bootstrap_preserva_o_break_glass_e_e_idempotente() {
    // R2 do plano: a chave HUMANA de emergência não pode sumir num bootstrap, nem no segundo.
    let home = sandbox("breakglass");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    let humana = "ssh-ed25519 AAAAHUMANA tom@notebook";
    let outra = "ssh-rsa AAAAOUTRA ci@github";
    std::fs::write(home.join(".ssh/authorized_keys"), format!("{humana}\n{outra}\n")).unwrap();

    let agente = "ssh-ed25519 AAAAAGENTE agente@schematize";
    let script = script_de_instalacao(
        Fronteira::OpsShellUsuario,
        &catalogo(),
        agente,
        &home.to_string_lossy(),
    )
    .expect("$HOME de teste é válido");

    for volta in 1..=2 {
        let (_, err, ok) = rodar(&script, &home);
        assert!(ok, "volta {volta} falhou: {err}");
        let ak = std::fs::read_to_string(home.join(".ssh/authorized_keys")).unwrap();
        assert!(ak.contains(humana), "volta {volta}: a chave humana SUMIU:\n{ak}");
        assert!(ak.contains(outra), "volta {volta}: a chave de CI sumiu:\n{ak}");
        // Idempotente: a linha do agente aparece UMA vez, não uma por execução.
        assert_eq!(
            ak.lines().filter(|l| l.contains(agente)).count(),
            1,
            "volta {volta}: a linha do agente duplicou:\n{ak}"
        );
        // E a chave humana continua SEM forced command — é o break-glass.
        let linha_humana = ak.lines().find(|l| l.contains(humana)).unwrap();
        assert!(!linha_humana.contains("command="), "o break-glass não pode ganhar forced command");
    }

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn o_shim_instalado_recusa_tudo_fora_do_catalogo() {
    let home = sandbox("shim");
    let script = script_de_instalacao(
        Fronteira::OpsShellUsuario,
        &catalogo(),
        "ssh-ed25519 AAAA a@b",
        &home.to_string_lossy(),
    )
    .expect("$HOME de teste é válido");
    let (_, err, ok) = rodar(&script, &home);
    assert!(ok, "instalação falhou: {err}");
    let shim = home.join(".schematize/ops-shell");

    let chamar = |pedido: &str| -> (String, i32) {
        let out = Command::new(&shim)
            .env("SSH_ORIGINAL_COMMAND", pedido)
            .env("HOME", &home)
            .output()
            .expect("rodar o shim");
        let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
        s.push_str(&String::from_utf8_lossy(&out.stderr));
        (s, out.status.code().unwrap_or(-1))
    };

    // --- caso NEGATIVO: o verbo legítimo roda de verdade ---------------------------------
    let (saida, code) = chamar("deploy");
    assert_eq!(code, 0, "o verbo do catálogo tem que rodar: {saida}");
    assert!(saida.contains("DEPLOY-RODOU"), "o comando real tem que executar: {saida}");

    // --- a recusa vem da DEFESA CERTA, não por acidente ----------------------------------
    // Sem isto, remover a checagem de metacaractere do shim passaria despercebido: o
    // casamento exato do catálogo recusaria `deploy; id` de qualquer jeito, por ser um verbo
    // desconhecido. Duas defesas com o mesmo desfecho e nenhum teste que as distinga = uma
    // delas pode ser apagada sem ninguém notar (achado no mutation testing).
    for (pedido, esperado) in [
        ("deploy; id", "uma palavra"),
        ("deploy $(id)", "uma palavra"),
        ("deploy --prod", "uma palavra"),
        ("restart", "verbo desconhecido"),
        ("", "shell interativo"),
    ] {
        let (saida, _) = chamar(pedido);
        assert!(
            saida.contains(esperado),
            "{pedido:?} tinha que ser recusado por {esperado:?}, veio: {saida}"
        );
    }

    // --- e tudo o mais é recusado, sem executar nada -------------------------------------
    let sentinela = home.join("NAO-DEVIA-EXISTIR");
    let ataques = [
        ("", "shell interativo"),
        ("restart", "verbo inexistente"),
        ("deploy --prod", "argumento extra"),
        ("deploy; id", "encadeamento com ;"),
        ("deploy && id", "encadeamento com &&"),
        ("deploy | sh", "pipe"),
        ("deploy `id`", "crase"),
        ("deploy $(id)", "substituição"),
        ("$(echo deploy)", "verbo por expansão"),
        ("deploy\nrestart", "quebra de linha"),
        ("/bin/sh", "shell direto"),
        ("../../bin/sh", "travessia"),
    ];
    for (pedido, rotulo) in ataques {
        let (saida, code) = chamar(pedido);
        assert_ne!(code, 0, "{rotulo}: {pedido:?} não pode sair 0 — {saida}");
        assert!(saida.contains("recusado"), "{rotulo}: a recusa tem que ser explícita — {saida}");
        assert!(!sentinela.exists(), "{rotulo}: algo executou quando não devia");
    }

    // --- o host mantém o PRÓPRIO log, independente do cliente ---------------------------
    let log = std::fs::read_to_string(home.join(".schematize/ops-shell.log")).expect("log do host");
    assert!(log.contains("\tallow\tdeploy"), "o allow tem que estar no log do host:\n{log}");
    // Cada ataque tem que ter DEIXADO RASTRO — asserção por conteúdo, não por contagem: a
    // contagem quebra sempre que a suíte ganha um caso novo, e aí a tentação é ajustar o
    // número em vez de conferir o que importa (achado ao acrescentar os casos de mensagem).
    for (pedido, rotulo) in ataques {
        let procurado = if pedido.is_empty() { "<vazio>" } else { pedido };
        // O log guarda a primeira linha do pedido (o `printf` corta no \n).
        let primeira = procurado.lines().next().unwrap_or(procurado);
        assert!(
            log.lines().any(|l| l.contains("\tdeny\t") && l.contains(primeira)),
            "{rotulo}: {pedido:?} não deixou rastro de recusa no log do host:\n{log}"
        );
    }

    let _ = std::fs::remove_dir_all(&home);
}
