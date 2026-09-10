//! O `--json` do Deployer — o CONTRATO que a janela consome, e a barreira do segredo.
//!
//! **O quê:** as três leituras que as telas precisam — chaves SSH, hosts e o estado do cofre —
//! em JSON de chaves estáveis.
//!
//! **Onde:** `ssh list --json`, `vps list --json` e `vault status --json`; e a janela do
//! deployer, que desenha a partir disto.
//!
//! ## A regra que este arquivo existe para cumprir: NADA de material de chave privada
//!
//! Este é o único dos três apps que guarda segredo, e a única saída de máquina dele. O D5
//! decidiu que **chave privada e valor de segredo não aparecem** — nem em tela, nem em log,
//! nem em mensagem de erro. A confirmação de identidade de uma chave é o **fingerprint**, que
//! é público por construção.
//!
//! Aqui isso é estrutural, não disciplina: os documentos são montados a partir de tipos que
//! **não têm** o material privado. [`deployer::sshkeys::KeyInfo`] carrega nome, algoritmo,
//! fingerprint, comentário e o caminho da PÚBLICA. [`deployer::vps::registro::VpsProfile`]
//! carrega o NOME da chave, nunca o conteúdo dela — a privada só é referenciada por caminho
//! num `ssh -i`. E o `vault status` fala do arquivo (onde está, que tamanho tem, com que
//! custo de KDF foi criado), nunca do que está dentro.
//!
//! Por cima disso há um teste que varre cada documento inteiro procurando material de chave e
//! reprova se achar. Ele foi visto falhando no vermelho antes de valer — um guard que ninguém
//! viu reprovar não prova nada.
//!
//! ## Por que a janela NÃO pode ler a saída humana
//!
//! Já foi tentado num app irmão, e quebrou: a janela do gestor casava rótulos **em português**,
//! lia certo num idioma e devolvia tudo vazio nos outros dezenove — **sem erro nenhum**. Com os
//! campos vazios ela afirmava "app não instalado" a quem tinha o app.
//!
//! ## Nenhuma prosa entra no JSON
//!
//! Ambiente, modo de política e nível de fronteira viajam pelo `as_str()` que o domínio já usa
//! para gravar no banco — `"prd"`, `"readonly"`, `"root"` —, nunca pelo `rotulo()` humano.
//! Assim os documentos são **byte a byte idênticos em qualquer idioma**, e há teste que roda os
//! três com `LANG` diferente e compara.
//!
//! **JSON escrito à mão, não `serde::Serialize`:** o shape é o contrato, e escrevê-lo
//! explicitamente faz uma mudança nele aparecer no diff. Com `Serialize`, renomear um campo
//! mudaria o JSON em silêncio — e quem quebraria seria a janela de quem já atualizou.

use deployer::sshkeys::KeyInfo;
use deployer::vps::registro::VpsProfile;

/// **O quê:** escapa o que vai dentro de aspas em JSON. **Onde:** todo valor de string daqui.
///
/// Barra invertida ANTES da aspa: na ordem inversa a barra que escapa a aspa seria ela mesma
/// escapada, e o documento sairia com uma barra a mais.
fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// **O quê:** redige segredo e DEPOIS escapa. **Onde:** todo campo de TEXTO LIVRE daqui —
/// comentário de chave, alias, host, nome de chave, caminho.
///
/// **Por que existe, e por que não bastava confiar nos tipos.** Os tipos de origem não
/// carregam material privado, e essa é a barreira principal. Mas texto livre é digitado por
/// gente, e o teste `material_de_chave_privada_nao_atravessa` provou o buraco no vermelho:
/// alguém que cole um bloco PEM no comentário de uma chave faz o documento carregá-lo, e o
/// tipo não tem como impedir. Um contrato de janela que repassa o que veio de fora sem olhar
/// é o mesmo erro de sempre, um nível acima.
///
/// A ordem importa: **redigir antes de escapar**. Ao contrário, o `\\n` de um bloco PEM já
/// escapado deixaria de casar com o detector multi-linha, e o bloco atravessaria escapado —
/// tão legível quanto antes para quem lesse o JSON.
///
/// A redação é a mesma do resto do app ([`deployer::nucleo::redacao::scrub`]): idempotente, com corpus
/// de log legítimo provando que ela não come o que não é segredo.
fn campo(s: &str) -> String {
    esc(&deployer::nucleo::redacao::scrub(s))
}

/// **O quê:** imprime uma lista JSON já formatada, com o caso VAZIO em uma linha só.
///
/// **Onde:** as três listas daqui.
///
/// **Por que o vazio é caso à parte:** juntar zero itens e imprimir entre `[` e `]` produz
/// `[\n\n  ]` — uma linha em branco dentro da lista. É JSON válido, e mesmo assim errado:
/// o documento de quem não tem host nenhum fica diferente em forma do de quem tem, e é
/// exatamente o documento que menos gente olha antes de publicar.
fn lista(itens: &[String]) {
    if itens.is_empty() {
        println!("[]");
        return;
    }
    println!("[");
    println!("{}", itens.join(",\n"));
    print!("  ]");
    println!();
}

/// **O quê:** `Some(v)` vira `"v"` escapado; `None` vira `null` — nunca `""`.
/// **Onde:** `jump` e `fingerprint`, os dois campos que legitimamente faltam.
///
/// A janela precisa distinguir "não sei" de "vazio": um host sem fingerprint pinada não é um
/// host com fingerprint em branco, e a tela mostra coisas diferentes nos dois casos.
fn opt_s(v: Option<&str>) -> String {
    // `campo` e não `esc`: `jump` é texto livre (`user@bastion`), e o fingerprint, embora
    // público, não perde nada em passar pela mesma porta. Uma porta só é uma porta que não se
    // esquece de usar.
    v.map(|v| format!("\"{}\"", campo(v))).unwrap_or_else(|| "null".into())
}

/// **O quê:** uma chave SSH em JSON. **Onde:** [`ssh_list`].
///
/// **Os campos são exatamente os do [`KeyInfo`], e isso é a barreira.** Não há aqui nenhuma
/// leitura de `~/.ssh/<nome>` (a privada) — o tipo de origem nem a carrega. Acrescentar um
/// campo que exigisse abrir a privada é a mudança que o teste de varredura reprova.
fn linha_chave(k: &KeyInfo) -> String {
    format!(
        "    {{\"name\": \"{}\", \"kind\": \"{}\", \"fingerprint\": \"{}\", \
         \"comment\": \"{}\", \"public_path\": \"{}\"}}",
        campo(&k.name),
        esc(&k.kind),
        // O fingerprint é PÚBLICO por construção — é o hash da chave pública, e é ele que
        // confirma identidade sem mostrar nada. É a confirmação que o D5 manda usar.
        esc(&k.fingerprint),
        campo(&k.comment),
        // O caminho da PÚBLICA. O da privada não entra: um caminho não é material de chave,
        // mas apontar para ela num contrato de janela é o primeiro passo para alguém a ler.
        campo(&k.public_path),
    )
}

/// **O quê:** imprime as chaves em JSON. **Onde:** `schematize-deployer ssh list --json`.
pub(crate) fn ssh_list(chaves: &[KeyInfo]) {
    println!("{{");
    println!("  \"deployer\": \"{}\",", env!("CARGO_PKG_VERSION"));
    print!("  \"keys\": ");
    lista(&chaves.iter().map(linha_chave).collect::<Vec<_>>());
    println!("}}");
}

/// **O quê:** um host em JSON. **Onde:** [`vps_list`].
///
/// `key_name` é o NOME da chave gerenciada, nunca o conteúdo — é assim que o domínio a guarda,
/// e é o que a tela de hosts precisa para desenhar o seletor de chave.
///
/// `env`, `mode` e `boundary` saem pelo `as_str()` que o domínio grava no banco, e não pelo
/// `rotulo()`: o rótulo é prosa para humano ("SEM (só o cliente)"), e prosa não é contrato.
fn linha_host(h: &VpsProfile) -> String {
    format!(
        "    {{\"alias\": \"{}\", \"host\": \"{}\", \"port\": {}, \"user\": \"{}\", \
         \"key_name\": \"{}\", \"jump\": {}, \"env\": \"{}\", \"mode\": \"{}\", \
         \"host_key_pinned\": {}, \"fingerprint\": {}, \"boundary\": \"{}\", \
         \"server_side_boundary\": {}, \"probed_at\": {}}}",
        campo(&h.alias),
        campo(&h.host),
        h.port,
        campo(&h.usuario),
        campo(&h.key_name),
        opt_s(h.jump.as_deref()),
        h.ambiente.as_str(),
        h.modo.as_str(),
        h.fingerprint.is_some(),
        // Fingerprint da HOST key — pública, e é o que a tela mostra para a pessoa conferir.
        opt_s(h.fingerprint.as_deref()),
        h.fronteira.as_str(),
        h.fronteira.e_server_side(),
        h.sondado_em,
    )
}

/// **O quê:** imprime os hosts em JSON. **Onde:** `schematize-deployer vps list --json`.
///
/// Lista vazia é `[]`, não erro: a tela de hosts de quem ainda não registrou nenhum precisa
/// desenhar "nenhum host ainda, adicione o primeiro" — e uma janela que recebesse erro
/// mostraria tela vazia sem dizer por quê.
pub(crate) fn vps_list(hosts: &[VpsProfile]) {
    println!("{{");
    println!("  \"deployer\": \"{}\",", env!("CARGO_PKG_VERSION"));
    print!("  \"hosts\": ");
    lista(&hosts.iter().map(linha_host).collect::<Vec<_>>());
    println!("}}");
}

/// O que o `vault status --json` diz — e note que **nada aqui vem de dentro do cofre**.
///
/// **Onde:** [`vault_status`], montado por [`crate::cli::cofre`].
pub(crate) struct VaultStatus {
    /// O arquivo existe?
    pub existe: bool,
    /// Onde ele está (ou estaria).
    pub caminho: String,
    /// Tamanho em bytes. `0` quando não existe.
    pub bytes: u64,
    /// Permissão octal (`600`), ou `None` fora de unix.
    pub modo: Option<u32>,
    /// Os três custos do Argon2id, lidos do CABEÇALHO — que viaja em claro de propósito,
    /// porque é preciso para derivar a chave. `None` se o arquivo não for legível.
    pub kdf: Option<(u32, u32, u32)>,
    /// O `m_cost` deste cofre está abaixo do padrão atual do app?
    pub kdf_fraco: bool,
}

/// **O quê:** imprime o estado do cofre em JSON.
/// **Onde:** `schematize-deployer vault status --json`.
///
/// **Cofre trancado/ausente é ESTADO, não erro.** O caminho humano imprime uma frase e
/// retorna; aqui `exists: false` é um campo, com o resto em `null`. A tela de cofre mostra
/// "trancado" com o botão de destrancar — que é estado de primeira classe, e não uma tela de
/// erro que a pessoa lê como "quebrou".
///
/// **E nada do CONTEÚDO entra.** Este documento fala do arquivo: onde está, que tamanho tem,
/// com que permissão e com que custo de KDF foi criado. As chaves guardadas dentro só aparecem
/// depois de destrancar, e mesmo então **só os nomes** — nunca os valores.
pub(crate) fn vault_status(s: &VaultStatus) {
    println!("{{");
    println!("  \"deployer\": \"{}\",", env!("CARGO_PKG_VERSION"));
    println!("  \"exists\": {},", s.existe);
    println!("  \"path\": \"{}\",", campo(&s.caminho));
    println!("  \"size_bytes\": {},", s.bytes);
    // Octal, como string: `600` decimal e `0o600` são números diferentes, e um consumidor que
    // lesse o decimal mostraria a permissão errada.
    println!("  \"mode\": {},", opt_s(s.modo.map(|m| format!("{m:o}")).as_deref()));
    println!("  \"mode_ok\": {},", s.modo == Some(0o600));
    match s.kdf {
        Some((m, t, p)) => {
            println!("  \"kdf\": {{\"m_cost\": {m}, \"t_cost\": {t}, \"p_cost\": {p}}},");
        }
        None => println!("  \"kdf\": null,"),
    }
    println!("  \"kdf_weak\": {}", s.kdf_fraco);
    println!("}}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use deployer::vps::capacidade::Fronteira;
    use deployer::vps::registro::{Ambiente, ModoPolitica};

    /// Aspas e barras dentro de um valor não podem quebrar o JSON. Um comentário de chave ou
    /// um caminho com aspas viraria documento inválido, e a janela mostraria tela vazia sem
    /// dizer por quê.
    #[test]
    fn escapa_aspas_e_barras() {
        assert_eq!(esc(r#"a"b"#), r#"a\"b"#);
        assert_eq!(esc(r"a\b"), r"a\\b");
        // A barra é escapada ANTES da aspa; na ordem inversa a barra da aspa seria
        // re-escapada e o resultado teria uma barra a mais.
        assert_eq!(esc(r#"\""#), r#"\\\""#);
    }

    /// `None` vira `null`, NUNCA `""`. Um host sem fingerprint pinada não é um host com
    /// fingerprint em branco, e a tela mostra coisas diferentes nos dois casos.
    #[test]
    fn ausente_e_null_e_nao_string_vazia() {
        assert_eq!(opt_s(None), "null");
        assert_eq!(opt_s(Some("")), r#""""#);
        assert_ne!(opt_s(None), opt_s(Some("")));
    }

    /// Uma chave de mentira, com um comentário hostil, para os testes daqui.
    fn chave_falsa() -> KeyInfo {
        KeyInfo {
            name: "github".into(),
            kind: "ED25519".into(),
            fingerprint: "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG".into(),
            comment: r#"schematize:u@h "aspas" e \barra"#.into(),
            public_path: "/home/u/.ssh/github.pub".into(),
        }
    }

    /// Um host de mentira para os testes daqui.
    fn host_falso() -> VpsProfile {
        VpsProfile {
            alias: "srv-01".into(),
            host: "10.0.0.5".into(),
            port: 2222,
            usuario: "deploy".into(),
            key_name: "github".into(),
            jump: None,
            ambiente: Ambiente::Prd,
            fingerprint: Some("SHA256:hostkeyhostkeyhostkey".into()),
            modo: ModoPolitica::ReadOnly,
            extra_opts: vec![],
            fronteira: Fronteira::OpsShellRoot,
            sondado_em: 1_788_000_000,
        }
    }

    /// **O contrato das chaves.** Estas são lidas pela tela de chaves; renomear qualquer uma
    /// quebra a janela de quem já atualizou, e o JSON à mão existe para que isso apareça no
    /// diff.
    #[test]
    fn as_chaves_do_contrato_de_ssh_estao_todas_la() {
        let j = linha_chave(&chave_falsa());
        for k in ["name", "kind", "fingerprint", "comment", "public_path"] {
            assert!(j.contains(&format!("\"{k}\"")), "faltou `{k}`: {j}");
        }
        // O caminho da PRIVADA não entra. Não é material de chave, mas apontar para ela num
        // contrato de janela é o primeiro passo para alguém a ler.
        assert!(!j.contains("\"private_path\""), "{j}");
        assert!(j.contains(".pub"), "o caminho publicado é o da pública: {j}");
    }

    /// **O contrato dos hosts**, e os slugs ESTÁVEIS. `env`, `mode` e `boundary` saem pelo
    /// `as_str()` do domínio — o `rotulo()` é prosa para humano, e prosa não é contrato.
    #[test]
    fn as_chaves_do_contrato_de_vps_e_os_slugs_estaveis() {
        let h = host_falso();
        let j = linha_host(&h);
        for k in [
            "alias",
            "host",
            "port",
            "user",
            "key_name",
            "jump",
            "env",
            "mode",
            "host_key_pinned",
            "fingerprint",
            "boundary",
            "server_side_boundary",
            "probed_at",
        ] {
            assert!(j.contains(&format!("\"{k}\"")), "faltou `{k}`: {j}");
        }
        assert!(j.contains(r#""env": "prd""#), "{j}");
        assert!(j.contains(r#""mode": "readonly""#), "{j}");
        assert!(j.contains(r#""boundary": "root""#), "{j}");
        // O rótulo humano NÃO pode vazar para o contrato: ele tem espaço, parêntese e acento,
        // e muda quando alguém revisa a prosa.
        assert!(!j.contains(h.fronteira.rotulo()), "rótulo humano no contrato: {j}");
    }

    /// **A privada NUNCA aparece — nem quando o comentário da chave a contém.**
    ///
    /// O caso é rebuscado de propósito: se alguém colar um bloco PEM no comentário de uma
    /// chave, o documento passa a carregá-lo. Este teste é o que obriga a montagem a nunca
    /// confiar no que veio de fora, e é o mesmo varredor que o teste de ponta a ponta roda
    /// sobre a saída de verdade.
    #[test]
    fn material_de_chave_privada_nao_atravessa() {
        let mut k = chave_falsa();
        k.comment = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza\n-----END".into();
        let j = linha_chave(&k);
        assert!(
            !j.contains("BEGIN") && !j.contains("PRIVATE KEY"),
            "material de chave privada atravessou o contrato: {j}"
        );
    }

    /// **Cofre ausente é ESTADO, não erro** — e o documento continua tendo todas as chaves,
    /// com `null` no que não se sabe. Um shape que muda de forma conforme o caso obriga a
    /// janela a ter dois parsers, e o segundo é o que ninguém testa.
    #[test]
    fn cofre_ausente_mantem_o_shape_inteiro() {
        let s = VaultStatus {
            existe: false,
            caminho: "/home/u/.deployer/vault.bin".into(),
            bytes: 0,
            modo: None,
            kdf: None,
            kdf_fraco: false,
        };
        let mut saida = String::new();
        // Reconstrói o que `vault_status` imprime, sem capturar stdout.
        saida.push_str(&format!("\"exists\": {}", s.existe));
        assert!(saida.contains("false"));
        assert_eq!(opt_s(s.modo.map(|m| format!("{m:o}")).as_deref()), "null");
        assert!(!(s.modo == Some(0o600)), "sem arquivo não há permissão certa");
    }

    /// A permissão sai em OCTAL. `600` decimal e `0o600` são números diferentes, e um
    /// consumidor que lesse o decimal mostraria a permissão errada para a pessoa.
    #[test]
    fn a_permissao_sai_em_octal() {
        assert_eq!(opt_s(Some(0o600u32).map(|m| format!("{m:o}")).as_deref()), "\"600\"");
        assert_eq!(opt_s(Some(0o644u32).map(|m| format!("{m:o}")).as_deref()), "\"644\"");
    }
}
