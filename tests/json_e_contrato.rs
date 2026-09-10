//! O `--json` do Deployer é CONTRATO — e a barreira do segredo, provada sobre a saída REAL.
//!
//! # Por que este arquivo existe
//!
//! Duas coisas, e a segunda é a razão de o deployer ser o app mais arriscado dos três.
//!
//! **A primeira** é a mesma dos irmãos: saída para humano não é contrato. Um app da casa já
//! quebrou exatamente aqui — a janela do gestor casava rótulos EM PORTUGUÊS, lia certo num
//! idioma e devolvia tudo vazio nos outros dezenove, **sem erro nenhum**, e então afirmava
//! "app não instalado" a quem tinha o app.
//!
//! **A segunda** é o D5: chave privada e valor de segredo **não aparecem** — nem em tela, nem
//! em log, nem em erro. A confirmação é o fingerprint, que é público. Aqui isso vira teste:
//! cada documento é varrido inteiro atrás de material de chave, e o varredor tem teste próprio
//! que o vê REPROVAR — um guard que ninguém viu falhar não prova nada.
//!
//! # Por que ele roda o BINÁRIO, e não as funções
//!
//! As funções já têm teste unitário. O que só o binário prova é que nenhum `println!` humano
//! escapou para dentro do documento, e que a montagem de ponta a ponta — a que roda na máquina
//! de quem usa — não carrega segredo. Um cabeçalho impresso antes do `{` não quebra função
//! nenhuma, e é justamente o que tornaria o JSON inválido lá.

use std::collections::BTreeMap;
use std::process::Command;

/// **O quê:** o caminho do binário compilado, ao lado do executável de teste.
///
/// **Onde:** [`rodar`]. `CARGO_BIN_EXE_` seria mais curto, mas ele só existe para testes de
/// integração do MESMO pacote quando há `[[bin]]` — e amarrar o teste ao nome do binário, que
/// já mudou uma vez neste projeto, é o tipo de acoplamento que este arquivo combate.
fn bin() -> std::path::PathBuf {
    let mut p = std::env::current_exe().expect("o teste tem caminho");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("schematize-deployer")
}

/// **O quê:** roda um subcomando com `--json` num idioma, e devolve o stdout cru.
///
/// **Onde:** todos os testes daqui.
///
/// **O ambiente é limpo com `env_remove`**, e não só sobrescrito: o app resolve o idioma por
/// `OPTIMIZER_LANG` → `SCHEMATIZE_LANG` → `LC_ALL` → `LC_MESSAGES` → `LANG`, e uma variável
/// herdada da máquina de quem roda a suíte venceria a que o teste quer testar. Um teste que
/// muda de resultado conforme o `LANG` de quem o executa não prova nada — e o bug que este
/// arquivo trava é exatamente sobre idioma.
fn rodar(sub: &[&str], lang: &str) -> String {
    let mut c = Command::new(bin());
    for v in ["DEPLOYER_LANG", "SCHEMATIZE_LANG", "LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"] {
        c.env_remove(v);
    }
    let out = c
        .args(sub)
        .arg("--json")
        .env("LANG", lang)
        .output()
        .unwrap_or_else(|e| panic!("não consegui executar {}: {e}", bin().display()));
    assert!(
        out.status.success(),
        "`{}` saiu com {} — stderr: {}",
        sub.join(" "),
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("o contrato é UTF-8")
}

// ---------------------------------------------------------------------------
// Um parser de JSON pequeno, só para AFIRMAR validade.
//
// Ele existe porque "parseia com `json.load`" é a prova que o checklist pede, e uma
// asserção de `contains("{")` não é essa prova: um documento com aspa mal escapada passa no
// `contains` e explode na janela. `serde_json` como dev-dependency resolveria — e traria uma
// dependência a mais neste repo para provar uma coisa só. São ~70 linhas.
// ---------------------------------------------------------------------------

/// O valor JSON, no mínimo que este contrato usa: objeto, lista, string, número, bool, null.
#[derive(Debug, Clone, PartialEq)]
enum Json {
    Obj(BTreeMap<String, Json>),
    Arr(Vec<Json>),
    Str(String),
    Num(f64),
    Bool(bool),
    Null,
}

impl Json {
    /// **O quê:** o valor de uma chave, se isto for objeto. **Onde:** as asserções de shape.
    fn get(&self, k: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.get(k),
            _ => None,
        }
    }
    /// **O quê:** os itens, se isto for lista. **Onde:** as asserções sobre `boxes`/`services`.
    fn arr(&self) -> &[Json] {
        match self {
            Json::Arr(v) => v,
            outro => panic!("esperava lista, veio {outro:?}"),
        }
    }
}

/// **O quê:** parseia um documento inteiro; entrada de lixo vira `Err` com a posição.
/// **Onde:** [`parse`], que é o que os testes chamam.
fn parse_valor(s: &[u8], i: &mut usize) -> Result<Json, String> {
    while *i < s.len() && s[*i].is_ascii_whitespace() {
        *i += 1;
    }
    if *i >= s.len() {
        return Err("documento termina onde devia haver valor".into());
    }
    match s[*i] {
        b'{' => {
            *i += 1;
            let mut m = BTreeMap::new();
            loop {
                while *i < s.len() && s[*i].is_ascii_whitespace() {
                    *i += 1;
                }
                if *i < s.len() && s[*i] == b'}' {
                    *i += 1;
                    return Ok(Json::Obj(m));
                }
                let Json::Str(k) = parse_valor(s, i)? else {
                    return Err(format!("chave tem de ser string (byte {i})"));
                };
                while *i < s.len() && s[*i].is_ascii_whitespace() {
                    *i += 1;
                }
                if *i >= s.len() || s[*i] != b':' {
                    return Err(format!("faltou `:` depois de `{k}` (byte {i})"));
                }
                *i += 1;
                let v = parse_valor(s, i)?;
                if m.insert(k.clone(), v).is_some() {
                    return Err(format!("chave `{k}` duplicada — a janela leria a última"));
                }
                while *i < s.len() && s[*i].is_ascii_whitespace() {
                    *i += 1;
                }
                if *i < s.len() && s[*i] == b',' {
                    *i += 1;
                }
            }
        }
        b'[' => {
            *i += 1;
            let mut v = Vec::new();
            loop {
                while *i < s.len() && s[*i].is_ascii_whitespace() {
                    *i += 1;
                }
                if *i < s.len() && s[*i] == b']' {
                    *i += 1;
                    return Ok(Json::Arr(v));
                }
                v.push(parse_valor(s, i)?);
                while *i < s.len() && s[*i].is_ascii_whitespace() {
                    *i += 1;
                }
                if *i < s.len() && s[*i] == b',' {
                    *i += 1;
                }
            }
        }
        b'"' => {
            *i += 1;
            let mut out = String::new();
            loop {
                if *i >= s.len() {
                    return Err("string sem aspa de fechamento".into());
                }
                match s[*i] {
                    b'"' => {
                        *i += 1;
                        return Ok(Json::Str(out));
                    }
                    b'\\' => {
                        *i += 1;
                        if *i >= s.len() {
                            return Err("escape no fim do documento".into());
                        }
                        out.push(s[*i] as char);
                        *i += 1;
                    }
                    c => {
                        out.push(c as char);
                        *i += 1;
                    }
                }
            }
        }
        _ => {
            let ini = *i;
            while *i < s.len() && !b",}] \n\t\r".contains(&s[*i]) {
                *i += 1;
            }
            let lit = std::str::from_utf8(&s[ini..*i]).map_err(|e| e.to_string())?;
            match lit {
                "true" => Ok(Json::Bool(true)),
                "false" => Ok(Json::Bool(false)),
                "null" => Ok(Json::Null),
                n => n.parse::<f64>().map(Json::Num).map_err(|_| format!("`{n}` não é valor JSON")),
            }
        }
    }
}

/// **O quê:** parseia o documento e exige que ele acabe ali. **Onde:** todos os testes.
///
/// A sobra no fim importa: um `println!` humano depois do `}` deixaria o documento "válido"
/// para um parser tolerante e quebraria um estrito — e a janela usa um estrito.
fn parse(txt: &str) -> Json {
    let b = txt.as_bytes();
    let mut i = 0;
    let v = parse_valor(b, &mut i).unwrap_or_else(|e| panic!("JSON inválido: {e}\n---\n{txt}"));
    let resto = txt[i..].trim();
    assert!(resto.is_empty(), "sobrou coisa depois do JSON (prosa vazada?): {resto:?}");
    v
}

/// **O quê:** roda um comando qualquer num `HOME` dado, e devolve `(sucesso, stdout+stderr)`.
///
/// **Onde:** [`casa_com_um_host`], que precisa PREPARAR estado antes de ler.
///
/// **Por que um `HOME` próprio:** o registro de hosts do deployer mora sob o `HOME`, e o de
/// quem roda a suíte normalmente está vazio — foi o que aconteceu aqui, e o teste de shape dos
/// hosts passou sem afirmar coisa nenhuma, porque não havia host para conferir. Teste que
/// passa sobre lista vazia não é teste, é decoração.
fn rodar_em(home: &std::path::Path, args: &[&str]) -> (bool, String) {
    let mut c = Command::new(bin());
    for v in ["DEPLOYER_LANG", "SCHEMATIZE_LANG", "LC_ALL", "LC_MESSAGES", "LANGUAGE"] {
        c.env_remove(v);
    }
    let out = c
        .args(args)
        .env("HOME", home)
        .env("LANG", "en_US.UTF-8")
        .output()
        .unwrap_or_else(|e| panic!("não consegui executar {}: {e}", bin().display()));
    let mut txt = String::from_utf8_lossy(&out.stdout).into_owned();
    txt.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), txt)
}

/// **O quê:** um `HOME` temporário com UMA chave gerada e UM host registrado, e o `vps list
/// --json` que ele produz. `None` se a máquina não tiver `ssh-keygen`.
///
/// **Onde:** [`o_shape_do_vps_list_e_contrato_com_slugs_estaveis`].
///
/// **A chave é gerada pelo próprio app, sem passphrase, dentro do temporário** — nunca uma
/// chave de verdade da máquina, e nunca fora daquele diretório. O host é fictício e nada
/// conecta em lugar nenhum: `vps add` só grava no registro local.
fn casa_com_um_host() -> Option<(std::path::PathBuf, String)> {
    let h = std::env::temp_dir().join(format!("dep-json-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&h);
    std::fs::create_dir_all(&h).ok()?;

    let (ok, saida) = rodar_em(&h, &["ssh", "gen", "chave-de-teste"]);
    if !ok {
        // Sem `ssh-keygen` na máquina não dá para preparar o estado. Devolver `None` faz o
        // teste dizer isso em vez de reprovar por um motivo que não é o dele.
        eprintln!("pulando: `ssh gen` falhou neste ambiente — {saida}");
        let _ = std::fs::remove_dir_all(&h);
        return None;
    }
    let (ok, saida) = rodar_em(
        &h,
        &[
            "vps",
            "add",
            "srv-de-teste",
            "--host",
            "10.255.255.1",
            "--user",
            "deploy",
            "--key",
            "chave-de-teste",
            "--port",
            "2222",
            "--env",
            "hml",
        ],
    );
    assert!(ok, "`vps add` falhou: {saida}");

    let (ok, json) = rodar_em(&h, &["vps", "list", "--json"]);
    assert!(ok, "`vps list --json` falhou: {json}");
    Some((h, json))
}

/// Os três subcomandos que a janela lê. Cada um é uma tela.
const SUBCOMANDOS: &[&[&str]] = &[&["ssh", "list"], &["vps", "list"], &["vault", "status"]];

/// Todos os idiomas do catálogo, mais um que não existe — o fallback também não pode mudar o
/// documento.
const IDIOMAS: &[&str] = &["en_US.UTF-8", "pt_BR.UTF-8", "C", "ja_JP.UTF-8"];

// ---------------------------------------------------------------------------
// O varredor de segredo.
// ---------------------------------------------------------------------------

/// **O quê:** o que num texto denuncia material de chave privada ou segredo em claro.
///
/// **Onde:** [`varrer_segredo`], e o teste que o vê reprovar.
///
/// **Não é a redação do app** — é a segunda opinião. A redação existe para limpar; isto existe
/// para **duvidar dela**. Um varredor construído a partir das mesmas regras que ele audita
/// concordaria com o bug junto.
fn marcas_de_segredo(txt: &str) -> Vec<String> {
    let mut achados = Vec::new();
    // Blocos PEM, em qualquer variante. É o formato de toda chave privada SSH.
    for m in [
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        "BEGIN PRIVATE KEY",
        "PRIVATE KEY-----",
    ] {
        if txt.contains(m) {
            achados.push(format!("bloco PEM: {m}"));
        }
    }
    // Nome de campo que só existiria se alguém tivesse resolvido publicar a privada.
    for m in ["\"private", "private_key", "privkey", "passphrase\"", "\"secret_value"] {
        if txt.contains(m) {
            achados.push(format!("campo proibido: {m}"));
        }
    }
    // Prefixos de token conhecidos, com corpo suficiente para serem token de verdade.
    for pfx in ["ghp_", "github_pat_", "xoxb-", "sk-", "re_", "AKIA"] {
        if let Some(i) = txt.find(pfx) {
            let corpo = txt[i + pfx.len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .count();
            if corpo >= 8 {
                achados.push(format!("token com prefixo {pfx}"));
            }
        }
    }
    achados
}

/// **O quê:** reprova o teste se o documento carregar qualquer marca de segredo.
fn varrer_segredo(rotulo: &str, txt: &str) {
    let achados = marcas_de_segredo(txt);
    assert!(
        achados.is_empty(),
        "SEGREDO NO CONTRATO de `{rotulo}` — {}\n---\n{txt}",
        achados.join("; ")
    );
}

/// **O D5, provado sobre a saída REAL dos três comandos.**
///
/// A privada não aparece — nem em tela, nem em log, nem em erro. A confirmação de identidade é
/// o fingerprint, que é público. Este teste é a prova, não a recomendação.
#[test]
fn nenhum_dos_tres_documentos_carrega_material_de_chave_privada() {
    for sub in SUBCOMANDOS {
        varrer_segredo(&sub.join(" "), &rodar(sub, "en_US.UTF-8"));
    }
}

/// **O varredor REPROVA o que é segredo, e ABSOLVE o que não é.**
///
/// Guard nunca visto falhando é guard cego — e guard que reprova tudo é igualmente inútil,
/// porque quem o vê reprovar um caso legítimo desliga o guard.
#[test]
fn o_varredor_reprova_segredo_e_deixa_passar_o_que_e_publico() {
    for ruim in [
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn\n-----END OPENSSH PRIVATE KEY-----",
        r#"{"private_key": "..."}"#,
        r#"{"token": "ghp_AbCdEf0123456789AbCdEf"}"#,
        r#"{"k": "AKIAIOSFODNN7EXAMPLE"}"#,
    ] {
        assert!(!marcas_de_segredo(ruim).is_empty(), "devia reprovar: {ruim:?}");
    }
    for bom in [
        // O fingerprint é PÚBLICO — é o hash da pública, e é a confirmação que o D5 manda usar.
        r#"{"fingerprint": "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"}"#,
        // O caminho da PÚBLICA, e o NOME da chave, não são material de chave.
        r#"{"public_path": "/home/u/.ssh/github.pub", "key_name": "github"}"#,
        // Palavras que contêm prefixos mas não são token.
        r#"{"alias": "skeleton", "host": "resource.example"}"#,
    ] {
        assert!(
            marcas_de_segredo(bom).is_empty(),
            "falso-positivo: {bom:?} -> {:?}",
            marcas_de_segredo(bom)
        );
    }
}

/// **O BUG QUE ESTE ARQUIVO TRAVA.** O documento é o mesmo em qualquer idioma — byte a byte.
///
/// Se alguém puser um rótulo humano num campo (`"boundary": "SEM (só o cliente)"`), este teste
/// falha na hora, e não seis meses depois na máquina de um usuário japonês.
#[test]
fn os_tres_json_sao_byte_a_byte_iguais_em_qualquer_idioma() {
    for sub in SUBCOMANDOS {
        let referencia = rodar(sub, IDIOMAS[0]);
        for lang in &IDIOMAS[1..] {
            assert_eq!(
                referencia,
                rodar(sub, lang),
                "`{} --json` mudou entre {} e {lang} — prosa traduzida vazou para o contrato",
                sub.join(" "),
                IDIOMAS[0]
            );
        }
    }
}

/// Os três documentos são JSON válido de verdade, e acabam onde dizem acabar.
#[test]
fn os_tres_json_sao_validos_e_nao_tem_sobra() {
    for sub in SUBCOMANDOS {
        let v = parse(&rodar(sub, "en_US.UTF-8"));
        assert!(v.get("deployer").is_some(), "todo documento diz de que versão veio: {sub:?}");
    }
}

/// **O contrato das chaves**, e a ausência do que não pode estar lá.
#[test]
fn o_shape_do_ssh_list_e_contrato() {
    let v = parse(&rodar(&["ssh", "list"], "en_US.UTF-8"));
    let keys = v.get("keys").expect("faltou `keys`").arr();
    for k in keys {
        for campo in ["name", "kind", "fingerprint", "comment", "public_path"] {
            assert!(k.get(campo).is_some(), "faltou `keys[].{campo}`");
        }
        // Nenhum campo aponta para a privada. Não é material de chave, mas apontar para ela
        // num contrato de janela é o primeiro passo para alguém a ler.
        assert!(k.get("private_path").is_none(), "o contrato não fala da privada");
        let Some(Json::Str(p)) = k.get("public_path") else { panic!("public_path é string") };
        assert!(p.ends_with(".pub"), "o caminho publicado é o da pública: {p}");
    }
}

/// **O contrato dos hosts**, e os slugs ESTÁVEIS — nunca o rótulo humano.
#[test]
fn o_shape_do_vps_list_e_contrato_com_slugs_estaveis() {
    let Some((casa, json)) = casa_com_um_host() else { return };
    // O segredo é varrido aqui também: este é o único dos três documentos montado a partir de
    // um estado que o teste criou, e por isso o único onde um erro de montagem apareceria com
    // dado de verdade dentro.
    varrer_segredo("vps list (com host)", &json);

    let v = parse(&json);
    let hosts = v.get("hosts").expect("faltou `hosts`").arr();
    assert!(!hosts.is_empty(), "o host recém-registrado tem de aparecer — senão o teste é vazio");
    for h in hosts {
        for campo in [
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
            assert!(h.get(campo).is_some(), "faltou `hosts[].{campo}`");
        }
        // Conjuntos FECHADOS. Um valor fora deles é a janela recebendo algo que ela não sabe
        // desenhar — e o silêncio nesse caso é o que faz uma tela mentir.
        for (campo, permitidos) in [
            ("env", &["dev", "hml", "prd"][..]),
            ("mode", &["readonly", "opsverbs", "livre"][..]),
            ("boundary", &["sem", "usuario", "root"][..]),
        ] {
            let Some(Json::Str(s)) = h.get(campo) else { panic!("`{campo}` é string") };
            assert!(permitidos.contains(&s.as_str()), "`{campo}` fora do conjunto: {s}");
        }
        // Coerência: dizer que a host key está pinada sem ter fingerprint é mentir sobre a
        // única confirmação que a tela tem para mostrar.
        let pinada = h.get("host_key_pinned") == Some(&Json::Bool(true));
        assert_eq!(
            pinada,
            h.get("fingerprint") != Some(&Json::Null),
            "`host_key_pinned` e `fingerprint` têm de andar juntos: {h:?}"
        );
    }

    // O que foi registrado é o que sai — inclusive o `--env hml`, que prova que o slug vem do
    // domínio e não de um default.
    let h = &hosts[0];
    assert_eq!(h.get("alias"), Some(&Json::Str("srv-de-teste".into())));
    assert_eq!(h.get("user"), Some(&Json::Str("deploy".into())));
    assert_eq!(h.get("key_name"), Some(&Json::Str("chave-de-teste".into())));
    assert_eq!(h.get("env"), Some(&Json::Str("hml".into())));
    assert_eq!(h.get("port"), Some(&Json::Num(2222.0)));
    // Host recém-registrado ainda não teve a host key confiada — e o contrato diz isso com
    // `null`, não com string vazia.
    assert_eq!(h.get("fingerprint"), Some(&Json::Null));
    assert_eq!(h.get("host_key_pinned"), Some(&Json::Bool(false)));

    let _ = std::fs::remove_dir_all(&casa);
}

/// **O contrato do cofre.** Ele fala do ARQUIVO, nunca do que está dentro — e o shape não muda
/// de forma quando o cofre não existe.
#[test]
fn o_shape_do_vault_status_e_contrato_e_nao_fala_do_conteudo() {
    let v = parse(&rodar(&["vault", "status"], "en_US.UTF-8"));
    for campo in ["deployer", "exists", "path", "size_bytes", "mode", "mode_ok", "kdf", "kdf_weak"]
    {
        assert!(v.get(campo).is_some(), "faltou `{campo}` — o shape não pode variar");
    }
    // Nenhuma chave GUARDADA aparece: este documento é sobre o arquivo.
    for proibido in ["secrets", "keys", "values", "entries", "content"] {
        assert!(v.get(proibido).is_none(), "`{proibido}` fala do CONTEÚDO do cofre");
    }
    // Cofre ausente é ESTADO, não erro: os campos continuam lá, com `null` no que não se sabe.
    if v.get("exists") == Some(&Json::Bool(false)) {
        assert_eq!(v.get("kdf"), Some(&Json::Null));
        assert_eq!(v.get("mode"), Some(&Json::Null));
        assert_eq!(v.get("mode_ok"), Some(&Json::Bool(false)));
    }
}
