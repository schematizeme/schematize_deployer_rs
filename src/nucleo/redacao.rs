//! REDAÇÃO de segredo — a barreira que faz o relatório ser compartilhável.
//! Puro (string -> string) e testado: token, chave privada, JWT, valor de env sensível.

/// Placeholder que substitui qualquer segredo detectado.
pub(crate) const RED: &str = "<REDIGIDO>";

/// Redige segredos de um texto qualquer vindo de env/arquivos/comandos. Cobre:
/// - tokens por prefixo: `re_…`, `sk-…`, `ghp_/gho_/ghu_/ghs_/ghr_/github_pat_…`, `xox[bap]-…`, `xapp-…`
/// - JWTs `eyJ….….…` (3 partes base64url)
/// - `Bearer <token>` (o token vira `<REDIGIDO>`)
/// - blocos `-----BEGIN … PRIVATE KEY-----` … `-----END …-----` (o bloco todo some)
/// - `NOME=valor` quando NOME contém KEY/TOKEN/SECRET/PASS/CRED, OU o valor parece um token
///
/// Idempotente e best-effort — na dúvida, redige (segurança-primeiro).
pub fn scrub(s: &str) -> String {
    // 1) Blocos de chave privada primeiro (são multi-linha).
    let s = redact_private_key_blocks(s);
    // 2) Linha a linha, PRESERVANDO o terminador de cada uma.
    //
    // `lines()` + `join("\n")` reescrevia `\r\n` como `\n` e comia o `\n` final — a redação
    // deixava de ser idempotente (redigir o já-redigido mudava o texto) e alterava conteúdo
    // além do que devia. Achado no fuzzing. Numa trilha de auditoria, reescrever silenciosamente
    // o que se está guardando é justamente o que não pode acontecer.
    let mut out = String::with_capacity(s.len());
    for (linha, fim) in linhas_com_terminador(&s) {
        out.push_str(&scrub_line(linha));
        out.push_str(fim);
    }
    out
}

/// Quebra em `(conteúdo, terminador)`, onde o terminador é `"\r\n"`, `"\n"` ou `""` (última
/// linha sem quebra). Preserva tudo — é o que torna [`scrub`] idempotente.
pub(crate) fn linhas_com_terminador(s: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    let mut resto = s;
    while let Some(i) = resto.find('\n') {
        let (linha, depois) = resto.split_at(i);
        let (linha, fim) = match linha.strip_suffix('\r') {
            Some(sem_cr) => (sem_cr, "\r\n"),
            None => (linha, "\n"),
        };
        out.push((linha, fim));
        resto = &depois[1..];
    }
    if !resto.is_empty() {
        out.push((resto, ""));
    }
    out
}

/// Some com o miolo de qualquer bloco PEM de chave PRIVADA (defesa extra — nós nunca
/// lemos ~/.ssh, mas se algum comando cuspir um bloco, ele não passa).
pub(crate) fn redact_private_key_blocks(s: &str) -> String {
    if !s.contains("PRIVATE KEY-----") {
        return s.to_string();
    }
    let mut out: Vec<String> = Vec::new();
    let mut in_key = false;
    for l in s.lines() {
        if !in_key && l.contains("-----BEGIN") && l.contains("PRIVATE KEY-----") {
            in_key = true;
            out.push(format!("{RED} (bloco de chave privada)"));
            continue;
        }
        if in_key {
            if l.contains("-----END") {
                in_key = false;
            }
            continue; // descarta as linhas do bloco
        }
        out.push(l.to_string());
    }
    out.join("\n")
}

/// Redige uma única linha: quebra em segmentos (espaço vs palavra), preserva o
/// espaçamento e aplica `scrub_word` em cada palavra. Trata `Bearer <token>`.
pub(crate) fn scrub_line(line: &str) -> String {
    let mut result = String::new();
    let mut prev_bearer = false;
    for (is_ws, seg) in segments(line) {
        if is_ws {
            result.push_str(&seg);
            continue;
        }
        if prev_bearer {
            result.push_str(RED);
            prev_bearer = false;
            continue;
        }
        prev_bearer = seg.eq_ignore_ascii_case("bearer");
        result.push_str(&scrub_word(&seg));
    }
    result
}

/// Quebra a linha em segmentos alternados (whitespace, não-whitespace), preservando tudo.
pub(crate) fn segments(line: &str) -> Vec<(bool, String)> {
    let mut segs: Vec<(bool, String)> = Vec::new();
    let mut cur = String::new();
    let mut cur_ws: Option<bool> = None;
    for ch in line.chars() {
        let ws = ch.is_whitespace();
        match cur_ws {
            Some(p) if p == ws => cur.push(ch),
            Some(p) => {
                segs.push((p, std::mem::take(&mut cur)));
                cur.push(ch);
                cur_ws = Some(ws);
            }
            None => {
                cur.push(ch);
                cur_ws = Some(ws);
            }
        }
    }
    if let Some(p) = cur_ws {
        segs.push((p, cur));
    }
    segs
}

/// Redige a SENHA de uma URL de conexão (`esquema://usuario:SENHA@host`), preservando o
/// resto — o host e o usuário são justamente o que se quer ler num log de diagnóstico.
///
/// **Onde:** [`scrub_word`], antes das outras regras. Fecha uma lacuna que o pentest (P10)
/// enumerou: `postgres://app:hunter2@db:5432/x` passava inteiro, e string de conexão é dos
/// jeitos mais comuns de um segredo aparecer em log de deploy.
pub(crate) fn redact_url_password(word: &str) -> Option<String> {
    let (esquema, resto) = word.split_once("://")?;
    // Esquema plausível de URL: só letras, números, `+`, `-`, `.` (evita casar `a://b` em prosa).
    if esquema.is_empty()
        || !esquema.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return None;
    }
    // Credencial fica antes do PRIMEIRO `@`; o `:` que separa usuário de senha, antes dele.
    let at = resto.find('@')?;
    let (cred, host) = resto.split_at(at);
    let (usuario, _senha) = cred.split_once(':')?;
    if usuario.is_empty() {
        return None;
    }
    Some(format!("{esquema}://{usuario}:{RED}{host}"))
}

/// Redige senha colada na flag, no estilo do `mysql`/`mysqldump` (`-pSENHA`, sem espaço).
///
/// **Onde:** [`scrub_word`]. Outra lacuna do P10. Exige >=3 caracteres depois do `-p` pra não
/// engolir um `-p` solto (que é a flag pedindo prompt) nem um `-p 5432` de porta.
pub(crate) fn redact_inline_password_flag(word: &str) -> Option<String> {
    let resto = word.strip_prefix("-p")?;
    if resto.len() < 3 || resto.chars().all(|c| c.is_ascii_digit()) {
        return None; // `-p`, `-p1`, `-p5432` (porta) ficam
    }
    Some(format!("-p{RED}"))
}

/// Identificadores de credencial da AWS: `AKIA…`/`ASIA…` seguidos de 16 alfanuméricos.
///
/// **Onde:** [`looks_like_secret_token`]. O access key id não é a chave secreta, mas identifica
/// a conta e costuma aparecer colado dela — e um log compartilhável não deve carregá-lo.
pub(crate) fn is_aws_key_id(w: &str) -> bool {
    for pfx in ["AKIA", "ASIA", "AIDA", "AROA"] {
        if let Some(idx) = w.find(pfx) {
            let after = &w[idx + pfx.len()..];
            let n =
                after.chars().take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit()).count();
            if n >= 16 {
                return true;
            }
        }
    }
    false
}

/// Redige UMA palavra (sem espaços): pares `NOME=valor` sensíveis e tokens soltos.
pub(crate) fn scrub_word(word: &str) -> String {
    // URL de conexão: preserva esquema/usuário/host, come só a senha.
    if let Some(r) = redact_url_password(word) {
        return r;
    }
    // Senha colada na flag (`-pSENHA`).
    if let Some(r) = redact_inline_password_flag(word) {
        return r;
    }
    // Par NOME=valor.
    if let Some(eq) = word.find('=') {
        let left = &word[..eq];
        let right = &word[eq + 1..];
        // O valor é uma URL de conexão? Come só a senha e PRESERVA o resto — `DATABASE_URL=`
        // é o nome mais comum de todos e não casa nenhum gatilho de `key_is_secret`, então
        // sem isto a senha passava inteira (achado ao montar o corpus).
        if let Some(r) = redact_url_password(right) {
            return format!("{left}={r}");
        }
        // Redige o valor se o NOME é sensível OU o valor parece um token.
        if !right.is_empty() && (key_is_secret(left) || looks_like_secret_token(right)) {
            return format!("{left}={RED}");
        }
    }
    // Token solto (com ou sem pontuação ao redor).
    if looks_like_secret_token(word) {
        return RED.to_string();
    }
    word.to_string()
}

/// O NOME (lado esquerdo do `=`) indica segredo? Substring case-insensitive dos gatilhos.
pub(crate) fn key_is_secret(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    ["KEY", "TOKEN", "SECRET", "PASS", "CRED"].iter().any(|k| up.contains(k))
}

/// A palavra CONTÉM algo que parece um token/segredo (prefixo conhecido + charset suficiente, ou JWT)?
pub(crate) fn looks_like_secret_token(w: &str) -> bool {
    if is_aws_key_id(w) {
        return true;
    }
    // JWT em qualquer posição.
    if let Some(idx) = w.find("eyJ") {
        if is_jwt(&w[idx..]) {
            return true;
        }
    }
    // Prefixos conhecidos, seguidos de >=8 chars do charset do token.
    const PREFIXES: &[&str] = &[
        "re_",
        "sk-",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "xoxb-",
        "xoxa-",
        "xoxp-",
        "xapp-",
    ];
    for pfx in PREFIXES {
        if let Some(idx) = w.find(pfx) {
            let after = &w[idx + pfx.len()..];
            let n = after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .count();
            if n >= 8 {
                return true;
            }
        }
    }
    false
}

// NOTA DE POSIÇÃO: esta função ficava DEPOIS do `mod tests_lacunas`, e isso não era
// cosmético. Nove testes de conformidade/pentest definem "código de produção" como
// `fonte.split("#[cfg(test)]").next()` — tudo que fica abaixo do primeiro módulo de teste
// some das varreduras. Uma primitiva de REDAÇÃO invisível pro scanner de segurança é
// exatamente o que essas varreduras existem pra impedir. Item de produção vem antes.
/// A fatia começa com um JWT `eyJ…`.`…`.`…` (3 partes base64url não-vazias)?
pub(crate) fn is_jwt(s: &str) -> bool {
    let run: String = s
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        .collect();
    let parts: Vec<&str> = run.split('.').collect();
    if parts.len() < 3 || !parts[0].starts_with("eyJ") {
        return false;
    }
    parts.iter().take(3).all(|p| {
        !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    })
}

#[cfg(test)]
mod tests_lacunas {
    use super::*;

    /// As três lacunas que o pentest (P10) enumerou — agora fechadas.
    #[test]
    fn fecha_as_lacunas_do_pentest() {
        let casos = [
            ("postgres://app:hunter2000@db.internal:5432/prod", "hunter2000", "senha em URL"),
            (
                "DATABASE_URL=mysql://root:s3nh4@127.0.0.1/app",
                "s3nh4",
                "senha em URL dentro de env",
            ),
            ("amqp://svc:p4ssw0rd@rabbit:5672/%2f", "p4ssw0rd", "senha em AMQP"),
            ("mysqldump -u root -psenhaSecreta app", "senhaSecreta", "senha colada no -p"),
            ("AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE", "access key id da AWS"),
            ("ASIAY34FZKBOKMUTVV7A", "ASIAY34FZKBOKMUTVV7A", "credencial temporária STS"),
        ];
        for (entrada, segredo, rotulo) in casos {
            let saida = scrub(entrada);
            assert!(!saida.contains(segredo), "{rotulo}: o segredo passou -> {saida}");
            assert!(saida.contains(RED), "{rotulo}: nada foi redigido -> {saida}");
        }
    }

    /// O que a redação PRESERVA da URL — e por que isso importa.
    #[test]
    fn a_url_continua_legivel_depois_de_redigida() {
        // Um log de diagnóstico existe pra dizer ONDE o app tentou conectar e COM QUEM.
        // Redigir a URL inteira transformaria a proteção num apagador de log útil.
        let s = scrub("postgres://app:hunter2000@db.internal:5432/prod");
        assert!(s.contains("postgres://"), "o esquema tem que ficar: {s}");
        assert!(s.contains("app"), "o usuário tem que ficar: {s}");
        assert!(s.contains("db.internal:5432"), "o host tem que ficar: {s}");
        assert!(s.contains("prod"), "o banco tem que ficar: {s}");
    }

    /// **O teste que mais importa:** corpus de log LEGÍTIMO que não pode ser tocado.
    ///
    /// Foi por medo deste caso que as lacunas ficaram abertas no primeiro pentest. Ampliar
    /// heurística de redação sem provar ausência de falso-positivo troca um problema
    /// (segredo no log) por outro (log ilegível, que faz o usuário desligar a redação).
    #[test]
    fn corpus_legitimo_passa_intacto() {
        let corpus = [
            // URLs sem credencial — o caso mais comum de todos.
            "https://github.com/schematizeme/schematize-cli",
            "git@github.com:schematizeme/app.git",
            "postgres://db.internal:5432/prod",
            "https://user@example.com/path",
            "file:///home/tom/.schematize/vps.db",
            "ssh://deploy@10.0.0.5:22",
            // Flags que começam com -p mas não são senha.
            "-p",
            "-p 5432",
            "-p5432",
            "psql -p 5432 -h db",
            "docker run -p 8080:80 nginx",
            "ssh -p 2222 deploy@host",
            // Palavras que contêm prefixos de token mas não são token.
            "sk-",
            "re_",
            "resource_id",
            "skeleton",
            "reset",
            "AKIA",
            "ASIAtico",
            "AROMA",
            // Saída normal de deploy.
            "systemctl status app.service",
            "Active: active (running) since Fri 2026-08-30 12:00:00 UTC",
            "warning: 3 files changed, 42 insertions(+), 7 deletions(-)",
            "Compiling schematize v0.55.0 (/home/tom/indev/schematize_app)",
            "test result: ok. 381 passed; 0 failed",
            "/usr/local/lib/schematize/ops-shell",
            "restrict,command=\"/home/deploy/.schematize/ops-shell\"",
        ];
        let mut tocados = Vec::new();
        for linha in corpus {
            let saida = scrub(linha);
            if saida != linha {
                tocados.push(format!("{linha:?} -> {saida:?}"));
            }
        }
        assert!(
            tocados.is_empty(),
            "falso-positivo: a redação comeu log legítimo:\n  {}",
            tocados.join("\n  ")
        );
    }

    /// Regressão do que já era pego — ampliar não pode quebrar o que funcionava.
    #[test]
    fn o_que_ja_era_pego_continua_sendo() {
        for (entrada, segredo) in [
            ("re_AbCdEf0123456789", "AbCdEf0123456789"),
            ("sk-abc123def456ghi789jkl", "abc123def456ghi789jkl"),
            ("ghp_AbCdEf0123456789AbCdEf0123456789Ab", "AbCdEf0123456789"),
            (
                "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.aaaa",
                "eyJhbGciOiJIUzI1NiJ9",
            ),
            ("DB_PASSWORD=hunter2000000", "hunter2000000"),
            ("API_KEY=qualquercoisa", "qualquercoisa"),
        ] {
            assert!(!scrub(entrada).contains(segredo), "regrediu: {entrada}");
        }
    }

    /// Idempotência: redigir o já-redigido não muda mais nada.
    #[test]
    fn a_redacao_e_idempotente() {
        for e in [
            "postgres://app:senha@db/x",
            "mysqldump -psenhaSecreta",
            "AKIAIOSFODNN7EXAMPLE",
            "re_AbCdEf0123456789",
        ] {
            let uma = scrub(e);
            assert_eq!(scrub(&uma), uma, "não é idempotente: {e}");
        }
    }
}
