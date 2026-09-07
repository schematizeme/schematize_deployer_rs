//! MCP — o servidor stdio que dá ao agente a porta auditada do gestor de VPS.
//! O quê: laço JSON-RPC 2.0 sobre stdin/stdout, expondo cinco tools (`vps_list`, `vps_open`,
//! `vps_exec`, `vps_tail`, `vps_close`).
//! Onde: `schematize mcp serve`, registrado no `.mcp.json` do projeto.
//!
//! ## Por que existe, se já há o hook e o CLI
//! O hook (`vps::hook`) **fecha** a porta errada; este módulo **abre** a certa, com nome e
//! schema que o agente entende sem adivinhar. Sem ele, o agente barrado pelo hook fica sem
//! saber o que fazer — que é exatamente o anti-padrão §37.48 aplicado a um agente.
//!
//! O protocolo (`protocolo`) e as tools (`tools`) são módulos separados e puros: o laço de
//! I/O aqui é fino de propósito, porque laço de I/O não se testa bem.

pub mod protocolo;
pub mod tools;

/// Tamanho máximo de UMA mensagem. Acima disto a linha é recusada sem ser materializada.
///
/// Existe porque `BufRead::lines()` aloca a linha inteira: no teste destrutivo, 300 MB de
/// entrada viraram **1,7 GB de RSS**. O servidor MCP roda como subprocesso na máquina do
/// usuário — um cliente com defeito (ou hostil) não pode derrubar a máquina dele.
/// 1 MB é ordens de grandeza acima de qualquer chamada legítima.
pub const MAX_LINHA: u64 = 1024 * 1024;

/// Roda o servidor até o stdin fechar. Uma mensagem JSON por linha.
///
/// **Onde:** `schematize mcp serve`. **Falha aberta por linha:** uma mensagem malformada vira
/// resposta de erro e o laço SEGUE — um servidor MCP que morre na primeira linha estranha
/// derruba a sessão inteira do usuário.
pub fn servir() {
    use std::io::Write;
    let schema = tools::schema();
    let entrada = std::io::stdin();
    let mut leitor = entrada.lock();
    let mut saida = std::io::stdout();
    loop {
        let resposta = match ler_linha(&mut leitor, MAX_LINHA) {
            Fim::Eof => break,
            Fim::Linha(l) if l.trim().is_empty() => continue,
            Fim::Linha(l) => match serde_json::from_str::<serde_json::Value>(&l) {
                Ok(msg) => protocolo::responder(&msg, &schema, tools::executar),
                Err(e) => Some(protocolo::erro_de(
                    serde_json::Value::Null,
                    protocolo::erro::PARSE,
                    &format!("JSON inválido: {e}"),
                )),
            },
            Fim::GrandeDemais => Some(protocolo::erro_de(
                serde_json::Value::Null,
                protocolo::erro::REQUISICAO_INVALIDA,
                &format!("mensagem acima do limite de {MAX_LINHA} bytes; foi descartada e o canal segue aberto"),
            )),
        };
        if let Some(r) = resposta {
            // stdout é o CANAL do protocolo: nada além de JSON-RPC pode sair por aqui, ou o
            // cliente perde o sincronismo. Diagnóstico vai pro stderr.
            if writeln!(saida, "{r}").is_err() || saida.flush().is_err() {
                break;
            }
        }
    }
}

/// O que a leitura de uma linha produziu.
enum Fim {
    /// Uma linha completa (sem o terminador).
    Linha(String),
    /// A linha passou do teto: foi DESCARTADA até a próxima quebra, e o canal segue utilizável.
    GrandeDemais,
    /// Fim da entrada.
    Eof,
}

/// Lê uma linha com teto de alocação. **Nunca materializa mais que `max` bytes.**
///
/// Quando a linha estoura o teto, o resto dela é consumido em pedaços de `max` (sem guardar)
/// até a quebra de linha, e o laço volta sincronizado — a mensagem SEGUINTE é atendida
/// normalmente. A primeira tentativa de correção descartava um bloco fixo e engolia a próxima
/// mensagem junto: o servidor sobrevivia mas ficava surdo, o que não é conserto.
///
/// **Onde:** [`servir`].
fn ler_linha(leitor: &mut impl std::io::BufRead, max: u64) -> Fim {
    // As duas traits precisam estar em ESCOPO: `Read` pelo `take`, `BufRead` pelo `read_until`.
    use std::io::{BufRead, Read};
    let mut bruto = Vec::new();
    let n = match leitor.by_ref().take(max).read_until(b'\n', &mut bruto) {
        Ok(n) => n,
        Err(_) => return Fim::Eof,
    };
    if n == 0 {
        return Fim::Eof;
    }
    if bruto.ends_with(b"\n") {
        while matches!(bruto.last(), Some(b'\n' | b'\r')) {
            bruto.pop();
        }
        return Fim::Linha(String::from_utf8_lossy(&bruto).into_owned());
    }
    // Sem quebra de linha: ou é a última linha da entrada, ou estourou o teto.
    if (n as u64) < max {
        return Fim::Linha(String::from_utf8_lossy(&bruto).into_owned());
    }
    drop(bruto);
    // Estourou: consome o resto DESTA linha, em pedaços, sem guardar nada.
    loop {
        let mut lixo = Vec::new();
        match leitor.by_ref().take(max).read_until(b'\n', &mut lixo) {
            Ok(0) => break,
            Ok(_) if lixo.ends_with(b"\n") => break,
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    Fim::GrandeDemais
}

/// O bloco que vai pro `.mcp.json` do projeto, pronto pra colar.
///
/// **Onde:** `schematize mcp install`, que grava o arquivo, e `mcp config`, que só imprime.
pub fn bloco_mcp_json(exe: &str) -> serde_json::Value {
    serde_json::json!({
        "mcpServers": {
            protocolo::NOME_DO_SERVIDOR: { "command": exe, "args": ["mcp", "serve"] }
        }
    })
}

/// Os nomes de permissão que o Claude Code usa pra estas tools (`mcp__<servidor>__<tool>`).
///
/// **Onde:** `schematize mcp install`, que os acrescenta ao `permissions.allow` — sem isso o
/// usuário aprova cada chamada à mão, e a ferramenta que existe pra tirar fricção vira
/// fricção.
pub fn nomes_de_permissao() -> Vec<String> {
    tools::schema()
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|t| t["name"].as_str())
                .map(|n| format!("mcp__{}__{n}", protocolo::NOME_DO_SERVIDOR))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn o_bloco_do_mcp_json_tem_a_forma_esperada() {
        let b = bloco_mcp_json("/usr/bin/schematize");
        assert_eq!(b["mcpServers"]["schematize-vps"]["command"], "/usr/bin/schematize");
        assert_eq!(b["mcpServers"]["schematize-vps"]["args"][0], "mcp");
        assert_eq!(b["mcpServers"]["schematize-vps"]["args"][1], "serve");
    }

    #[test]
    fn nomes_de_permissao_cobrem_as_cinco_tools() {
        let n = nomes_de_permissao();
        assert_eq!(n.len(), 5);
        assert!(n.contains(&"mcp__schematize-vps__vps_exec".to_string()));
        for x in &n {
            assert!(x.starts_with("mcp__schematize-vps__"), "{x}");
        }
    }
}
