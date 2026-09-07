//! PROTOCOLO — a camada JSON-RPC 2.0 do servidor MCP, pura e testável.
//! O quê: [`responder`] recebe uma mensagem e devolve a resposta (ou `None`, para
//! notificações, que por definição não respondem).
//! Onde: `mcp::servir` faz o laço de stdin/stdout em cima disto.
//!
//! Puro de propósito: todo o comportamento do protocolo — inclusive o hostil (id ausente,
//! método desconhecido, JSON malformado, tipo errado) — é exercitável sem processo, sem pipe
//! e sem Claude Code do outro lado.

use serde_json::{json, Value};

/// Versão do protocolo MCP que este servidor fala.
pub const PROTOCOL_VERSION: &str = "2024-11-05";

/// Nome do servidor, como aparece no `.mcp.json` e nos nomes de tool (`mcp__<nome>__<tool>`).
pub const NOME_DO_SERVIDOR: &str = "schematize-vps";

/// Códigos de erro do JSON-RPC 2.0 que este servidor usa.
pub mod erro {
    /// JSON malformado na linha. **Onde:** `mcp::servir`, quando o parse falha.
    pub const PARSE: i64 = -32700;
    /// Mensagem sem `method`, ou com `jsonrpc` diferente de `"2.0"`.
    pub const REQUISICAO_INVALIDA: i64 = -32600;
    /// Método que este servidor não implementa (ex.: `resources/list`).
    pub const METODO_NAO_ENCONTRADO: i64 = -32601;
    /// `tools/call` sem `name`, ou com `arguments` que não é objeto.
    pub const PARAMS_INVALIDOS: i64 = -32602;
    /// Falha interna. Reservado — hoje nenhum caminho o emite: recusa de tool é `result`
    /// com `isError`, não erro de transporte.
    pub const INTERNO: i64 = -32603;
}

/// Resposta de sucesso.
pub fn ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// Resposta de erro do PROTOCOLO (mensagem malformada, método inexistente).
///
/// Distinto do erro de TOOL: uma tool que recusa por política devolve `result` com
/// `isError: true`, porque a recusa é resultado legítimo — o agente precisa LER o motivo, não
/// receber um erro de transporte.
pub fn erro_de(id: Value, codigo: i64, mensagem: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": codigo, "message": mensagem } })
}

/// Conteúdo de resposta de uma tool.
///
/// `isError: true` sinaliza "a tool rodou e o resultado é uma recusa/falha" — o texto vai
/// pro agente ler e agir. É assim que a recusa da política chega até ele com o motivo
/// inteiro, em vez de virar um erro opaco.
pub fn resultado_de_tool(texto: &str, e_erro: bool) -> Value {
    json!({ "content": [ { "type": "text", "text": texto } ], "isError": e_erro })
}

/// Trata uma mensagem já parseada. `None` = notificação (não se responde a notificação).
///
/// `executar_tool` é injetado pra que o protocolo não conheça as tools — é o que permite
/// testar o protocolo com tools de mentira, e testar as tools sem protocolo.
pub fn responder<F>(msg: &Value, tools: &Value, executar_tool: F) -> Option<Value>
where
    F: FnOnce(&str, &Value) -> Result<String, String>,
{
    let metodo = msg.get("method").and_then(Value::as_str).unwrap_or("");
    // Notificação = mensagem sem `id`. Nunca se responde — responder a uma notificação é erro
    // de protocolo e alguns clientes fecham a conexão.
    let id = msg.get("id").cloned()?;
    if msg.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Some(erro_de(id, erro::REQUISICAO_INVALIDA, "esperava jsonrpc: \"2.0\""));
    }

    match metodo {
        "initialize" => Some(ok(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": NOME_DO_SERVIDOR, "version": env!("CARGO_PKG_VERSION") }
            }),
        )),
        "ping" => Some(ok(id, json!({}))),
        "tools/list" => Some(ok(id, json!({ "tools": tools }))),
        "tools/call" => {
            let params = msg.get("params").cloned().unwrap_or(Value::Null);
            let nome = params.get("name").and_then(Value::as_str).unwrap_or("");
            if nome.is_empty() {
                return Some(erro_de(id, erro::PARAMS_INVALIDOS, "faltou o campo `name`"));
            }
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            // Argumento que não é objeto é entrada hostil como qualquer outra: recusa clara,
            // nunca panic (o `unwrap_or` acima já cobre o ausente).
            if !args.is_object() {
                return Some(erro_de(
                    id,
                    erro::PARAMS_INVALIDOS,
                    "`arguments` precisa ser um objeto",
                ));
            }
            match executar_tool(nome, &args) {
                Ok(texto) => Some(ok(id, resultado_de_tool(&texto, false))),
                // Recusa/falha da tool é RESULTADO, não erro de transporte: o agente precisa
                // ler o motivo pra saber o que fazer.
                Err(motivo) => Some(ok(id, resultado_de_tool(&motivo, true))),
            }
        }
        "" => Some(erro_de(id, erro::REQUISICAO_INVALIDA, "faltou o campo `method`")),
        outro => Some(erro_de(
            id,
            erro::METODO_NAO_ENCONTRADO,
            &format!("método não suportado: {outro}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tools_falsas() -> Value {
        json!([{ "name": "t", "description": "d", "inputSchema": { "type": "object" } }])
    }

    fn resp(msg: Value) -> Option<Value> {
        responder(&msg, &tools_falsas(), |n, _| {
            if n == "t" {
                Ok("feito".into())
            } else {
                Err(format!("tool desconhecida: {n}"))
            }
        })
    }

    #[test]
    fn initialize_declara_versao_e_capacidade() {
        let r = resp(json!({"jsonrpc":"2.0","id":1,"method":"initialize"})).unwrap();
        assert_eq!(r["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(r["result"]["serverInfo"]["name"], NOME_DO_SERVIDOR);
        assert!(r["result"]["capabilities"]["tools"].is_object());
        assert_eq!(r["id"], 1);
    }

    #[test]
    fn tools_list_devolve_o_catalogo() {
        let r = resp(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})).unwrap();
        assert_eq!(r["result"]["tools"][0]["name"], "t");
    }

    #[test]
    fn notificacao_nao_recebe_resposta() {
        // Responder a notificação é erro de protocolo — alguns clientes fecham a conexão.
        assert!(resp(json!({"jsonrpc":"2.0","method":"notifications/initialized"})).is_none());
        assert!(resp(json!({"jsonrpc":"2.0","method":"qualquer"})).is_none());
    }

    #[test]
    fn recusa_da_tool_vira_resultado_lido_pelo_agente_nao_erro_de_transporte() {
        let r = responder(
            &json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{"name":"t","arguments":{}}}),
            &tools_falsas(),
            |_, _| Err("recusado pela política: comando catastrófico".into()),
        )
        .unwrap();
        assert!(r.get("error").is_none(), "não pode ser erro de JSON-RPC");
        assert_eq!(r["result"]["isError"], true);
        let texto = r["result"]["content"][0]["text"].as_str().unwrap();
        assert!(texto.contains("recusado pela política"), "o agente tem que LER o motivo: {texto}");
    }

    #[test]
    fn entrada_hostil_vira_erro_estruturado_nunca_panic() {
        // Um por vetor: cada um destes já derrubou algum servidor MCP por aí.
        let casos = [
            json!({"jsonrpc":"2.0","id":1,"method":"nao/existe"}),
            json!({"jsonrpc":"2.0","id":1}),
            json!({"jsonrpc":"1.0","id":1,"method":"initialize"}),
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call"}),
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}),
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":""}}),
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":42}}),
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":"texto"}}),
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":123}}),
            json!({"jsonrpc":"2.0","id":null,"method":"initialize"}),
            json!({"jsonrpc":"2.0","id":"str","method":"initialize"}),
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t\u{0}x","arguments":{}}}),
        ];
        for c in casos {
            let r = resp(c.clone());
            assert!(r.is_some(), "toda requisição com id tem que ter resposta: {c}");
            let r = r.unwrap();
            assert_eq!(r["jsonrpc"], "2.0");
            assert!(r.get("id").is_some(), "a resposta tem que ecoar o id: {r}");
            assert!(
                r.get("error").is_some() || r.get("result").is_some(),
                "ou erro ou resultado, nunca nenhum dos dois: {r}"
            );
        }
    }

    #[test]
    fn id_e_ecoado_do_jeito_que_veio() {
        // Cliente pode usar número, string ou null — o eco tem que ser fiel.
        for id in [json!(7), json!("abc"), json!(null)] {
            let r = resp(json!({"jsonrpc":"2.0","id":id,"method":"initialize"})).unwrap();
            assert_eq!(r["id"], id);
        }
    }

    #[test]
    fn metodo_desconhecido_e_erro_de_protocolo_com_codigo_certo() {
        let r = resp(json!({"jsonrpc":"2.0","id":1,"method":"resources/list"})).unwrap();
        assert_eq!(r["error"]["code"], erro::METODO_NAO_ENCONTRADO);
    }
}
