//! TOOLS — as cinco funções que o agente enxerga do gestor de VPS.
//! O quê: o schema declarado (`tools/list`) e a execução de cada uma.
//! Onde: `mcp::protocolo` despacha pra cá; a lib `vps` faz o trabalho.
//!
//! ## O agente NÃO pode se autoconfirmar
//!
//! `vps_exec` sempre passa [`Confirmacao::Ausente`]. Um host de produção, ou um comando com
//! encadeamento, devolve a recusa pedindo confirmação humana — e não há argumento, campo ou
//! combinação de parâmetros que faça o agente responder essa pergunta por conta própria.
//! Confirmação humana que o agente pode dar sozinho não é confirmação humana.
//!
//! ## Nada aqui reimplementa regra
//! Toda tool passa por `vps::executar`, que avalia a política e grava a auditoria. O MCP é
//! uma porta a mais para a MESMA lógica — se ele tivesse a sua própria, seria só mais um jeito
//! de escapar.

use crate::vps;
use serde_json::{json, Value};

/// O schema das cinco tools, como o `tools/list` devolve.
///
/// **Onde:** `mcp::servir`. As descrições são escritas pro AGENTE ler: dizem o que a tool faz
/// e, principalmente, o que ela **não** faz — é o que evita ele tentar o caminho errado e
/// bater na política três vezes antes de entender.
pub fn schema() -> Value {
    json!([
        {
            "name": "vps_list",
            "description": "Lista as VPS registradas, com ambiente, modo de política, se a host key está pinada e que nível de fronteira cada uma tem no servidor. Comece por aqui.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
        },
        {
            "name": "vps_open",
            "description": "Abre uma VPS: devolve os dados do host e o CATÁLOGO DE VERBOS que ele aceita. Não conecta nem executa nada — é o passo que diz o que você pode pedir naquele host.",
            "inputSchema": {
                "type": "object",
                "properties": { "alias": { "type": "string", "description": "o alias do host (veja vps_list)" } },
                "required": ["alias"],
                "additionalProperties": false
            }
        },
        {
            "name": "vps_exec",
            "description": "Executa um comando (ou um verbo do catálogo) numa VPS, com política e auditoria. Host de produção e comandos com encadeamento exigem confirmação de um HUMANO: a tool devolve o pedido de confirmação, e não há como você confirmar sozinho — peça ao usuário.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "alias": { "type": "string", "description": "o alias do host" },
                    "comando": { "type": "string", "description": "o comando ou verbo a executar" }
                },
                "required": ["alias", "comando"],
                "additionalProperties": false
            }
        },
        {
            "name": "vps_tail",
            "description": "Mostra as últimas execuções auditadas de uma VPS (comando, veredito, exit code, duração). Use pra ver o que já foi feito antes de repetir algo.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "alias": { "type": "string", "description": "o alias do host; vazio = todos" },
                    "n": { "type": "integer", "description": "quantas linhas (padrão 20, máximo 200)" }
                },
                "additionalProperties": false
            }
        },
        {
            "name": "vps_close",
            "description": "Encerra o trabalho numa VPS e devolve o resumo do que rodou nesta sessão. Use ao terminar uma tarefa no host.",
            "inputSchema": {
                "type": "object",
                "properties": { "alias": { "type": "string" } },
                "required": ["alias"],
                "additionalProperties": false
            }
        }
    ])
}

/// Extrai um campo string obrigatório, com erro que ENSINA em vez de só reclamar.
///
/// **Onde:** cada tool que recebe `alias`/`comando`. Tipo errado é entrada hostil comum
/// (um agente manda número onde esperava string) e não pode virar panic.
fn campo_str(args: &Value, nome: &str) -> Result<String, String> {
    match args.get(nome) {
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(s.trim().to_string()),
        Some(Value::String(_)) | None => Err(format!("faltou o parâmetro `{nome}`")),
        Some(outro) => Err(format!(
            "o parâmetro `{nome}` tem que ser texto, veio {}",
            match outro {
                Value::Number(_) => "número",
                Value::Bool(_) => "booleano",
                Value::Array(_) => "lista",
                Value::Object(_) => "objeto",
                Value::Null => "null",
                Value::String(_) => "texto",
            }
        )),
    }
}

/// Despacha uma chamada de tool.
///
/// **Onde:** `mcp::servir`, via `protocolo::responder`. **Erros:** devolvidos como `Err`, que
/// o protocolo transforma em `isError: true` — o agente lê o motivo e corrige o rumo.
pub fn executar(nome: &str, args: &Value) -> Result<String, String> {
    let conn = vps::db::open()?;
    match nome {
        "vps_list" => {
            let hosts = vps::listar(&conn, )?;
            if hosts.is_empty() {
                return Ok("Nenhuma VPS registrada. O usuário precisa registrar uma com `schematize vps add <alias> --host <ip> --user <user> --key <chave>` — você não pode fazer isso por ele.".into());
            }
            let mut s = String::from("VPS registradas:\n");
            for h in &hosts {
                s.push_str(&format!(
                    "- {} — {}@{}:{} · ambiente={} · modo={} · host key={} · fronteira={}\n",
                    h.alias, h.usuario, h.host, h.port,
                    h.ambiente.as_str(), h.modo.as_str(),
                    if vps::esta_confiado(h) { "pinada" } else { "NÃO CONFIADA (peça ao usuário: `schematize vps trust`)" },
                    h.fronteira.rotulo()
                ));
            }
            Ok(s)
        }
        "vps_open" => {
            let alias = campo_str(args, "alias")?;
            let h = vps::buscar(&conn, &alias)?.ok_or_else(|| host_ausente(&alias))?;
            let verbos = vps::verbos::listar(&conn, &alias)?;
            let mut s = format!(
                "{} — {}@{}:{}\nambiente: {} (produção exige confirmação humana em toda execução)\nmodo: {}\nfronteira: {}\n{}\n",
                h.alias, h.usuario, h.host, h.port,
                h.ambiente.as_str(), h.modo.as_str(), h.fronteira.rotulo(), h.fronteira.explicacao()
            );
            if !vps::esta_confiado(&h) {
                s.push_str("\nATENÇÃO: a host key não está pinada — nenhuma execução vai funcionar até o usuário rodar `schematize vps trust <alias>`.\n");
            }
            if verbos.is_empty() {
                s.push_str("\nCatálogo de verbos: vazio.\n");
                if h.modo == vps::ModoPolitica::OpsVerbs {
                    s.push_str("Como o modo é ops-verbs, NADA será aceito até o usuário criar verbos.\n");
                }
            } else {
                s.push_str(&format!("\nCatálogo — {} verbo(s) que este host aceita:\n", verbos.len()));
                for v in &verbos {
                    s.push_str(&format!("  {:<16} {}\n", v.nome, v.comando));
                }
            }
            Ok(s)
        }
        "vps_exec" => {
            let alias = campo_str(args, "alias")?;
            let comando = campo_str(args, "comando")?;
            let p = vps::buscar(&conn, &alias)?.ok_or_else(|| host_ausente(&alias))?;
            // SEMPRE `Ausente`. Não existe parâmetro que mude isto — ver o doc do módulo.
            let out = vps::executar(&conn, &p, &comando, "mcp", vps::Confirmacao::Ausente)?;
            let mut s = format!(
                "exit={} · {} ms · auditado (id {})\n",
                out.exit_code.map(|c| c.to_string()).unwrap_or_else(|| "sinal".into()),
                out.duracao_ms, out.auditoria_id
            );
            if !out.stdout.trim().is_empty() {
                s.push_str(&format!("\n--- saída ---\n{}\n", out.stdout.trim_end()));
            }
            if !out.stderr.trim().is_empty() {
                s.push_str(&format!("\n--- erros ---\n{}\n", out.stderr.trim_end()));
            }
            if let Some(e) = &out.erro {
                s.push_str(&format!("\nfalha de conexão: {e}\n"));
            }
            Ok(s)
        }
        "vps_tail" => {
            let alias = args.get("alias").and_then(Value::as_str).unwrap_or("").trim().to_string();
            let n = args.get("n").and_then(Value::as_i64).unwrap_or(20).clamp(1, 200) as usize;
            let linhas = vps::listar_comandos(&conn, &alias, n)?;
            if linhas.is_empty() {
                return Ok("Nada registrado ainda.".into());
            }
            let mut s = format!("Últimas {} execução(ões):\n", linhas.len());
            for l in &linhas {
                s.push_str(&format!(
                    "- [{}] {} · {} · exit={} · {}ms · {}\n",
                    l.ts, l.alias, l.veredito,
                    l.exit_code.map(|c| c.to_string()).unwrap_or_else(|| "-".into()),
                    l.duracao_ms, l.comando
                ));
            }
            Ok(s)
        }
        "vps_close" => {
            let alias = campo_str(args, "alias")?;
            if vps::buscar(&conn, &alias)?.is_none() {
                return Err(host_ausente(&alias));
            }
            let n = vps::contar_comandos(&conn, &alias)?;
            Ok(format!(
                "Sessão em {alias:?} encerrada. {n} execução(ões) na trilha deste host — consulte com vps_tail."
            ))
        }
        outro => Err(format!(
            "tool desconhecida: {outro:?}. As que existem: vps_list, vps_open, vps_exec, vps_tail, vps_close"
        )),
    }
}

/// Mensagem de host inexistente, escrita pro agente saber o próximo passo.
fn host_ausente(alias: &str) -> String {
    format!(
        "não existe VPS registrada com o alias {alias:?}. Use vps_list pra ver as que existem. Registrar uma nova é ação do usuário (`schematize vps add`), não sua."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn o_schema_declara_exatamente_as_cinco_tools() {
        let s = schema();
        let nomes: Vec<&str> =
            s.as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(nomes, ["vps_list", "vps_open", "vps_exec", "vps_tail", "vps_close"]);
    }

    #[test]
    fn toda_tool_tem_schema_de_entrada_valido() {
        for t in schema().as_array().unwrap() {
            let nome = t["name"].as_str().unwrap();
            assert!(!t["description"].as_str().unwrap_or("").is_empty(), "{nome} sem descrição");
            assert_eq!(t["inputSchema"]["type"], "object", "{nome}");
            assert!(t["inputSchema"]["properties"].is_object(), "{nome}");
        }
    }

    #[test]
    fn a_descricao_do_exec_avisa_que_o_agente_nao_se_autoconfirma() {
        let s = schema();
        let exec = s.as_array().unwrap().iter().find(|t| t["name"] == "vps_exec").unwrap();
        let d = exec["description"].as_str().unwrap();
        assert!(d.contains("HUMANO"), "o agente precisa saber disso antes de tentar: {d}");
        assert!(d.contains("não há como você confirmar sozinho"), "{d}");
    }

    #[test]
    fn o_exec_nao_expoe_campo_de_confirmacao() {
        // Se algum dia alguém acrescentar `confirmar` ao schema, isto cai — e tem que cair.
        let s = schema();
        let exec = s.as_array().unwrap().iter().find(|t| t["name"] == "vps_exec").unwrap();
        let props = exec["inputSchema"]["properties"].as_object().unwrap();
        for proibido in ["confirmar", "confirm", "force", "yes", "skip_policy"] {
            assert!(
                !props.contains_key(proibido),
                "o agente não pode se autoconfirmar: {proibido}"
            );
        }
        assert_eq!(exec["inputSchema"]["additionalProperties"], false, "nada além do declarado");
    }

    #[test]
    fn campo_str_recusa_tipo_errado_com_mensagem_que_ensina() {
        assert_eq!(campo_str(&json!({"alias":"srv"}), "alias").unwrap(), "srv");
        assert_eq!(campo_str(&json!({"alias":"  srv  "}), "alias").unwrap(), "srv");
        for (v, esperado) in [
            (json!({"alias": 42}), "número"),
            (json!({"alias": true}), "booleano"),
            (json!({"alias": ["a"]}), "lista"),
            (json!({"alias": {}}), "objeto"),
            (json!({"alias": null}), "null"),
        ] {
            let e = campo_str(&v, "alias").unwrap_err();
            assert!(e.contains(esperado), "esperava {esperado:?} na mensagem: {e}");
        }
        assert!(campo_str(&json!({}), "alias").is_err());
        assert!(campo_str(&json!({"alias":"   "}), "alias").is_err(), "só espaço é ausente");
    }

    #[test]
    fn tool_desconhecida_lista_as_que_existem() {
        let e = executar("vps_apaga_tudo", &json!({})).unwrap_err();
        assert!(e.contains("vps_list") && e.contains("vps_exec"), "{e}");
    }
}
