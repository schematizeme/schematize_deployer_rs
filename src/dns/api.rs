//! DNS — o cliente da API da Cloudflare.
//!
//! **O quê:** monta as requisições, interpreta o envelope de resposta e traduz erro da API em
//! mensagem acionável. O **transporte** é um trait, e é isso que torna tudo aqui testável.
//!
//! **Onde:** `dns::operacoes`, que é quem a CLI chama.
//!
//! ## Por que o transporte é um trait
//!
//! Sem isso, cada teste desta lógica exigiria rede, uma conta de verdade e um token de
//! verdade — e testes assim não rodam no CI, então não rodam. Com [`Transporte`], o
//! interpretador de resposta, o construtor de URL e a tradução de erro são exercitados contra
//! respostas de mentira, incluindo as que ninguém consegue provocar sob demanda (429, 5xx,
//! JSON truncado).
//!
//! ## O token nunca sai daqui
//!
//! Ele entra no header `Authorization` **dentro do processo**. Não vai para argv (que `ps`
//! mostra para qualquer processo do usuário), não vai para arquivo temporário, e não aparece
//! em nenhuma mensagem de erro — [`redigir`] existe para garantir a última parte, porque a
//! Cloudflare às vezes ecoa parte da requisição no corpo do erro.

use serde::Deserialize;

/// Base da API v4. Constante para o teste poder afirmar a URL montada sem adivinhar.
pub const BASE: &str = "https://api.cloudflare.com/client/v4";

/// Uma resposta crua do transporte: código HTTP + corpo.
#[derive(Debug, Clone)]
pub struct Resposta {
    pub status: u16,
    pub corpo: String,
}

/// **O quê:** como as requisições saem da máquina.
///
/// **Onde:** [`Cloudflare`]. Implementado por [`Ureq`] em produção e por dublês nos testes.
pub trait Transporte {
    /// Executa `metodo url` com o token e um corpo JSON opcional.
    fn enviar(
        &self,
        metodo: &str,
        url: &str,
        token: &str,
        corpo: Option<&serde_json::Value>,
    ) -> Result<Resposta, String>;
}

/// O transporte de verdade, em processo.
pub struct Ureq;

impl Transporte for Ureq {
    fn enviar(
        &self,
        metodo: &str,
        url: &str,
        token: &str,
        corpo: Option<&serde_json::Value>,
    ) -> Result<Resposta, String> {
        let req = ureq::request(metodo, url)
            .set("Authorization", &format!("Bearer {token}"))
            .set("Content-Type", "application/json")
            .set("User-Agent", "schematize-deployer");
        let r = match corpo {
            Some(c) => req.send_json(c.clone()),
            None => req.call(),
        };
        match r {
            Ok(resp) => {
                let status = resp.status();
                let corpo = resp.into_string().unwrap_or_default();
                Ok(Resposta { status, corpo })
            }
            // 4xx/5xx não são erro de transporte: a Cloudflare põe o motivo no CORPO, e é ele
            // que interessa. Tratar como falha de rede aqui apagaria a mensagem útil.
            Err(ureq::Error::Status(status, resp)) => {
                Ok(Resposta { status, corpo: resp.into_string().unwrap_or_default() })
            }
            Err(e) => Err(format!("falha de rede: {}", redigir(&e.to_string(), token))),
        }
    }
}

/// **O quê:** troca toda ocorrência do token por `***` num texto.
///
/// **Onde:** toda mensagem de erro que sai deste módulo.
///
/// **Por que:** o corpo de erro da Cloudflare às vezes ecoa parte da requisição, e uma
/// mensagem de rede pode carregar a URL com header. Um token que vaza no `stderr` vai parar
/// no log do agente, que é exatamente o lugar de onde ele foi tirado. Função PURA e testada.
pub fn redigir(texto: &str, token: &str) -> String {
    if token.is_empty() {
        return texto.to_string();
    }
    texto.replace(token, "***")
}

/// O envelope que a Cloudflare devolve em toda rota da v4.
#[derive(Debug, Deserialize)]
struct Envelope<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<ErroCf>,
    // Sem `#[serde(default)]`: num `Option<T>` genérico ele exigiria `T: Default`, e o que se
    // quer — "campo ausente vira `None`" — o `Option` já faz sozinho.
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct ErroCf {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

/// **O quê:** interpreta o envelope e devolve o `result`, ou um erro que diz o que fazer.
///
/// **Onde:** todas as operações. Função quase pura (só texto → resultado), e por isso coberta
/// por teste com corpos de mentira — inclusive os que não se consegue provocar sob demanda.
///
/// **Por que o status HTTP e o `success` são checados juntos:** a Cloudflare devolve 200 com
/// `success: false` em alguns casos, e status 4xx com um envelope completo em outros. Confiar
/// em só um dos dois deixa metade das falhas passar por sucesso.
pub fn interpretar<T: serde::de::DeserializeOwned>(
    r: &Resposta,
    token: &str,
    contexto: &str,
) -> Result<T, String> {
    let env: Envelope<T> = serde_json::from_str(&r.corpo).map_err(|e| {
        format!(
            "{contexto}: a Cloudflare respondeu {} com algo que não é o JSON esperado ({}). \
             Corpo: {}",
            r.status,
            e,
            redigir(&r.corpo.chars().take(200).collect::<String>(), token)
        )
    })?;

    if !env.success || !(200..300).contains(&r.status) {
        return Err(traduzir_erro(r.status, &env.errors, contexto, token));
    }
    env.result.ok_or_else(|| format!("{contexto}: a Cloudflare respondeu sem `result`"))
}

/// **O quê:** transforma o erro da Cloudflare numa mensagem que diz o PRÓXIMO PASSO.
///
/// **Onde:** [`interpretar`]. Função PURA — recebe status e erros, devolve texto.
///
/// **Por que existe:** `10000 Authentication error` não diz a ninguém que o token está errado
/// ou sem permissão de Zone:DNS:Edit. §37.48: a mensagem ensina, e não culpa.
/// A instrução para toda falha de autenticação — uma só, para os dois braços do `match`.
const AUTH_DICA: &str = "\n  → o token não foi aceito. Confira com `deployer dns auth --status`, \
     e que ele tenha as permissões Zone:Read e DNS:Edit das zonas que for gerir. \
     Guarde outro com `deployer dns auth`";

fn traduzir_erro(status: u16, erros: &[ErroCf], contexto: &str, token: &str) -> String {
    let detalhe = if erros.is_empty() {
        format!("HTTP {status}")
    } else {
        erros
            .iter()
            .map(|e| format!("[{}] {}", e.code, redigir(&e.message, token)))
            .collect::<Vec<_>>()
            .join("; ")
    };
    // Os códigos da família "o token não presta". `10000` é o documentado, mas um token
    // malformado devolve **6003** (`Invalid request headers`) com status 400 — medido contra
    // a API de verdade —, e `6111` quando o header não casa o formato. Sem eles nesta lista,
    // o caso MAIS COMUM (colar o token errado) sai sem instrução nenhuma.
    const AUTH: &[i64] = &[10000, 6003, 6111, 9109];
    let dica = match (status, erros.first().map(|e| e.code)) {
        (401, _) | (403, _) => AUTH_DICA,
        (_, Some(c)) if AUTH.contains(&c) => AUTH_DICA,
        (429, _) => {
            "\n  → limite de requisições da Cloudflare. Espere um pouco e repita; se for um \
             laço, reduza o ritmo"
        }
        (s, _) if s >= 500 => "\n  → falha do lado da Cloudflare. Repetir costuma resolver",
        (404, _) => "\n  → não achei. Confira o nome da zona com `deployer dns zones`",
        _ => "",
    };
    format!("{contexto}: {detalhe}{dica}")
}

/// O cliente. Genérico no transporte para o teste poder trocá-lo.
pub struct Cloudflare<T: Transporte> {
    transporte: T,
    token: String,
}

impl<T: Transporte> Cloudflare<T> {
    pub fn novo(transporte: T, token: String) -> Self {
        Cloudflare { transporte, token }
    }

    /// **O quê:** faz a chamada e já interpreta o envelope.
    /// **Onde:** todas as operações de `dns::operacoes`.
    pub fn chamar<R: serde::de::DeserializeOwned>(
        &self,
        metodo: &str,
        caminho: &str,
        corpo: Option<&serde_json::Value>,
        contexto: &str,
    ) -> Result<R, String> {
        let url = format!("{BASE}{caminho}");
        let r = self.transporte.enviar(metodo, &url, &self.token, corpo)?;
        interpretar(&r, &self.token, contexto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Dublê: guarda o que foi pedido e devolve o que o teste mandar.
    struct Fake {
        resposta: Resposta,
        visto: RefCell<Vec<(String, String, Option<String>)>>,
    }
    impl Fake {
        fn com(status: u16, corpo: &str) -> Self {
            Fake {
                resposta: Resposta { status, corpo: corpo.to_string() },
                visto: RefCell::new(Vec::new()),
            }
        }
    }
    impl Transporte for Fake {
        fn enviar(
            &self,
            metodo: &str,
            url: &str,
            _token: &str,
            corpo: Option<&serde_json::Value>,
        ) -> Result<Resposta, String> {
            self.visto.borrow_mut().push((
                metodo.to_string(),
                url.to_string(),
                corpo.map(|c| c.to_string()),
            ));
            Ok(self.resposta.clone())
        }
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct Zona {
        id: String,
        name: String,
    }

    /// Caminho feliz: envelope com `success: true` devolve o `result`, e a URL montada é a
    /// da API v4 — sem barra dupla nem caminho relativo perdido.
    #[test]
    fn sucesso_devolve_result_e_monta_a_url() {
        let f = Fake::com(
            200,
            r#"{"success":true,"errors":[],"result":[{"id":"z1","name":"ex.com"}]}"#,
        );
        let cf = Cloudflare::novo(f, "tok".into());
        let z: Vec<Zona> = cf.chamar("GET", "/zones", None, "listar zonas").unwrap();
        assert_eq!(z, vec![Zona { id: "z1".into(), name: "ex.com".into() }]);
        let visto = cf.transporte.visto.borrow();
        assert_eq!(visto[0].0, "GET");
        assert_eq!(visto[0].1, "https://api.cloudflare.com/client/v4/zones");
    }

    /// **O caso que engana:** HTTP 200 com `success: false`. Confiar só no status deixaria
    /// esta falha passar por sucesso.
    #[test]
    fn status_200_com_success_falso_e_erro() {
        let f = Fake::com(
            200,
            r#"{"success":false,"errors":[{"code":81044,"message":"registro duplicado"}],"result":null}"#,
        );
        let cf = Cloudflare::novo(f, "tok".into());
        let r: Result<Vec<Zona>, _> = cf.chamar("GET", "/zones", None, "listar zonas");
        let e = r.unwrap_err();
        assert!(e.contains("81044") && e.contains("duplicado"), "{e}");
    }

    /// Cada erro conhecido vira uma instrução diferente — `10000` sozinho não diz nada.
    #[test]
    fn erros_conhecidos_viram_proximo_passo() {
        let auth = traduzir_erro(
            403,
            &[ErroCf { code: 10000, message: "Authentication error".into() }],
            "listar",
            "tok",
        );
        assert!(auth.contains("Zone:Read"), "tem de dizer a permissão que falta: {auth}");

        // MEDIDO contra a API de verdade: token malformado devolve 400/6003, não 10000.
        // Sem este código na lista, o erro mais comum sai sem instrução nenhuma.
        let seis = traduzir_erro(
            400,
            &[ErroCf { code: 6003, message: "Invalid request headers".into() }],
            "listar",
            "tok",
        );
        assert!(seis.contains("dns auth"), "6003 é o erro real de token errado: {seis}");

        let lim = traduzir_erro(429, &[], "listar", "tok");
        assert!(lim.contains("limite"), "{lim}");

        let cf5 = traduzir_erro(503, &[], "listar", "tok");
        assert!(cf5.contains("Cloudflare"), "{cf5}");

        let nf = traduzir_erro(404, &[], "listar", "tok");
        assert!(nf.contains("dns zones"), "tem de dizer como descobrir a zona: {nf}");
    }

    /// **O token NUNCA aparece numa mensagem de erro.** A Cloudflare às vezes ecoa parte da
    /// requisição; sem esta redação, o token iria para o stderr — e daí para o log do agente,
    /// que é exatamente de onde ele foi tirado.
    #[test]
    fn o_token_nunca_vaza_em_erro() {
        let tok = "cf-token-super-secreto";
        let corpo = format!(
            r#"{{"success":false,"errors":[{{"code":10000,"message":"bad token {tok}"}}],"result":null}}"#
        );
        let f = Fake::com(403, &corpo);
        let cf = Cloudflare::novo(f, tok.into());
        let r: Result<Vec<Zona>, _> = cf.chamar("GET", "/zones", None, "listar");
        let e = r.unwrap_err();
        assert!(!e.contains(tok), "o token vazou na mensagem: {e}");
        assert!(e.contains("***"), "devia estar redigido: {e}");
    }

    /// Corpo que não é JSON (proxy corporativo devolvendo HTML, por exemplo) dá erro legível
    /// com um trecho — e o trecho também é redigido.
    #[test]
    fn corpo_nao_json_da_erro_legivel_e_redigido() {
        let tok = "tok-secreto";
        let f = Fake::com(502, &format!("<html>proxy barrou {tok}</html>"));
        let cf = Cloudflare::novo(f, tok.into());
        let r: Result<Vec<Zona>, _> = cf.chamar("GET", "/zones", None, "listar");
        let e = r.unwrap_err();
        assert!(e.contains("502"), "tem de dizer o status: {e}");
        assert!(!e.contains(tok), "vazou o token no trecho do corpo: {e}");
    }

    /// `redigir` é pura e cobre o caso do token vazio (não pode virar `***` em todo lugar).
    #[test]
    fn redigir_e_pura_e_tolera_token_vazio() {
        assert_eq!(redigir("olha o abc aqui", "abc"), "olha o *** aqui");
        assert_eq!(redigir("nada a esconder", ""), "nada a esconder", "token vazio não redige");
        assert_eq!(redigir("abc abc", "abc"), "*** ***", "redige TODAS as ocorrências");
    }

    /// O corpo enviado chega ao transporte — é o que garante que um `add` manda mesmo o
    /// registro, e não um POST vazio.
    #[test]
    fn o_corpo_json_chega_ao_transporte() {
        let f = Fake::com(
            200,
            r#"{"success":true,"errors":[],"result":{"id":"r1","name":"a.ex.com"}}"#,
        );
        let cf = Cloudflare::novo(f, "tok".into());
        let corpo = serde_json::json!({"type":"A","name":"a.ex.com","content":"1.2.3.4"});
        let _: serde_json::Value =
            cf.chamar("POST", "/zones/z1/dns_records", Some(&corpo), "criar").unwrap();
        let visto = cf.transporte.visto.borrow();
        assert_eq!(visto[0].0, "POST");
        let enviado = visto[0].2.as_ref().expect("o corpo tinha de ir");
        assert!(enviado.contains("1.2.3.4"), "o conteúdo do registro não foi enviado: {enviado}");
    }
}
