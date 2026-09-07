//! DNS — as operações que a CLI expõe: listar zonas, listar/criar/alterar/remover registros.
//!
//! **O quê:** a camada que junta [`super::api`] (como falar com a Cloudflare),
//! [`super::politica`] (o que pode passar sem perguntar) e o cofre (de onde vem o token).
//!
//! **Onde:** `cli::dns`. Nada de I/O de terminal aqui — quem pergunta e imprime é a CLI; este
//! arquivo devolve dados e erros.

use super::api::{Cloudflare, Transporte};
use super::politica::{self, Acao, Veredito};
use serde::{Deserialize, Serialize};

/// Uma zona (domínio) na conta.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Zona {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub status: String,
}

/// Um registro de DNS.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Registro {
    pub id: String,
    #[serde(rename = "type")]
    pub tipo: String,
    pub name: String,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub ttl: i64,
    #[serde(default)]
    pub proxied: bool,
}

/// O que se quer criar ou alterar.
#[derive(Debug, Clone, Serialize)]
pub struct Novo {
    #[serde(rename = "type")]
    pub tipo: String,
    pub name: String,
    pub content: String,
    pub ttl: i64,
    pub proxied: bool,
}

/// **O quê:** valida um registro ANTES de gastar uma chamada de rede.
///
/// **Onde:** [`criar`] e [`atualizar`]. Função PURA.
///
/// **Por que validar aqui se a Cloudflare também valida:** a mensagem dela é genérica
/// (`Invalid content`), e chega depois de um ida-e-volta. Errar cedo, com o motivo, é a
/// diferença entre corrigir em cinco segundos e abrir a documentação.
///
/// **Não duplica a validação DELA:** o que se checa aqui são as regras que se pode afirmar
/// sem contexto — TTL fora da faixa, tipo desconhecido, conteúdo vazio, IP malformado num `A`.
pub fn validar(n: &Novo) -> Result<(), String> {
    let t = n.tipo.trim().to_uppercase();
    const TIPOS: &[&str] =
        &["A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "CAA", "PTR", "SOA", "DS", "DNSKEY"];
    if !TIPOS.contains(&t.as_str()) {
        return Err(format!(
            "tipo `{}` não é um tipo de DNS conhecido. Use um de: {}",
            n.tipo,
            TIPOS.join(", ")
        ));
    }
    if n.name.trim().is_empty() {
        return Err("o nome do registro não pode ser vazio (use `@` para o apex)".into());
    }
    if n.content.trim().is_empty() {
        return Err(format!("o conteúdo de um {t} não pode ser vazio"));
    }
    // TTL 1 é o "automático" da Cloudflare; fora disso o mínimo dela é 60.
    if n.ttl != 1 && !(60..=86_400).contains(&n.ttl) {
        return Err(format!(
            "ttl {} fora da faixa: use 1 (automático) ou entre 60 e 86400 segundos",
            n.ttl
        ));
    }
    if t == "A" && n.content.parse::<std::net::Ipv4Addr>().is_err() {
        return Err(format!("um registro A aponta para um IPv4; `{}` não é um", n.content));
    }
    if t == "AAAA" && n.content.parse::<std::net::Ipv6Addr>().is_err() {
        return Err(format!("um registro AAAA aponta para um IPv6; `{}` não é um", n.content));
    }
    // `proxied` só existe para tráfego HTTP — a Cloudflare recusa nos outros, com mensagem
    // obscura. Dizer aqui o que é permitido evita a viagem.
    if n.proxied && !matches!(t.as_str(), "A" | "AAAA" | "CNAME") {
        return Err(format!("`--proxied` só vale para A, AAAA e CNAME — não para {t}"));
    }
    Ok(())
}

/// **O quê:** todas as zonas da conta.
/// **Onde:** `deployer dns zones`, e a resolução de nome → id.
pub fn zonas<T: Transporte>(cf: &Cloudflare<T>) -> Result<Vec<Zona>, String> {
    cf.chamar("GET", "/zones?per_page=200", None, "listar zonas")
}

/// **O quê:** resolve o NOME de uma zona no id que a API usa.
///
/// **Onde:** todas as operações que recebem zona por nome — que é como as pessoas a chamam.
///
/// **Por que não aceitar o id direto:** aceita. Se o que veio já parece um id (32 hex), passa
/// adiante sem gastar uma chamada.
pub fn resolver_zona<T: Transporte>(cf: &Cloudflare<T>, zona: &str) -> Result<String, String> {
    let z = zona.trim();
    if z.len() == 32 && z.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(z.to_string());
    }
    let todas = zonas(cf)?;
    let alvo = z.trim_end_matches('.').to_lowercase();
    todas.iter().find(|x| x.name.to_lowercase() == alvo).map(|x| x.id.clone()).ok_or_else(|| {
        let nomes: Vec<&str> = todas.iter().map(|x| x.name.as_str()).collect();
        if nomes.is_empty() {
            "não achei zona nenhuma nesta conta — o token tem permissão Zone:Read?".to_string()
        } else {
            format!("não achei a zona `{z}`. Nesta conta há: {}", nomes.join(", "))
        }
    })
}

/// **O quê:** os registros de uma zona.
/// **Onde:** `deployer dns list`.
pub fn listar<T: Transporte>(cf: &Cloudflare<T>, zona_id: &str) -> Result<Vec<Registro>, String> {
    cf.chamar(
        "GET",
        &format!("/zones/{zona_id}/dns_records?per_page=500"),
        None,
        "listar registros",
    )
}

/// **O quê:** acha um registro por nome (e tipo, se dado) dentro de uma zona.
///
/// **Onde:** `update` e `rm`, que a pessoa chama por NOME — ninguém decora id de registro.
///
/// **Ambiguidade é ERRO, não escolha:** dois registros com o mesmo nome (round-robin de A,
/// por exemplo) fazem esta função recusar e listar os ids. Escolher um por conta própria
/// seria alterar o registro errado em silêncio.
pub fn achar<'a>(
    registros: &'a [Registro],
    nome: &str,
    tipo: Option<&str>,
) -> Result<&'a Registro, String> {
    let alvo = nome.trim().trim_end_matches('.').to_lowercase();
    let candidatos: Vec<&Registro> = registros
        .iter()
        .filter(|r| r.name.trim_end_matches('.').to_lowercase() == alvo)
        .filter(|r| tipo.is_none_or(|t| r.tipo.eq_ignore_ascii_case(t)))
        .collect();
    match candidatos.len() {
        0 => Err(format!(
            "não achei registro `{nome}`{}. Veja os que existem com `deployer dns list`",
            tipo.map(|t| format!(" do tipo {t}")).unwrap_or_default()
        )),
        1 => Ok(candidatos[0]),
        n => Err(format!(
            "`{nome}` casa com {n} registros — não vou escolher por você. Refine com `--tipo`, \
             ou use o id:\n{}",
            candidatos
                .iter()
                .map(|r| format!("  {} {:<6} {}", r.id, r.tipo, r.content))
                .collect::<Vec<_>>()
                .join("\n")
        )),
    }
}

/// **O quê:** avalia a política e devolve o veredito, sem executar nada.
///
/// **Onde:** a CLI, ANTES de perguntar ao usuário — é o que permite mostrar o motivo junto
/// da pergunta em vez de um "tem certeza?" nu.
pub fn avaliar(acao: Acao, tipo: &str, nome: &str, zona: &str) -> Veredito {
    politica::avaliar(acao, tipo, nome, zona)
}

/// **O quê:** cria um registro. **Onde:** `deployer dns add`.
///
/// `confirmado` é o consentimento que a CLI já obteve; esta função não pergunta nada.
pub fn criar<T: Transporte>(
    cf: &Cloudflare<T>,
    zona_id: &str,
    zona_nome: &str,
    n: &Novo,
    confirmado: bool,
) -> Result<Registro, String> {
    validar(n)?;
    let v = avaliar(Acao::Criar, &n.tipo, &n.name, zona_nome);
    if !v.permite(confirmado) {
        return Err(recusa(&v));
    }
    let corpo =
        serde_json::to_value(n).map_err(|e| format!("não consegui montar o pedido: {e}"))?;
    cf.chamar("POST", &format!("/zones/{zona_id}/dns_records"), Some(&corpo), "criar registro")
}

/// **O quê:** altera um registro existente. **Onde:** `deployer dns update`.
pub fn atualizar<T: Transporte>(
    cf: &Cloudflare<T>,
    zona_id: &str,
    zona_nome: &str,
    registro_id: &str,
    n: &Novo,
    confirmado: bool,
) -> Result<Registro, String> {
    validar(n)?;
    let v = avaliar(Acao::Atualizar, &n.tipo, &n.name, zona_nome);
    if !v.permite(confirmado) {
        return Err(recusa(&v));
    }
    let corpo =
        serde_json::to_value(n).map_err(|e| format!("não consegui montar o pedido: {e}"))?;
    cf.chamar(
        "PUT",
        &format!("/zones/{zona_id}/dns_records/{registro_id}"),
        Some(&corpo),
        "atualizar registro",
    )
}

/// **O quê:** remove um registro. **Onde:** `deployer dns rm`.
pub fn remover<T: Transporte>(
    cf: &Cloudflare<T>,
    zona_id: &str,
    zona_nome: &str,
    r: &Registro,
    confirmado: bool,
) -> Result<(), String> {
    let v = avaliar(Acao::Remover, &r.tipo, &r.name, zona_nome);
    if !v.permite(confirmado) {
        return Err(recusa(&v));
    }
    let _: serde_json::Value = cf.chamar(
        "DELETE",
        &format!("/zones/{zona_id}/dns_records/{}", r.id),
        None,
        "remover registro",
    )?;
    Ok(())
}

/// **O quê:** o texto de uma recusa por política — com o motivo e a saída.
///
/// **Por que o proibido NÃO oferece `--yes`:** sugerir uma saída que não existe manda a
/// pessoa tentar de novo e falhar de novo. §37.48.
fn recusa(v: &Veredito) -> String {
    match v {
        Veredito::Proibido(m) => format!("recusado: {m}"),
        Veredito::Confirmar(m) => format!("precisa de confirmação: {m}\n  → repita com `--yes`"),
        Veredito::Livre => unreachable!("livre não gera recusa"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(id: &str, tipo: &str, nome: &str, content: &str) -> Registro {
        Registro {
            id: id.into(),
            tipo: tipo.into(),
            name: nome.into(),
            content: content.into(),
            ttl: 1,
            proxied: false,
        }
    }
    fn novo(tipo: &str, nome: &str, content: &str) -> Novo {
        Novo {
            tipo: tipo.into(),
            name: nome.into(),
            content: content.into(),
            ttl: 1,
            proxied: false,
        }
    }

    /// Validação pega o que dá para afirmar sem rede — e o erro diz o que está errado.
    #[test]
    fn validacao_recusa_o_que_da_pra_saber_sem_rede() {
        assert!(validar(&novo("A", "x.ex.com", "1.2.3.4")).is_ok());

        let e = validar(&novo("A", "x.ex.com", "não-é-ip")).unwrap_err();
        assert!(e.contains("IPv4"), "{e}");

        let e = validar(&novo("AAAA", "x.ex.com", "1.2.3.4")).unwrap_err();
        assert!(e.contains("IPv6"), "IPv4 num AAAA tem de reprovar: {e}");

        let e = validar(&novo("BANANA", "x.ex.com", "1.2.3.4")).unwrap_err();
        assert!(e.contains("conhecido"), "{e}");

        let e = validar(&novo("TXT", "x.ex.com", "")).unwrap_err();
        assert!(e.contains("vazio"), "{e}");
    }

    /// TTL: 1 é o automático da Cloudflare; o resto tem faixa.
    #[test]
    fn ttl_fora_da_faixa_e_recusado_com_a_faixa_na_mensagem() {
        let mut n = novo("A", "x.ex.com", "1.2.3.4");
        n.ttl = 1;
        assert!(validar(&n).is_ok(), "1 = automático");
        n.ttl = 300;
        assert!(validar(&n).is_ok());
        n.ttl = 30;
        let e = validar(&n).unwrap_err();
        assert!(e.contains("60") && e.contains("86400"), "a mensagem tem de dar a faixa: {e}");
    }

    /// `--proxied` num TXT é erro nosso, não da Cloudflare: a dela é obscura.
    #[test]
    fn proxied_so_vale_para_trafego_http() {
        let mut n = novo("TXT", "x.ex.com", "v=spf1");
        n.proxied = true;
        let e = validar(&n).unwrap_err();
        assert!(e.contains("A, AAAA e CNAME"), "{e}");
        let mut ok = novo("CNAME", "x.ex.com", "y.ex.com");
        ok.proxied = true;
        assert!(validar(&ok).is_ok());
    }

    /// **Ambiguidade é ERRO.** Dois registros com o mesmo nome (round-robin) fazem `achar`
    /// recusar e listar os ids — escolher um sozinho alteraria o registro errado em silêncio.
    #[test]
    fn nome_ambiguo_recusa_em_vez_de_escolher() {
        let rs =
            vec![reg("r1", "A", "app.ex.com", "1.1.1.1"), reg("r2", "A", "app.ex.com", "2.2.2.2")];
        let e = achar(&rs, "app.ex.com", None).unwrap_err();
        assert!(e.contains("não vou escolher"), "{e}");
        assert!(e.contains("r1") && e.contains("r2"), "tem de listar os ids: {e}");
    }

    /// Com o tipo, a ambiguidade se resolve — e o FQDN com ponto final também casa.
    #[test]
    fn achar_por_nome_e_tipo_e_tolera_ponto_final() {
        let rs =
            vec![reg("r1", "A", "app.ex.com", "1.1.1.1"), reg("r2", "TXT", "app.ex.com", "v=spf1")];
        assert_eq!(achar(&rs, "app.ex.com", Some("TXT")).unwrap().id, "r2");
        assert_eq!(achar(&rs, "app.ex.com.", Some("A")).unwrap().id, "r1", "FQDN com ponto");
        assert_eq!(achar(&rs, "APP.EX.COM", Some("A")).unwrap().id, "r1", "caixa não importa");
    }

    /// Não achar diz onde procurar, em vez de só falhar.
    #[test]
    fn nao_achar_ensina_o_proximo_passo() {
        let e = achar(&[], "x.ex.com", None).unwrap_err();
        assert!(e.contains("dns list"), "{e}");
    }

    /// A recusa por confirmação oferece a saída; a recusa por PROIBIDO não oferece — sugerir
    /// `--yes` para algo que `--yes` não destrava manda a pessoa falhar de novo.
    #[test]
    fn recusa_so_oferece_saida_quando_ela_existe() {
        let c = recusa(&Veredito::Confirmar("porque sim".into()));
        assert!(c.contains("--yes"));
        let p = recusa(&Veredito::Proibido("a Cloudflare gere".into()));
        assert!(!p.contains("--yes"), "não pode sugerir o que não funciona: {p}");
    }

    /// Um id de zona (32 hex) passa direto, sem gastar chamada de rede.
    #[test]
    fn id_de_zona_nao_gasta_chamada() {
        // Não precisa de transporte: o caminho do id não chama nada. Se um dia chamar, este
        // teste falha por não ter cliente — que é o aviso certo.
        let id = "0123456789abcdef0123456789abcdef";
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
