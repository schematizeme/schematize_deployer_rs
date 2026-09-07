//! DNS — o que se pode mudar sem perguntar, e o que não.
//!
//! **O quê:** classifica cada operação de DNS em `Livre`, `Confirmar` ou `Proibido`, a partir
//! do tipo de registro e do nome.
//!
//! **Onde:** `dns::operacoes`, antes de qualquer escrita. Função PURA — nenhuma rede, nenhum
//! disco —, e é por isso que cada regra abaixo tem teste.
//!
//! ## Por que DNS precisa de política, se o VPS já tem
//!
//! O `vps::politica` protege contra comando que estraga um servidor. Aqui o dano é de outra
//! natureza e maior: **um registro errado no apex tira o site do ar para o mundo inteiro**, e
//! a propagação faz o estrago durar depois de desfeito. Trocar o `MX` desvia e-mail; mexer no
//! `NS` entrega a zona.
//!
//! São, todos, danos **sem undo imediato** — o critério do `vps::catastrofico`. A diferença é
//! que aqui não existe "modo somente-leitura no servidor" que segure: a fronteira é a
//! Cloudflare, e o token que a atravessa é o mesmo. Então a fronteira tem de ser aqui.
//!
//! ## O que esta política NÃO é
//!
//! **Não é barreira de segurança contra agente hostil.** Quem tem o binário e o cofre
//! destravado pode chamar a API direto. É rede contra **acidente** — a mesma honestidade do
//! `vps::hook`, que documenta o próprio limite em vez de fingir ser fronteira.
//!
//! O que de fato segura é: a confirmação humana nas operações caras, e a auditoria de tudo.

/// O veredito sobre uma operação.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Veredito {
    /// Pode seguir sem perguntar.
    Livre,
    /// Precisa de confirmação explícita (`--yes` ou o prompt). O texto diz **por quê**.
    Confirmar(String),
    /// Não passa nem com `--yes`. O texto diz o que fazer em vez disso.
    Proibido(String),
}

impl Veredito {
    /// **O quê:** dá para executar com o consentimento que se tem?
    /// **Onde:** `dns::operacoes`, no ponto da escrita.
    pub fn permite(&self, confirmado: bool) -> bool {
        match self {
            Veredito::Livre => true,
            Veredito::Confirmar(_) => confirmado,
            Veredito::Proibido(_) => false,
        }
    }

    /// **O quê:** o motivo, para a mensagem ao usuário. `None` quando é livre.
    pub fn motivo(&self) -> Option<&str> {
        match self {
            Veredito::Livre => None,
            Veredito::Confirmar(m) | Veredito::Proibido(m) => Some(m),
        }
    }
}

/// A operação sendo avaliada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acao {
    Criar,
    Atualizar,
    Remover,
}

/// Tipos que reconfiguram a ZONA, não um serviço dentro dela.
///
/// Mexer neles não derruba uma página: entrega o domínio (`NS`), desvia o e-mail (`MX`) ou
/// muda quem pode emitir certificado (`CAA`). São os que nunca passam calados.
const TIPOS_ESTRUTURAIS: &[&str] = &["NS", "MX", "SOA", "CAA", "DNSKEY", "DS"];

/// **O quê:** o nome é o APEX da zona (o domínio nu, sem subdomínio)?
///
/// **Onde:** [`avaliar`]. A Cloudflare representa o apex como `@` ou como o próprio nome da
/// zona — as duas formas contam, e tratar só uma deixaria a outra passar livre.
pub fn e_apex(nome: &str, zona: &str) -> bool {
    let n = nome.trim().trim_end_matches('.').to_lowercase();
    let z = zona.trim().trim_end_matches('.').to_lowercase();
    n == "@" || n.is_empty() || n == z
}

/// **O quê:** avalia uma operação de DNS.
///
/// **Onde:** `dns::operacoes`, sempre antes de escrever.
///
/// **A escala:** remover é sempre mais caro que criar, porque criar errado deixa um registro
/// a mais (visível, reversível) e remover certo apaga o que fazia a coisa funcionar.
pub fn avaliar(acao: Acao, tipo: &str, nome: &str, zona: &str) -> Veredito {
    let t = tipo.trim().to_uppercase();

    // SOA não se cria nem se apaga por API — a Cloudflare o gerencia. Recusar aqui, com a
    // explicação, é melhor que deixar a API devolver um erro que não ensina nada.
    if t == "SOA" {
        return Veredito::Proibido(
            "o registro SOA é gerido pela Cloudflare e não se altera por aqui".into(),
        );
    }

    if TIPOS_ESTRUTURAIS.contains(&t.as_str()) {
        return Veredito::Confirmar(format!(
            "{t} reconfigura a ZONA, não um serviço: NS entrega o domínio, MX desvia o e-mail, \
             CAA muda quem emite certificado. O efeito é imediato e a propagação o faz durar"
        ));
    }

    if e_apex(nome, zona) {
        return Veredito::Confirmar(format!(
            "`{nome}` é o apex de {zona} — é o domínio nu, o que o mundo digita. Um {t} errado \
             aqui tira o site do ar inteiro, não uma página"
        ));
    }

    match acao {
        // Remover apaga o que fazia algo funcionar, e o registro não volta sozinho.
        Acao::Remover => Veredito::Confirmar(format!(
            "remover `{nome}` ({t}) é irreversível por aqui: o registro some e só volta se \
             alguém o recriar igual"
        )),
        // Criar e atualizar subdomínio comum: o caso do dia a dia, e o que se quer fluido.
        Acao::Criar | Acao::Atualizar => Veredito::Livre,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// O caso do dia a dia passa liso — se tudo pedisse confirmação, ninguém leria nenhuma.
    #[test]
    fn subdominio_comum_e_livre() {
        assert_eq!(avaliar(Acao::Criar, "A", "app.ex.com", "ex.com"), Veredito::Livre);
        assert_eq!(avaliar(Acao::Atualizar, "CNAME", "www.ex.com", "ex.com"), Veredito::Livre);
        assert_eq!(avaliar(Acao::Criar, "TXT", "_acme.ex.com", "ex.com"), Veredito::Livre);
    }

    /// Remover NUNCA é livre, nem num subdomínio banal: criar errado deixa um registro a
    /// mais; remover certo apaga o que fazia a coisa funcionar.
    #[test]
    fn remover_sempre_pede_confirmacao() {
        let v = avaliar(Acao::Remover, "A", "app.ex.com", "ex.com");
        assert!(matches!(v, Veredito::Confirmar(_)));
        assert!(v.motivo().unwrap().contains("irreversível"));
        assert!(!v.permite(false), "sem confirmar, não passa");
        assert!(v.permite(true), "com --yes, passa");
    }

    /// **O apex nas DUAS formas.** A Cloudflare usa `@` e o nome da zona; tratar só uma
    /// deixaria a outra passar livre — e é a que tira o site do ar.
    #[test]
    fn apex_e_reconhecido_nas_duas_formas() {
        assert!(e_apex("@", "ex.com"));
        assert!(e_apex("ex.com", "ex.com"));
        assert!(e_apex("ex.com.", "ex.com"), "com ponto final (FQDN)");
        assert!(e_apex("EX.COM", "ex.com"), "maiúscula: DNS não é sensível a caixa");
        assert!(!e_apex("www.ex.com", "ex.com"));
        // O caso traiçoeiro: um domínio que TERMINA com o nome da zona não é o apex dela.
        assert!(!e_apex("naoex.com", "ex.com"));
    }

    /// Mexer no apex pede confirmação mesmo com um tipo banal.
    #[test]
    fn apex_pede_confirmacao_ate_para_tipo_comum() {
        for nome in ["@", "ex.com"] {
            let v = avaliar(Acao::Criar, "A", nome, "ex.com");
            assert!(matches!(v, Veredito::Confirmar(_)), "{nome} devia pedir confirmação");
            assert!(v.motivo().unwrap().contains("apex"));
        }
    }

    /// Tipos que reconfiguram a zona pedem confirmação até fora do apex.
    #[test]
    fn tipos_estruturais_pedem_confirmacao() {
        for t in ["NS", "MX", "CAA", "DS", "DNSKEY"] {
            let v = avaliar(Acao::Criar, t, "sub.ex.com", "ex.com");
            assert!(matches!(v, Veredito::Confirmar(_)), "{t} devia pedir confirmação");
        }
        // E a caixa não importa: `mx` é `MX`.
        assert!(matches!(
            avaliar(Acao::Criar, "mx", "sub.ex.com", "ex.com"),
            Veredito::Confirmar(_)
        ));
    }

    /// SOA é PROIBIDO — nem com `--yes`. A Cloudflare o gere, e recusar aqui com a explicação
    /// é melhor que deixar a API responder algo que não ensina nada.
    #[test]
    fn soa_e_proibido_mesmo_com_yes() {
        let v = avaliar(Acao::Atualizar, "SOA", "ex.com", "ex.com");
        assert!(matches!(v, Veredito::Proibido(_)));
        assert!(!v.permite(true), "`--yes` NÃO pode destravar o proibido");
    }

    /// Todo veredito que não é livre traz um motivo — mensagem sem porquê vira ruído que a
    /// pessoa aprende a ignorar, e aí a confirmação deixa de significar algo.
    #[test]
    fn todo_bloqueio_explica_o_porque() {
        let casos = [
            avaliar(Acao::Remover, "A", "x.ex.com", "ex.com"),
            avaliar(Acao::Criar, "MX", "x.ex.com", "ex.com"),
            avaliar(Acao::Criar, "A", "@", "ex.com"),
            avaliar(Acao::Criar, "SOA", "ex.com", "ex.com"),
        ];
        for v in casos {
            let m = v.motivo().expect("não-livre tem de ter motivo");
            assert!(m.len() > 30, "motivo curto demais para ensinar algo: {m}");
        }
    }
}
