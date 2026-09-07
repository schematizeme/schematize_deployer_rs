//! Subcomandos de DNS (`deployer dns <sub>`).
//!
//! **O quê:** a interface que a pessoa — e o agente — usam para gerir o DNS da Cloudflare.
//! Lê o token do cofre, chama [`deployer::dns::operacoes`] e imprime.
//!
//! **Onde:** despachado por `main.rs` (`Cmd::Dns`).
//!
//! ## A confirmação é mostrada com o MOTIVO, nunca como "tem certeza?"
//!
//! Toda operação que a política não libera imprime **o que vai acontecer e por que é caro**
//! antes de perguntar. Um "tem certeza? (s/N)" nu treina a pessoa a responder `s` sem ler — e
//! aí a confirmação deixa de proteger de qualquer coisa.
//!
//! ## Por que o token não vem por `--token`
//!
//! Argumento de linha de comando aparece no `ps` para qualquer processo do usuário e fica no
//! histórico do shell. O token entra uma vez, pelo terminal, e vai para o cofre.

use crate::cli::args::DnsCmd;
use deployer::dns::{
    api::{Cloudflare, Ureq},
    credencial, operacoes as ops,
    politica::Acao,
};

/// **O quê:** a passphrase do cofre, pelo terminal (ou stdin, sem terminal).
///
/// **Onde:** todo comando deste arquivo — cada invocação destrava o cofre uma vez.
///
/// **Por que não há sessão persistente:** guardar a chave destravada em disco a deixaria
/// legível por qualquer processo do usuário, o que anularia o cofre. O custo é digitar a
/// passphrase por comando; quem automatiza usa `DEPLOYER_COFRE_PASS`, e a variável está
/// documentada como o caminho mais fraco justamente por aparecer em `/proc/PID/environ`.
fn passphrase() -> Result<String, String> {
    if let Ok(p) = std::env::var("DEPLOYER_COFRE_PASS") {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    crate::cli::cofre::ler_passphrase_pub("passphrase do cofre: ")
}

/// **O quê:** monta o cliente já com o token do cofre.
/// **Onde:** todo comando que fala com a Cloudflare.
fn cliente() -> Result<Cloudflare<Ureq>, String> {
    let pass = passphrase()?;
    let token = credencial::ler(&pass)?;
    Ok(Cloudflare::novo(Ureq, token))
}

/// **O quê:** pergunta (s/N) mostrando o motivo. Falha FECHADA: EOF, erro ou qualquer coisa
/// diferente de sim é NÃO.
fn confirmar(motivo: &str, o_que: &str) -> bool {
    use std::io::Write;
    eprintln!();
    eprintln!("  {o_que}");
    eprintln!("  motivo: {motivo}");
    eprint!("  confirmar? (s/N) ");
    let _ = std::io::stderr().flush();
    let mut l = String::new();
    if std::io::stdin().read_line(&mut l).is_err() {
        return false;
    }
    matches!(l.trim().to_lowercase().as_str(), "s" | "sim" | "y" | "yes")
}

/// Despacha `deployer dns <sub>`.
pub(crate) fn dns_cmd(sub: DnsCmd) -> Result<(), String> {
    match sub {
        DnsCmd::Auth { status, remover } => {
            let pass = passphrase()?;
            if status {
                let s = deployer::cofre::segredos::carregar(&pass)?;
                if credencial::existe(&s) {
                    // Diz QUE existe, nunca QUAL é.
                    println!("token da Cloudflare: guardado no cofre");
                } else {
                    println!("token da Cloudflare: não guardado");
                    println!("  guarde um com `deployer dns auth`");
                }
                return Ok(());
            }
            if remover {
                let tinha = credencial::remover(&pass)?;
                println!(
                    "{}",
                    if tinha { "token removido do cofre." } else { "não havia token guardado." }
                );
                return Ok(());
            }
            println!("Cole o token de API da Cloudflare (ele não aparece na tela).");
            println!("Crie um em: https://dash.cloudflare.com/profile/api-tokens");
            println!("Permissões necessárias: Zone:Read e DNS:Edit das zonas que for gerir.");
            let token = crate::cli::cofre::ler_passphrase_pub("token: ")?;
            let substituiu = credencial::guardar(&pass, &token)?;
            println!(
                "{}",
                if substituiu {
                    // Trocar credencial sem querer não pode passar calado.
                    "token SUBSTITUÍDO no cofre (havia outro guardado)."
                } else {
                    "token guardado no cofre."
                }
            );
            Ok(())
        }

        DnsCmd::Zones => {
            let cf = cliente()?;
            let zs = ops::zonas(&cf)?;
            if zs.is_empty() {
                println!("nenhuma zona nesta conta (o token tem permissão Zone:Read?)");
                return Ok(());
            }
            println!("{:<34} {:<24} STATUS", "ID", "ZONA");
            for z in zs {
                println!("{:<34} {:<24} {}", z.id, z.name, z.status);
            }
            Ok(())
        }

        DnsCmd::List { zona, tipo } => {
            let cf = cliente()?;
            let zid = ops::resolver_zona(&cf, &zona)?;
            let mut rs = ops::listar(&cf, &zid)?;
            if let Some(t) = &tipo {
                rs.retain(|r| r.tipo.eq_ignore_ascii_case(t));
            }
            if rs.is_empty() {
                println!(
                    "nenhum registro em {zona}{}",
                    tipo.map(|t| format!(" do tipo {t}")).unwrap_or_default()
                );
                return Ok(());
            }
            println!("{:<34} {:<7} {:<34} {:<8} CONTEÚDO", "ID", "TIPO", "NOME", "TTL");
            for r in rs {
                let ttl = if r.ttl == 1 { "auto".to_string() } else { r.ttl.to_string() };
                let prox = if r.proxied { " (proxied)" } else { "" };
                println!(
                    "{:<34} {:<7} {:<34} {:<8} {}{}",
                    r.id, r.tipo, r.name, ttl, r.content, prox
                );
            }
            Ok(())
        }

        DnsCmd::Add { zona, tipo, nome, conteudo, ttl, proxied, yes } => {
            let cf = cliente()?;
            let zid = ops::resolver_zona(&cf, &zona)?;
            let n = ops::Novo { tipo, name: nome, content: conteudo, ttl, proxied };
            // Avalia ANTES de perguntar, para a pergunta trazer o motivo.
            let v = ops::avaliar(Acao::Criar, &n.tipo, &n.name, &zona);
            let ok = yes
                || v.motivo().is_none_or(|m| {
                    confirmar(m, &format!("criar {} {} → {}", n.tipo, n.name, n.content))
                });
            let r = ops::criar(&cf, &zid, &zona, &n, ok)?;
            println!("criado: {} {} {} → {}", r.id, r.tipo, r.name, r.content);
            Ok(())
        }

        DnsCmd::Update { zona, nome, tipo, conteudo, ttl, proxied, yes } => {
            let cf = cliente()?;
            let zid = ops::resolver_zona(&cf, &zona)?;
            let rs = ops::listar(&cf, &zid)?;
            let atual = ops::achar(&rs, &nome, tipo.as_deref())?;
            let n = ops::Novo {
                tipo: tipo.unwrap_or_else(|| atual.tipo.clone()),
                name: atual.name.clone(),
                content: conteudo,
                ttl: ttl.unwrap_or(atual.ttl),
                proxied: proxied.unwrap_or(atual.proxied),
            };
            let v = ops::avaliar(Acao::Atualizar, &n.tipo, &n.name, &zona);
            let ok = yes
                || v.motivo().is_none_or(|m| {
                    confirmar(
                        m,
                        &format!(
                            "alterar {} {}: {} → {}",
                            n.tipo, n.name, atual.content, n.content
                        ),
                    )
                });
            let id = atual.id.clone();
            let r = ops::atualizar(&cf, &zid, &zona, &id, &n, ok)?;
            println!("alterado: {} {} {} → {}", r.id, r.tipo, r.name, r.content);
            Ok(())
        }

        DnsCmd::Rm { zona, nome, tipo, yes } => {
            let cf = cliente()?;
            let zid = ops::resolver_zona(&cf, &zona)?;
            let rs = ops::listar(&cf, &zid)?;
            let alvo = ops::achar(&rs, &nome, tipo.as_deref())?.clone();
            let v = ops::avaliar(Acao::Remover, &alvo.tipo, &alvo.name, &zona);
            // Remover SEMPRE tem motivo (a política nunca o libera), então a confirmação é
            // obrigatória a menos que venha `--yes`.
            let ok = yes
                || v.motivo().is_none_or(|m| {
                    confirmar(m, &format!("REMOVER {} {} → {}", alvo.tipo, alvo.name, alvo.content))
                });
            ops::remover(&cf, &zid, &zona, &alvo, ok)?;
            println!("removido: {} {} {}", alvo.id, alvo.tipo, alvo.name);
            Ok(())
        }
    }
}
