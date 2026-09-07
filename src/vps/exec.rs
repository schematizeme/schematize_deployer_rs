//! EXEC — execução não-interativa e auditada de um comando num host.
//! O quê: [`executar`] avalia a política, roda o `ssh` capturando stdout/stderr/exit/duração,
//! e grava a linha de auditoria — inclusive quando o comando é RECUSADO.
//! Onde: CLI `schematize vps exec`, o servidor MCP (Fase 2) e o painel da GUI.
//!
//! **Sem PTY de propósito.** A execução é por pipe, que é portátil (o spike U0a deixou o
//! ConPTY do Windows em aberto). A sessão *interativa* — que precisa de PTY — é Fase 4.
//!
//! ## `confirmado` NÃO é `--force`
//! [`Confirmacao`] carrega a resposta de um humano a um veredito `Confirm`. Ela não pula a
//! política: um `Deny` continua `Deny` com ela ligada. A diferença importa — `--force` seria
//! a válvula de escape que o `politica.rs` proíbe; isto é o humano respondendo à pergunta que
//! a política fez.

use super::auditoria::{self, Sessao};
use super::conexao::{self, ErroSsh};
use super::politica::{avaliar_com_catalogo, Veredito};
use super::registro::VpsProfile;
use rusqlite::Connection;
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Quanto de saída do host é GUARDADO, por canal.
///
/// O host controla quanto ele imprime, e `Command::output()` bufferiza sem teto: no teste
/// destrutivo, um host que respondia `cat /dev/zero` levou o cliente a **7 GB de RSS em 25
/// segundos**. E não precisa de host malicioso — um verbo `logs` num journal grande faz igual,
/// por acidente.
///
/// 8 MB é muito acima de qualquer saída de deploy legítima, e o que passa disso é DESCARTADO
/// (não interrompido): o comando remoto termina normalmente e o exit code continua confiável.
pub const MAX_SAIDA: usize = 8 * 1024 * 1024;

/// Teto de tempo de UMA execução. Sem ele, um host que jorra para sempre nunca devolve o
/// controle — a memória fica limitada, mas o processo trava para sempre.
pub const TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// A resposta humana a um veredito `Confirm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmacao {
    /// Ninguém confirmou nada — um `Confirm` vira erro pedindo a confirmação.
    Ausente,
    /// Um humano viu o motivo e disse sim.
    HumanoConfirmou,
}

/// O resultado de uma execução.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOut {
    /// Exit code do `ssh` (`None` se morto por sinal).
    pub exit_code: Option<i32>,
    /// Saída padrão do comando remoto.
    pub stdout: String,
    /// Saída de erro (do comando remoto e do próprio `ssh`).
    pub stderr: String,
    /// Quanto durou, em milissegundos.
    pub duracao_ms: i64,
    /// Id da linha de auditoria gravada.
    pub auditoria_id: i64,
    /// Erro classificado, quando o `ssh` falhou por um motivo que sabemos nomear.
    pub erro: Option<ErroSsh>,
}

impl ExecOut {
    /// O comando remoto terminou bem?
    pub fn sucesso(&self) -> bool {
        self.exit_code == Some(0) && self.erro.is_none()
    }
}

/// Executa `comando` em `p`, com política e auditoria. **Ponto único de execução remota** —
/// nem o CLI nem a GUI nem o MCP montam `ssh` por conta própria.
///
/// A auditoria é gravada em TODOS os caminhos, inclusive recusa e falha de conexão: a
/// tentativa faz parte da trilha.
///
/// **Erros:** política recusou, confirmação faltando, host não confiado, ou falha ao spawnar.
/// Uma execução que roda e volta com exit != 0 **não** é `Err` — é `Ok` com `exit_code`
/// preenchido, porque o comando remoto falhar é resultado, não erro nosso.
pub fn executar(
    conn: &Connection,
    p: &VpsProfile,
    comando: &str,
    origem: &str,
    confirmacao: Confirmacao,
) -> Result<ExecOut, String> {
    let sessao = auditoria::abrir_sessao(conn, &p.alias, origem)?;
    let r = executar_na_sessao(conn, &sessao, p, comando, confirmacao);
    auditoria::fechar_sessao(conn, &sessao);
    r
}

/// Execução INTERNA do app: sondagem e bootstrap. **Pula a política do CLIENTE, e continua
/// auditada** — com veredito próprio (`interno`), pra que a trilha distinga o que o app fez
/// do que alguém pediu.
///
/// ## Por que isto não é a válvula de escape que o `politica.rs` proíbe
///
/// A política do cliente existe para conter o **agente**. Estes comandos não vêm dele:
///
/// - são **escritos por nós** (`SCRIPT_DE_SONDAGEM`, `script_de_instalacao`), nunca montados
///   a partir de entrada;
/// - só são alcançáveis por `vps probe` / `vps bootstrap`, que um **humano** roda no CLI ou
///   clica na GUI;
/// - **o MCP não os expõe** — as cinco tools do agente não incluem probe nem bootstrap, e
///   `mcp::tools::executar` só chama [`executar`], nunca esta função.
///
/// Sem ela, o app fica preso num impasse encontrado no Q.A. contra sshd real: posto o host em
/// modo `OpsVerbs`, a própria sondagem vira "comando fora do catálogo" e é recusada — o app
/// perde a capacidade de diagnosticar e de consertar exatamente o host que ele protegeu.
///
/// **Onde:** `capacidade::sondar`, `capacidade::sondar_pelo_shim` e `bootstrap::instalar`.
pub fn executar_interno(
    conn: &Connection,
    p: &VpsProfile,
    comando: &str,
    origem: &str,
) -> Result<ExecOut, String> {
    let sessao = auditoria::abrir_sessao(conn, &p.alias, origem)?;
    let r = rodar(
        conn,
        &sessao,
        p,
        comando,
        &Veredito::Confirm("operação interna do app (sondagem/bootstrap)".into()),
    );
    auditoria::fechar_sessao(conn, &sessao);
    r
}

/// O miolo de [`executar`], com a sessão já aberta. Separado pra que a GUI possa rodar vários
/// comandos numa sessão só (um painel aberto = uma sessão, N comandos).
pub fn executar_na_sessao(
    conn: &Connection,
    sessao: &Sessao,
    p: &VpsProfile,
    comando: &str,
    confirmacao: Confirmacao,
) -> Result<ExecOut, String> {
    // O catálogo é carregado aqui, não dentro da política: a política continua PURA (dados de
    // entrada, veredito de saída), e é isso que a torna testável sem banco.
    let catalogo = super::verbos::listar(conn, &p.alias).unwrap_or_default();
    let veredito = avaliar_com_catalogo(p, comando, &catalogo);

    // Recusa e falta de confirmação: registra a TENTATIVA e devolve erro. Nada roda.
    match (&veredito, confirmacao) {
        (Veredito::Deny(motivo), _) => {
            auditoria::registrar_comando(conn, sessao, comando, &veredito, None, 0, "")?;
            return Err(format!("recusado pela política: {motivo}"));
        }
        (Veredito::Confirm(motivo), Confirmacao::Ausente) => {
            auditoria::registrar_comando(conn, sessao, comando, &veredito, None, 0, "")?;
            return Err(format!(
                "este comando precisa de confirmação humana: {motivo}. Rode de novo com --confirmar (ou confirme no modal da janela)"
            ));
        }
        _ => {}
    }

    // Daqui pra baixo, TODA saída de erro passa por `falhou`, que registra a tentativa antes
    // de propagar — o que não conseguiu rodar é exatamente o que se quer ver depois.
    rodar(conn, sessao, p, comando, &veredito)
}

/// Roda de fato — política já decidida. Separado pra que [`executar_na_sessao`] e
/// [`executar_interno`] compartilhem a execução e a auditoria sem duplicar nenhuma delas.
fn rodar(
    conn: &Connection,
    sessao: &Sessao,
    p: &VpsProfile,
    comando: &str,
    veredito: &Veredito,
) -> Result<ExecOut, String> {
    let falhou = |e: String| -> String {
        let _ = auditoria::registrar_comando(
            conn,
            sessao,
            comando,
            veredito,
            None,
            0,
            &format!("--- falha local ---\n{e}\n"),
        );
        e
    };
    let args = conexao::ssh_args(p, &[comando.to_string()]).map_err(falhou)?;
    let ssh = crate::agentrun::resolve_bin("ssh").ok_or_else(|| {
        falhou("não achei o cliente `ssh` no sistema. No Linux/macOS ele vem com o openssh-client; no Windows, com o OpenSSH Client (Configurações > Recursos opcionais)".to_string())
    })?;

    let inicio = Instant::now();
    let filho = Command::new(&ssh)
        .args(&args)
        .stdin(Stdio::null()) // nada de herdar stdin: o agente não pode ser perguntado nada
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| falhou(format!("falha ao executar o ssh: {e}")))?;
    let capt = capturar_limitado(filho).map_err(falhou)?;
    let duracao_ms = inicio.elapsed().as_millis() as i64;

    let stdout = capt.stdout;
    let stderr = capt.stderr;
    let exit_code = capt.exit_code;

    // Classifica só quando o ssh falhou; um comando remoto que sai != 0 é resultado dele.
    let sucesso_do_ssh = exit_code == Some(0);
    let erro = if !sucesso_do_ssh && !stderr.trim().is_empty() {
        match conexao::classificar_erro(&stderr) {
            ErroSsh::Outro(_) => None, // erro do comando remoto, não da conexão
            e => Some(e),
        }
    } else {
        None
    };

    let mut transcript = montar_transcript(&stdout, &stderr);
    if capt.truncado {
        transcript.push_str(&format!(
            "\n--- AVISO ---\nA saída passou de {} MB e foi cortada; o comando remoto seguiu até o fim e o exit code é o dele.\n",
            MAX_SAIDA / (1024 * 1024)
        ));
    }
    if capt.tempo_esgotado {
        transcript.push_str("\n--- AVISO ---\nO tempo limite estourou e o ssh foi encerrado. O comando pode ainda estar rodando NO HOST.\n");
    }
    let auditoria_id = auditoria::registrar_comando(
        conn,
        sessao,
        comando,
        veredito,
        exit_code,
        duracao_ms,
        &transcript,
    )?;

    Ok(ExecOut { exit_code, stdout, stderr, duracao_ms, auditoria_id, erro })
}

/// O resultado de uma captura limitada.
struct Capturado {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
    /// A saída passou de [`MAX_SAIDA`] e o excedente foi descartado.
    truncado: bool,
    /// O [`TIMEOUT`] estourou e o `ssh` foi encerrado.
    tempo_esgotado: bool,
}

/// Lê stdout e stderr do filho com TETO DE MEMÓRIA, e mata se o tempo estourar.
///
/// Duas decisões que valem explicar:
///
/// **Descarta, não interrompe.** Ao bater o teto, os bytes seguintes são lidos e jogados fora
/// em vez de a leitura parar. Se parasse, o pipe encheria e o comando remoto ficaria travado
/// escrevendo — abortando um deploy no meio por ele ter logado demais. Assim o comando termina
/// e o exit code continua valendo.
///
/// **Um canal por thread.** Ler stdout até o fim e só então stderr trava quando o filho enche
/// o pipe de stderr — é o deadlock clássico de `spawn` com dois pipes.
///
/// **Onde:** [`rodar`].
fn capturar_limitado(mut filho: Child) -> Result<Capturado, String> {
    let ler = |canal: Option<Box<dyn Read + Send>>| {
        canal.map(|mut c| {
            std::thread::spawn(move || {
                let mut guardado: Vec<u8> = Vec::new();
                let mut lixo = [0u8; 64 * 1024];
                let mut estourou = false;
                loop {
                    match c.read(&mut lixo) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let cabe = MAX_SAIDA.saturating_sub(guardado.len());
                            if cabe > 0 {
                                guardado.extend_from_slice(&lixo[..n.min(cabe)]);
                            }
                            if n > cabe {
                                estourou = true;
                            }
                        }
                    }
                }
                (String::from_utf8_lossy(&guardado).into_owned(), estourou)
            })
        })
    };
    let h_out = ler(filho.stdout.take().map(|c| Box::new(c) as Box<dyn Read + Send>));
    let h_err = ler(filho.stderr.take().map(|c| Box::new(c) as Box<dyn Read + Send>));

    // Espera com teto de tempo. `try_wait` em laço em vez de `wait`: precisa poder desistir.
    let inicio = Instant::now();
    let mut tempo_esgotado = false;
    let status = loop {
        match filho.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {
                if inicio.elapsed() > TIMEOUT {
                    let _ = filho.kill();
                    tempo_esgotado = true;
                    break filho.wait().ok();
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(format!("o ssh não finalizou: {e}")),
        }
    };
    let (stdout, t1) = h_out.and_then(|h| h.join().ok()).unwrap_or_default();
    let (stderr, t2) = h_err.and_then(|h| h.join().ok()).unwrap_or_default();
    Ok(Capturado {
        stdout,
        stderr,
        exit_code: status.and_then(|s| s.code()),
        truncado: t1 || t2,
        tempo_esgotado,
    })
}

/// Junta stdout e stderr num transcript legível, marcando de onde veio cada parte.
///
/// **Onde:** [`executar_na_sessao`], antes de entregar à auditoria (que redige). Separado
/// pra ser testável sem rede.
pub fn montar_transcript(stdout: &str, stderr: &str) -> String {
    let mut t = String::new();
    if !stdout.trim().is_empty() {
        t.push_str("--- stdout ---\n");
        t.push_str(stdout.trim_end());
        t.push('\n');
    }
    if !stderr.trim().is_empty() {
        t.push_str("--- stderr ---\n");
        t.push_str(stderr.trim_end());
        t.push('\n');
    }
    if t.is_empty() {
        t.push_str("(sem saída)\n");
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vps::db_de_teste;
    use crate::vps::registro::{Ambiente, ModoPolitica, VpsProfile};

    fn ambiente(nome: &str) -> (Connection, VpsProfile) {
        let c = super::super::db::open_at(&db_de_teste(nome)).unwrap();
        let mut p = VpsProfile::novo("srv", "10.0.0.5", "deploy", "k");
        p.modo = ModoPolitica::Livre;
        p.ambiente = Ambiente::Hml;
        (c, p)
    }

    #[test]
    fn comando_recusado_nao_roda_e_entra_na_auditoria() {
        let (c, p) = ambiente("recusa");
        let e = executar(&c, &p, "rm -rf /", "teste", Confirmacao::Ausente).unwrap_err();
        assert!(e.contains("recusado pela política"), "{e}");
        // Nada rodou, mas a tentativa ficou registrada.
        assert_eq!(auditoria::contar_comandos(&c, "srv").unwrap(), 1);
        let l = &auditoria::listar_comandos(&c, "srv", 1).unwrap()[0];
        assert_eq!(l.veredito, "deny");
    }

    #[test]
    fn prd_sem_confirmacao_nao_roda_e_a_mensagem_ensina_o_caminho() {
        let (c, mut p) = ambiente("prd");
        p.ambiente = Ambiente::Prd;
        let e = executar(&c, &p, "uptime", "teste", Confirmacao::Ausente).unwrap_err();
        assert!(e.contains("confirmação humana"), "{e}");
        assert!(e.contains("--confirmar"), "a mensagem tem que dizer o que fazer: {e}");
        assert_eq!(
            auditoria::contar_comandos(&c, "srv").unwrap(),
            1,
            "a tentativa entra na trilha"
        );
    }

    #[test]
    fn confirmacao_nao_e_force_um_deny_continua_deny() {
        // A distinção que o módulo inteiro depende: confirmar responde a um `Confirm`,
        // não atropela um `Deny`.
        let (c, mut p) = ambiente("naoforce");
        p.ambiente = Ambiente::Prd;
        let e = executar(&c, &p, "rm -rf /", "teste", Confirmacao::HumanoConfirmou).unwrap_err();
        assert!(
            e.contains("recusado pela política"),
            "confirmar não pode liberar catastrófico: {e}"
        );
    }

    #[test]
    fn host_nao_confiado_falha_mas_entra_na_trilha() {
        let (c, p) = ambiente("naoconfiado");
        // Perfil sem fingerprint: o `ssh_args` recusa antes de spawnar nada.
        let e = executar(&c, &p, "uptime", "teste", Confirmacao::HumanoConfirmou).unwrap_err();
        assert!(e.contains("não confiado"), "{e}");
        // O que NÃO conseguiu rodar é justamente o que se quer ver depois.
        assert_eq!(
            auditoria::contar_comandos(&c, "srv").unwrap(),
            1,
            "a falha local também é trilha"
        );
        let l = &auditoria::listar_comandos(&c, "srv", 1).unwrap()[0];
        assert!(
            l.transcript.contains("falha local"),
            "o motivo tem que ficar registrado: {}",
            l.transcript
        );
        assert_eq!(l.exit_code, None);
    }

    #[test]
    fn execucao_interna_nao_e_barrada_pela_politica_do_cliente() {
        // O impasse achado no Q.A. contra sshd real: posto o host em `OpsVerbs`, a sondagem
        // do PRÓPRIO app virava "comando fora do catálogo" e era recusada — o app perdia a
        // capacidade de diagnosticar e consertar o host que ele mesmo protegeu.
        let (c, mut p) = ambiente("interna");
        p.modo = ModoPolitica::OpsVerbs; // catálogo vazio: recusaria QUALQUER comando
        crate::vps::registro::salvar(&c, &p).unwrap();

        // Pela porta do agente: recusado, como deve ser.
        let e = executar(&c, &p, "schematize-probe", "mcp", Confirmacao::Ausente).unwrap_err();
        assert!(e.contains("recusado pela política"), "a porta do agente continua fechada: {e}");

        // Pela porta interna: passa da política e falha só por falta de host confiado —
        // ou seja, chegou até a tentativa de conectar.
        let e = executar_interno(&c, &p, "schematize-probe", "probe").unwrap_err();
        assert!(!e.contains("recusado pela política"), "a interna não pode ser barrada: {e}");
        assert!(e.contains("não confiado"), "chegou até a conexão: {e}");
    }

    #[test]
    fn execucao_interna_continua_auditada_com_veredito_proprio() {
        let (c, p) = ambiente("interna-audit");
        let _ = executar_interno(&c, &p, "schematize-probe", "probe");
        let l = &auditoria::listar_comandos(&c, "srv", 1).unwrap()[0];
        assert_eq!(l.veredito, "confirm", "operação interna entra na trilha, não some dela");
        assert!(l.comando.contains("schematize-probe"));
    }

    #[test]
    fn o_mcp_nao_alcanca_a_execucao_interna() {
        // O que sustenta a segurança da porta interna: o agente não tem como chamá-la.
        let fonte = include_str!("../mcp/tools.rs");
        assert!(!fonte.contains("executar_interno"), "o MCP não pode expor a porta interna");
        assert!(fonte.contains("vps::executar("), "o MCP usa a porta normal, com política");
    }

    #[test]
    fn erro_de_conexao_e_distinguivel_de_saida_vazia() {
        // O que sustenta o diagnóstico da sondagem: `erro` preenchido significa "não falei com
        // o host", e isso NÃO pode ser confundido com "o host respondeu nada".
        let base = ExecOut {
            exit_code: Some(255),
            stdout: String::new(),
            stderr: String::new(),
            duracao_ms: 1,
            auditoria_id: 1,
            erro: None,
        };
        let sem_conexao = ExecOut { erro: Some(ErroSsh::PermissaoNegada), ..base.clone() };
        let respondeu_vazio = ExecOut { exit_code: Some(0), ..base };
        assert!(sem_conexao.erro.is_some() && !sem_conexao.sucesso());
        assert!(respondeu_vazio.erro.is_none() && respondeu_vazio.sucesso());
    }

    #[test]
    fn transcript_marca_de_onde_veio_cada_parte() {
        let t = montar_transcript("linha de saida", "algo deu errado");
        assert!(t.contains("--- stdout ---") && t.contains("linha de saida"));
        assert!(t.contains("--- stderr ---") && t.contains("algo deu errado"));
        assert_eq!(montar_transcript("", "").trim(), "(sem saída)");
        assert!(!montar_transcript("so stdout", "").contains("stderr"));
    }

    #[test]
    fn sucesso_exige_exit_zero_e_nenhum_erro_de_conexao() {
        let base = ExecOut {
            exit_code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
            duracao_ms: 1,
            auditoria_id: 1,
            erro: None,
        };
        assert!(base.sucesso());
        assert!(!ExecOut { exit_code: Some(1), ..base.clone() }.sucesso());
        assert!(!ExecOut { erro: Some(ErroSsh::PermissaoNegada), ..base.clone() }.sucesso());
        assert!(!ExecOut { exit_code: None, ..base }.sucesso(), "morto por sinal não é sucesso");
    }
}
