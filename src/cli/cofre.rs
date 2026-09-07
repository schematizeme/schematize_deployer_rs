//! Subcomandos do COFRE (`deployer cofre <sub>`).
//!
//! **O quê:** criar o cofre, ver o estado e trocar a passphrase.
//!
//! **Onde:** despachado por `main.rs` (`Cmd::Cofre`). A criptografia mora em
//! [`deployer::cofre`]; aqui só há entrada e saída.
//!
//! ## A passphrase nunca vem por argumento
//!
//! Não há `--passphrase` nestes comandos, e a ausência é a decisão. Argumento de linha de
//! comando aparece em `ps` para **qualquer processo da máquina** — inclusive o agente que
//! este cofre existe para manter longe do segredo — e fica no histórico do shell.
//!
//! O `ssh import` tem `--passphrase` por um motivo diferente e legítimo: lá ela é da chave
//! que já existe, e o comando precisa rodar sem interação (script, GUI). Aqui a passphrase é
//! *a* do cofre: se ela vazar, vaza tudo.

use deployer::cofre;

/// **O quê:** lê uma passphrase sem eco pelo terminal; se não houver terminal, cai para o
/// stdin — avisando o que isso custa.
///
/// **Onde:** todo comando deste arquivo.
///
/// **Por que o fallback existe:** o `rpassword` lê de `/dev/tty`, e fora de um terminal isso
/// falha com `os error 6` — uma mensagem que não diz nada a ninguém. Quem roda o comando de
/// dentro de um script, de um CI ou de um terminal aberto por lançador de desktop batia
/// nesse erro sem saber o que fazer. §37.48: edge case que um leigo atinge é bug do
/// software, não erro do usuário.
///
/// **Por que o fallback AVISA:** passphrase por pipe fica no histórico do shell e no `ps` de
/// quem a gerou. Ainda é melhor que não ter caminho nenhum, mas quem usa precisa saber —
/// silenciar seria dar a garantia sem o suporte dela.
/// **O quê:** a mesma leitura sem eco, exposta para o `cli::dns`.
///
/// **Onde:** `cli::dns`. Reexportada em vez de duplicada: o tratamento de "não há terminal"
/// custou uma medição para ficar certo, e ter duas cópias é ter uma que envelhece.
pub(crate) fn ler_passphrase_pub(prompt: &str) -> Result<String, String> {
    ler_passphrase(prompt)
}

fn ler_passphrase(prompt: &str) -> Result<String, String> {
    match rpassword::prompt_password(prompt) {
        Ok(p) => Ok(p),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound || sem_terminal(&e) => {
            eprintln!("aviso: sem terminal — lendo a passphrase do stdin.");
            eprintln!("       Por pipe ela pode ficar no histórico do shell e no `ps`.");
            eprintln!("       Num terminal de verdade este comando não ecoa nem registra nada.");
            let mut linha = String::new();
            std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut linha)
                .map_err(|e| format!("não consegui ler a passphrase do stdin: {e}"))?;
            Ok(linha.trim_end_matches(['\n', '\r']).to_string())
        }
        Err(e) => Err(format!(
            "não consegui ler a passphrase: {e}. Rode `deployer vault …` num terminal, \
             ou passe a passphrase pelo stdin (`printf '%s\\n' \"$SENHA\" | deployer …`)"
        )),
    }
}

/// **O quê:** o erro do `rpassword` é "não há terminal aqui"?
///
/// **Onde:** [`ler_passphrase`]. O `ENXIO` (`os error 6`) é o que o Linux devolve ao abrir
/// `/dev/tty` sem terminal de controle; o macOS e o Windows respondem outros. Casar por
/// `kind` cobre o que o Rust classifica, e o `raw_os_error` cobre o `ENXIO` que ele deixa
/// como `Uncategorized`.
fn sem_terminal(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(6)) // ENXIO
        || e.kind() == std::io::ErrorKind::BrokenPipe
        || e.kind() == std::io::ErrorKind::PermissionDenied
}

/// **O quê:** lê a passphrase duas vezes e exige que batam.
///
/// **Onde:** criação e troca. Errar de dedo ao **criar** um cofre é perder o conteúdo para
/// sempre — não há recuperação, e é isso que faz a confirmação ser obrigatória e não gentileza.
fn ler_passphrase_nova() -> Result<String, String> {
    let a = ler_passphrase("nova passphrase do cofre: ")?;
    if a.trim().is_empty() {
        return Err("a passphrase não pode ser vazia — sem ela o cofre não protege nada".into());
    }
    let b = ler_passphrase("repita a passphrase: ")?;
    if a != b {
        return Err("as duas não bateram — nada foi gravado".into());
    }
    Ok(a)
}

/// Despacha `deployer cofre <sub>`.
pub(crate) fn cofre_cmd(sub: crate::cli::args::VaultCmd) -> Result<(), String> {
    match sub {
        crate::cli::args::VaultCmd::Init => {
            if cofre::arquivo::existe() {
                // Falha fechada: recriar por cima apagaria o conteúdo, e não há desfazer.
                return Err(format!(
                    "já existe um cofre em {}. Para trocar a senha use `deployer cofre \
                     trocar-senha`; para recomeçar do zero, apague o arquivo você mesmo — \
                     não faço isso por você porque não há como voltar atrás",
                    cofre::arquivo::caminho().display()
                ));
            }
            let pass = ler_passphrase_nova()?;
            // Cofre novo nasce com um conteúdo mínimo válido: assim `abrir` funciona de
            // imediato e o formato é exercitado agora, não na primeira gravação de verdade.
            cofre::arquivo::gravar(&pass, b"{}")?;
            println!("cofre criado em {}", cofre::arquivo::caminho().display());
            println!();
            println!("Guarde essa passphrase. NÃO há recuperação: ela não é armazenada em");
            println!("lugar nenhum — é ela que deriva a chave, e sem ela o conteúdo é ruído.");
            Ok(())
        }

        crate::cli::args::VaultCmd::Status => {
            let p = cofre::arquivo::caminho();
            if !cofre::arquivo::existe() {
                println!("cofre: não existe ainda (crie com `deployer vault init`)");
                return Ok(());
            }
            println!("cofre: {}", p.display());
            let bytes = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            println!("  tamanho: {bytes} bytes");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(m) = std::fs::metadata(&p) {
                    let modo = m.permissions().mode() & 0o777;
                    let ok = if modo == 0o600 { "ok" } else { "ATENÇÃO: devia ser 600" };
                    println!("  permissão: {modo:o} ({ok})");
                }
            }
            // O cabeçalho viaja em claro de propósito — é preciso para derivar a chave. Mostrar
            // os parâmetros deixa auditável se este cofre foi criado com custo forte.
            match std::fs::read(&p).map_err(|e| e.to_string()).and_then(|b| {
                cofre::cripto::Cabecalho::ler(&b).map(|c| (c.m_cost, c.t_cost, c.p_cost))
            }) {
                Ok((m, t, pp)) => {
                    println!("  kdf: argon2id m={m}KiB t={t} p={pp}");
                    if m < cofre::cripto::M_COST {
                        println!(
                            "  NOTA: custo de memória abaixo do padrão atual ({}KiB). \
                             `trocar-senha` regrava com o custo novo.",
                            cofre::cripto::M_COST
                        );
                    }
                }
                Err(e) => println!("  cabeçalho ilegível: {e}"),
            }
            Ok(())
        }

        crate::cli::args::VaultCmd::ChangePassphrase => {
            let atual = ler_passphrase("passphrase atual: ")?;
            // Abre ANTES de pedir a nova: sem isto, quem erra a atual só descobre depois de
            // digitar a nova duas vezes.
            let conteudo = cofre::arquivo::abrir(&atual)?;
            let nova = ler_passphrase_nova()?;
            // Regrava com salt, nonce E parâmetros de KDF novos — trocar a senha é também a
            // forma de subir o custo de um cofre antigo.
            cofre::arquivo::gravar(&nova, &conteudo)?;
            println!("passphrase trocada. O conteúdo continua o mesmo.");
            Ok(())
        }
    }
}
