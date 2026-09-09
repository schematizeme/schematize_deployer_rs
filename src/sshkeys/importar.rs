//! IMPORTAR uma chave que já existe para a gestão do app.
//!
//! **O quê:** traz um par já existente (outra máquina, backup, cofre) para `~/.ssh/<name>`,
//! com as permissões do piso, derivando a PÚBLICA da própria privada.
//!
//! **Onde:** `schematize ssh import` (CLI) e o botão "importar" da tela de chaves (GUI).
//! Fecha o buraco de o gestor só saber CRIAR: quem já tinha chave não conseguia usá-la.
//!
//! ## Três decisões que este arquivo toma, e por quê
//!
//! **1. Copia primeiro, valida depois.** O `ssh-keygen -y` se RECUSA a ler um arquivo com
//! permissão aberta (`Load key: bad permissions`) — e chave vinda de pendrive, de backup ou
//! de `/tmp` está quase sempre em 644. Validar na origem faria a importação falhar, para o
//! caso mais comum, com um erro do OpenSSH que não diz o que fazer. Então o arquivo é
//! copiado para um temporário **no próprio `~/.ssh`** já em 600, e é o temporário que se
//! valida. Temporário no mesmo diretório também é o que torna o `rename` final atômico
//! (temp em `/tmp` dá `EXDEV` — invariante 4 da casa).
//!
//! **2. `-P` SEMPRE, mesmo vazio.** Sem `-P`, uma chave cifrada faz o `ssh-keygen` **travar
//! pedindo a passphrase** — e redirecionar o stdin NÃO resolve, porque ele abre `/dev/tty`
//! direto (medido: `</dev/null` continua pendurado até o timeout matar). Passar `-P` sempre
//! é o que garante que a importação falha rápido em vez de pendurar a GUI. Isso é estrutura,
//! não sorte: [`readpub_args`] é pura e há teste exigindo o `-P`.
//!
//! **3. A passphrase da chave é PRESERVADA.** Só usamos a passphrase para *derivar a
//! pública*; o arquivo privado é copiado byte a byte. Uma chave que chegou cifrada continua
//! cifrada em `~/.ssh` — importar não é desproteger.
//!
//! ## Segurança
//!
//! A privada nunca é lida para memória nem impressa: `fs::copy` a move de arquivo para
//! arquivo, e o que sai daqui é só a linha PÚBLICA. A passphrase vai no `-P`, como o
//! `generate` já faz no `-N` — e, como lá, **fica visível num `ps` durante a chamada**.
//! Não há alternativa não-interativa no `ssh-keygen` (não lê senha de stdin nem de env com
//! `-y`); o registro fica aqui para a decisão ser consciente, não acidental.

use super::*;

/// Sufixo do arquivo temporário usado durante a importação, dentro do próprio `~/.ssh`.
const TMP_SUFFIX: &str = ".schematize-importando";

/// **O quê:** monta os argumentos do `ssh-keygen -y` (deriva a pública a partir da privada).
/// Função PURA — testável sem tocar em `~/.ssh` nem executar nada.
///
/// **Onde:** [`derivar_publica`], único chamador.
///
/// **Por que o `-P` entra sempre, inclusive vazio:** é o que impede o `ssh-keygen` de abrir
/// prompt de passphrase numa chave cifrada. Sem ele o processo **trava** — e não adianta
/// fechar o stdin, porque ele lê de `/dev/tty`. Ver o cabeçalho do módulo.
pub fn readpub_args(priv_path: &str, passphrase: &str) -> Vec<String> {
    vec![
        "-y".into(),
        // -P sempre presente: vazio significa "sem senha", NUNCA "pergunte".
        "-P".into(),
        passphrase.into(),
        "-f".into(),
        priv_path.into(),
    ]
}

/// **O quê:** traduz o erro cru do `ssh-keygen` numa mensagem que diz o que FAZER.
/// Função PURA — recebe o texto do erro, devolve o texto do usuário.
///
/// **Onde:** [`import`], quando a derivação da pública falha.
///
/// **Por que existe:** o OpenSSH responde `error in libcrypto` para "isto não é uma chave
/// privada", que não ajuda ninguém — e é exatamente o que sai quando a pessoa aponta para o
/// `.pub` por engano, que é o engano mais provável. Piso "prever macacos" (§37.48): a
/// mensagem diz o próximo passo e não culpa quem digitou.
pub fn classificar_erro(stderr: &str, origem_parece_publica: bool) -> String {
    let s = stderr.to_lowercase();
    if s.contains("incorrect passphrase") {
        return "a chave está protegida por passphrase. Repita com --passphrase <senha> \
                (ela é usada só para ler a chave; a chave continua cifrada em ~/.ssh)"
            .to_string();
    }
    if s.contains("bad permissions") {
        // Não deveria acontecer: copiamos para 600 antes de validar. Se aparecer, o
        // diagnóstico honesto é "o piso não foi aplicado", não "arrume suas permissões".
        return "o arquivo temporário não ficou em 600 antes da validação — isto é um bug \
                do schematize, não da sua chave. Reporte com `schematize doctor`"
            .to_string();
    }
    if origem_parece_publica {
        return "isso é uma chave PÚBLICA (.pub). Aponte para a PRIVADA — o arquivo de mesmo \
                nome, sem a extensão .pub"
            .to_string();
    }
    "não consegui ler isso como chave privada SSH. Formatos aceitos: OpenSSH e PEM. \
     Se o arquivo veio de PuTTY (.ppk), converta antes com `puttygen chave.ppk -O private-openssh -o chave`"
        .to_string()
}

/// **O quê:** deriva a linha da chave PÚBLICA a partir de uma privada em disco.
/// Devolve a linha (`ssh-ed25519 AAAA… comentário`) ou o erro cru do `ssh-keygen`.
///
/// **Onde:** [`import`], sobre o arquivo TEMPORÁRIO já em 600 — nunca sobre a origem.
fn derivar_publica(priv_path: &Path, passphrase: &str) -> Result<String, String> {
    let args = readpub_args(&priv_path.to_string_lossy(), passphrase);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let saida = util::run("ssh-keygen", &refs)?;
    let linha = saida.trim().to_string();
    if linha.is_empty() {
        return Err("ssh-keygen não devolveu chave pública".to_string());
    }
    Ok(linha)
}

/// **O quê:** garante que a linha pública tenha comentário; sem ele, usa o padrão da casa.
///
/// **Onde:** [`import`]. Chave sem comentário vira uma linha anônima no `authorized_keys` de
/// um servidor, e ninguém depois sabe de quem é — é o comentário que torna a chave
/// revogável na prática.
fn com_comentario(linha: &str, override_c: Option<&str>) -> String {
    let mut campos = linha.split_whitespace();
    let algo = campos.next().unwrap_or("").to_string();
    let material = campos.next().unwrap_or("").to_string();
    let atual: String = campos.collect::<Vec<_>>().join(" ");
    let comentario = match override_c {
        Some(c) if !c.trim().is_empty() => c.trim().to_string(),
        _ if !atual.trim().is_empty() => atual,
        _ => default_comment(),
    };
    format!("{algo} {material} {comentario}")
}

/// **O quê:** importa um par de chaves já existente para `~/.ssh/<name>`, derivando a
/// pública da privada e aplicando o piso de permissões (privada 600, pública 644).
///
/// **Onde:** `schematize ssh import` e o wire da GUI. Contrapartida de [`generate`]: um
/// cria, o outro adota.
///
/// Recusa sobrescrever um par existente sem `force`. NUNCA imprime nem retorna a privada.
pub fn import(
    origem: &Path,
    name: &str,
    passphrase: Option<&str>,
    comment: Option<&str>,
    force: bool,
) -> Result<KeyInfo, String> {
    valid_name(name)?;

    if !origem.exists() {
        return Err(format!("não achei o arquivo: {}", origem.display()));
    }
    if !origem.is_file() {
        return Err(format!("{} não é um arquivo", origem.display()));
    }

    let dir = ensure_ssh_dir()?;
    let priv_p = dir.join(name);
    let pub_p = dir.join(format!("{name}.pub"));

    // Importar sobre si mesmo apagaria a chave: o temporário é copiado da origem e depois
    // renomeado por cima dela. Falha fechada, antes de tocar em qualquer coisa.
    let mesma = std::fs::canonicalize(origem).ok().zip(std::fs::canonicalize(&priv_p).ok());
    if let Some((a, b)) = mesma {
        if a == b {
            return Err(format!("'{name}' JÁ É a chave gerenciada — nada a importar"));
        }
    }

    if (priv_p.exists() || pub_p.exists()) && !force {
        return Err(format!(
            "a chave '{name}' já existe em ~/.ssh — use --force para sobrescrever"
        ));
    }

    let origem_parece_publica =
        origem.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("pub"))
            == Some(true);
    let bytes = fs::read(origem).map_err(|e| format!("não consegui ler a chave: {e}"))?;
    gravar_e_validar(&bytes, name, passphrase, comment, force, origem_parece_publica)
}

/// **O quê:** grava a chave privada em `~/.ssh` com segurança e valida que ela é real.
///
/// **Onde:** [`import`] (a partir de arquivo) e [`import_texto`] (a partir de colagem).
///
/// ## A ordem aqui é a segurança, e nenhuma etapa é enfeite
///
/// 1. **Temporário no MESMO diretório, já em 600.** Validar na origem falharia por permissão no
///    caso mais comum (chave vinda de backup com modo aberto), e temporário fora do diretório
///    quebraria o `rename` atômico do passo 3 — `rename` só é atômico dentro do mesmo
///    filesystem.
/// 2. **Validação DE VERDADE.** Se o `ssh-keygen` deriva a pública, então é chave privada
///    legítima e a passphrase (quando há) está certa. Nada de heurística sobre o cabeçalho: um
///    arquivo que começa com `-----BEGIN` pode ser qualquer coisa.
/// 3. **`rename` atômico.** Ou a chave está inteira em `~/.ssh`, ou não está — nunca meio
///    gravada. Uma chave privada truncada é pior que chave nenhuma: ela parece existir.
///
/// **É função compartilhada de propósito.** A colagem não pode ter um caminho com menos
/// verificação que o arquivo — e teria, se cada entrada repetisse estes três passos por conta.
fn gravar_e_validar(
    bytes: &[u8],
    name: &str,
    passphrase: Option<&str>,
    comment: Option<&str>,
    _force: bool,
    origem_parece_publica: bool,
) -> Result<KeyInfo, String> {
    let dir = ensure_ssh_dir()?;
    let priv_p = dir.join(name);
    let pub_p = dir.join(format!("{name}.pub"));

    let tmp_p = dir.join(format!("{name}{TMP_SUFFIX}"));
    let _ = fs::remove_file(&tmp_p); // resto de uma tentativa anterior interrompida
    fs::write(&tmp_p, bytes).map_err(|e| format!("não consegui gravar a chave: {e}"))?;
    crate::util::definir_modo(&tmp_p, 0o600);

    let linha_pub = match derivar_publica(&tmp_p, passphrase.unwrap_or("")) {
        Ok(l) => l,
        Err(cru) => {
            // Não deixa rastro de chave meio-importada em ~/.ssh.
            let _ = fs::remove_file(&tmp_p);
            return Err(classificar_erro(&cru, origem_parece_publica));
        }
    };
    let linha_pub = com_comentario(&linha_pub, comment);

    fs::rename(&tmp_p, &priv_p).map_err(|e| {
        let _ = fs::remove_file(&tmp_p);
        format!("não consegui gravar a privada em ~/.ssh: {e}")
    })?;
    fs::write(&pub_p, format!("{linha_pub}\n"))
        .map_err(|e| format!("não consegui gravar a pública: {e}"))?;
    crate::util::definir_modo(&priv_p, 0o600);
    crate::util::definir_modo(&pub_p, 0o644);

    read_info(name)
}

/// **O quê:** normaliza uma chave privada COLADA para o formato que o OpenSSH aceita. PURA.
///
/// **Onde:** [`import_texto`], antes de qualquer coisa tocar o disco.
///
/// ## Por que isto existe, e por que é a metade que importa da colagem
///
/// Chave colada de um cofre de senhas ou de um navegador chega quebrada de jeitos previsíveis,
/// e o `ssh-keygen` responde a TODOS com o mesmo *"invalid format"*. A pessoa conclui que a
/// chave está corrompida, quando o que faltava era um `\n`:
///
/// - **Sem `\n` final** — o caso mais comum. Copiar o campo de um cofre não leva a quebra de
///   linha do fim, e o OpenSSH **exige** que o `-----END …-----` termine em nova linha.
/// - **CRLF** — passou por Windows, por campo de texto web ou por anexo de e-mail.
/// - **Linhas em branco antes/depois** — do clique que seleciona o parágrafo inteiro.
/// - **Espaço à direita** nas linhas, de alguns campos de formulário.
///
/// O que NÃO se toca: o miolo Base64 e a ordem das linhas. Normalizar conserta **transporte**,
/// não adivinha conteúdo — se o material estiver mesmo corrompido, a validação por
/// `ssh-keygen` continua reprovando, que é o certo.
pub fn normalizar_colado(bruto: &str) -> String {
    let unificado = bruto.replace("\r\n", "\n").replace('\r', "\n");
    let linhas: Vec<&str> = unificado.lines().map(str::trim_end).collect();
    let inicio = linhas.iter().position(|l| !l.trim().is_empty());
    let fim = linhas.iter().rposition(|l| !l.trim().is_empty());
    match (inicio, fim) {
        // O `\n` final é obrigatório — é exatamente o que a colagem de cofre costuma comer.
        (Some(i), Some(f)) => format!("{}\n", linhas[i..=f].join("\n")),
        _ => String::new(),
    }
}

/// **O quê:** importa uma chave privada a partir de TEXTO colado, sem arquivo nenhum.
///
/// **Onde:** `ssh import --paste`, e a janela quando a pessoa cola em vez de escolher arquivo.
///
/// ## Por que o texto NUNCA entra por argumento de linha de comando
///
/// `--private "-----BEGIN…"` colocaria a chave privada no histórico do shell, no `ps` de
/// qualquer usuário da máquina e no log de quem audita comando. O texto entra por **stdin**,
/// que não deixa nenhum desses rastros.
///
/// O resto do caminho é IDÊNTICO ao do arquivo — temporário em 600 no mesmo diretório,
/// validação por `ssh-keygen` (o que prova que é chave de verdade) e `rename` atômico.
/// Compartilhar esse trecho não é economia de linhas: é o que impede a colagem de ganhar um
/// caminho com menos verificação que o arquivo.
pub fn import_texto(
    texto: &str,
    name: &str,
    passphrase: Option<&str>,
    comment: Option<&str>,
    force: bool,
) -> Result<KeyInfo, String> {
    valid_name(name)?;
    let conteudo = normalizar_colado(texto);
    if conteudo.is_empty() {
        return Err("não veio nada — o texto colado está vazio".into());
    }
    // Colar a PÚBLICA por engano é o erro mais provável aqui: quem tem só a `ssh-rsa AAAA…` na
    // mão acha que aquilo é "a chave". Custa nada dizer ANTES de gravar.
    if conteudo.starts_with("ssh-") || conteudo.starts_with("ecdsa-") {
        return Err("isso é a chave PÚBLICA (começa com `ssh-…`). Cole a PRIVADA — o bloco \
                    entre `-----BEGIN OPENSSH PRIVATE KEY-----` e `-----END …-----`"
            .to_string());
    }
    gravar_e_validar(conteudo.as_bytes(), name, passphrase, comment, force, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// O `-P` tem de estar SEMPRE, inclusive com passphrase vazia — é o que impede o
    /// `ssh-keygen` de pendurar num prompt de senha. Sem esta asserção, alguém "limpa" o
    /// argumento vazio um dia e a GUI passa a travar em chave cifrada, sem erro nenhum.
    #[test]
    fn readpub_args_sempre_tem_p_mesmo_vazio() {
        let a = readpub_args("/home/u/.ssh/k", "");
        let i = a.iter().position(|s| s == "-P").expect("-P é o que impede o prompt");
        assert_eq!(a[i + 1], "", "passphrase vazia = sem senha, não 'pergunte'");
        assert!(a.contains(&"-y".to_string()));
        let fi = a.iter().position(|s| s == "-f").unwrap();
        assert_eq!(a[fi + 1], "/home/u/.ssh/k");
    }

    /// Com passphrase, ela é repassada no `-P` — e o caminho continua no `-f`.
    #[test]
    fn readpub_args_repassa_a_passphrase() {
        let a = readpub_args("/k", "s3nh4");
        let i = a.iter().position(|s| s == "-P").unwrap();
        assert_eq!(a[i + 1], "s3nh4");
    }

    /// Cada erro do OpenSSH vira uma instrução diferente. O caso do `.pub` é o engano mais
    /// provável, e o `error in libcrypto` sozinho não diz nada a ninguém.
    #[test]
    fn erros_viram_mensagem_acionavel() {
        let p = classificar_erro("Load key \"/k\": incorrect passphrase supplied", false);
        assert!(p.contains("--passphrase"), "deve ensinar o próximo passo: {p}");

        let pubx = classificar_erro("Load key \"/k.pub\": error in libcrypto", true);
        assert!(pubx.contains("PÚBLICA"), "deve apontar o engano do .pub: {pubx}");

        let generico = classificar_erro("Load key \"/k\": error in libcrypto", false);
        assert!(generico.contains("OpenSSH"), "deve dizer os formatos aceitos: {generico}");
        assert!(generico.contains("ppk"), "PuTTY é a origem clássica: {generico}");

        // A passphrase vence o palpite do `.pub`: se a senha está errada, o arquivo É uma
        // chave privada, e mandar "aponte para a privada" seria mandar consertar o certo.
        let ambos = classificar_erro("incorrect passphrase supplied", true);
        assert!(ambos.contains("--passphrase"), "passphrase tem precedência: {ambos}");
    }

    /// Nenhuma mensagem pode ecoar a passphrase — ela chega aqui dentro do texto do erro.
    #[test]
    fn mensagem_nunca_ecoa_o_erro_cru() {
        let cru = "Load key: incorrect passphrase supplied s3nh4-secreta";
        let msg = classificar_erro(cru, false);
        assert!(!msg.contains("s3nh4-secreta"), "vazou o conteúdo do erro cru: {msg}");
    }

    /// Comentário: preserva o que a chave já tinha, aceita override, e nunca deixa vazio.
    #[test]
    fn comentario_e_preservado_sobrescrito_ou_preenchido() {
        let l = "ssh-ed25519 AAAAC3Nza deploy@antigo";
        assert_eq!(com_comentario(l, None), l, "sem override, preserva o original");

        let sobrescrito = com_comentario(l, Some("novo@host"));
        assert!(sobrescrito.ends_with("novo@host"));
        assert!(sobrescrito.starts_with("ssh-ed25519 AAAAC3Nza"), "material não pode mudar");

        // Sem comentário nenhum: cai no padrão da casa, nunca numa linha anônima.
        let anonima = com_comentario("ssh-ed25519 AAAAC3Nza", None);
        assert!(anonima.starts_with("schematize:") || anonima.contains("schematize:"));
        assert_eq!(anonima.split_whitespace().count(), 3, "algo + material + comentário");
    }

    /// Nome inválido é recusado ANTES de qualquer I/O — a importação não pode ser o caminho
    /// que escapa de `~/.ssh` (o `generate` já é blindado; este não pode ser a porta dos fundos).
    #[test]
    fn import_recusa_nome_que_escaparia_de_ssh() {
        let inexistente = std::path::Path::new("/tmp/nao-existe-schematize-teste");
        for mau in ["../evil", "a/b", "", ".hidden"] {
            let r = import(inexistente, mau, None, None, false);
            assert!(r.is_err(), "nome {mau:?} devia ser recusado");
            let e = r.unwrap_err();
            assert!(e.contains("inválido"), "recusa tem de ser pelo NOME, não pelo arquivo: {e}");
        }
    }
}

#[cfg(test)]
mod tests_colagem {
    use super::*;

    /// **O caso que motivou tudo.** Chave copiada de um gerenciador de senhas vem SEM a quebra
    /// de linha final, e o OpenSSH exige que o `-----END …-----` termine em `\n`. Medido: o
    /// texto cru faz o `ssh-keygen` responder `error in libcrypto` — e a pessoa conclui que a
    /// chave está corrompida, quando o que falta é um caractere.
    #[test]
    fn colagem_sem_quebra_final_ganha_a_quebra() {
        let sem = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----";
        assert!(!sem.ends_with('\n'));
        assert!(normalizar_colado(sem).ends_with("-----END OPENSSH PRIVATE KEY-----\n"));
    }

    /// Passou por Windows, campo web ou anexo de e-mail: CRLF vira LF.
    #[test]
    fn crlf_vira_lf() {
        let n = normalizar_colado("-----BEGIN X-----\r\nabc\r\n-----END X-----\r\n");
        assert!(!n.contains('\r'), "sobrou CR: {n:?}");
        assert_eq!(n, "-----BEGIN X-----\nabc\n-----END X-----\n");
    }

    /// Clique que seleciona o parágrafo inteiro traz linhas em branco em volta; alguns campos
    /// de formulário deixam espaço à direita.
    #[test]
    fn linhas_em_branco_e_espaco_a_direita_somem() {
        let n = normalizar_colado("\n\n  -----BEGIN X-----  \nabc   \n-----END X-----\n\n  \n");
        assert_eq!(n, "  -----BEGIN X-----\nabc\n-----END X-----\n");
    }

    /// O MIOLO não é tocado: normalizar conserta transporte, não adivinha conteúdo. Se o
    /// Base64 estiver corrompido de verdade, a validação por `ssh-keygen` tem de reprovar.
    #[test]
    fn o_base64_do_meio_nao_e_alterado() {
        let corpo = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU";
        let n = normalizar_colado(&format!("-----BEGIN X-----\n{corpo}\n-----END X-----"));
        assert!(n.contains(corpo), "o miolo mudou: {n}");
    }

    /// Texto vazio (ou só espaço) não vira uma chave vazia gravada em `~/.ssh`.
    #[test]
    fn vazio_continua_vazio() {
        assert_eq!(normalizar_colado(""), "");
        assert_eq!(normalizar_colado("\n\n  \n"), "");
        assert!(import_texto("   \n", "x", None, None, false).is_err());
    }

    /// Colar a PÚBLICA por engano é o erro mais provável: quem tem só a `ssh-rsa AAAA…` na mão
    /// acha que aquilo é "a chave". A mensagem diz o que colar, em vez de "formato inválido".
    #[test]
    fn publica_colada_por_engano_e_dita_antes_de_gravar() {
        let e = import_texto("ssh-ed25519 AAAAC3Nz teste@x\n", "k", None, None, false).unwrap_err();
        assert!(e.contains("PÚBLICA"), "{e}");
        assert!(e.contains("BEGIN OPENSSH PRIVATE KEY"), "tem de dizer o que colar: {e}");
    }

    /// Nome inválido é recusado ANTES de qualquer escrita — o caminho da colagem não pode ter
    /// menos validação que o do arquivo.
    #[test]
    fn nome_invalido_e_recusado_na_colagem_tambem() {
        assert!(import_texto(
            "-----BEGIN X-----\nabc\n-----END X-----\n",
            "../fuga",
            None,
            None,
            false
        )
        .is_err());
    }
}
