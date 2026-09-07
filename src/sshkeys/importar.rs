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

    // 1. Copia para um temporário NO MESMO diretório, já em 600. Ver o cabeçalho: validar na
    //    origem falharia por permissão no caso mais comum, e temp fora do dir quebra o rename.
    let tmp_p = dir.join(format!("{name}{TMP_SUFFIX}"));
    let _ = fs::remove_file(&tmp_p); // resto de uma tentativa anterior interrompida
    fs::copy(origem, &tmp_p).map_err(|e| format!("não consegui copiar a chave: {e}"))?;
    crate::util::definir_modo(&tmp_p, 0o600);

    // 2. Valida DE VERDADE: se o ssh-keygen deriva a pública, é chave privada legítima e a
    //    passphrase (se houver) está certa. Nada de heurística sobre o cabeçalho do arquivo.
    let origem_parece_publica =
        origem.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("pub"))
            == Some(true);
    let linha_pub = match derivar_publica(&tmp_p, passphrase.unwrap_or("")) {
        Ok(l) => l,
        Err(cru) => {
            // Não deixa rastro de chave meio-importada em ~/.ssh.
            let _ = fs::remove_file(&tmp_p);
            return Err(classificar_erro(&cru, origem_parece_publica));
        }
    };
    let linha_pub = com_comentario(&linha_pub, comment);

    // 3. Só agora publica o par. `rename` no mesmo diretório é atômico: ou a chave está
    //    inteira em ~/.ssh, ou não está — nunca meio gravada.
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
