//! COFRE — a camada de disco: gravar e abrir o arquivo selado.
//!
//! **O quê:** [`gravar`] sela um segredo e o põe em disco de forma **atômica**; [`abrir`] lê
//! e destrava. O formato é `cabeçalho em claro || cifrado`, com o cabeçalho autenticado como
//! dado associado (ver [`super::cripto`]).
//!
//! **Onde:** `deployer cofre init|abrir` e, adiante, o registro de hosts.
//!
//! ## Escrita atômica, e por que não é zelo excessivo
//!
//! Grava num temporário **no mesmo diretório** e faz `rename`. Um `write` direto que morra no
//! meio — máquina desligada, disco cheio — deixa o cofre truncado, e cofre truncado é
//! **perda total do segredo**, não uma linha faltando. `rename` no mesmo sistema de arquivos
//! é atômico; temporário em `/tmp` daria `EXDEV` e viraria cópia não-atômica sem avisar.
//! É a invariante 4 da casa, aqui com a consequência mais cara possível.
//!
//! O temporário nasce em **600** antes de receber conteúdo: entre criar e restringir há uma
//! janela em que outro usuário leria, e ela não precisa existir.

use super::cripto::{self, Cabecalho};
use std::path::{Path, PathBuf};

/// **O quê:** caminho do cofre. **Onde:** [`gravar`] e [`abrir`], quando o chamador não
/// passa um explícito (os testes passam).
pub fn caminho() -> PathBuf {
    crate::nucleo::util::dados_dir().join("deployer-cofre.bin")
}

/// **O quê:** o cofre já existe? **Onde:** decide entre "destrave" e "crie" na primeira vez.
pub fn existe() -> bool {
    caminho().is_file()
}

/// **O quê:** sela `claro` com `passphrase` e grava atomicamente em `destino`.
///
/// **Onde:** [`gravar`] e os testes. Cada gravação sorteia **salt e nonce novos** — reusar
/// nonce com a mesma chave destrói o sigilo, e derivar de novo custa um segundo que só o
/// dono paga.
pub fn gravar_em(destino: &Path, passphrase: &str, claro: &[u8]) -> Result<(), String> {
    if passphrase.is_empty() {
        // Falha fechada: cofre sem passphrase é arquivo com etapa extra, não cofre.
        return Err("a passphrase não pode ser vazia — sem ela o cofre não protege nada".into());
    }
    let cab = Cabecalho::novo()?;
    let chave = cripto::derivar(passphrase, &cab)?;
    let selado = cripto::selar(&chave, &cab, claro)?;

    let dir =
        destino.parent().ok_or_else(|| format!("{} não tem diretório pai", destino.display()))?;
    std::fs::create_dir_all(dir)
        .map_err(|e| format!("não consegui criar {}: {e}", dir.display()))?;

    let mut corpo = cab.bytes();
    corpo.extend_from_slice(&selado);

    // Temporário NO MESMO diretório — é o que torna o `rename` atômico.
    let tmp = destino.with_extension("tmp");
    escrever_restrito(&tmp, &corpo)?;
    std::fs::rename(&tmp, destino).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("não consegui publicar o cofre: {e}")
    })?;
    crate::nucleo::util::definir_modo(destino, 0o600);
    Ok(())
}

/// **O quê:** cria o arquivo já em 600 e escreve. **Onde:** [`gravar_em`].
///
/// **Por que 600 na CRIAÇÃO e não depois:** criar em 644 e restringir em seguida deixa uma
/// janela — pequena, mas real — em que outro usuário da máquina lê o cofre. Janela que não
/// precisa existir não deve existir.
fn escrever_restrito(p: &Path, dados: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(p).map_err(|e| format!("não consegui abrir {}: {e}", p.display()))?;
    f.write_all(dados).map_err(|e| format!("não consegui escrever {}: {e}", p.display()))?;
    // `sync_all` antes do rename: sem isto o rename pode chegar ao disco ANTES do conteúdo, e
    // uma queda de energia no meio deixa um cofre publicado e vazio.
    f.sync_all().map_err(|e| format!("não consegui sincronizar {}: {e}", p.display()))
}

/// **O quê:** grava no caminho padrão. **Onde:** a CLI.
pub fn gravar(passphrase: &str, claro: &[u8]) -> Result<(), String> {
    gravar_em(&caminho(), passphrase, claro)
}

/// **O quê:** lê `origem`, destrava com `passphrase` e devolve o segredo em claro.
///
/// **Onde:** [`abrir`] e os testes. O erro de passphrase errada e o de arquivo adulterado são
/// o **mesmo texto**, de propósito (ver [`super::cripto::abrir`]).
pub fn abrir_de(origem: &Path, passphrase: &str) -> Result<Vec<u8>, String> {
    let bruto = std::fs::read(origem).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => {
            "não há cofre ainda — crie um com `deployer cofre init`".to_string()
        }
        _ => format!("não consegui ler o cofre: {e}"),
    })?;
    let cab = Cabecalho::ler(&bruto)?;
    let chave = cripto::derivar(passphrase, &cab)?;
    cripto::abrir(&chave, &cab, &bruto[Cabecalho::tamanho()..])
}

/// **O quê:** abre o cofre do caminho padrão. **Onde:** a CLI.
pub fn abrir(passphrase: &str) -> Result<Vec<u8>, String> {
    abrir_de(&caminho(), passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox(nome: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("deployer-cofre-{nome}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("cofre.bin")
    }

    /// Ida e volta pelo disco.
    #[test]
    fn grava_e_abre_pelo_disco() {
        let p = sandbox("roundtrip");
        gravar_em(&p, "senha-boa", b"host=srv user=deploy").unwrap();
        assert_eq!(abrir_de(&p, "senha-boa").unwrap(), b"host=srv user=deploy");
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    /// **A prova que o plano cobrou, agora sobre o ARQUIVO de verdade:** o que está em
    /// repouso não revela host, usuário nem caminho de chave.
    #[test]
    fn o_arquivo_em_repouso_nao_revela_o_segredo() {
        let p = sandbox("repouso");
        gravar_em(
            &p,
            "senha-boa",
            b"host=servidor-de-producao user=root key=/home/u/.ssh/id_ed25519",
        )
        .unwrap();
        let bytes = std::fs::read(&p).unwrap();
        let texto = String::from_utf8_lossy(&bytes);
        for agulha in ["servidor-de-producao", "root", "id_ed25519", ".ssh", "host="] {
            assert!(!texto.contains(agulha), "o arquivo em repouso vazou {agulha:?}");
        }
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    /// O cofre sai em 600 — ninguém mais do sistema lê.
    #[test]
    #[cfg(unix)]
    fn o_cofre_fica_em_600() {
        use std::os::unix::fs::PermissionsExt;
        let p = sandbox("modo");
        gravar_em(&p, "s", b"x").unwrap();
        let m = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(m, 0o600, "cofre legível por outro usuário");
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    /// Passphrase vazia é recusada: cofre sem senha é arquivo com etapa extra.
    #[test]
    fn passphrase_vazia_e_recusada() {
        let p = sandbox("vazia");
        let e = gravar_em(&p, "", b"x").unwrap_err();
        assert!(e.contains("vazia"), "{e}");
        assert!(!p.exists(), "não pode ter criado arquivo nenhum");
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    /// Regravar sorteia salt e nonce NOVOS — dois cofres com o mesmo conteúdo e a mesma
    /// senha não podem produzir o mesmo arquivo, senão dá para comparar blobs e inferir.
    #[test]
    fn regravar_nao_repete_salt_nem_nonce() {
        let p = sandbox("nonce");
        gravar_em(&p, "s3nh4", b"mesmo conteudo").unwrap();
        let a = std::fs::read(&p).unwrap();
        gravar_em(&p, "s3nh4", b"mesmo conteudo").unwrap();
        let b = std::fs::read(&p).unwrap();
        assert_ne!(a, b, "mesmo conteúdo + mesma senha não pode dar o mesmo arquivo");
        // …e ambos continuam abrindo.
        assert_eq!(abrir_de(&p, "s3nh4").unwrap(), b"mesmo conteudo");
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    /// Adulterar o arquivo em disco é recusado — inclusive no cabeçalho, que viaja em claro.
    #[test]
    fn adulterar_o_arquivo_e_recusado() {
        let p = sandbox("adulterado");
        gravar_em(&p, "s3nh4", b"segredo").unwrap();
        let mut b = std::fs::read(&p).unwrap();
        let ultimo = b.len() - 1;
        b[ultimo] ^= 0xFF;
        std::fs::write(&p, &b).unwrap();
        assert!(abrir_de(&p, "s3nh4").is_err());
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    /// Cofre ausente dá uma mensagem que diz o PRÓXIMO PASSO, não um erro de I/O cru.
    #[test]
    fn cofre_ausente_ensina_o_proximo_passo() {
        let p = sandbox("ausente");
        let e = abrir_de(&p, "s").unwrap_err();
        assert!(e.contains("cofre init"), "a mensagem tem de dizer o que fazer: {e}");
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }

    /// Uma gravação que falha não pode destruir o cofre que já existia: o conteúdo antigo
    /// continua abrindo. É o que a escrita atômica compra.
    #[test]
    fn falha_na_gravacao_preserva_o_cofre_anterior() {
        let p = sandbox("atomico");
        gravar_em(&p, "s3nh4", b"conteudo bom").unwrap();
        // Passphrase vazia falha ANTES de tocar o disco.
        assert!(gravar_em(&p, "", b"conteudo novo").is_err());
        assert_eq!(abrir_de(&p, "s3nh4").unwrap(), b"conteudo bom", "o cofre anterior se perdeu");
        // E não sobrou temporário.
        assert!(!p.with_extension("tmp").exists(), "sobrou .tmp");
        let _ = std::fs::remove_dir_all(p.parent().unwrap());
    }
}
