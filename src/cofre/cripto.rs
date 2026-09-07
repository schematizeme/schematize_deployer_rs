//! COFRE — a criptografia, separada de disco e de sessão.
//!
//! **O quê:** deriva a chave da passphrase (Argon2id), sela e abre o segredo
//! (XChaCha20-Poly1305), e define o formato do cabeçalho que viaja em claro.
//!
//! **Onde:** [`super::arquivo`] põe o resultado disto em disco; [`super::sessao`] guarda a
//! chave aberta em memória. Aqui não há I/O nenhum — é o que torna estas regras testáveis
//! sem `~/.schematize` e sem passphrase de verdade.
//!
//! ## As três escolhas, e por que cada uma
//!
//! **Argon2id, não PBKDF2 nem bcrypt.** O adversário deste arquivo é quem tem o **disco** —
//! um agente com `Bash`, um backup vazado, uma máquina roubada. Contra ele o que vale é
//! custo de memória, que é o que Argon2id impõe e o que GPU não contorna barato. É também o
//! que o piso 3 da casa manda.
//!
//! **XChaCha20-Poly1305, não AES-GCM.** O nonce do XChaCha tem **24 bytes** — grande o
//! bastante para ser sorteado a cada gravação, sem contador. Com AES-GCM (12 bytes) manter
//! contador correto entre processos vira estado que se erra **em silêncio**, e um nonce
//! repetido não degrada a confidencialidade: destrói.
//!
//! **O cabeçalho entra como dado ASSOCIADO.** Ele viaja em claro (é preciso, para saber como
//! derivar a chave), mas é autenticado junto: quem editar os parâmetros de KDF no arquivo —
//! baixando `m_cost` para 8 KiB, por exemplo, para depois quebrar por força bruta — faz a
//! abertura **falhar**, em vez de conseguir um downgrade silencioso.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Marca do formato. Muda junto com [`VERSAO`] quando o layout mudar.
pub const MAGICO: &[u8; 8] = b"SZDPLYR\x01";
/// Versão do formato em disco.
pub const VERSAO: u8 = 1;
/// Tamanho do salt do Argon2id, em bytes.
pub const SALT_LEN: usize = 16;
/// Tamanho do nonce do XChaCha20, em bytes.
pub const NONCE_LEN: usize = 24;
/// Tamanho da chave derivada, em bytes.
pub const CHAVE_LEN: usize = 32;

/// Custo de memória do Argon2id, em KiB (64 MiB).
///
/// Bem acima do mínimo do OWASP (19 MiB) de propósito: isto roda **uma vez** ao destravar,
/// num desktop, e o segundo que custa ao dono é o que custa milhões de tentativas a quem
/// tem o blob.
pub const M_COST: u32 = 65_536;
/// Iterações do Argon2id.
pub const T_COST: u32 = 3;
/// Paralelismo do Argon2id.
pub const P_COST: u32 = 4;

/// Chave derivada. **Zera na saída de escopo** — sem isto ela sobrevive em heap liberado e
/// vai parar em core dump e em swap.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Chave([u8; CHAVE_LEN]);

impl Chave {
    /// **O quê:** empresta os bytes. Deliberadamente `pub(crate)`: chave que sai do crate
    /// vira chave que alguém loga.
    pub(crate) fn bytes(&self) -> &[u8; CHAVE_LEN] {
        &self.0
    }
}

/// O cabeçalho que viaja EM CLARO no arquivo — e é autenticado como dado associado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cabecalho {
    pub versao: u8,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
}

impl Cabecalho {
    /// **O quê:** um cabeçalho novo, com salt e nonce sorteados do CSPRNG do sistema.
    /// **Onde:** toda gravação do cofre — salt e nonce **nunca** se repetem entre escritas.
    pub fn novo() -> Result<Cabecalho, String> {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut salt).map_err(|e| format!("CSPRNG indisponível: {e}"))?;
        getrandom::getrandom(&mut nonce).map_err(|e| format!("CSPRNG indisponível: {e}"))?;
        Ok(Cabecalho {
            versao: VERSAO,
            m_cost: M_COST,
            t_cost: T_COST,
            p_cost: P_COST,
            salt,
            nonce,
        })
    }

    /// **O quê:** os bytes do cabeçalho, em layout fixo e determinístico.
    ///
    /// **Onde:** gravado no início do arquivo **e** passado como dado associado ao AEAD. As
    /// duas coisas vêm da MESMA função de propósito: se a serialização e a autenticação
    /// pudessem divergir, o dado associado deixaria de proteger o que está no disco.
    pub fn bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(8 + 1 + 12 + SALT_LEN + NONCE_LEN);
        v.extend_from_slice(MAGICO);
        v.push(self.versao);
        v.extend_from_slice(&self.m_cost.to_le_bytes());
        v.extend_from_slice(&self.t_cost.to_le_bytes());
        v.extend_from_slice(&self.p_cost.to_le_bytes());
        v.extend_from_slice(&self.salt);
        v.extend_from_slice(&self.nonce);
        v
    }

    /// Tamanho fixo do cabeçalho serializado.
    pub const fn tamanho() -> usize {
        8 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN
    }

    /// **O quê:** lê um cabeçalho dos primeiros bytes de um arquivo.
    ///
    /// **Onde:** [`super::arquivo::abrir`]. Falha fechada: magia errada, versão desconhecida
    /// ou tamanho insuficiente é recusa, nunca interpretação otimista.
    pub fn ler(b: &[u8]) -> Result<Cabecalho, String> {
        if b.len() < Self::tamanho() {
            return Err("arquivo de cofre truncado".into());
        }
        if &b[..8] != MAGICO {
            return Err("isto não é um cofre do deployer".into());
        }
        let versao = b[8];
        if versao != VERSAO {
            return Err(format!(
                "cofre na versão {versao}; este deployer entende a {VERSAO}. Atualize o app."
            ));
        }
        let u32_em = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        salt.copy_from_slice(&b[21..21 + SALT_LEN]);
        nonce.copy_from_slice(&b[21 + SALT_LEN..21 + SALT_LEN + NONCE_LEN]);
        Ok(Cabecalho {
            versao,
            m_cost: u32_em(9),
            t_cost: u32_em(13),
            p_cost: u32_em(17),
            salt,
            nonce,
        })
    }
}

/// **O quê:** deriva a chave de 32 bytes a partir da passphrase e dos parâmetros do
/// cabeçalho.
///
/// **Onde:** [`selar`] e [`abrir`]. Os parâmetros vêm do cabeçalho, e não de constantes,
/// para que um cofre gravado por uma versão antiga continue abrindo — mas o cabeçalho é
/// autenticado, então ninguém os rebaixa por fora.
pub fn derivar(passphrase: &str, cab: &Cabecalho) -> Result<Chave, String> {
    let params = Params::new(cab.m_cost, cab.t_cost, cab.p_cost, Some(CHAVE_LEN))
        .map_err(|e| format!("parâmetros de KDF inválidos: {e}"))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut chave = [0u8; CHAVE_LEN];
    a2.hash_password_into(passphrase.as_bytes(), &cab.salt, &mut chave)
        .map_err(|e| format!("derivação falhou: {e}"))?;
    let k = Chave(chave);
    chave.zeroize();
    Ok(k)
}

/// **O quê:** sela `claro` com a chave, autenticando o cabeçalho junto.
/// **Onde:** [`super::arquivo::gravar`].
pub fn selar(chave: &Chave, cab: &Cabecalho, claro: &[u8]) -> Result<Vec<u8>, String> {
    let c = XChaCha20Poly1305::new(chave.bytes().into());
    let ad = cab.bytes();
    c.encrypt(XNonce::from_slice(&cab.nonce), Payload { msg: claro, aad: &ad })
        .map_err(|_| "falha ao selar o cofre".to_string())
}

/// **O quê:** abre `cifrado`. Erro é sempre o MESMO texto, seja senha errada ou adulteração.
///
/// **Onde:** [`super::arquivo::abrir`].
///
/// **Por que a mensagem não distingue os casos:** dizer "a senha está certa mas o arquivo foi
/// adulterado" conta a quem tem o blob que aquela senha é a boa. O dono não perde nada — para
/// ele a ação é a mesma — e o atacante perde um oráculo.
pub fn abrir(chave: &Chave, cab: &Cabecalho, cifrado: &[u8]) -> Result<Vec<u8>, String> {
    let c = XChaCha20Poly1305::new(chave.bytes().into());
    let ad = cab.bytes();
    c.decrypt(XNonce::from_slice(&cab.nonce), Payload { msg: cifrado, aad: &ad }).map_err(|_| {
        "não consegui abrir o cofre: passphrase errada ou arquivo alterado".to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Passphrase mais fraca da bateria — os testes exercitam a MECÂNICA, não a força.
    const PASS: &str = "senha-de-teste";

    fn cab_fixo() -> Cabecalho {
        // Parâmetros mínimos: o teste afirma a REGRA, e 64 MiB × dezenas de testes tornaria a
        // suíte lenta a ponto de alguém desligá-la — que é como um teste morre de verdade.
        Cabecalho {
            versao: VERSAO,
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
            salt: [7u8; SALT_LEN],
            nonce: [9u8; NONCE_LEN],
        }
    }

    /// Ida e volta: o que entra sai igual.
    #[test]
    fn ida_e_volta_devolve_o_mesmo_segredo() {
        let cab = cab_fixo();
        let k = derivar(PASS, &cab).unwrap();
        let claro = b"host=srv-01 user=deploy key=/home/u/.ssh/deploy";
        let selado = selar(&k, &cab, claro).unwrap();
        assert_ne!(selado.as_slice(), claro, "o selado não pode ser o claro");
        assert_eq!(abrir(&k, &cab, &selado).unwrap(), claro);
    }

    /// **A prova que o plano cobrou:** o blob em repouso não revela host, usuário nem chave.
    #[test]
    fn o_blob_em_repouso_nao_revela_nada() {
        let cab = cab_fixo();
        let k = derivar(PASS, &cab).unwrap();
        let claro = b"host=servidor-de-producao user=root key=/home/luna/.ssh/id_ed25519";
        let selado = selar(&k, &cab, claro).unwrap();

        // O que vai pro disco é cabeçalho + selado. Nada disso pode conter os termos.
        let mut disco = cab.bytes();
        disco.extend_from_slice(&selado);
        let texto = String::from_utf8_lossy(&disco);
        for agulha in ["servidor-de-producao", "root", "id_ed25519", "host=", ".ssh"] {
            assert!(!texto.contains(agulha), "o blob vazou {agulha:?}");
        }
    }

    /// Passphrase errada não devolve lixo: devolve ERRO. É o AEAD, não uma checagem nossa.
    #[test]
    fn passphrase_errada_falha_em_vez_de_devolver_lixo() {
        let cab = cab_fixo();
        let certa = derivar(PASS, &cab).unwrap();
        let selado = selar(&certa, &cab, b"segredo").unwrap();
        let errada = derivar("outra-senha", &cab).unwrap();
        assert!(abrir(&errada, &cab, &selado).is_err());
    }

    /// Um bit trocado no cifrado é recusado — integridade, não só sigilo.
    #[test]
    fn adulterar_o_cifrado_e_recusado() {
        let cab = cab_fixo();
        let k = derivar(PASS, &cab).unwrap();
        let mut selado = selar(&k, &cab, b"segredo").unwrap();
        selado[0] ^= 0x01;
        assert!(abrir(&k, &cab, &selado).is_err());
    }

    /// **O ataque que o dado associado existe para impedir:** rebaixar o custo do KDF no
    /// arquivo para depois quebrar a passphrase barato. Sem o cabeçalho autenticado, isto
    /// passaria — e o cofre viraria teatro.
    #[test]
    fn rebaixar_o_custo_do_kdf_no_arquivo_e_recusado() {
        let cab = cab_fixo();
        let k = derivar(PASS, &cab).unwrap();
        let selado = selar(&k, &cab, b"segredo").unwrap();

        let mut fraco = cab.clone();
        fraco.m_cost = 8; // já era 8 no fixture; o que muda é o t_cost abaixo
        fraco.t_cost = 1;
        fraco.p_cost = 2; // <- adulterado
        assert!(
            abrir(&k, &fraco, &selado).is_err(),
            "cabeçalho adulterado tem de reprovar: é ele que autentica os parâmetros do KDF"
        );
    }

    /// O cabeçalho sobrevive à ida e volta em bytes, campo a campo.
    #[test]
    fn cabecalho_ida_e_volta() {
        let cab = Cabecalho::novo().unwrap();
        let lido = Cabecalho::ler(&cab.bytes()).unwrap();
        assert_eq!(lido, cab);
        assert_eq!(cab.bytes().len(), Cabecalho::tamanho());
        // Os parâmetros de produção são os que o cofre novo grava.
        assert_eq!((cab.m_cost, cab.t_cost, cab.p_cost), (M_COST, T_COST, P_COST));
    }

    /// Salt e nonce são sorteados a cada cofre — nunca constantes.
    #[test]
    fn cada_cofre_novo_tem_salt_e_nonce_proprios() {
        let a = Cabecalho::novo().unwrap();
        let b = Cabecalho::novo().unwrap();
        assert_ne!(a.salt, b.salt, "salt repetido derrota o Argon2id");
        assert_ne!(a.nonce, b.nonce, "nonce repetido com a mesma chave destrói o sigilo");
    }

    /// Falha FECHADA na leitura: nada de interpretar arquivo alheio com otimismo.
    #[test]
    fn cabecalho_invalido_e_recusado_com_motivo() {
        assert!(Cabecalho::ler(b"curto").unwrap_err().contains("truncado"));

        let mut errado = Cabecalho::novo().unwrap().bytes();
        errado[0] = b'X';
        assert!(Cabecalho::ler(&errado).unwrap_err().contains("não é um cofre"));

        let mut futuro = Cabecalho::novo().unwrap().bytes();
        futuro[8] = 99;
        let e = Cabecalho::ler(&futuro).unwrap_err();
        assert!(e.contains("99") && e.contains("Atualize"), "erro tem de dizer o passo: {e}");
    }

    /// A mensagem de erro NÃO distingue senha errada de arquivo adulterado — dizer a
    /// diferença entregaria a quem tem o blob que aquela senha é a boa.
    #[test]
    fn erro_nao_vira_oraculo_de_senha() {
        let cab = cab_fixo();
        let k = derivar(PASS, &cab).unwrap();
        let selado = selar(&k, &cab, b"x").unwrap();

        let senha_errada = abrir(&derivar("nao-e-essa", &cab).unwrap(), &cab, &selado).unwrap_err();
        let mut adulterado = selado.clone();
        adulterado[2] ^= 0xFF;
        let alterado = abrir(&k, &cab, &adulterado).unwrap_err();

        assert_eq!(senha_errada, alterado, "as duas falhas têm de ser indistinguíveis");
    }
}
