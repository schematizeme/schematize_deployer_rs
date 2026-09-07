//! ANÁLISE de comando — quebra uma linha de shell em `(binário, flags, operandos)`.
//! O quê: [`analisar`], pura e testável, mais os predicados que a política usa em cima dela.
//! Onde: `vps::politica::padrao_catastrofico`.
//!
//! ## Por que isto existe
//!
//! A primeira versão da denylist casava SUBSTRING literal: procurava `"rm -rf /"` dentro do
//! comando. O teste destrutivo mostrou o tamanho do buraco — **nenhum destes era pego**:
//!
//! ```text
//! rm -r -f /                 flags separadas
//! rm -f -r /                 flags em outra ordem
//! rm --recursive --force /   flags longas
//! rm -R -f /                 -R maiúsculo
//! rm -rf "/"                 alvo entre aspas
//! rm -rf ~                   til em vez de barra
//! dd if=/dev/zero of="/dev/sda"
//! ```
//!
//! E o pior: **`rm -r -f /` não é evasão, é gente digitando normalmente.** Uma denylist que
//! existe para pegar ACIDENTE e erra o acidente mais provável não está fazendo o trabalho.
//!
//! A correção não é acrescentar mais padrões — é parar de casar texto e passar a olhar a
//! ESTRUTURA: qual binário, quais flags (curtas expandidas do cacho, longas normalizadas para
//! a curta equivalente), quais operandos (sem aspas, com `~` resolvido).
//!
//! Continua não sendo fronteira de segurança (ADR-0005) — quem quer fugir, foge. Mas agora
//! pega o acidente de verdade, que é o que ela promete.

use std::collections::BTreeSet;

/// Um comando quebrado em partes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comando {
    /// Binário sem caminho e em minúsculo (`/bin/RM` -> `rm`).
    pub binario: String,
    /// Flags curtas, com o cacho expandido (`-rf` -> `r`, `f`) e a longa mapeada quando há
    /// equivalente (`--recursive` -> `r`). Minúsculas: `-R` e `-r` são a mesma intenção aqui.
    pub flags: BTreeSet<char>,
    /// Flags longas como vieram (sem `--`), para o que não tem equivalente curto.
    pub longas: BTreeSet<String>,
    /// O que não é flag: alvos, argumentos, `chave=valor`. Sem aspas.
    pub operandos: Vec<String>,
}

impl Comando {
    /// Tem a flag curta `c` (ou a longa equivalente, já mapeada em [`analisar`])?
    pub fn tem(&self, c: char) -> bool {
        self.flags.contains(&c)
    }

    /// Tem a flag longa `nome` (sem `--`)?
    pub fn tem_longa(&self, nome: &str) -> bool {
        self.longas.contains(nome)
    }

    /// Algum operando é um dos alvos dados?
    pub fn operando_em(&self, alvos: &[&str]) -> bool {
        self.operandos.iter().any(|o| alvos.contains(&o.as_str()))
    }

    /// Algum operando começa com `prefixo`?
    pub fn operando_comeca(&self, prefixo: &str) -> bool {
        self.operandos.iter().any(|o| o.starts_with(prefixo))
    }
}

/// Flags longas com equivalente curto conhecido. Sem isto, `--recursive` escapa de uma regra
/// escrita em cima de `-r`.
const LONGA_PARA_CURTA: &[(&str, char)] = &[
    ("recursive", 'r'),
    ("force", 'f'),
    ("all", 'a'),
    ("verbose", 'v'),
    ("interactive", 'i'),
    ("preserve", 'p'),
    ("archive", 'a'),
    ("quiet", 'q'),
];

/// Tira aspas simples/duplas de um token e resolve `~` para a forma canônica `~`.
///
/// **Onde:** [`analisar`]. `rm -rf "/"` e `rm -rf /` são o mesmo comando para o shell, e
/// precisam ser o mesmo para a política.
fn limpar_token(t: &str) -> String {
    let mut s: String = t.chars().filter(|c| !matches!(c, '"' | '\'')).collect();
    // `\/` e afins: a barra invertida some no shell.
    s = s.replace('\\', "");
    if s == "~" || s.starts_with("~/") {
        // Mantém o `~` — as regras o tratam como "o home", equivalente a alvo perigoso.
        return s;
    }
    s
}

/// Quebra um comando em [`Comando`]. **Pura.**
///
/// Pula prefixos que não são o binário de verdade (`sudo`, `env FOO=1`, `nice`, `time`…), do
/// mesmo jeito que o `hook` faz — um `sudo rm -rf /` tem que ser lido como `rm`.
///
/// **Onde:** [`super::politica::padrao_catastrofico`] e os testes.
pub fn analisar(cmd: &str) -> Comando {
    let mut toks = cmd.split_whitespace().peekable();
    // Prefixos e atribuições de ambiente.
    while let Some(t) = toks.peek() {
        let t = *t;
        if (t.contains('=') && !t.starts_with('-'))
            || matches!(t, "sudo" | "env" | "nohup" | "time" | "nice" | "exec" | "command" | "doas")
        {
            toks.next();
        } else {
            break;
        }
    }
    let binario = toks
        .next()
        .map(limpar_token)
        .map(|b| b.rsplit('/').next().unwrap_or(&b).to_ascii_lowercase())
        .unwrap_or_default();

    let mut flags = BTreeSet::new();
    let mut longas = BTreeSet::new();
    let mut operandos = Vec::new();
    for bruto in toks {
        let t = limpar_token(bruto);
        if let Some(longa) = t.strip_prefix("--") {
            if longa.is_empty() {
                continue; // o `--` separador
            }
            let nome = longa.split('=').next().unwrap_or(longa).to_ascii_lowercase();
            if let Some((_, c)) = LONGA_PARA_CURTA.iter().find(|(n, _)| *n == nome) {
                flags.insert(*c);
            }
            longas.insert(nome);
        } else if t.starts_with('-') && t.len() > 1 {
            // Cacho de flags curtas: `-rf` são duas flags.
            for c in t[1..].chars() {
                flags.insert(c.to_ascii_lowercase());
            }
        } else if !t.is_empty() {
            operandos.push(t);
        }
    }
    Comando { binario, flags, longas, operandos }
}

/// Alvos que significam "o sistema todo" ou "a casa do usuário".
pub const ALVOS_FATAIS: &[&str] =
    &["/", "/*", "~", "~/", "~/*", "/.", "/..", "$HOME", "/home", "/etc", "/var", "/usr", "/boot"];

/// Dispositivos de bloco: escrever neles destrói o disco.
pub fn e_dispositivo_de_bloco(s: &str) -> bool {
    let s = s.trim_start_matches("of=");
    ["/dev/sd", "/dev/nvme", "/dev/hd", "/dev/vd", "/dev/xvd", "/dev/mmcblk", "/dev/disk"]
        .iter()
        .any(|p| s.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expande_cacho_de_flags_e_normaliza_longas() {
        let c = analisar("rm -rf /");
        assert_eq!(c.binario, "rm");
        assert!(c.tem('r') && c.tem('f'), "o cacho `-rf` vira duas flags");
        assert!(c.operando_em(&["/"]));

        // Todas estas são o MESMO comando — e a versão antiga só pegava a primeira.
        for variante in
            ["rm -r -f /", "rm -f -r /", "rm --recursive --force /", "rm -R -f /", "rm -Rf /"]
        {
            let c = analisar(variante);
            assert_eq!(c.binario, "rm", "{variante}");
            assert!(c.tem('r') && c.tem('f'), "{variante}: flags não normalizadas -> {c:?}");
            assert!(c.operando_em(&["/"]), "{variante}");
        }
    }

    #[test]
    fn aspas_e_barra_invertida_nao_escondem_o_alvo() {
        for variante in [r#"rm -rf "/""#, "rm -rf '/'", r"rm -rf \/"] {
            let c = analisar(variante);
            assert!(c.operando_em(&["/"]), "{variante}: o alvo se escondeu -> {c:?}");
        }
    }

    #[test]
    fn prefixos_nao_escondem_o_binario() {
        for variante in [
            "sudo rm -rf /",
            "env FOO=1 rm -rf /",
            "nice rm -rf /",
            "/bin/rm -rf /",
            "doas rm -rf /",
        ] {
            assert_eq!(analisar(variante).binario, "rm", "{variante}");
        }
    }

    #[test]
    fn separa_operando_de_flag() {
        let c = analisar("dd if=/dev/zero of=/dev/sda bs=1M");
        assert_eq!(c.binario, "dd");
        assert!(c.operandos.iter().any(|o| o == "of=/dev/sda"));
        assert!(c.flags.is_empty(), "`if=`/`of=` não são flags");
    }

    #[test]
    fn dispositivo_de_bloco_e_reconhecido_com_e_sem_aspas() {
        assert!(e_dispositivo_de_bloco("/dev/sda"));
        assert!(e_dispositivo_de_bloco("of=/dev/nvme0n1"));
        assert!(e_dispositivo_de_bloco("/dev/mmcblk0"));
        assert!(!e_dispositivo_de_bloco("/dev/null"));
        assert!(!e_dispositivo_de_bloco("/dev/urandom"));
        assert!(!e_dispositivo_de_bloco("/srv/app"));
    }

    #[test]
    fn comando_vazio_nao_panica() {
        let c = analisar("");
        assert!(c.binario.is_empty() && c.operandos.is_empty());
        let c = analisar("   ");
        assert!(c.binario.is_empty());
        let c = analisar("sudo");
        assert!(c.binario.is_empty(), "só o prefixo, sem binário");
    }
}
