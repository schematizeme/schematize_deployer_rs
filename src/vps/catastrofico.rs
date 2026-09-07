//! CATASTRÓFICO — o catálogo do que nunca pode rodar, e como se reconhece.
//!
//! O quê: as listas (`CATASTROFICOS`, `BINARIOS_FATAIS`, `FLAGS_PERIGOSAS`,
//! `METACARACTERES`) e as funções que decidem se um comando cai em alguma delas.
//!
//! Onde: [`super::politica`], que é quem faz a pergunta. Este módulo não conhece perfil de
//! host, modo nem ambiente — só responde "isto é fatal?".
//!
//! # Por que é um módulo à parte
//!
//! "O que é proibido" e "como se decide o veredito" são duas perguntas diferentes, e viviam
//! no mesmo arquivo. Separá-las deixa cada uma legível sozinha — e o `politica.rs` voltou pra
//! dentro do teto de 750 linhas da casa, que a adoção do `rustfmt` tinha estourado.
//!
//! # ISTO NÃO É UMA FRONTEIRA DE SEGURANÇA (ADR-0005)
//!
//! Vale aqui a mesma advertência do [`super::politica`]: esta lista roda no CLIENTE e é UX.
//! Ela encarece o ACIDENTE; não impede a INTENÇÃO. Quem recusa de verdade é o
//! `restrict,command=` no `authorized_keys` do servidor. NUNCA acrescente aqui um caminho de
//! escape — o valor da lista é ela não ter exceção.

use super::analise::{analisar, e_dispositivo_de_bloco, Comando, ALVOS_FATAIS};

/// Padrões que nunca passam, em modo nenhum, em ambiente nenhum. Cada entrada é
/// `(agulha, motivo)`; a agulha é casada contra o comando NORMALIZADO (minúsculo, espaços
/// colapsados).
///
/// A lista é de **acidente caro e irreversível**, não de "comando avançado": o critério pra
/// entrar aqui é "se rodar por engano, o dano não tem undo".
const CATASTROFICOS: &[(&str, &str)] = &[
    // Fork bomb: não é um binário, é sintaxe.
    (":(){", "fork bomb"),
    (":() {", "fork bomb"),
    // SQL destrutivo dentro de aspas — `psql -c 'DROP DATABASE x'` não é analisável como
    // comando de shell, então aqui o casamento textual é a ferramenta certa.
    ("drop database", "destrói o banco"),
    ("drop schema", "destrói o schema"),
    ("truncate table", "esvazia a tabela sem undo"),
    // Baixar-e-executar: o padrão é o encadeamento, não o binário.
    ("| sh", "baixa e executa código sem revisão"),
    ("| bash", "baixa e executa código sem revisão"),
    ("|sh ", "baixa e executa código sem revisão"),
    // Docker: o perigo está no SUBCOMANDO, e `docker` sozinho é legítimo.
    ("docker system prune", "apaga volumes/imagens em uso"),
    ("docker volume prune", "apaga volumes de dados"),
    ("docker volume rm", "apaga volume de dados"),
    // Rede e rastro.
    ("iptables -f", "zera o firewall — costuma cortar o próprio acesso"),
    ("ufw disable", "desliga o firewall"),
    ("history -c", "apaga o rastro — nada legítimo faz isso num deploy"),
    ("init 0", "derruba o host"),
    ("init 6", "reinicia o host"),
    // Execução embutida em busca.
    ("-exec rm", "execução de rm embutida em outro comando"),
    ("find / -delete", "apaga a partir da raiz"),
];

/// Sequências que indicam encadeamento/expansão de shell. Fora do modo `Livre`, o comando
/// deveria ser UM comando — encadeamento é o caminho clássico de escapar de uma allowlist.
const METACARACTERES: &[&str] =
    &[";", "&&", "||", "|", "`", "$(", "${", "$'", ">", "<", "\n", "\r", "&"];

/// Sub-flags perigosas de binários que, sozinhos, seriam inofensivos.
///
/// É o que separa `find /var/log -name '*.gz'` (leitura) de `find / -exec sh -c ...`
/// (execução arbitrária), e `git log` de `git -c alias.x='!sh'`.
const FLAGS_PERIGOSAS: &[(&str, &str)] = &[
    ("-exec", "executa comando arbitrário a partir de outro binário"),
    ("-execdir", "executa comando arbitrário a partir de outro binário"),
    ("-delete", "apaga arquivos como efeito de uma busca"),
    ("-c alias.", "alias de git é um shell disfarçado"),
    ("--upload-pack", "executa comando arbitrário no outro lado"),
    ("--receive-pack", "executa comando arbitrário no outro lado"),
    ("-o proxycommand", "executa comando arbitrário via ssh"),
    ("--to-command", "canaliza a saída do tar pra um shell"),
    ("--use-compress-program", "executa programa arbitrário via tar"),
];

/// Normaliza o comando pra casar padrão: minúsculo e espaços colapsados.
///
/// **Onde:** [`padrao_catastrofico`] e a checagem de flags. Não é sanitização — é só pra que
/// `RM  -RF  /` e `rm -rf /` recebam o mesmo veredito.
pub(crate) fn normalizar(cmd: &str) -> String {
    cmd.to_ascii_lowercase().split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Binários cuja mera invocação já é catastrófica num deploy — não há flag que os torne
/// seguros, e nenhum deles tem lugar num fluxo de deploy legítimo.
const BINARIOS_FATAIS: &[(&str, &str)] = &[
    ("mkfs", "formata um sistema de arquivos"),
    ("wipefs", "apaga a assinatura do sistema de arquivos — o disco vira lixo"),
    ("shred", "sobrescreve arquivos sem recuperação"),
    ("blkdiscard", "descarta todos os blocos do dispositivo"),
    ("fdisk", "reparticiona o disco"),
    ("sfdisk", "reparticiona o disco"),
    ("parted", "reparticiona o disco"),
    ("sgdisk", "reparticiona o disco"),
    ("mkswap", "formata partição de swap"),
    ("shutdown", "derruba o host"),
    ("poweroff", "derruba o host"),
    ("reboot", "reinicia o host"),
    ("halt", "derruba o host"),
    ("telinit", "troca o runlevel"),
    ("userdel", "remove usuário do sistema"),
    ("groupdel", "remove grupo do sistema"),
    ("passwd", "troca senha de conta"),
    ("visudo", "edita o sudoers de forma interativa"),
    ("killall", "mata processos por nome — inclusive o sshd que sustenta esta sessão"),
    ("pkill", "mata processos por padrão — inclusive o sshd que sustenta esta sessão"),
    ("chattr", "torna arquivos imutáveis e pode travar o sistema"),
    ("setfacl", "reescreve ACLs em massa"),
    ("dpkg-reconfigure", "reconfigura pacote de forma interativa"),
];

/// O comando é catastrófico? Devolve o motivo.
///
/// **Duas camadas, e a ordem importa.** Primeiro a ANÁLISE ESTRUTURAL (binário + flags +
/// operandos), que é o que pega `rm -r -f /` e `rm --recursive --force "/"`; depois o
/// casamento textual da [`CATASTROFICOS`], que ainda serve para o que não é um comando de
/// shell — SQL dentro de aspas (`psql -c 'DROP DATABASE x'`), fork bomb, e afins.
///
/// **Onde:** [`avaliar`]. Ver o doc de `analise` para o porquê de a camada estrutural existir.
pub fn padrao_catastrofico(cmd: &str) -> Option<&'static str> {
    if let Some(m) = catastrofico_por_estrutura(&analisar(cmd)) {
        return Some(m);
    }
    let n = normalizar(cmd);
    CATASTROFICOS.iter().find(|(a, _)| n.contains(a)).map(|(_, m)| *m)
}

/// A camada estrutural: decide pelo QUE o comando é, não por como foi escrito.
fn catastrofico_por_estrutura(c: &Comando) -> Option<&'static str> {
    // Binário que não tem uso legítimo aqui (casa por prefixo: `mkfs.ext4` conta como `mkfs`).
    if let Some((_, motivo)) = BINARIOS_FATAIS.iter().find(|(b, _)| c.binario.starts_with(b)) {
        return Some(motivo);
    }
    // Remoção recursiva apontada para a raiz, o home ou um diretório de sistema.
    if matches!(c.binario.as_str(), "rm" | "unlink" | "rmdir") {
        if c.tem_longa("no-preserve-root") {
            return Some("desliga a única proteção do rm contra apagar a raiz");
        }
        if (c.tem('r') || c.binario == "rmdir") && c.operando_em(ALVOS_FATAIS) {
            return Some("apaga a raiz do sistema ou um diretório essencial");
        }
    }
    // Escrita em dispositivo de bloco, por qualquer caminho.
    if c.operandos.iter().any(|o| e_dispositivo_de_bloco(o)) {
        // Ler de um dispositivo é inofensivo; escrever nele destrói o disco.
        let escreve = c.binario == "dd"
            && c.operandos.iter().any(|o| o.starts_with("of=") && e_dispositivo_de_bloco(o));
        let escreve = escreve
            || matches!(c.binario.as_str(), "mkfs" | "wipefs" | "blkdiscard" | "tee" | "cp" | "mv");
        if escreve {
            return Some("escreve direto no dispositivo de bloco — destrói o disco");
        }
    }
    // Mover a raiz ou um diretório essencial é tão destrutivo quanto apagar.
    if matches!(c.binario.as_str(), "mv" | "rename") && c.operando_em(ALVOS_FATAIS) {
        return Some("move a raiz do sistema ou um diretório essencial");
    }

    // Permissão/dono recursivos apontados para alvo fatal.
    if matches!(c.binario.as_str(), "chmod" | "chown" | "chgrp") && c.operando_em(ALVOS_FATAIS) {
        return Some("troca permissão ou dono na raiz do sistema — quebra o host inteiro");
    }
    // Esvaziar arquivo de sistema.
    if c.binario == "truncate" && c.operando_comeca("/etc") {
        return Some("esvazia arquivo de configuração do sistema");
    }
    // Desligar o que sustenta o acesso.
    if c.binario == "systemctl" {
        let acao = c.operandos.first().map(String::as_str).unwrap_or("");
        let alvo_critico = c.operandos.iter().any(|o| o.contains("ssh") || o.contains("network"));
        if matches!(acao, "mask" | "stop" | "disable") && alvo_critico {
            return Some("desliga o serviço que sustenta o próprio acesso ao host");
        }
    }
    None
}

/// O comando tem metacaractere de shell? Devolve o primeiro encontrado.
pub fn metacaractere(cmd: &str) -> Option<&'static str> {
    METACARACTERES.iter().find(|m| cmd.contains(**m)).copied()
}

/// O comando usa alguma sub-flag perigosa? Devolve o motivo.
pub fn flag_perigosa(cmd: &str) -> Option<&'static str> {
    let n = normalizar(cmd);
    FLAGS_PERIGOSAS.iter().find(|(a, _)| n.contains(a)).map(|(_, m)| *m)
}

/// O comando é ASCII imprimível? Fora do modo `Livre`, caractere de controle ou não-ASCII
/// vira recusa: é o vetor de homóglifo (um `rm` com `r` cirílico passa por qualquer lista) e
/// o de byte nulo.
pub fn ascii_imprimivel(cmd: &str) -> bool {
    cmd.chars().all(|c| c.is_ascii_graphic() || c == ' ')
}

/// Descreve os caracteres não-ASCII de um comando, pra que a recusa (ou o modal) mostre
/// EXATAMENTE o que há de estranho em vez de um "caractere inválido" que não ajuda ninguém.
///
/// **Onde:** [`avaliar`], ao montar o motivo.
pub(crate) fn descrever_nao_ascii(cmd: &str) -> String {
    let mut achados: Vec<String> = cmd
        .chars()
        .filter(|c| !(c.is_ascii_graphic() || *c == ' '))
        .map(|c| format!("U+{:04X}", c as u32))
        .collect();
    achados.dedup();
    achados.truncate(5);
    achados.join(", ")
}
