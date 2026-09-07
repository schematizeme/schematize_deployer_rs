//! CAPACIDADE — quanto de fronteira este host consegue sustentar, DESCOBERTO em vez de
//! declarado.
//! O quê: [`Fronteira`] (os três níveis), [`sondar`] (pergunta ao host o que dá pra fazer) e
//! o roteiro de decisão que o bootstrap segue.
//! Onde: `vps bootstrap` e `vps probe` (CLI), o badge da GUI, e `vps list`.
//!
//! ## Por que três níveis, e não "tem shim / não tem"
//!
//! A pergunta "as VPS têm root pra instalar o shim?" tem a resposta honesta *às vezes sim,
//! às vezes não* — e é essa a resposta certa, porque **um parque de servidores real é
//! heterogêneo** e não dá pra prever todos os casos. Software que exige uma resposta única
//! quebra no primeiro host que foge do molde, e aí culpa o usuário (§37.48).
//!
//! O que destrava os três níveis é um detalhe que passou batido no ADR-0005: **o forced
//! command NÃO precisa de root.** `~/.ssh/authorized_keys` é do próprio usuário. Um shim no
//! home dele, apontado por `restrict,command=`, já é fronteira REAL contra o agente — o sshd
//! recusa antes de existir shell. O que root acrescenta é proteger o shim *daquele mesmo
//! usuário*, o que importa contra um invasor com shell interativo, não contra o agente.
//!
//! Daí os níveis, do mais forte ao mais fraco — e o app fica com o melhor que o host aguentar:
//!
//! | Nível | Onde o shim mora | Quem recusa | Limite honesto |
//! |---|---|---|---|
//! | [`Fronteira::OpsShellRoot`] | `/usr/local/lib/schematize/`, dono root | o sshd | — |
//! | [`Fronteira::OpsShellUsuario`] | `~/.schematize/ops-shell`, dono do usuário | o sshd | quem já tem shell como esse usuário pode reescrever o shim |
//! | [`Fronteira::Sem`] | não há | só o cliente | pega acidente, não intenção |
//!
//! **Nenhum host fica de fora**, e cada um mostra o que de fato tem. Degradação graciosa é
//! piso (10), não consolo.

use super::registro::VpsProfile;

/// O nível de fronteira que um host sustenta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Fronteira {
    /// Nada no servidor: só a política do cliente, que pega acidente e não intenção.
    Sem,
    /// Forced command apontando pra um shim no home do usuário.
    OpsShellUsuario,
    /// Forced command apontando pra um shim do sistema, dono root.
    OpsShellRoot,
}

impl Fronteira {
    /// Texto canônico gravado no banco.
    pub fn as_str(self) -> &'static str {
        match self {
            Fronteira::Sem => "sem",
            Fronteira::OpsShellUsuario => "usuario",
            Fronteira::OpsShellRoot => "root",
        }
    }

    /// Interpreta texto do banco. **Falha fechada: desconhecido vira [`Fronteira::Sem`]** — na
    /// dúvida, o app assume que NÃO há fronteira e avisa, em vez de prometer o que não tem.
    pub fn from_raw(s: &str) -> Fronteira {
        match s.trim().to_ascii_lowercase().as_str() {
            "root" | "opsshellroot" => Fronteira::OpsShellRoot,
            "usuario" | "user" | "opsshellusuario" => Fronteira::OpsShellUsuario,
            _ => Fronteira::Sem,
        }
    }

    /// Rótulo curto pro `vps list` e pro badge da GUI.
    pub fn rotulo(self) -> &'static str {
        match self {
            Fronteira::OpsShellRoot => "ops-shell (root)",
            Fronteira::OpsShellUsuario => "ops-shell (usuário)",
            Fronteira::Sem => "SEM (só o cliente)",
        }
    }

    /// A frase honesta sobre o que este nível garante e o que não garante. Vai pra UI: o
    /// usuário precisa saber o que comprou, sem precisar ler um ADR.
    pub fn explicacao(self) -> &'static str {
        match self {
            Fronteira::OpsShellRoot =>
                "o sshd recusa qualquer coisa fora do catálogo, e o shim é do root — nem quem tem shell como este usuário reescreve.",
            Fronteira::OpsShellUsuario =>
                "o sshd recusa qualquer coisa fora do catálogo. O shim é do próprio usuário: quem JÁ tiver shell interativo como ele poderia reescrevê-lo — mas o agente não, porque o agente não tem shell.",
            Fronteira::Sem =>
                "não há fronteira no servidor: vale só a política do cliente, que pega acidente (rm -rf, curl|sh) mas não impede um comando determinado.",
        }
    }

    /// Existe fronteira no SERVIDOR (qualquer nível)?
    pub fn e_server_side(self) -> bool {
        self != Fronteira::Sem
    }
}

/// O que a sondagem descobriu sobre um host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sondagem {
    /// O melhor nível que este host consegue sustentar AGORA.
    pub possivel: Fronteira,
    /// O nível efetivamente instalado agora.
    pub instalada: Fronteira,
    /// `sudo -n` funciona sem senha?
    pub sudo_sem_senha: bool,
    /// O usuário consegue escrever no próprio `~/.ssh/authorized_keys`?
    pub pode_escrever_authkeys: bool,
    /// Um shell POSIX utilizável foi encontrado?
    pub tem_shell: bool,
    /// O `$HOME` REAL do usuário no host, resolvido pela sondagem.
    ///
    /// Existe porque `command="$HOME/..."` no `authorized_keys` depende do shell de LOGIN
    /// expandir a variável — e um shell restrito, um `nologin` ou um `csh` quebram isso em
    /// silêncio, deixando o forced command apontando pra lugar nenhum. Resolver o caminho
    /// aqui, uma vez, torna a linha literal e previsível.
    pub home: String,
    /// O que foi observado, em linguagem de gente — vai pra UI e pro log.
    pub notas: Vec<String>,
}

impl Sondagem {
    /// Há o que instalar/melhorar neste host?
    ///
    /// **Onde:** `vps bootstrap`, pra decidir entre agir e dizer "já está no melhor possível".
    pub fn pode_melhorar(&self) -> bool {
        self.possivel > self.instalada
    }
}

/// Script de sondagem — **somente leitura**, roda no host e imprime `chave=valor`.
///
/// POSIX `sh` puro de propósito: não assume `bash`, nem `python`, nem coreutils do GNU. É o
/// mesmo raciocínio do §37.48 aplicado ao servidor — o host pode ser um Alpine mínimo, um
/// container distroless-ish ou um BSD, e o app não pode quebrar por isso.
///
/// **Onde:** [`sondar`]. Não escreve nada, então roda mesmo em host de produção sem cerimônia.
pub const SCRIPT_DE_SONDAGEM: &str = r#"
sudo_ok=nao
if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then sudo_ok=sim; fi
ak="$HOME/.ssh/authorized_keys"
ak_ok=nao
if [ -w "$ak" ]; then ak_ok=sim
elif [ ! -e "$ak" ] && [ -w "$HOME" ]; then ak_ok=sim; fi
shim=nenhum
if [ -x /usr/local/lib/schematize/ops-shell ]; then shim=root
elif [ -x "$HOME/.schematize/ops-shell" ]; then shim=usuario; fi
forced=nao
if [ -f "$ak" ] && grep -q 'command="[^"]*ops-shell' "$ak" 2>/dev/null; then forced=sim; fi
echo "sudo=$sudo_ok"
echo "authkeys=$ak_ok"
echo "shim=$shim"
echo "forced=$forced"
echo "shell=sim"
echo "home=$HOME"
"#;

/// Interpreta a saída do [`SCRIPT_DE_SONDAGEM`]. **Função pura** — testável sem host.
///
/// **Onde:** [`sondar`] e os testes. Chave desconhecida é ignorada (o script pode crescer sem
/// quebrar cliente velho); chave ausente cai no valor mais restritivo.
pub fn interpretar_sondagem(saida: &str) -> Sondagem {
    let val = |k: &str| -> String {
        saida
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{k}=")))
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let sudo_sem_senha = val("sudo") == "sim";
    let pode_escrever_authkeys = val("authkeys") == "sim";
    let tem_shell = val("shell") == "sim";
    let shim = val("shim");
    let forced = val("forced") == "sim";
    let home = val("home");
    // `via=shim`: a resposta veio do PRÓPRIO shim, não do script de sondagem — o que só
    // acontece quando a fronteira já está instalada e (corretamente) recusou o script.
    let via_shim = val("via") == "shim";

    // Instalada = só conta se o shim EXISTE **e** o forced command aponta pra ele. Um dos dois
    // sozinho não é fronteira nenhuma — é meia instalação, e meia fronteira é nenhuma.
    let instalada = match (shim.as_str(), forced) {
        ("root", true) => Fronteira::OpsShellRoot,
        ("usuario", true) => Fronteira::OpsShellUsuario,
        _ => Fronteira::Sem,
    };

    // Atrás do shim não dá pra ver `sudo` nem a escrita no authorized_keys — o shim recusa
    // qualquer comando que investigasse isso, que é o trabalho dele. O que se sabe com certeza
    // é o nível que JÁ está instalado; assumir mais seria inventar.
    if via_shim {
        let notas = vec![
            "sondado ATRAVÉS do shim: a fronteira está ativa e recusou o script de sondagem, como deve. Daqui não dá pra ver se o host ganhou sudo desde a instalação — pra reavaliar, use a chave humana de break-glass."
                .to_string(),
        ];
        return Sondagem {
            possivel: instalada,
            instalada,
            sudo_sem_senha: false,
            pode_escrever_authkeys: false,
            tem_shell: false,
            home,
            notas,
        };
    }

    // Possível = o melhor que dá pra alcançar daqui.
    let possivel = if !pode_escrever_authkeys {
        // Sem escrever no authorized_keys não há forced command — e sem forced command não há
        // fronteira, por mais root que se tenha.
        Fronteira::Sem
    } else if sudo_sem_senha {
        Fronteira::OpsShellRoot
    } else {
        Fronteira::OpsShellUsuario
    };

    let mut notas = Vec::new();
    if !tem_shell {
        notas.push("o host não respondeu a um shell POSIX — sondagem incompleta".into());
    }
    if !pode_escrever_authkeys {
        notas.push(
            "sem escrita em ~/.ssh/authorized_keys: nenhuma fronteira server-side é possível por aqui. \
             Costuma ser host gerenciado (chave provisionada pela plataforma). Peça ao provedor uma chave \
             com forced command, ou aceite rodar só com a política do cliente."
                .into(),
        );
    }
    if !sudo_sem_senha && pode_escrever_authkeys {
        notas.push(
            "sem sudo sem senha: o shim vai pro home do usuário. Continua sendo fronteira de verdade \
             contra o agente (o sshd recusa antes de existir shell); o que se perde é a proteção contra \
             quem JÁ tem shell interativo como este usuário."
                .into(),
        );
    }
    if shim != "nenhum" && !forced {
        notas.push(format!(
            "há um shim instalado ({shim}) mas o authorized_keys NÃO aponta pra ele — instalação pela metade, \
             que não vale como fronteira. `vps bootstrap` conserta."
        ));
    }
    // Sem HOME resolvido não dá pra montar um forced command literal — cai pro mais restritivo.
    let possivel = if home.is_empty() && possivel == Fronteira::OpsShellUsuario {
        notas.push(
            "o host não informou o $HOME — não dá pra montar um forced command literal".into(),
        );
        Fronteira::Sem
    } else {
        possivel
    };
    Sondagem { possivel, instalada, sudo_sem_senha, pode_escrever_authkeys, tem_shell, home, notas }
}

/// Pergunta ao host o que ele aguenta. Não escreve nada lá.
///
/// **Onde:** `vps probe` (CLI), `vps bootstrap` (antes de agir) e o refresh da GUI.
/// **Erros:** os mesmos de qualquer execução remota (host não confiado, sem acesso).
pub fn sondar(conn: &rusqlite::Connection, p: &VpsProfile) -> Result<Sondagem, String> {
    // 1) Host COM fronteira instalada responde ao pedido embutido do shim — e recusa qualquer
    //    outra coisa. Tenta este primeiro quando já se sabe que há shim.
    if p.fronteira.e_server_side() {
        if let Some(s) = sondar_pelo_shim(conn, p) {
            return Ok(s);
        }
    }
    // 2) Host sem fronteira (ou com o shim removido por fora): o script completo.
    //    Somente-leitura, mas passa pela MESMA porta auditada que tudo o mais.
    let out = super::exec::executar_interno(conn, p, SCRIPT_DE_SONDAGEM.trim(), "probe")?;
    // Falha de CONEXÃO não pode virar diagnóstico. Sem isto, um host onde a autenticação
    // falhou devolvia saída vazia e era interpretado como "host gerenciado, nenhuma fronteira
    // é possível" — a mensagem mais errada possível, porque manda o usuário procurar solução
    // no provedor quando o problema é a chave dele. Achado no Q.A. contra sshd Alpine.
    if let Some(e) = &out.erro {
        return Err(format!(
            "não consegui sondar {}: {e}. Enquanto a conexão não funcionar, não dá pra saber que fronteira este host aguenta",
            p.alias
        ));
    }
    // A recusa do shim vem pelo STDERR — sem olhá-lo, um host protegido pareceria vazio.
    if out.stderr.contains(MARCA_DO_SHIM) {
        if let Some(s) = sondar_pelo_shim(conn, p) {
            return Ok(s);
        }
    }
    let s = interpretar_sondagem(&out.stdout);
    // 3) O script não passou: ou o host é estranho, ou há um shim recusando (instalado por
    //    fora, ou por um bootstrap anterior). Pergunta ao shim antes de concluir "sem fronteira".
    if !s.tem_shell {
        if let Some(s) = sondar_pelo_shim(conn, p) {
            return Ok(s);
        }
    }
    Ok(s)
}

/// Assinatura que o shim imprime ao recusar. Reconhecê-la é o que separa "este host não tem
/// fronteira" de "este host tem uma fronteira que está me recusando" — dois diagnósticos
/// opostos que, sem isto, produziam a mesma saída vazia.
pub const MARCA_DO_SHIM: &str = "schematize-ops-shell: recusado";

/// Pergunta ao shim quem ele é. `None` quando não há shim (ou é anterior à introspecção).
///
/// **Onde:** [`sondar`], nos dois sentidos — host que já se sabia protegido, e host que
/// recusou o script (sinal de que ganhou fronteira por fora).
fn sondar_pelo_shim(conn: &rusqlite::Connection, p: &VpsProfile) -> Option<Sondagem> {
    let out = super::exec::executar_interno(conn, p, "schematize-probe", "probe").ok()?;
    // Conexão quebrada não é "não há shim" — deixa o chamador reportar o erro de verdade.
    if out.erro.is_some() {
        return None;
    }
    if out.stdout.contains("via=shim") {
        return Some(interpretar_sondagem(&out.stdout));
    }
    // O shim está lá e recusou até a introspecção: é de uma versão ANTERIOR a ela.
    if out.stderr.contains(MARCA_DO_SHIM) || out.stdout.contains(MARCA_DO_SHIM) {
        return Some(sondagem_de_shim_antigo(&p.fronteira));
    }
    None
}

/// Diagnóstico de um host protegido por um shim que não fala a introspecção.
///
/// **Onde:** [`sondar_pelo_shim`]. O ponto desta função é não confundir dois estados opostos:
/// um host SEM fronteira e um host cuja fronteira está funcionando tão bem que recusa até o
/// nosso diagnóstico. Antes, os dois davam saída vazia e viravam `Sem` — o pior erro possível,
/// porque diria "desprotegido" justamente sobre o host mais protegido.
fn sondagem_de_shim_antigo(conhecida: &Fronteira) -> Sondagem {
    // Sabe-se que HÁ fronteira; o nível exato só pelo que já estava registrado.
    let instalada = if conhecida.e_server_side() { *conhecida } else { Fronteira::OpsShellUsuario };
    Sondagem {
        possivel: instalada,
        instalada,
        sudo_sem_senha: false,
        pode_escrever_authkeys: false,
        tem_shell: false,
        home: String::new(),
        notas: vec![
            "há um shim ATIVO neste host, de uma versão anterior à introspecção — ele recusou até o pedido de diagnóstico, que é exatamente o trabalho dele.".into(),
            "ATUALIZAR o shim exige a chave humana de break-glass: a chave do agente está trancada no catálogo e não consegue substituir o próprio guardião. Isso é a propriedade de segurança funcionando, não um defeito.".into(),
            "Para atualizar: conecte com a chave humana, remova a linha `restrict,command=` do ~/.ssh/authorized_keys do usuário, rode `schematize vps bootstrap <alias>` e confira o resultado.".into(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saida(sudo: &str, ak: &str, shim: &str, forced: &str) -> String {
        format!(
            "sudo={sudo}\nauthkeys={ak}\nshim={shim}\nforced={forced}\nshell=sim\nhome=/home/d\n"
        )
    }

    #[test]
    fn sem_home_resolvido_nao_da_pra_montar_forced_command() {
        let s =
            interpretar_sondagem("sudo=nao\nauthkeys=sim\nshim=nenhum\nforced=nao\nshell=sim\n");
        assert_eq!(s.possivel, Fronteira::Sem, "sem $HOME o command= apontaria pra lugar nenhum");
    }

    #[test]
    fn home_resolvido_vem_da_sondagem() {
        let s = interpretar_sondagem(&saida("nao", "sim", "nenhum", "nao"));
        assert_eq!(s.home, "/home/d");
    }

    #[test]
    fn host_com_sudo_alcanca_o_nivel_root() {
        let s = interpretar_sondagem(&saida("sim", "sim", "nenhum", "nao"));
        assert_eq!(s.possivel, Fronteira::OpsShellRoot);
        assert_eq!(s.instalada, Fronteira::Sem);
        assert!(s.pode_melhorar());
    }

    #[test]
    fn host_sem_sudo_ainda_alcanca_fronteira_de_verdade() {
        // O ponto central deste módulo: sem root NÃO é sinônimo de sem fronteira.
        let s = interpretar_sondagem(&saida("nao", "sim", "nenhum", "nao"));
        assert_eq!(s.possivel, Fronteira::OpsShellUsuario);
        assert!(s.possivel.e_server_side(), "o sshd continua recusando antes de existir shell");
        assert!(
            s.notas.iter().any(|n| n.contains("home do usuário")),
            "a nota tem que explicar o trade-off"
        );
    }

    #[test]
    fn host_gerenciado_sem_escrita_no_authkeys_nao_tem_fronteira_possivel() {
        // Nem com sudo: sem forced command não há fronteira, por mais root que se tenha.
        let s = interpretar_sondagem(&saida("sim", "nao", "nenhum", "nao"));
        assert_eq!(s.possivel, Fronteira::Sem);
        assert!(
            !s.pode_melhorar(),
            "não há o que instalar — e o app tem que dizer isso, não tentar"
        );
        assert!(s.notas.iter().any(|n| n.contains("gerenciado")), "a nota tem que explicar o caso");
    }

    #[test]
    fn instalacao_pela_metade_nao_conta_como_fronteira() {
        // Shim no disco mas authorized_keys sem forced command: o agente entra com shell normal.
        let s = interpretar_sondagem(&saida("sim", "sim", "root", "nao"));
        assert_eq!(s.instalada, Fronteira::Sem, "meia instalação é fronteira nenhuma");
        assert!(s.notas.iter().any(|n| n.contains("pela metade")));
        // E o inverso: forced command sem shim no disco.
        let s = interpretar_sondagem(&saida("sim", "sim", "nenhum", "sim"));
        assert_eq!(s.instalada, Fronteira::Sem);
    }

    #[test]
    fn instalacao_completa_e_reconhecida_nos_dois_niveis() {
        assert_eq!(
            interpretar_sondagem(&saida("sim", "sim", "root", "sim")).instalada,
            Fronteira::OpsShellRoot
        );
        assert_eq!(
            interpretar_sondagem(&saida("nao", "sim", "usuario", "sim")).instalada,
            Fronteira::OpsShellUsuario
        );
    }

    #[test]
    fn no_melhor_nivel_nao_ha_o_que_melhorar() {
        let s = interpretar_sondagem(&saida("sim", "sim", "root", "sim"));
        assert!(!s.pode_melhorar());
    }

    #[test]
    fn saida_truncada_ou_estranha_cai_no_mais_restritivo() {
        // Host que respondeu lixo, ou nada, não pode virar "tem fronteira".
        for lixo in ["", "erro qualquer", "sudo=", "sudo=talvez\nauthkeys=quem sabe"] {
            let s = interpretar_sondagem(lixo);
            assert_eq!(s.possivel, Fronteira::Sem, "{lixo:?}");
            assert_eq!(s.instalada, Fronteira::Sem, "{lixo:?}");
        }
    }

    #[test]
    fn sondagem_atraves_do_shim_reporta_o_nivel_instalado_sem_inventar() {
        // O bug que o Q.A. contra sshd REAL encontrou: instalada a fronteira, o script de
        // sondagem passa a ser recusado pelo próprio shim (como deve), e o app reportava
        // "sem fronteira" justamente onde a fronteira existe.
        let s = interpretar_sondagem("via=shim\nshim=root\nforced=sim\nhome=/root\ncatalogo=6\n");
        assert_eq!(s.instalada, Fronteira::OpsShellRoot);
        assert_eq!(s.possivel, Fronteira::OpsShellRoot, "atrás do shim, possível == instalada");
        assert!(!s.pode_melhorar(), "não pode sugerir bootstrap num host já protegido");
        // E é HONESTO sobre o que não dá pra ver daqui.
        assert!(
            s.notas.iter().any(|n| n.contains("break-glass")),
            "tem que explicar por que não dá pra reavaliar: {:?}",
            s.notas
        );
        assert!(!s.sudo_sem_senha, "atrás do shim não dá pra saber — não pode chutar `sim`");
    }

    #[test]
    fn sondagem_pelo_shim_reconhece_o_nivel_de_usuario() {
        let s =
            interpretar_sondagem("via=shim\nshim=usuario\nforced=sim\nhome=/home/d\ncatalogo=3\n");
        assert_eq!(s.instalada, Fronteira::OpsShellUsuario);
        assert_eq!(s.home, "/home/d");
    }

    #[test]
    fn a_ordem_dos_niveis_e_a_da_forca() {
        assert!(Fronteira::OpsShellRoot > Fronteira::OpsShellUsuario);
        assert!(Fronteira::OpsShellUsuario > Fronteira::Sem);
        assert!(!Fronteira::Sem.e_server_side());
    }

    #[test]
    fn cada_nivel_explica_o_que_garante_e_o_que_nao() {
        for f in [Fronteira::Sem, Fronteira::OpsShellUsuario, Fronteira::OpsShellRoot] {
            let e = f.explicacao();
            assert!(e.len() > 60, "a explicação tem que ser útil: {e}");
        }
        // O nível do meio precisa ser HONESTO sobre o limite dele.
        assert!(Fronteira::OpsShellUsuario.explicacao().contains("reescrevê-lo"));
        assert!(Fronteira::Sem.explicacao().contains("não impede"));
    }

    #[test]
    fn fronteira_desconhecida_falha_fechada() {
        for x in ["", "qualquer", "SIM", "true", "\0"] {
            assert_eq!(Fronteira::from_raw(x), Fronteira::Sem, "{x:?}");
        }
        assert_eq!(Fronteira::from_raw("root"), Fronteira::OpsShellRoot);
        assert_eq!(Fronteira::from_raw("usuario"), Fronteira::OpsShellUsuario);
    }
}
