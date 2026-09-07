//! O QUE: audita se o CÓDIGO cumpre o que os ADRs e o plano PROMETERAM. Cada afirmação
//! normativa vira uma asserção verificável.
//!
//! POR QUE EXISTE: "nada sai do planejado" só é verdade se alguém conferir. Um ADR `accepted`
//! cuja decisão foi silenciosamente desfeita no código é pior que ADR nenhum: dá segurança
//! falsa a quem lê a documentação em vez do fonte. Este teste é o gate que impede a
//! documentação e o código de divergirem sem alguém notar.
//!
//! DE ONDE VEM: os fontes do repo. PRA ONDE VAI: só asserção.

/// Lê um fonte do crate, já cortando o módulo de testes (só o código de PRODUÇÃO conta).
fn producao(caminho: &str) -> String {
    let s = std::fs::read_to_string(caminho).unwrap_or_else(|e| panic!("{caminho}: {e}"));
    s.split("#[cfg(test)]").next().unwrap_or("").to_string()
}

/// Como [`producao`], mas SEM comentários — é o que vale quando a pergunta é "o código faz X?".
///
/// Sem isto, um doc-comment que EXPLICA por que não usamos `accept-new` faria o teste acusar
/// que usamos. Verificar conformidade lendo comentário é o oposto do ponto.
fn codigo(caminho: &str) -> String {
    producao(caminho)
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            !t.starts_with("//") && !t.starts_with("*") && !t.starts_with("/*")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// ADR-0006 emenda 1 — o `~/.ssh/config` do usuário não entra; o perfil é a fonte única.
#[test]
fn adr0006_o_perfil_e_a_fonte_unica_da_conexao() {
    let c = codigo("src/vps/conexao.rs");
    assert!(
        c.contains(r#"a.push("-F".into());"#) && c.contains(r#"a.push("none".into());"#),
        "o `-F none` sumiu — o config do usuário voltaria a entrar e a auditoria poderia mentir"
    );
    assert!(c.contains("IdentitiesOnly=yes"), "sem IdentitiesOnly, outras chaves são oferecidas");
    assert!(c.contains("StrictHostKeyChecking=yes"), "o pinning virou TOFU");
    assert!(!c.contains("accept-new"), "TOFU cego voltou ao caminho de conexão");
    assert!(c.contains("BatchMode=yes"), "sem BatchMode o agente pendura num prompt de senha");
}

/// ADR-0006 — envelopar o OpenSSH do sistema; nada de cripto própria.
#[test]
fn adr0006_nenhuma_implementacao_propria_de_ssh() {
    let toml = std::fs::read_to_string("Cargo.toml").expect("Cargo.toml");
    for crate_proibido in ["russh", "ssh2", "thrussh", "libssh"] {
        assert!(!toml.contains(crate_proibido),
                "{crate_proibido} entrou como dependência — o ADR-0006 decidiu envelopar o ssh do sistema");
    }
}

/// ADR-0005 — a chave privada NUNCA é lida; só referenciada por caminho.
#[test]
fn adr0005_a_privada_nunca_e_lida() {
    for f in
        ["src/vps/conexao.rs", "src/vps/exec.rs", "src/vps/bootstrap.rs", "src/vps/registro.rs"]
    {
        let s = producao(f);
        for leitura in ["read_to_string(&chave", "read_to_string(&key", "fs::read(&chave"] {
            assert!(!s.contains(leitura), "{f}: alguém está LENDO a chave privada ({leitura})");
        }
    }
    // A pública é que sai — e é só ela que o bootstrap manda pro host.
    assert!(
        producao("src/vps/bootstrap.rs").contains("export_public"),
        "o bootstrap tem que enviar a PÚBLICA"
    );
}

/// ADR-0005 — não existe válvula de escape em lugar nenhum do caminho de decisão.
#[test]
fn adr0005_sem_valvula_de_escape() {
    let alvos = [
        "src/vps/politica.rs",
        "src/vps/exec.rs",
        "src/mcp/tools.rs",
        "src/vps/hook.rs",
        "src/vps/conexao.rs",
    ];
    for f in alvos {
        let s = producao(f);
        for proibido in [
            "skip_policy",
            "force_policy",
            "bypass_policy",
            "ignore_policy",
            "no_audit",
            "skip_audit",
        ] {
            assert!(!s.contains(proibido), "{f}: válvula de escape {proibido:?}");
        }
    }
    // E no shim, que é a fronteira de verdade.
    let shim = std::fs::read_to_string("packaging/ops-shell/schematize-ops-shell").expect("shim");
    for proibido in ["--force", "skip_catalog", "bypass", "SCHEMATIZE_DEBUG"] {
        assert!(!shim.contains(proibido), "o shim ganhou um escape: {proibido:?}");
    }
}

/// ADR-0005 — o agente não alcança nem a execução interna nem a auditoria.
#[test]
fn adr0005_o_mcp_nao_alcanca_o_que_nao_deve() {
    let t = producao("src/mcp/tools.rs");
    for proibido in [
        "executar_interno",
        "registrar_comando",
        "abrir_sessao",
        "bootstrap::",
        "sondar",
        "confiar",
        "salvar",
    ] {
        assert!(!t.contains(proibido), "o MCP alcança {proibido:?} — o agente não pode");
    }
    assert!(t.contains("Confirmacao::Ausente"), "o MCP tem que passar Ausente sempre");
    assert!(!t.contains("HumanoConfirmou"), "o agente não pode se autoconfirmar");
}

/// Piso da casa — auditoria append-only: nenhum caminho de remoção ou reescrita.
#[test]
fn piso_auditoria_append_only() {
    let a = producao("src/vps/auditoria.rs");
    for proibido in ["DELETE FROM comandos", "DELETE FROM sessoes", "UPDATE comandos", "DROP TABLE"]
    {
        assert!(!a.contains(proibido), "auditoria deixou de ser append-only: {proibido}");
    }
    // A redação acontece na ESCRITA (se migrar pra leitura, o segredo vai ao disco em claro).
    let escrita = a.split("pub fn registrar_comando").nth(1).expect("a função de escrita");
    assert!(escrita.contains("scrub("), "a redação saiu do caminho de escrita");
}

/// Piso da casa — nada de SQL concatenado, em nenhum módulo que fale com o banco.
#[test]
fn piso_sql_sempre_parametrizado() {
    for f in ["src/vps/registro.rs", "src/vps/auditoria.rs", "src/vps/verbos.rs", "src/vps/db.rs"] {
        for (n, l) in producao(f).lines().enumerate() {
            let t = l.trim();
            // DML nunca pode ser concatenado — para esses o `?` existe.
            let dml = ["SELECT ", "INSERT ", "UPDATE ", "DELETE "].iter().any(|k| t.contains(k));
            assert!(!(dml && t.contains("format!")), "{f}:{}: SQL concatenado -> {t}", n + 1);
            // DDL não aceita `?` em identificador, então a exigência muda de forma: quem
            // monta DDL com `format!` TEM que blindar o identificador antes.
            if t.contains("ALTER TABLE") && t.contains("format!") {
                assert!(
                    producao(f).contains("identificador_ok"),
                    "{f}:{}: DDL concatenado SEM blindagem de identificador -> {t}",
                    n + 1
                );
            }
        }
    }
}

/// Piso da casa — zero `unwrap`/`expect` no código de produção dos módulos novos.
#[test]
fn piso_nenhum_unwrap_em_producao() {
    let modulos = [
        "src/vps/mod.rs",
        "src/vps/db.rs",
        "src/vps/registro.rs",
        "src/vps/conexao.rs",
        "src/vps/exec.rs",
        "src/vps/auditoria.rs",
        "src/vps/politica.rs",
        "src/vps/hook.rs",
        "src/vps/capacidade.rs",
        "src/vps/bootstrap.rs",
        "src/vps/verbos.rs",
        "src/mcp/mod.rs",
        "src/mcp/protocolo.rs",
        "src/mcp/tools.rs",
        "src/cli/vps.rs",
        "src/cli/mcp.rs",
    ];
    let mut culpados = Vec::new();
    for f in modulos {
        let s = producao(f);
        let n = s.matches(".unwrap()").count() + s.matches(".expect(").count();
        if n > 0 {
            culpados.push(format!("{f}: {n}"));
        }
    }
    assert!(culpados.is_empty(), "unwrap/expect em produção: {culpados:?}");
}

/// Piso da casa (§6) — arquivo ≤ 750 linhas, e SINALIZA acima de 300 linhas úteis.
///
/// **O quê:** varre `src/**/*.rs` recursivamente. Acima de 750 linhas totais **reprova**;
/// acima de 300 linhas úteis (sem comentário, sem linha em branco) **imprime**, sem barrar.
///
/// **Onde / por quê:** este teste varria só `src/vps` e `src/mcp` — os diretórios da
/// entrega em que ele nasceu. `src/cli/args.rs` cresceu com os subcomandos de VPS, chegou a
/// 780 linhas e **passou batido**, porque estava fora do recorte. Um piso que só olha onde
/// a última entrega mexeu não é piso, é lembrete.
///
/// A linha útil é o critério da casa por um motivo: o teto de 750 pressupõe ~250 linhas
/// reservadas a comentário. Um arquivo bem documentado chega perto do teto sem estar
/// inchado; um arquivo de 700 linhas úteis e zero comentário é outro problema. Por isso o
/// bloqueio é no total e o **aviso** é no útil — e observabilidade tem folga natural.
#[test]
fn piso_tamanho_de_arquivo() {
    /// Todo `.rs` sob `raiz`, recursivo.
    fn fontes(raiz: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(dir) = std::fs::read_dir(raiz) else {
            return;
        };
        for e in dir.flatten() {
            let p = e.path();
            if p.is_dir() {
                fontes(&p, out);
            } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }
    let mut arquivos = Vec::new();
    fontes(std::path::Path::new("src"), &mut arquivos);
    arquivos.sort();
    // Guarda de SANIDADE da varredura ("achei o crate?"), não o piso. O número era 50
    // no schematize, que carrega o crate inteiro; aqui são três contextos. O piso de
    // tamanho (750 duras / 300 de flag) é o do laço abaixo e não mudou uma linha.
    assert!(arquivos.len() > 20, "a varredura não achou o crate: {} arquivos", arquivos.len());

    let mut grandes = Vec::new();
    let mut densos = Vec::new();
    for p in &arquivos {
        let src = std::fs::read_to_string(p).unwrap();
        let total = src.lines().count();
        if total > 750 {
            grandes.push(format!("{}: {total}", p.display()));
        }
        let uteis = src
            .lines()
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with("//")
            })
            .count();
        if uteis > 300 {
            densos.push(format!("{}: {uteis} úteis", p.display()));
        }
    }

    // FLAG, não bloqueio: registra a dívida sem travar a entrega (§6).
    if !densos.is_empty() {
        println!(
            "FLAG §6 — acima de 300 linhas úteis ({}), dívida a revisitar:\n  {}",
            densos.len(),
            densos.join("\n  ")
        );
    }
    assert!(
        grandes.is_empty(),
        "acima do teto de 750 linhas (§6): quebre em módulos por coesão, não por corte \
         arbitrário — e se for definição de superfície pública (CLI, API, schema), congele \
         a superfície num snapshot ANTES de cortar:\n  {}",
        grandes.join("\n  ")
    );
}

/// Piso da casa — TODA função pública comentada (é o que alimenta o índice §39).
#[test]
fn piso_toda_funcao_publica_documentada() {
    let mut sem_doc = Vec::new();
    for dir in ["src/vps", "src/mcp"] {
        for entrada in std::fs::read_dir(dir).unwrap() {
            let p = entrada.unwrap().path();
            if p.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let src = std::fs::read_to_string(&p).unwrap();
            let prod = src.split("#[cfg(test)]").next().unwrap_or("");
            let linhas: Vec<&str> = prod.lines().collect();
            for (i, l) in linhas.iter().enumerate() {
                if !l.trim_start().starts_with("pub fn ")
                    && !l.trim_start().starts_with("pub const ")
                {
                    continue;
                }
                // A linha anterior (ignorando atributos) tem que ser doc-comment.
                let mut j = i;
                while j > 0 && linhas[j - 1].trim_start().starts_with('#') {
                    j -= 1;
                }
                let anterior = if j > 0 { linhas[j - 1].trim_start() } else { "" };
                if !anterior.starts_with("///") {
                    sem_doc.push(format!("{}:{}: {}", p.display(), i + 1, l.trim()));
                }
            }
        }
    }
    assert!(
        sem_doc.is_empty(),
        "função/const pública sem doc-comment (quebra o índice §39):\n  {}",
        sem_doc.join("\n  ")
    );
}

/// Plano §5 R2 — o break-glass humano nunca é removido pelo bootstrap.
#[test]
fn plano_r2_break_glass_preservado() {
    let b = producao("src/vps/bootstrap.rs");
    assert!(b.contains("grep -v -F \"$PUB\""), "o bootstrap deixou de filtrar SÓ a própria chave");
    assert!(!b.contains("> \"$AK\"\n"), "o bootstrap trunca o authorized_keys inteiro");
    assert!(b.contains("<<'__SCHEMATIZE_SHIM__'"), "o here-doc voltou a ser expansível");
}

// Os dois testes que liam o fonte da GUI MUDARAM DE REPO (2026-09-01).
//
// `piso10_a_gui_nao_bloqueia_na_rede` e `p12_toctou_no_trust` (este em `vps_pentest.rs`)
// asseveravam propriedades de `schematize_gui_slint/src/wire/vps.rs`, lido daqui por
// caminho relativo (`../schematize_gui_slint/...`). Passavam na maquina de quem
// desenvolve, com os dois repos lado a lado, e **falhavam sempre no CI**, onde so um repo
// e clonado — foi o que reprovou o primeiro run verde deste workflow.
//
// Teste que nao consegue passar no CI e teste que ensina a ignorar o CI, ou que alguem
// apaga. Foram pro repo dono do arquivo, no modulo de teste do proprio `wire/vps.rs`,
// onde o fonte esta sempre presente. Nao foram enfraquecidos nem removidos.
//
// A licao geral: **teste nao atravessa fronteira de repo por caminho relativo.** O que
// um repo pode afirmar sobre o outro e o CONTRATO que ele consome, nao o texto do fonte
// alheio.

/// A convenção "produção = tudo antes do primeiro `#[cfg(test)]`" tem que ser VERDADE.
///
/// **O quê:** varre todo `src/**/*.rs` e reprova qualquer item de nível superior que apareça
/// DEPOIS do primeiro `#[cfg(test)]` sem estar ele mesmo marcado como teste.
///
/// **Onde / por quê:** nove testes deste repo — conformidade, pentest e destrutivo — recortam
/// o "código de produção" com `fonte.split("#[cfg(test)]").next()`. É um recorte por convenção,
/// não por parser: qualquer função escrita abaixo do módulo de teste fica INVISÍVEL pras
/// varreduras de SQL concatenado, de doc-comment obrigatório e de alcance do MCP — e some
/// calada, sem erro nenhum. Já aconteceu duas vezes: `is_jwt` (primitiva de redação) em
/// `debugreport/redacao.rs` e o trio `ambiente`/`versao_de`/`parece_versao` no
/// `debugreport/mod.rs`, que monta o relatório mandado pro suporte. Este teste é o que
/// transforma a convenção em invariante checada.
#[test]
fn teste_no_fim_do_arquivo() {
    /// Todo `.rs` sob `raiz`, recursivo.
    fn fontes(raiz: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(raiz).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                fontes(&p, out);
            } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }
    let mut arquivos = Vec::new();
    fontes(std::path::Path::new("src"), &mut arquivos);
    arquivos.sort();
    assert!(arquivos.len() > 20, "a varredura não achou os fontes: {}", arquivos.len());

    let inicios =
        ["pub ", "fn ", "const ", "static ", "struct ", "enum ", "impl ", "type ", "trait "];
    let mut violacoes = Vec::new();
    for arq in &arquivos {
        let src = std::fs::read_to_string(arq).unwrap();
        let mut passou_teste = false;
        let mut gatilho_de_teste = false; // o item logo abaixo tem `#[cfg(test)]` próprio?
        for (n, linha) in src.lines().enumerate() {
            let t = linha.trim_start();
            // Só nível superior: item indentado está DENTRO de outro bloco (inclusive do
            // próprio `mod tests`), e o recorte por split já o descarta junto com o pai.
            let topo = linha.len() == t.len();
            if t.starts_with("#[cfg(test)]") {
                if topo {
                    passou_teste = true;
                    gatilho_de_teste = true;
                }
                continue;
            }
            if !topo || t.is_empty() || t.starts_with("//") {
                continue;
            }
            let item = inicios.iter().any(|i| t.starts_with(i)) || t.starts_with("mod ");
            if item && passou_teste && !gatilho_de_teste {
                violacoes.push(format!("{}:{}: {}", arq.display(), n + 1, t));
            }
            if item || t.starts_with('#') {
                // Atributo (`#[derive]`, `#[allow]`) não consome o gatilho; item consome.
                if item {
                    gatilho_de_teste = false;
                }
            }
        }
    }
    assert!(
        violacoes.is_empty(),
        "item de PRODUÇÃO depois do módulo de teste — invisível pras varreduras que recortam \
         o fonte em `split(\"#[cfg(test)]\")`. Mova o item para cima do primeiro `#[cfg(test)]` \
         (ou o módulo de teste para o fim do arquivo):\n  {}",
        violacoes.join("\n  ")
    );
}

/// Ler-modificar-escrever nunca pode partir de `unwrap_or_default()`.
///
/// **O quê:** varre `src/**/*.rs` e reprova toda linha que faça
/// `read_to_string(…).unwrap_or_default()` tendo uma escrita no mesmo arquivo logo abaixo.
///
/// **Onde / por quê:** esse idioma mapeia TODA falha de leitura para "arquivo vazio", e a
/// escrita seguinte reescreve o arquivo inteiro a partir do vazio — ou seja, **um erro de
/// leitura apaga o arquivo do usuário**. Estava em sete pontos dos três crates, sempre sobre
/// arquivo que a pessoa se importa: `.bashrc`, `~/.ssh/config`, `.gitignore`, `CHECKLIST.md`,
/// `DECISOES.md`. O gatilho é banal: `read_to_string` devolve `InvalidData` para qualquer
/// arquivo que não seja UTF-8 válido, e um comentário acentuado em Latin-1 num `.bashrc` é
/// situação corriqueira. O caminho certo é `util::ler_para_modificar`, que separa "não existe"
/// (vazio, legítimo) de "não deu pra ler" (erro, não escreve).
#[test]
fn ler_modificar_escrever_nunca_parte_de_vazio() {
    // Exceção documentada, não varrida pra baixo do tapete: `marker_path()` é um arquivo
    // do PRÓPRIO app cujo conteúdo é um link único, substituído por inteiro a cada
    // escrita — não há conteúdo do usuário pra perder. O pior caso de uma leitura falha é
    // reanunciar um post, não destruir dado.
    //
    // A exceção casa por CONTEÚDO, não por `arquivo:linha`. A primeira versão usava
    // `src/news.rs:116` e quebrou na primeira passada do `cargo fmt`, que empurrou a linha
    // pra 126. O modo de falhar barulhento foi esse; o silencioso é pior: se o código
    // andasse de tal jeito que uma violação de VERDADE caísse na linha 116, ela herdaria a
    // isenção sem ninguém notar. Allowlist ancorada em número de linha é armadilha.
    let permitidos: &[(&str, &str)] = &[("src/news.rs", "marker_path()")];

    /// Todo `.rs` sob `raiz`, recursivo.
    fn fontes(raiz: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(raiz).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                fontes(&p, out);
            } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }
    let mut arquivos = Vec::new();
    fontes(std::path::Path::new("src"), &mut arquivos);
    arquivos.sort();

    let mut violacoes = Vec::new();
    for arq in &arquivos {
        let src = std::fs::read_to_string(arq).unwrap();
        let prod: Vec<&str> = src.split("#[cfg(test)]").next().unwrap_or("").lines().collect();
        for (i, l) in prod.iter().enumerate() {
            if !(l.contains("read_to_string(") && l.contains("unwrap_or_default()")) {
                continue;
            }
            let fim = (i + 31).min(prod.len());
            let janela = prod[i + 1..fim].join("\n");
            if !(janela.contains("fs::write(") || janela.contains("escreve_atomico(")) {
                continue; // leitura pura: `unwrap_or_default` aqui é legítimo.
            }
            let caminho = arq.display().to_string();
            if permitidos.iter().any(|(f, marca)| caminho.ends_with(f) && l.contains(marca)) {
                continue;
            }
            violacoes.push(format!("{caminho}:{}: {}", i + 1, l.trim()));
        }
    }
    assert!(
        violacoes.is_empty(),
        "ler-modificar-escrever partindo de `unwrap_or_default()`: uma falha de leitura vira \
         arquivo vazio e a escrita seguinte APAGA o conteúdo do usuário. Use \
         `util::ler_para_modificar`, que devolve vazio só quando o arquivo não existe:\n  {}",
        violacoes.join("\n  ")
    );
}

/// Nenhum teste pode ler arquivo FORA deste repositório.
///
/// **O quê:** varre `tests/**` e `src/**` e reprova qualquer caminho literal que comece com
/// `../` — o jeito de alcançar um repo irmão a partir daqui.
///
/// **Onde / por quê:** dois testes deste repo liam o fonte da GUI em
/// `../schematize_gui_slint/src/wire/vps.rs`. Passavam na máquina de quem desenvolve, com os
/// dois repos lado a lado, e **falhavam sempre no CI**, onde só um repo é clonado. Foi o que
/// reprovou o primeiro run do workflow recém-criado — o CI achou, no primeiro dia, um teste
/// que nunca teve como passar nele.
///
/// Teste que não consegue passar no CI é teste que ensina a ignorar o CI, ou que alguém
/// apaga. Os dois foram pro repo dono do arquivo, onde o fonte está sempre presente.
///
/// **A regra:** teste não atravessa fronteira de repo por caminho relativo. O que um repo
/// pode afirmar sobre o outro é o CONTRATO que ele consome — o crate, a API, o schema —,
/// nunca o texto do fonte alheio.
#[test]
fn nenhum_teste_le_fora_do_repo() {
    /// Todo `.rs` sob `raiz`, recursivo.
    fn fontes(raiz: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(dir) = std::fs::read_dir(raiz) else {
            return;
        };
        for e in dir.flatten() {
            let p = e.path();
            if p.is_dir() {
                fontes(&p, out);
            } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }
    let mut arquivos = Vec::new();
    fontes(std::path::Path::new("tests"), &mut arquivos);
    fontes(std::path::Path::new("src"), &mut arquivos);
    arquivos.sort();

    /// Normaliza `a/b/../c` sem tocar o disco, e diz se o caminho ESCAPA da raiz.
    ///
    /// **Onde:** o laço abaixo, uma vez por literal encontrado.
    ///
    /// **Por que resolver em vez de olhar o prefixo:** `../` sozinho não é defeito. Num
    /// `include_str!` ele é relativo ao ARQUIVO, e `src/vps/bootstrap.rs` alcançando
    /// `../../packaging/...` continua dentro deste repo — legítimo. O que não pode é o
    /// caminho terminar FORA da raiz, porque aí só existe na máquina de quem desenvolve.
    fn escapa(base: &std::path::Path, alvo: &str) -> bool {
        let mut prof: i32 = base.components().count() as i32;
        for c in std::path::Path::new(alvo).components() {
            match c {
                std::path::Component::ParentDir => prof -= 1,
                std::path::Component::CurDir => {}
                _ => prof += 1,
            }
            if prof < 0 {
                return true;
            }
        }
        false
    }

    // `include_str!`/`include_bytes!` resolvem contra o DIRETÓRIO DO ARQUIVO; leitura em
    // tempo de execução resolve contra a raiz do crate. Bases diferentes, mesma pergunta.
    const EMBUTIDOS: &[&str] = &["include_str!(", "include_bytes!("];
    const LEITURAS: &[&str] =
        &["read_to_string(", "read_dir(", "File::open(", "fs::read(", "fs::metadata("];

    let mut violacoes = Vec::new();
    for arq in &arquivos {
        let src = std::fs::read_to_string(arq).unwrap();
        for (i, l) in src.lines().enumerate() {
            let trecho = l.trim();
            // A própria explicação deste piso cita o caminho — em comentário.
            if trecho.starts_with("//") {
                continue;
            }
            let Some(depois) = l.split_once("\"..").map(|(_, d)| d) else {
                continue;
            };
            let Some(resto) = depois.split('"').next() else {
                continue;
            };
            let alvo = format!("..{resto}");

            let embutido = EMBUTIDOS.iter().any(|f| l.contains(f));
            let leitura = LEITURAS.iter().any(|f| l.contains(f));
            if !embutido && !leitura {
                continue; // literal `"../…"` como VETOR de path traversal: é teste, não leitura.
            }
            // Base: o diretório do arquivo (embutido) ou a raiz do crate (leitura).
            let base = if embutido {
                arq.parent().unwrap_or(std::path::Path::new(""))
            } else {
                std::path::Path::new("")
            };
            if escapa(base, &alvo) {
                violacoes.push(format!("{}:{}: {trecho}", arq.display(), i + 1));
            }
        }
    }
    assert!(
        violacoes.is_empty(),
        "caminho pra fora do repo: no CI só ESTE repositório é clonado, então isto falha \
         sempre lá e passa sempre aqui. Mova a asserção pro repo dono do arquivo, ou \
         afirme sobre o CONTRATO consumido em vez do fonte alheio:\n  {}",
        violacoes.join("\n  ")
    );
}
// ---------------------------------------------------------------------------
// REMOVIDO NA MUDANÇA DE REPO: `release_publica_gui_deterministica`
//
// Ele afirmava que o `release.yml` compila a GUI com `packaging/gui-pin.txt` +
// `--precise`, em vez de clonar o HEAD do main dos dois repos. Isso guarda um problema que
// só existe quando **CLI e GUI moram em repositórios diferentes** — e o ADR-0010 decidiu
// que aqui elas moram no MESMO repo, com dois binários, exatamente para que esse problema
// não possa acontecer. Um teste que guarda um risco estruturalmente inexistente não é
// segurança extra: é ruído que passa a ser mantido para sempre.
//
// NÃO é dispensa do risco: o teste continua vivo e verde no `schematize_cli_rs`, onde os
// dois repos de fato existem.
//
// DÍVIDA, e é dívida de verdade: quando este repo ganhar `release.yml` (fase 6 do plano),
// ele precisa do teste EQUIVALENTE para a garantia daqui — que os dois binários saem do
// MESMO commit. Enquanto não houver pipeline, não há o que afirmar.
// ---------------------------------------------------------------------------
