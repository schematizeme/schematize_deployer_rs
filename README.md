# schematize deployer

Chaves SSH, VPS e acesso remoto **auditado** — com a credencial fora do alcance do agente.

Funciona **sozinho**. Integra-se ao schematize quando os dois convivem.

```sh
deployer ssh gen deploy            # gera um par ed25519
deployer ssh import ~/backup/chave # adota uma chave que já existe
deployer vps add srv-01 host user ~/.ssh/deploy
deployer vps exec srv-01 -- systemctl status app
```

---

## Por que este app existe separado

O `schematize` acumulou 128 comandos, e **28 deles** pertenciam a um domínio que nada tem a
ver com skills e overdev: operar servidor. Isso é o piso 6 da casa (sem monólito que mistura
bounded contexts) sendo violado por acréscimo, um comando de cada vez.

Mas o motivo de fundo não é organização. É que **a credencial de deploy não deve ficar ao
alcance do agente**. O [ADR-0005] registrou o loop: toda vez que um deploy é pedido a uma IA,
a chave SSH entra no contexto. Lá a resposta foi mover a fronteira para o servidor (*forced
command*), porque allowlist no cliente é contornável por qualquer binário permitido que abra
shell. O hook `PreToolUse` acrescentou uma rede contra acidente — e **documenta o próprio
limite**: ele falha aberta de propósito, porque um hook que trava por JSON inesperado
quebraria toda tool use do usuário.

Sobra o segredo **em repouso na máquina**. É o que este app existe para resolver.

## O que o cofre protege — e o que não protege

O **cofre existe** (`deployer cofre init`) e o que entra nele é ilegível para quem tem o
disco: Argon2id de 64 MiB + XChaCha20-Poly1305, arquivo em 600, cabeçalho autenticado. Mas o
escopo dele hoje é preciso, e vale dizer exatamente qual:

| | protegido pelo cofre? |
|---|---|
| O que você guardar nele | **sim** — em repouso é ruído sem a passphrase |
| O inventário de hosts (`vps.db`: alias, host, usuário, ambiente) | **ainda não** — a migração é o resto da fase 3 |
| Suas chaves privadas em `~/.ssh/*` | **não, e nunca será** — quem as protege é a passphrase **da própria chave** |
| O processo já destravado | **não** — enquanto aberto, a chave está em memória |

> **Duas coisas que este cofre NÃO faz, ditas antes que alguém suponha.**
>
> Ele não protege chave SSH sem passphrase: uma chave sem senha em `~/.ssh` continua legível
> por qualquer processo seu, e nenhum cofre em outro arquivo muda isso. O `deployer ssh
> import` **preserva** a passphrase da chave justamente por isso.
>
> E ele não protege contra quem já está dentro do processo destravado. Isso não é conserto
> pendente — é o limite de qualquer cofre de desktop. O que encurta a janela é o auto-lock,
> não uma promessa.

Está escrito aqui, em cima e não em rodapé, porque a armadilha que o [ADR-0004] nomeou é
exatamente esta: a defesa que **dá confiança sem dar garantia**.

## Estado

| fase | o quê | estado |
|---|---|---|
| 0 | ADR aceito | **feito** |
| 1 | Repo próprio, três contextos movidos, comportamento idêntico | **feito** |
| 2 | CLI própria + snapshot de superfície | **feito** (33 comandos congelados) |
| 3 | **Cofre cifrado** | **feito** (primitiva + CLI); migrar o `vps.db` para dentro dele segue aberto |
| 4 | GUI própria (standalone) | aberto |
| 5 | Ponte com o schematize (subprocesso, superfície tipada) | aberto |
| 6 | Instalação pelos dois caminhos + release | aberto |
| 7 | Remoção do que migrou, do schematize (primeiro como shim) | aberto |

**Nada saiu do schematize ainda.** Os 28 comandos continuam lá e funcionando; é isso que
torna cada fase reversível (piso 2 — não fazer big bang).

## Arquitetura

```
src/
├── sshkeys/   gerar · IMPORTAR · listar · exportar · usar  (a privada nunca é lida)
├── vps/       registro de hosts · política · auditoria · execução mediada
├── mcp/       as tools tipadas que o agente enxerga, e só elas
├── cofre/     Argon2id + XChaCha20-Poly1305, escrita atômica, arquivo em 600
└── nucleo/    infraestrutura: caminhos, processo, permissão, redação, i18n, config
```

O `nucleo/` é **cópia deliberada** do que existe no `schematize_cli_rs`. Depender daquele
crate amarraria os dois apps e mataria a propriedade que justifica este repo — abrir e
funcionar sozinho. São ~600 linhas de plataforma (`home()`, `run()`, `chmod`), e a
alternativa seria um quinto repositório só para elas. **Nada de domínio entra ali:** o piso 6
veta `commons` de domínio, e se um dia o `nucleo` souber o que é um host ou uma chave, o corte
foi feito errado.

## Integração com o schematize

Já funciona: o Deployer **herda o idioma** escolhido no schematize (lê o `config.json` dele) —
e **nunca escreve** nesse arquivo, porque ele carrega campos (`dev_dirs`, `projects`) que este
app não conhece e um `load`+`save` ingênuo apagaria. Sem o schematize instalado, cai no
ambiente e no default: degradação graciosa (piso 10), não erro.

Cada app é dono das **suas** entradas no `settings.json` do Claude Code: o schematize tem os
hooks do overdev, o Deployer tem o `vps guard` e as tools de MCP. Desligar um não pode levar o
outro — e há teste afirmando isso.

## Desenvolvimento

```sh
cargo test                       # 249 testes
cargo clippy --all-targets -- -D warnings
cargo fmt --check
DEPLOYER_REGRAVA_SUPERFICIE=1 cargo test superficie   # só quando a mudança for intencional
```

[ADR-0004]: ../schematize_app_archive/decisoes/ADR-0004-efeitos-externos-nao-producao.md
[ADR-0005]: ../schematize_app_archive/decisoes/ADR-0005-acesso-remoto-mediado.md
