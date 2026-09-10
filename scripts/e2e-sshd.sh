#!/bin/sh
# CAMADA 10 do Q.A. — a fronteira contra um sshd DE VERDADE.
#
# POR QUE ISTO EXISTE
# -------------------
# `tests/vps_bootstrap_e2e.rs` roda o script de instalação com `sh -c` e um `$HOME` de
# sandbox. Prova que o script FAZ o que promete; não prova que a fronteira FUNCIONA — porque
# quem aplica o `command=` do `authorized_keys` é o **sshd**, e não há sshd naquele teste.
#
# Foi exatamente nessa diferença que os dois piores achados do Q.A. anterior moraram: o log
# do host falhando calado no nível mais protegido, e o `vps probe` ficando cego justamente no
# host que o shim protegia. Nenhum dos dois aparece sem um servidor real.
#
# O QUE FAZ: sobe um container com sshd, instala a chave, roda o BOOTSTRAP DE VERDADE por
# ssh, e depois ataca a fronteira pela porta da frente — cada verificação é uma sessão ssh
# real contra o forced command.
#
# Uso: scripts/e2e-sshd.sh          (precisa de docker; sem docker, PULA e diz por quê)
set -eu

CT=schematize-deployer-e2e-sshd
TMP=$(mktemp -d)
falhas=0

limpar() { docker rm -f "$CT" >/dev/null 2>&1 || true; rm -rf "$TMP"; }
trap limpar EXIT INT TERM

command -v docker >/dev/null 2>&1 || {
    echo "docker ausente — camada 10 PULADA (e isso não é verde, é 'não verificado')" >&2
    exit 2
}

echo "== subindo sshd"
docker rm -f "$CT" >/dev/null 2>&1 || true
docker run -d --name "$CT" -p 0:22 debian:stable-slim sh -c '
    apt-get update -qq >/dev/null && apt-get install -y -qq openssh-server >/dev/null
    mkdir -p /run/sshd /home/deploy/.ssh
    useradd -m -s /bin/sh deploy 2>/dev/null || true
    chown -R deploy:deploy /home/deploy
    exec /usr/sbin/sshd -D -e
' >/dev/null

# Espera o sshd atender, em vez de dormir um número mágico.
PORTA=""
i=0
while [ $i -lt 60 ]; do
    PORTA=$(docker port "$CT" 22/tcp 2>/dev/null | head -1 | sed 's/.*://')
    [ -n "$PORTA" ] && docker exec "$CT" sh -c 'pgrep sshd >/dev/null' 2>/dev/null && break
    i=$((i + 1)); sleep 1
done
[ -n "$PORTA" ] || { echo "sshd não subiu" >&2; exit 1; }
echo "   porta $PORTA"

echo "== duas chaves, duas funções (é o modelo real)"
# `k` = HUMANO: entra sem restrição e roda o bootstrap.
# `ka` = AGENTE: é a que o `restrict,command=` prende ao shim, e é com ela que se ataca.
# Atacar com a chave humana testaria a linha errada do authorized_keys — e diria que a
# fronteira não existe. Foi o primeiro resultado desta camada, e o erro era do harness.
ssh-keygen -q -t ed25519 -N "" -f "$TMP/k" -C e2e-humano
ssh-keygen -q -t ed25519 -N "" -f "$TMP/ka" -C e2e-agente
PUB=$(cat "$TMP/k.pub")
docker exec "$CT" sh -c "mkdir -p /home/deploy/.ssh && printf '%s\n' '$PUB' > /home/deploy/.ssh/authorized_keys && chmod 700 /home/deploy/.ssh && chmod 600 /home/deploy/.ssh/authorized_keys && chown -R deploy:deploy /home/deploy/.ssh"

SSH_HUMANO="ssh -F none -i $TMP/k -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o LogLevel=ERROR -p $PORTA deploy@127.0.0.1"
SSH=$(printf '%s' "$SSH_HUMANO" | sed "s|-i $TMP/k |-i $TMP/ka |")

echo "== bootstrap DE VERDADE, pela sessão ssh"
# O mesmo script que o `vps bootstrap` gera. Gerado aqui pelo binário, não copiado à mão:
# copiar é como o teste e a produção divergem sem ninguém ver.
cargo run --quiet --example bootstrap-script -- /home/deploy "$(cat "$TMP/ka.pub")" > "$TMP/boot.sh"
[ -s "$TMP/boot.sh" ] || { echo "não consegui gerar o script de bootstrap" >&2; exit 1; }
# shellcheck disable=SC2086
$SSH_HUMANO "sh -s" < "$TMP/boot.sh" > "$TMP/boot.out" 2>&1 || true
grep -q SCHEMATIZE_BOOTSTRAP_OK "$TMP/boot.out" || {
    echo "   bootstrap NÃO confirmou:"; sed 's/^/     /' "$TMP/boot.out"; exit 1; }
echo "   confirmado no host"

checar() {
    nome=$1; pedido=$2; rc_esp=$3; contem=$4
    # shellcheck disable=SC2086
    saida=$($SSH "$pedido" 2>&1) && rc=0 || rc=$?
    if [ "$rc" != "$rc_esp" ]; then
        printf '   FALHA %-34s rc=%s (esperado %s)\n' "$nome" "$rc" "$rc_esp"
        falhas=$((falhas + 1)); return
    fi
    case "$saida" in
        *"$contem"*) printf '   ok    %s\n' "$nome" ;;
        *) printf '   FALHA %-34s saída sem %s: %s\n' "$nome" "$contem" "$saida"
           falhas=$((falhas + 1)) ;;
    esac
}

echo "== atacando a fronteira pela porta da frente"
checar "shell interativo recusado"   ""                  126 "não abre shell interativo"
checar "verbo desconhecido recusado" "rm -rf /"          126 "uma palavra só"
checar "encadeamento recusado"       "deploy;id"         126 "uma palavra só"
# shellcheck disable=SC2016  # o `$(id)` é o VETOR de ataque, não uma expansão a fazer aqui
checar "substituicao recusada"       'deploy$(id)'       126 "uma palavra só"
checar "probe responde"              "schematize-probe"    0 "forced=sim"

# O log do HOST — controle independente do cliente. Se ele some, sobra a palavra do cliente.
if docker exec "$CT" sh -c 'grep -q deny /home/deploy/.schematize/ops-shell.log' 2>/dev/null; then
    echo "   ok    log do host registrou as recusas"
else
    echo "   FALHA log do host não registrou recusa"; falhas=$((falhas + 1))
fi

# A prova NEGATIVA que dá sentido às outras: sem o forced command, o mesmo pedido PASSARIA.
# A chave HUMANA nao passa pelo shim — se `id` roda por ela e nao pela do agente, o que
# barrou foi a fronteira, e nao um sshd quebrado ou uma chave invalida.
# shellcheck disable=SC2086
if $SSH_HUMANO "id" >/dev/null 2>&1; then
    echo '   ok    self-check: sem o forced command, id roda (a fronteira era o que barrava)'
else
    echo '   FALHA self-check: id nao rodou nem SEM a fronteira — o teste estava cego'
    falhas=$((falhas + 1))
fi

echo
[ "$falhas" = "0" ] || { printf 'VERMELHO — %s verificação(ões) falharam.\n' "$falhas"; exit 1; }
echo "VERDE — a fronteira se comporta contra um sshd real."
