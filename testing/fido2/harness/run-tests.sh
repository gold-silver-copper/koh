#!/usr/bin/env bash
# End-to-end FIDO2 / security-key test for `koh --require-sk`.
#
# Runs entirely inside the container image built from testing/fido2/Dockerfile, which provides:
#   - the real `koh` binary (built from this checkout),
#   - a from-source OpenSSH whose `ssh-keygen`/`ssh-agent`/`ssh-add` support security keys, and
#   - `sk-dummy.so`, OpenSSH's *software* FIDO2 authenticator (the same one the OpenSSH project uses
#     to test sk keys without hardware). It signs in software and asserts user-presence, so it drives
#     the exact production path koh relies on — real sk key, real ssh-agent signing, real
#     `sk-ssh-ed25519@openssh.com` signature format — with no physical token.
#
# It stands up koh servers on loopback and runs several connection scenarios, asserting each is
# admitted or rejected as expected, and prints diagnostics as it goes.
set -uo pipefail

# ---------------------------------------------------------------------------
# Presentation helpers
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    BOLD=$'\e[1m'; DIM=$'\e[2m'; RED=$'\e[31m'; GRN=$'\e[32m'; YLW=$'\e[33m'; BLU=$'\e[36m'; RST=$'\e[0m'
else
    BOLD=""; DIM=""; RED=""; GRN=""; YLW=""; BLU=""; RST=""
fi
strip_ansi() { sed $'s/\x1b\\[[0-9;]*m//g'; }
step()  { printf '%s\n' "${BLU}${BOLD}==>${RST} ${BOLD}$*${RST}"; }
info()  { printf '    %s\n' "${DIM}$*${RST}"; }
pass()  { printf '    %s\n' "${GRN}✓ PASS${RST} $*"; }
fail()  { printf '    %s\n' "${RED}✗ FAIL${RST} $*"; }

PASS_COUNT=0
FAIL_COUNT=0
declare -a RESULTS=()

# ---------------------------------------------------------------------------
# Environment / setup
# ---------------------------------------------------------------------------
export SK_PROVIDER="${SK_PROVIDER:-/opt/openssh/sk-dummy.so}"
export SSH_SK_HELPER="${SSH_SK_HELPER:-/opt/openssh/ssh-sk-helper}"
export PATH="/opt/openssh:$PATH"
# koh identity keys are always encrypted at rest; feed a passphrase non-interactively (>= 12 chars).
export KOH_KEY_NEW_PASSPHRASE="fido2-harness-passphrase"
export KOH_KEY_PASSPHRASE="fido2-harness-passphrase"

WORK="$(mktemp -d /tmp/koh-fido2.XXXXXX)"
cd "$WORK"
mkdir -p keys logs
KOH="$(command -v koh)"

cleanup() {
    [ -n "${SERVER_SK_PID:-}" ] && kill "$SERVER_SK_PID" 2>/dev/null
    [ -n "${SERVER_PLAIN_PID:-}" ] && kill "$SERVER_PLAIN_PID" 2>/dev/null
    [ -n "${SSH_AGENT_PID:-}" ] && kill "$SSH_AGENT_PID" 2>/dev/null
}
trap cleanup EXIT

# koh_id <keyfile> — print the koh endpoint id for a (created-on-demand) identity key.
koh_id() { "$KOH" id --key-file "$1" 2>/dev/null; }

# make_sk_key <name> <comment> — create an OpenSSH ed25519-sk key via the software authenticator.
make_sk_key() {
    ssh-keygen -t ed25519-sk -w "$SK_PROVIDER" -f "keys/$1" -N '' -C "$2" >/dev/null 2>&1 \
        || { fail "could not create sk key $1"; exit 2; }
}

# wait_for_ready <logfile> — block until a koh server prints its ready banner (or time out).
wait_for_ready() {
    for _ in $(seq 1 100); do
        grep -q "server ready" "$1" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

# port_from_log <logfile> — extract the loopback port koh bound (from the `--direct <ip>:PORT` hint).
port_from_log() { grep -oE '<this-host-ip>:[0-9]+' "$1" | head -1 | grep -oE '[0-9]+'; }

# ---------------------------------------------------------------------------
# A single scenario: connect and assert the admission outcome.
#
#   run_case <name> <expect: admit|reject> <server-id> <port> <client-key> [sk-pub]
#
# Admission is observed authoritatively from the SERVER's structured auth log (`koh::auth`): an
# `outcome=accepted` line means the peer cleared every gate (allowlist + security key); an
# `outcome=rejected` line (or the absence of an accept) means it did not. The client's own output is
# captured purely for diagnostics.
# ---------------------------------------------------------------------------
run_case() {
    local name="$1" expect="$2" server_id="$3" port="$4" client_key="$5" sk_pub="${6:-}"
    local srv_log="$SRV_LOG"
    local before after client_out
    before="$(wc -l < "$srv_log")"

    local args=(connect --direct "127.0.0.1:$port" --key-file "$client_key")
    [ -n "$sk_pub" ] && args+=(--sk-key "$sk_pub")
    args+=("$server_id")

    step "Test: $name"
    info "client: koh ${args[*]/$client_key/$(basename "$client_key")}"
    # The connected client would enter a full-screen TUI needing a real TTY; here we only care about
    # the admission decision, which is fully determined before that. Feed /dev/null and cap the run.
    client_out="$(timeout 25 "$KOH" "${args[@]}" </dev/null 2>&1)"

    # Give the server a beat to flush its decision to the log, then read only the new lines.
    sleep 0.4
    after="$(wc -l < "$srv_log")"
    # koh's tracing log includes ANSI colour codes even when redirected; strip them so the asserts
    # (and the diagnostics) see plain text.
    local delta; delta="$(sed -n "$((before + 1)),${after}p" "$srv_log" | strip_ansi)"

    local got
    if grep -qiE 'outcome=.?accepted' <<<"$delta"; then
        got="admit"
    else
        got="reject"
    fi

    # Diagnostics: the server's auth decisions and the client's user-facing line.
    local authlines; authlines="$(grep -iE 'koh::auth|authn|authz|security[- ]key' <<<"$delta" | sed 's/^/        /')"
    [ -n "$authlines" ] && { info "server auth log:"; printf '%s\n' "$authlines"; }
    local cline; cline="$(grep -iE 'connected|not authorized|security-key|did not admit|rejected|allowlist' <<<"$client_out" | head -2 | sed 's/^/        /')"
    [ -n "$cline" ] && { info "client said:"; printf '%s\n' "$cline"; }

    if [ "$got" = "$expect" ]; then
        pass "expected $expect, got $got"
        PASS_COUNT=$((PASS_COUNT + 1)); RESULTS+=("${GRN}PASS${RST}  $name")
    else
        fail "expected $expect, got $got"
        FAIL_COUNT=$((FAIL_COUNT + 1)); RESULTS+=("${RED}FAIL${RST}  $name (expected $expect, got $got)")
    fi
    echo
}

# ===========================================================================
printf '%s\n' "${BOLD}koh FIDO2 / security-key end-to-end test${RST}"
printf '%s\n\n' "${DIM}real koh + real ssh-agent + OpenSSH sk-dummy software authenticator${RST}"

step "Setup"
info "koh:        $("$KOH" --version 2>/dev/null || echo koh)"
info "ssh:        $(ssh -V 2>&1)"
info "sk-dummy:   $SK_PROVIDER"

# 1. Security keys (software FIDO2). `good` is the one the server will trust; `wrong` is a valid sk
#    key that is simply not on the server's allowlist.
make_sk_key good  koh-good
make_sk_key wrong koh-wrong
info "created sk keys: $(cut -d' ' -f1 keys/good.pub) (good), (wrong)"

# 2. ssh-agent holding both sk keys. `-P` allows our out-of-tree provider (OpenSSH defaults to a
#    system path allowlist and would otherwise refuse it).
eval "$(ssh-agent -P "$SK_PROVIDER" -s)" >/dev/null
ssh-add -S "$SK_PROVIDER" keys/good keys/wrong >/dev/null 2>&1 \
    || { fail "ssh-agent refused the sk keys"; exit 2; }
info "ssh-agent loaded: $(ssh-add -l | wc -l | tr -d ' ') security key(s)"

# 3. koh identities: an allowlisted client, an un-allowlisted client, and two servers.
CLIENT_OK="keys/client_ok.key";   CLIENT_OK_ID="$(koh_id "$CLIENT_OK")"
CLIENT_BAD="keys/client_bad.key"; CLIENT_BAD_ID="$(koh_id "$CLIENT_BAD")"
SERVER_SK="keys/server_sk.key"
SERVER_PLAIN="keys/server_plain.key"
info "allowlisted client id:   $CLIENT_OK_ID"
info "un-allowlisted client id: $CLIENT_BAD_ID"
echo

# 4. Server A — requires a security key (the good one) AND the allowlisted client id.
step "Launching koh server (--require-sk)"
SRV_LOG="logs/server_sk.log"
"$KOH" serve --local --key-file "$SERVER_SK" \
    --allow "$CLIENT_OK_ID" \
    --require-sk --allow-sk keys/good.pub >"$SRV_LOG" 2>&1 &
SERVER_SK_PID=$!
wait_for_ready "$SRV_LOG" || { fail "server did not become ready"; sed 's/^/        /' "$SRV_LOG"; exit 2; }
SERVER_SK_ID="$(koh_id "$SERVER_SK")"
PORT_SK="$(port_from_log "$SRV_LOG")"
grep -E '2nd factor|security key REQUIRED|SHA256:' "$SRV_LOG" | sed 's/^/    /'
info "listening on 127.0.0.1:$PORT_SK"
echo

# 5. Server B — plain endpoint-id auth only (no --require-sk), to prove the default path is unchanged.
step "Launching koh server (default, no security key)"
SRV_PLAIN_LOG="logs/server_plain.log"
"$KOH" serve --local --key-file "$SERVER_PLAIN" --allow "$CLIENT_OK_ID" >"$SRV_PLAIN_LOG" 2>&1 &
SERVER_PLAIN_PID=$!
wait_for_ready "$SRV_PLAIN_LOG" || { fail "plain server did not become ready"; exit 2; }
SERVER_PLAIN_ID="$(koh_id "$SERVER_PLAIN")"
PORT_PLAIN="$(port_from_log "$SRV_PLAIN_LOG")"
info "listening on 127.0.0.1:$PORT_PLAIN"
echo

# ===========================================================================
# Scenarios
# ===========================================================================
# T1 — allowlisted id + the correct security key  → admitted
run_case "correct id + correct security key is admitted" \
    admit "$SERVER_SK_ID" "$PORT_SK" "$CLIENT_OK" "keys/good.pub"

# T2 — allowlisted id + a security key NOT on --allow-sk → rejected
run_case "wrong (un-allowlisted) security key is rejected" \
    reject "$SERVER_SK_ID" "$PORT_SK" "$CLIENT_OK" "keys/wrong.pub"

# T3 — allowlisted id but NO security-key proof → rejected
run_case "no security key against --require-sk is rejected" \
    reject "$SERVER_SK_ID" "$PORT_SK" "$CLIENT_OK" ""

# T4 — correct security key but an un-allowlisted endpoint id → rejected (before the sk gate)
SRV_LOG_SAVE="$SRV_LOG"
run_case "un-allowlisted endpoint id is rejected before the security-key gate" \
    reject "$SERVER_SK_ID" "$PORT_SK" "$CLIENT_BAD" "keys/good.pub"

# T5 — default path: allowlisted id, no security key, server without --require-sk → admitted
SRV_LOG="$SRV_PLAIN_LOG"
run_case "default endpoint-id-only auth still works (no security key)" \
    admit "$SERVER_PLAIN_ID" "$PORT_PLAIN" "$CLIENT_OK" ""
SRV_LOG="$SRV_LOG_SAVE"

# ===========================================================================
# Summary
# ===========================================================================
printf '%s\n' "${BOLD}────────────────────────────────────────────────────────${RST}"
printf '%s\n' "${BOLD}Summary${RST}"
for r in "${RESULTS[@]}"; do printf '  %s\n' "$r"; done
printf '%s\n' "${BOLD}────────────────────────────────────────────────────────${RST}"
if [ "$FAIL_COUNT" -eq 0 ]; then
    printf '%s\n' "${GRN}${BOLD}All $PASS_COUNT tests passed.${RST}"
    exit 0
else
    printf '%s\n' "${RED}${BOLD}$FAIL_COUNT of $((PASS_COUNT + FAIL_COUNT)) tests failed.${RST}"
    exit 1
fi
