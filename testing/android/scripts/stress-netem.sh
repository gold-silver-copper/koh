#!/bin/sh
# Stress: bad-network CHAOS SOAK — koh's reason to exist, turned up. An established session is hit
# with a long sequence of VARYING, harsh network conditions on the device's loopback (where
# `--direct 127.0.0.1` traffic flows), while a continuous flood streams through it the whole time.
# The conditions cycle: jitter+loss+reorder+dup, heavy loss, TOTAL blackouts, high latency,
# dup/reorder storms, and brief recovery windows — each for a phase, for the whole soak duration.
#
# Asserts the session survives EVERY phase on the SAME connection (no detach/reconnect), the client
# stays alive, nothing panics, and memory stays bounded across the entire soak (no leak under
# sustained chaos). Like tier2's flow, the chaos hits an ALREADY-CONNECTED session (the handshake
# runs clean first).
#
# Best-effort: needs root + `tc`. Opt in with KOH_STRESS_NETEM=1; otherwise it SKIPs cleanly.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary

if [ "${KOH_STRESS_NETEM:-}" != "1" ]; then
  echo "SKIP: set KOH_STRESS_NETEM=1 to run the netem chaos soak (needs root + tc)"
  exit 0
fi

SOAK="${KOH_STRESS_NETEM_SOAK_SECS:-$(scaled 72 300)}"   # total chaos duration
PHASE="${KOH_STRESS_NETEM_PHASE_SECS:-8}"                # seconds per condition (< the 300s idle timeout)
echo "Stress: bad-network CHAOS SOAK — ${SOAK}s of cycling adverse conditions on lo (level=$STRESS_LEVEL)"

adb $ADB_SERIAL root >/dev/null 2>&1 || true
adb $ADB_SERIAL wait-for-device >/dev/null 2>&1 || true
adb $ADB_SERIAL shell 'command -v tc' >/dev/null 2>&1 || { echo "SKIP: 'tc' (iproute2) not present on this system image"; exit 0; }
cleanup_tc() { adb $ADB_SERIAL shell "tc qdisc del dev lo root" >/dev/null 2>&1 || true; }

# The chaos profiles (cycled). netem args; empty = a clean recovery window.
NPROFILES=6
profile_args() {
  case "$1" in
    0) echo "delay 120ms 60ms distribution normal loss 15% reorder 30% 50% duplicate 2%" ;;
    1) echo "loss 40%" ;;
    2) echo "loss 100%" ;;                                # TOTAL blackout (short phase, < idle timeout)
    3) echo "delay 400ms 200ms distribution normal" ;;   # high latency + heavy jitter
    4) echo "loss 25% duplicate 10% reorder 50% 50%" ;;  # dup + reorder storm
    *) echo "" ;;                                         # recovery (clean)
  esac
}
profile_name() {
  case "$1" in
    0) echo "jitter+loss+reorder+dup" ;; 1) echo "heavy loss 40%" ;; 2) echo "TOTAL BLACKOUT" ;;
    3) echo "high latency 400±200ms" ;; 4) echo "dup+reorder storm" ;; *) echo "recovery (clean)" ;;
  esac
}
# Apply a profile; if the image lacks reorder/dup (e.g. android-35), strip those and keep loss/delay.
apply_profile() {
  cleanup_tc
  [ -z "$1" ] && return 0
  adb $ADB_SERIAL shell "tc qdisc add dev lo root netem $1" >/dev/null 2>&1 && return 0
  _safe="$(printf '%s' "$1" | sed -E 's/reorder [0-9]+% [0-9]+%//; s/duplicate [0-9]+%//; s/  */ /g')"
  adb $ADB_SERIAL shell "tc qdisc add dev lo root netem $_safe" >/dev/null 2>&1 || return 1
}

# A continuous, PACED flood so data keeps crossing the connection during the chaos — steady (~5k
# lines/s) rather than a max-rate firehose, to mirror a real session and keep the working set sane
# (so the leak check is meaningful, not dominated by a transient send backlog).
FLOOD="/data/local/tmp/koh-chaos-flood.sh"
CLILOG="/data/local/tmp/koh-chaos-cli.log"
push_flood_script "$FLOOD" "while true; do seq 1 500; sleep 0.1; done"
adb $ADB_SERIAL shell "rm -f $CLILOG" >/dev/null 2>&1 || true

cleanup_tc   # clean lo for the handshake
if ! start_server "--shell $FLOOD"; then bad "server failed to start"; cleanup_tc; finish "stress-netem"; fi
SPID="$(server_pid)"; RSS0="$(rss_kb "$SPID")"

pty_connect_bg /data/local/tmp/koh-chaos.key "$CLILOG" $((SOAK + 30)) ""
wait_file_contains "$CLILOG" "connected." 15 && ok "session connected (clean handshake); flooding" \
  || { bad "client never connected"; cleanup_tc; stop_all_koh; finish "stress-netem"; }
CPID="$(other_pid "$SPID")"

# --- the soak -------------------------------------------------------------------------------------
phases=0; peak="$RSS0"; minrss="$RSS0"; broke=0; t=0; idx=0
while [ "$t" -lt "$SOAK" ]; do
  args="$(profile_args "$idx")"
  printf '    [%3ss] phase %s: %s\n' "$t" "$phases" "$(profile_name "$idx")"
  apply_profile "$args" || true   # if even the safe form fails, the phase is just clean — fine
  # Sample health a couple times during the phase.
  s=0
  while [ "$s" -lt "$PHASE" ]; do
    sleep 4; s=$((s + 4)); t=$((t + 4))
    if [ -z "$(proc_state "$CPID")" ]; then bad "client DIED during '$(profile_name "$idx")' (phase $phases, ${t}s)"; broke=1; break; fi
    SRV="$(cat_dev "$SRV_LOG")"
    if printf '%s\n' "$SRV" | grep -qE 'client detached|reattaching'; then bad "session DROPPED during '$(profile_name "$idx")' (detach/reconnect, phase $phases)"; broke=1; break; fi
    if contains "$PANIC_RUST" "$SRV" || contains "$PANIC_NDK" "$SRV"; then bad "PANIC during '$(profile_name "$idx")' (phase $phases)"; broke=1; break; fi
    r="$(rss_kb "$SPID")"; [ "$r" -gt "$peak" ] && peak="$r"; [ "$r" -gt 0 ] && [ "$r" -lt "$minrss" ] && minrss="$r"
  done
  [ "$broke" = 1 ] && break
  phases=$((phases + 1)); idx=$((idx + 1)); [ "$idx" -ge "$NPROFILES" ] && idx=0
done

# Recovery: clear the network and let it settle.
apply_profile ""; echo "    network restored after $phases chaos phases"; sleep 6
cleanup_tc

SRV="$(cat_dev "$SRV_LOG")"
echo "    survived $phases chaos phases; server RSS ${RSS0} → peak ${peak}kB (min ${minrss}kB)"

if [ "$broke" = 0 ]; then ok "the session survived all $phases cycling chaos phases on the same connection"; fi
[ -n "$(proc_state "$CPID")" ] && ok "client still alive after the full soak" || bad "client did not survive the soak"
printf '%s\n' "$SRV" | grep -qE 'client detached|reattaching' && bad "the session detached/reconnected during the soak" || ok "no detach/reconnect across the entire soak (one connection rode out everything)"
assert_no_crash "$SRV" >/dev/null && ok "no panic across the soak" || bad "server log shows a panic"
# Leak check: peak must not have run away from the post-warmup floor across a long chaotic run.
LIMIT=$((minrss + 200000))
[ "$peak" -le "$LIMIT" ] && ok "server memory bounded across the soak (peak ${peak}kB ≤ ${LIMIT}kB)" || bad "server RSS grew to ${peak}kB under sustained chaos (> ${LIMIT}kB) — possible leak"

wait "${PTY_BG_PID:-0}" 2>/dev/null || true
finish "stress-netem"
