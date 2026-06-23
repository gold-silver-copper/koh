#!/bin/sh
# Stress: endpoint-bind storm. Repeatedly bind the iroh endpoint (which constructs iroh's
# DnsResolver — the Android panic path) and confirm it NEVER panics or degrades across many binds.
# This is the basic regression turned into a soak: an intermittent ndk-context failure or a
# resource leak in endpoint setup would surface here.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
. "$HERE/stress-lib.sh"

require_device_or_skip
push_binary

ITERS="${KOH_STRESS_BIND_ITERS:-$(scaled 20 100)}"
echo "Stress: bind storm — $ITERS rapid koh-serve endpoint binds (level=$STRESS_LEVEL)"

ok_count=0
i=1
while [ "$i" -le "$ITERS" ]; do
  if start_server "" ; then
    SRV="$(cat_dev "$SRV_LOG")"
    if ! contains "$PANIC_NDK" "$SRV" && ! contains "$PANIC_RUST" "$SRV"; then
      ok_count=$((ok_count + 1))
    else
      bad "iteration $i: crash signature in serve output"
      printf '%s\n' "$SRV" | grep -E 'ndk-context|panic' | sed 's/^/      /' | head -3
      stop_all_koh; break
    fi
  else
    bad "iteration $i: server never printed its ready banner (endpoint did not bind)"
    stop_all_koh; break
  fi
  stop_all_koh
  i=$((i + 1))
done

echo "  bound cleanly: $ok_count/$ITERS"
[ "$ok_count" = "$ITERS" ] && ok "every endpoint bind constructed the DnsResolver with no panic"
finish "stress-bind-storm"
