#!/usr/bin/env bash
# Inject OS-level latency / jitter / loss / reordering / duplication on a container interface,
# *beneath* iroh — so you test the real QUIC stack's reaction, complementary to the in-process
# Tier-0 simulated transport. Run inside a container that has CAP_NET_ADMIN.
#
# Usage: netem.sh [iface] [delay_ms] [jitter_ms] [loss_pct] [reorder_pct]
#   netem.sh eth0 120 40 8 25     # 120±40ms, 8% loss, 25% reordered
#   netem.sh eth0 0 0 0 0         # clear (removes the qdisc)
set -euo pipefail

IFACE="${1:-eth0}"
DELAY="${2:-80}"
JITTER="${3:-20}"
LOSS="${4:-5}"
REORDER="${5:-25}"

if [ "$DELAY" = "0" ] && [ "$LOSS" = "0" ] && [ "$REORDER" = "0" ]; then
    tc qdisc del dev "$IFACE" root 2>/dev/null || true
    echo "netem cleared on $IFACE"
    exit 0
fi

tc qdisc replace dev "$IFACE" root netem \
    delay "${DELAY}ms" "${JITTER}ms" distribution normal \
    loss "${LOSS}%" \
    reorder "${REORDER}%" 50% \
    duplicate 1%

echo "netem on $IFACE: delay ${DELAY}±${JITTER}ms, loss ${LOSS}%, reorder ${REORDER}%, dup 1%"
tc -s qdisc show dev "$IFACE"
