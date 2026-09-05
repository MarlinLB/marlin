#!/usr/bin/env bash
#
# Marlin — L2 DSR development rig for WSL2.
#
# One mode, one script. tests/integration/netns-topo.sh builds both modes in a
# single topology for the integration suite; this is the smaller thing you want
# while developing the L2 DSR path alone. Namespace names, device names and
# prefixes are disjoint from that script's, so both rigs can be up at once.
#
# Development only. WSL2 runs Microsoft's kernel and veth has no native XDP, so
# the attach must be xdpgeneric. netns-topo.sh deliberately refuses that fallback
# (docs/design/02-architecture.md); this script does not, and the difference is
# real: generic XDP runs on an skb after GRO, so the program sees a frame the
# driver hook would not. Use this rig to iterate, not to accept.
#
# Topology
# --------
#
#   ns ml2cli                  root ns                    ns ml2be
#   ┌────────────────┐   ┌──────────────────────┐   ┌────────────────────┐
#   │ ml2cli0        │   │ ml2lan0  ← XDP here  │   │ ml2be0             │
#   │ 198.19.1.2/24  │   │ 198.19.1.10/24       │   │ 198.19.1.21/24     │
#   └───────┬────────┘   └──────────┬───────────┘   │ lo  198.18.1.1/32  │
#           │                       │               └─────────┬──────────┘
#      ml2cli0-br              ml2lan0-br                 ml2be0-br
#           └───────────────────────┴─────────────────────────┘
#                          bridge ml2br (root ns)
#
# A bridge rather than a veth pair, because L2 DSR rewrites the destination MAC
# and XDP_TX's out the *ingress* interface (docs/design/14-forwarding-modes.md
# §7.1), so the backend must sit on the ingress broadcast domain — and that
# domain needs three members: client, Marlin, backend.
#
#   VIP        198.18.1.1     RFC 2544 benchmark range. ipip_wsl.sh uses
#                             198.18.2.1 and netns-topo.sh uses 198.18.0.1, so
#                             the three rigs never share a VIP.
#   Segment    198.19.1.0/24  same range, deliberately not one of the
#                             documentation prefixes netns-topo.sh occupies.
#
# MACs are pinned (02:00:00:00:01:xx, locally administered) so tests can assert
# emitted frames byte-for-byte and so backend.mac can be configured by hand.
#
# Usage:  sudo ./l2dsr_wsl.sh up | status | down
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------

VIP=198.18.1.1
SEG=198.19.1

MARLIN_IF=ml2lan0            # the interface the XDP program attaches to (root ns)
MARLIN_BR=ml2lan0-br         # its peer, a bridge port
MARLIN_IP=${SEG}.10
MARLIN_MAC=02:00:00:00:01:10

CLI_IF=ml2cli0;  CLI_BR=ml2cli0-br;  CLI_IP=${SEG}.2;   CLI_MAC=02:00:00:00:01:02
BE_IF=ml2be0;    BE_BR=ml2be0-br;    BE_IP=${SEG}.21;   BE_MAC=02:00:00:00:01:21

BR=ml2br
NS_CLI=ml2cli
NS_BE=ml2be
NS_ALL=("${NS_CLI}" "${NS_BE}")

# Root-namespace devices this script owns. down() deletes exactly these.
ROOT_DEVS=("${MARLIN_IF}" "${MARLIN_BR}" "${CLI_BR}" "${BE_BR}" "${BR}")

# No MTU parameter. L2 DSR prepends nothing — "No packet growth"
# (docs/design/14-forwarding-modes.md §7.1) — so the default 1500 is the honest
# underlay here, and config.max_frame is not required for a pool with no
# encapsulating backend (docs/design/20-configuration-validation.md).

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

need_root() {
	[[ ${EUID} -eq 0 ]] || { echo "must run as root (sudo)" >&2; exit 1; }
}

nsx() { # run a command in a namespace, or in the root ns when given "-"
	local ns=$1; shift
	if [[ ${ns} == "-" ]]; then "$@"; else ip netns exec "${ns}" "$@"; fi
}

sc() { # sysctl inside a namespace, quietly
	local ns=$1; shift
	nsx "${ns}" sysctl -qw "$@"
}

# XDP cannot see GSO super-frames or CHECKSUM_PARTIAL skbs; veth offers both by
# default. Under xdpgeneric this matters more, not less: the hook sits after GRO,
# so a coalesced skb reaches the program as one oversized "frame".
#
# One feature per invocation on purpose: several of these are fixed on veth, and a
# single ethtool call carrying an unsupported key applies *none* of the others.
noffl() {
	local ns=$1 dev=$2 k
	for k in tso gso gro tx rx rxvlan txvlan; do
		nsx "${ns}" ethtool -K "${dev}" "${k}" off >/dev/null 2>&1 || true
	done
}

# The VIP goes on lo, per docs/design/14-forwarding-modes.md §7.1: the packet
# still carries the VIP as destination, so the backend must hold it on a loopback
# or dummy interface with ARP/NDP suppression. lo is per-namespace, so nothing
# leaks into the WSL2 host.
#
# The suppression is load-bearing here, not decoration. Client and backend share
# one broadcast domain; without arp_ignore the backend answers ARP for the VIP,
# the client addresses frames straight to it, and the rig forwards traffic
# successfully while never once entering the XDP program.
backend_vip() {
	local ns=$1 dev=$2
	nsx "${ns}" ip addr add "${VIP}/32" dev lo
	sc "${ns}" net.ipv4.conf.all.arp_ignore=1
	sc "${ns}" net.ipv4.conf.all.arp_announce=2
	sc "${ns}" "net.ipv4.conf.${dev}.arp_ignore=1"
	sc "${ns}" "net.ipv4.conf.${dev}.arp_announce=2"
}

# ---------------------------------------------------------------------------
# up
# ---------------------------------------------------------------------------

up() {
	need_root
	down_quiet

	modprobe -q veth   2>/dev/null || true
	modprobe -q bridge 2>/dev/null || true

	for ns in "${NS_ALL[@]}"; do ip netns add "${ns}"; done

	# --- the broadcast domain ----------------------------------------------
	ip link add "${BR}" type bridge forward_delay 0 stp_state 0
	ip link set "${BR}" up

	# --- Marlin: root ns ---------------------------------------------------
	# Kept in the root namespace so bpftool, the pins under /sys/fs/bpf and the
	# C# control plane all see one bpffs (docs/design/02-architecture.md).
	ip link add "${MARLIN_IF}" address "${MARLIN_MAC}" type veth peer name "${MARLIN_BR}"
	ip link set "${MARLIN_BR}" master "${BR}" up
	ip addr add "${MARLIN_IP}/24" dev "${MARLIN_IF}"
	ip link set "${MARLIN_IF}" up

	# --- client ------------------------------------------------------------
	ip link add "${CLI_IF}" address "${CLI_MAC}" type veth peer name "${CLI_BR}"
	ip link set "${CLI_BR}" master "${BR}" up
	ip link set "${CLI_IF}" netns "${NS_CLI}"
	nsx "${NS_CLI}" ip link set lo up
	nsx "${NS_CLI}" ip addr add "${CLI_IP}/24" dev "${CLI_IF}"
	nsx "${NS_CLI}" ip link set "${CLI_IF}" up
	# The VIP is off-segment on purpose. On-link, the client would ARP for it,
	# and backend_vip() suppresses exactly that ARP — the packet would never be
	# built. A host route addresses the frame to Marlin's MAC instead, which is
	# what puts it in front of the XDP program.
	nsx "${NS_CLI}" ip route add "${VIP}/32" via "${MARLIN_IP}" dev "${CLI_IF}"
	# Static, because resolving ${MARLIN_IP} means sending an ARP request *into*
	# the XDP program. Whether the datapath passes a non-IP ethertype is a
	# property of the code under test, so a rig whose first packet depends on it
	# fails at ARP and looks like a forwarding bug. Pinning the entry takes the
	# question out of the path.
	nsx "${NS_CLI}" ip neigh replace "${MARLIN_IP}" lladdr "${MARLIN_MAC}" \
		dev "${CLI_IF}" nud permanent

	# --- backend -----------------------------------------------------------
	ip link add "${BE_IF}" address "${BE_MAC}" type veth peer name "${BE_BR}"
	ip link set "${BE_BR}" master "${BR}" up
	ip link set "${BE_IF}" netns "${NS_BE}"
	nsx "${NS_BE}" ip link set lo up
	nsx "${NS_BE}" ip addr add "${BE_IP}/24" dev "${BE_IF}"
	nsx "${NS_BE}" ip link set "${BE_IF}" up
	backend_vip "${NS_BE}" "${BE_IF}"
	# Not strictly needed on this topology — the reply's return path is the
	# segment the request arrived on, so strict RPF passes — but DSR replies are
	# sourced from an address that lives on no segment, and leaving the check on
	# makes any later change to the rig fail in a way that looks like a datapath
	# bug. Same reason netns-topo.sh clears it.
	sc "${NS_BE}" net.ipv4.conf.all.rp_filter=0
	sc "${NS_BE}" "net.ipv4.conf.${BE_IF}.rp_filter=0"

	# --- offloads ----------------------------------------------------------
	noffl -          "${MARLIN_IF}"
	noffl -          "${MARLIN_BR}"
	noffl -          "${CLI_BR}"
	noffl -          "${BE_BR}"
	noffl "${NS_CLI}" "${CLI_IF}"
	noffl "${NS_BE}"  "${BE_IF}"

	echo "l2dsr rig up."
	echo
	summary
}

# ---------------------------------------------------------------------------
# status / down
# ---------------------------------------------------------------------------

summary() {
	cat <<EOF
Values this rig implies for the maps:

  VIP                          ${VIP}
  vip mode                     L2 DSR (docs/design/14-forwarding-modes.md §7.1)
  backend.addr                 ${BE_IP}
  backend.mac                  ${BE_MAC}
  backend flags                MARLIN_BE_F_FIB clear — the stored MAC is the
                               fast path. Zero backend.mac instead to exercise
                               the bpf_fib_lookup() fallback and watch
                               mac_fallback (docs/design/15-nexthop-l2dsr.md).
  config.tunnel_src            unused — nothing is encapsulated
  config.max_frame             not required with no encapsulating backend
                               (docs/design/20-configuration-validation.md)

Attach — xdpgeneric, because WSL2 veth has no native XDP:

  mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
  mkdir -p /sys/fs/bpf/marlin
  bpftool prog loadall data-plane/marlin.bpf.o /sys/fs/bpf/marlin pinmaps /sys/fs/bpf/marlin
  bpftool net attach xdpgeneric pinned /sys/fs/bpf/marlin/xdp_marlin dev ${MARLIN_IF}

Drive it:

  ip netns exec ${NS_CLI} ping -c1 ${VIP}
  ip netns exec ${NS_CLI} curl -sS --max-time 2 http://${VIP}/

Watch it:

  ip netns exec ${NS_BE} tcpdump -nei ${BE_IF}   # VIP intact, dst MAC now ${BE_MAC}
  ip link show ${MARLIN_IF}                      # expect "xdpgeneric"
  bpftool map dump name drop_stats

Detach, without tearing the rig down:

  bpftool net detach xdpgeneric dev ${MARLIN_IF}
EOF
}

status() {
	for ns in "${NS_ALL[@]}"; do
		ip netns list | grep -qw "${ns}" || { echo "l2dsr rig is down"; return 1; }
	done
	echo "== root ns =="
	ip -br addr show "${MARLIN_IF}" 2>/dev/null || true
	ip -d link show "${MARLIN_IF}" | sed -n '2,3p'
	bridge link show 2>/dev/null | grep -w "${BR}" || true
	for ns in "${NS_ALL[@]}"; do
		echo "== ns ${ns} =="
		ip netns exec "${ns}" ip -br addr
	done
}

# Idempotent: safe to run when nothing exists. up() calls it first.
down_quiet() {
	ip link set dev "${MARLIN_IF}" xdpgeneric off 2>/dev/null || true
	ip link set dev "${MARLIN_IF}" xdp off 2>/dev/null || true
	for ns in "${NS_ALL[@]}"; do ip netns del "${ns}" 2>/dev/null || true; done
	for d in "${ROOT_DEVS[@]}"; do ip link del "${d}" 2>/dev/null || true; done
}

down() {
	need_root
	down_quiet
	echo "l2dsr rig down."
}

# ---------------------------------------------------------------------------

case "${1:-}" in
	up)     up ;;
	status) status ;;
	down)   down ;;
	*)      echo "usage: $0 {up|status|down}" >&2; exit 2 ;;
esac
