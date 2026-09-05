#!/usr/bin/env bash
#
# Marlin — IPIP development rig for WSL2.
#
# One mode, one script. tests/integration/netns-topo.sh builds both modes in a
# single topology for the integration suite; this is the smaller thing you want
# while developing the IPIP path alone. Namespace names, device names and
# prefixes are disjoint from that script's and from l2dsr_wsl.sh's, so all three
# rigs can be up at once.
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
#   ns mipcli            ns miprt (router)              root ns
#   ┌────────────────┐   ┌──────────────────────┐
#   │ mipcli0        ├───┤ miprt-c              │
#   │ 198.19.4.2/24  │   │ 198.19.4.1/24        │
#   └────────────────┘   │                      │       miplan0  ← XDP here
#                        │ miprt-a ─────────────┼────── 198.19.2.10/24
#                        │ 198.19.2.1/24        │       (= config.tunnel_src)
#                        │                      │
#                        │                      │      ns mipbe
#                        │ miprt-b ─────────────┼────── mipbe0 198.19.3.22/24
#                        │ 198.19.3.1/24        │       ipip0 local .22 remote .2.10
#                        └──────────────────────┘       lo    198.18.2.1/32
#
# Point-to-point veths, no bridge, and a real router namespace — because IPIP
# does not address the backend at layer 2. It MAC-swaps and XDP_TX's the
# encapsulated packet back at the *upstream router*, which then routes the outer
# header onward (docs/design/15-nexthop-l2dsr.md, "MAC swap — default for IPIP and
# GUE"). The backend therefore has to be somewhere the router reaches and Marlin
# does not, which is what the second segment is for. A rig with the backend on
# Marlin's own segment would forward, and would prove nothing.
#
# The router hairpins nothing here: the outer packet arrives on miprt-a and
# leaves on miprt-b. send_redirects is cleared anyway, because the production
# requirement in docs/design/15-nexthop-l2dsr.md is unconditional and a rig that
# only satisfies it by accident of topology is not evidence.
#
#   VIP        198.18.2.1     RFC 2544 benchmark range. l2dsr_wsl.sh uses
#                             198.18.1.1 and netns-topo.sh uses 198.18.0.1, so
#                             the three rigs never share a VIP.
#   Segments   198.19.2.0/24  Marlin  <-> router   (the tunnel source side)
#              198.19.3.0/24  router  <-> backend  (the tunnel destination side)
#              198.19.4.0/24  client  <-> router
#
# MACs are pinned (02:00:00:00:02:xx, locally administered) so tests can assert
# emitted frames byte-for-byte.
#
# Usage:  sudo ./ipip_wsl.sh up | status | down
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------

VIP=198.18.2.1

SEG_M=198.19.2               # Marlin <-> router
SEG_B=198.19.3               # router <-> backend
SEG_C=198.19.4               # client <-> router

MARLIN_IF=miplan0            # the interface the XDP program attaches to (root ns)
MARLIN_IP=${SEG_M}.10        # this is config.tunnel_src
MARLIN_MAC=02:00:00:00:02:10

RT_A=miprt-a;  RT_A_IP=${SEG_M}.1;  RT_A_MAC=02:00:00:00:02:01
RT_B=miprt-b;  RT_B_IP=${SEG_B}.1;  RT_B_MAC=02:00:00:00:02:02
RT_C=miprt-c;  RT_C_IP=${SEG_C}.1;  RT_C_MAC=02:00:00:00:02:03

BE_IF=mipbe0;  BE_IP=${SEG_B}.22;   BE_MAC=02:00:00:00:02:22   # <- backend.addr
CLI_IF=mipcli0; CLI_IP=${SEG_C}.2;  CLI_MAC=02:00:00:00:02:04

NS_RT=miprt
NS_BE=mipbe
NS_CLI=mipcli
NS_ALL=("${NS_RT}" "${NS_BE}" "${NS_CLI}")

# Root-namespace devices this script owns. down() deletes exactly these. The
# last two normally die with their namespaces; they are listed so that a run of
# up() that failed between creating a veth and moving it still cleans up.
ROOT_DEVS=("${MARLIN_IF}" "${BE_IF}" "${CLI_IF}")

# The underlay carries the 20-byte outer header. docs/design/23-mtu.md's strategy
# is jumbo frames on the Marlin->backend path; the client link stays at 1500 and
# is deliberately left alone.
#
# config.max_frame is the *frame*, not the MTU: "egress MTU + ETH_HLEN"
# (docs/design/08-types.md, DEPLOYMENT.md §1.7). So 1600 here means 1614 there.
# To exercise frame_too_big instead, drop MTU_UNDERLAY to 1500, set max_frame to
# 1514, and send a full-size packet.
MTU_UNDERLAY=1600
MAX_FRAME=$((MTU_UNDERLAY + 14))

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

mtu() {
	local ns=$1; shift
	local d
	for d in "$@"; do nsx "${ns}" ip link set "${d}" mtu "${MTU_UNDERLAY}" || true; done
}

# The VIP goes on lo, per docs/design/14-forwarding-modes.md §7.2: the *inner*
# packet retains the VIP, so the backend must still hold it locally after
# decapsulation. lo is per-namespace, so nothing leaks into the WSL2 host.
#
# ARP/NDP suppression is not load-bearing on this topology — the backend shares no
# segment with anything that would ask for the VIP — but it is the documented
# backend requirement (§7.1, and §7.2 inherits it), and a rig that omits it
# teaches the wrong backend recipe.
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

	modprobe -q veth 2>/dev/null || true
	modprobe -q ipip 2>/dev/null || true
	modprobe -q sit  2>/dev/null || true

	for ns in "${NS_ALL[@]}"; do ip netns add "${ns}"; done

	# --- Marlin: root ns, facing the router --------------------------------
	# Kept in the root namespace so bpftool, the pins under /sys/fs/bpf and the
	# C# control plane all see one bpffs (docs/design/02-architecture.md).
	ip link add "${MARLIN_IF}" address "${MARLIN_MAC}" type veth peer name "${RT_A}"
	ip link set "${RT_A}" address "${RT_A_MAC}"
	ip link set "${RT_A}" netns "${NS_RT}"
	ip addr add "${MARLIN_IP}/24" dev "${MARLIN_IF}"
	ip link set "${MARLIN_IF}" up

	# --- router: three legs -------------------------------------------------
	ip link add "${BE_IF}"  address "${BE_MAC}"  type veth peer name "${RT_B}"
	ip link add "${CLI_IF}" address "${CLI_MAC}" type veth peer name "${RT_C}"
	ip link set "${RT_B}" address "${RT_B_MAC}"
	ip link set "${RT_C}" address "${RT_C_MAC}"
	ip link set "${RT_B}"  netns "${NS_RT}"
	ip link set "${RT_C}"  netns "${NS_RT}"
	ip link set "${BE_IF}" netns "${NS_BE}"
	ip link set "${CLI_IF}" netns "${NS_CLI}"

	nsx "${NS_RT}" ip link set lo up
	nsx "${NS_RT}" ip addr add "${RT_A_IP}/24" dev "${RT_A}"
	nsx "${NS_RT}" ip addr add "${RT_B_IP}/24" dev "${RT_B}"
	nsx "${NS_RT}" ip addr add "${RT_C_IP}/24" dev "${RT_C}"
	nsx "${NS_RT}" ip link set "${RT_A}" up
	nsx "${NS_RT}" ip link set "${RT_B}" up
	nsx "${NS_RT}" ip link set "${RT_C}" up

	sc "${NS_RT}" net.ipv4.ip_forward=1
	# The VIP is routed to Marlin over miprt-a, but DSR replies arrive from the
	# backend carrying the VIP as *source*, on miprt-b. Strict reverse-path
	# filtering drops exactly that. This is a property of DSR, not of the rig.
	sc "${NS_RT}" net.ipv4.conf.all.rp_filter=0
	sc "${NS_RT}" net.ipv4.conf.default.rp_filter=0
	sc "${NS_RT}" "net.ipv4.conf.${RT_A}.rp_filter=0"
	sc "${NS_RT}" "net.ipv4.conf.${RT_B}.rp_filter=0"
	# docs/design/15-nexthop-l2dsr.md: redirect generation suppressed on the
	# segment Marlin MAC-swaps back onto.
	sc "${NS_RT}" net.ipv4.conf.all.send_redirects=0
	sc "${NS_RT}" "net.ipv4.conf.${RT_A}.send_redirects=0"

	# Everything for the VIP goes to Marlin.
	nsx "${NS_RT}" ip route add "${VIP}/32" via "${MARLIN_IP}" dev "${RT_A}"
	# Static, because resolving ${MARLIN_IP} means sending an ARP request *into*
	# the XDP program. Whether the datapath passes a non-IP ethertype is a
	# property of the code under test, so a rig whose first packet depends on it
	# fails at ARP and looks like a forwarding bug. Pinning the entry takes the
	# question out of the path.
	nsx "${NS_RT}" ip neigh replace "${MARLIN_IP}" lladdr "${MARLIN_MAC}" \
		dev "${RT_A}" nud permanent

	# --- client -------------------------------------------------------------
	nsx "${NS_CLI}" ip link set lo up
	nsx "${NS_CLI}" ip addr add "${CLI_IP}/24" dev "${CLI_IF}"
	nsx "${NS_CLI}" ip link set "${CLI_IF}" up
	nsx "${NS_CLI}" ip route add default via "${RT_C_IP}" dev "${CLI_IF}"

	# --- backend -------------------------------------------------------------
	nsx "${NS_BE}" ip link set lo up
	nsx "${NS_BE}" ip addr add "${BE_IP}/24" dev "${BE_IF}"
	nsx "${NS_BE}" ip link set "${BE_IF}" up
	nsx "${NS_BE}" ip route add default via "${RT_B_IP}" dev "${BE_IF}"
	backend_vip "${NS_BE}" "${BE_IF}"

	# Protocol 4 — IPv4 inner. docs/design/14-forwarding-modes.md §7.2.
	nsx "${NS_BE}" ip link add ipip0 type ipip \
		local "${BE_IP}" remote "${MARLIN_IP}" ttl 64
	nsx "${NS_BE}" ip link set ipip0 up
	# Protocol 41 — IPv6 inner over the IPv4 outer. §7.2: "A backend serving both
	# inner families needs both devices." Phase 2b, harmless before then.
	nsx "${NS_BE}" ip link add sit-m type sit \
		local "${BE_IP}" remote "${MARLIN_IP}" ttl 64 2>/dev/null || \
		echo "note: sit device not created (CONFIG_IPV6_SIT off) — IPv6 inner untestable"
	nsx "${NS_BE}" ip link set sit-m up 2>/dev/null || true

	# The decapsulated packet is addressed to the VIP but sourced from the client,
	# whose route back is the default gateway on ${BE_IF}, not ipip0. Same
	# rp_filter problem as the router, same reason.
	sc "${NS_BE}" net.ipv4.conf.all.rp_filter=0
	sc "${NS_BE}" "net.ipv4.conf.${BE_IF}.rp_filter=0"
	sc "${NS_BE}" net.ipv4.conf.ipip0.rp_filter=0

	# --- offloads ------------------------------------------------------------
	noffl -           "${MARLIN_IF}"
	noffl "${NS_RT}"  "${RT_A}"
	noffl "${NS_RT}"  "${RT_B}"
	noffl "${NS_RT}"  "${RT_C}"
	noffl "${NS_BE}"  "${BE_IF}"
	noffl "${NS_CLI}" "${CLI_IF}"

	# --- underlay MTU --------------------------------------------------------
	# Both encapsulated segments. The client link keeps 1500.
	mtu -          "${MARLIN_IF}"
	mtu "${NS_RT}" "${RT_A}" "${RT_B}"
	mtu "${NS_BE}" "${BE_IF}"

	echo "ipip rig up."
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
  vip mode                     IPIP (docs/design/14-forwarding-modes.md §7.2)
  config.tunnel_src            ${MARLIN_IP}
  config.max_frame             ${MAX_FRAME}   (MTU ${MTU_UNDERLAY} + ETH_HLEN)
  backend.addr                 ${BE_IP}
  backend.mac                  unused — MAC swap, not a stored MAC
                               (docs/design/15-nexthop-l2dsr.md)

Attach — xdpgeneric, because WSL2 veth has no native XDP:

  mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
  mkdir -p /sys/fs/bpf/marlin
  bpftool prog loadall data-plane/marlin.bpf.o /sys/fs/bpf/marlin pinmaps /sys/fs/bpf/marlin
  bpftool net attach xdpgeneric pinned /sys/fs/bpf/marlin/xdp_marlin dev ${MARLIN_IF}

Drive it:

  ip netns exec ${NS_CLI} ping -c1 ${VIP}
  ip netns exec ${NS_CLI} curl -sS --max-time 2 http://${VIP}/

Watch it, in path order:

  ip netns exec ${NS_RT} tcpdump -nei ${RT_A}            # in from client, back out encapsulated
  ip netns exec ${NS_BE} tcpdump -nei ${BE_IF} 'proto 4' # outer ${MARLIN_IP} -> ${BE_IP}
  ip netns exec ${NS_BE} tcpdump -nei ipip0              # after decapsulation, VIP intact
  ip link show ${MARLIN_IF}                              # expect "xdpgeneric"
  bpftool map dump name drop_stats

Detach, without tearing the rig down:

  bpftool net detach xdpgeneric dev ${MARLIN_IF}
EOF
}

status() {
	for ns in "${NS_ALL[@]}"; do
		ip netns list | grep -qw "${ns}" || { echo "ipip rig is down"; return 1; }
	done
	echo "== root ns =="
	ip -br addr show "${MARLIN_IF}" 2>/dev/null || true
	ip -d link show "${MARLIN_IF}" | sed -n '2,3p'
	for ns in "${NS_ALL[@]}"; do
		echo "== ns ${ns} =="
		ip netns exec "${ns}" ip -br addr
	done
	echo "== ns ${NS_BE} routes =="
	ip netns exec "${NS_BE}" ip route
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
	echo "ipip rig down."
}

# ---------------------------------------------------------------------------

case "${1:-}" in
	up)     up ;;
	status) status ;;
	down)   down ;;
	*)      echo "usage: $0 {up|status|down}" >&2; exit 2 ;;
esac
