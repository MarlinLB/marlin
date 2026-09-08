#!/usr/bin/env bash
#
# Marlin — integration test topology for L2 DSR and IPIP, in WSL2.
#
# Builds what docs/design/24-testing.md ("Integration tests") calls for: network
# namespaces and veth pairs with real tunnel devices on simulated backends.
# Placement per docs/REPO-STRUCTURE.md §2 (tests/integration/).
#
# Two modes need two different return paths, so they need two different segments:
#
#   - L2 DSR  rewrites the destination MAC and XDP_TX's out the *ingress*
#             interface (docs/design/14-forwarding-modes.md §7.1), so the backend
#             must sit on the ingress broadcast domain. Segment A is a bridge, not
#             a bare veth pair, because that domain needs three members: the
#             upstream router, Marlin, and the backend.
#
#   - IPIP    MAC-swaps and XDP_TX's back to the upstream *router*, which then
#             routes the outer packet onward (docs/design/15-nexthop-l2dsr.md,
#             "MAC swap — default for IPIP and GUE"). So the topology needs a real
#             router namespace and a backend the router reaches over a second
#             segment.
#
# Topology
# --------
#
#   ns mcli                ns mrt (router)                root ns
#   ┌───────────┐          ┌──────────────────┐
#   │ cli0      ├──────────┤ rt-cli           │
#   │ 203.0.113.2/24       │ 203.0.113.1/24   │
#   └───────────┘          │                  │        ┌─── mlan0  192.0.2.10/24  ← XDP attaches here
#                          │ rt-a ────────────┼─ mbr-a ┤        (config.tunnel_src)
#                          │ 192.0.2.1/24     │        │
#                          │                  │        └─── ns mbe1  192.0.2.21/24   ← L2 DSR backend
#                          │                  │                 vip0 198.18.0.1/32
#                          │ rt-b ────────────┼─ mbr-b ──── ns mbe2  198.51.100.22/24 ← IPIP backend
#                          │ 198.51.100.1/24  │                 ipip0 local .22 remote 192.0.2.10
#                          └──────────────────┘                 vip0 198.18.0.1/32
#
#   VIP 198.18.0.1        — RFC 2544 benchmark range, deliberately not a documentation
#                           prefix, so it cannot collide with a segment below.
#   Segment A 192.0.2.0/24      (TEST-NET-1)  router + Marlin + L2 DSR backend
#   Segment B 198.51.100.0/24   (TEST-NET-2)  router + IPIP backend
#   Client    203.0.113.0/24    (TEST-NET-3)  point-to-point, no bridge
#
# MACs are pinned (02:00:00:00:00:xx, locally administered) so tests can assert
# emitted frames byte-for-byte and so backend.mac can be configured by hand.
#
# Usage:  sudo ./netns-topo.sh check | up | status | down
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------

VIP=198.18.0.1

SEG_A=192.0.2         # router + marlin + L2 DSR backend
SEG_B=198.51.100      # router + IPIP backend
SEG_C=203.0.113       # client <-> router

MARLIN_IF=mlan0       # the interface the XDP program attaches to (root ns)
MARLIN_IP=${SEG_A}.10 # this is config.tunnel_src for IPIP
MARLIN_MAC=02:00:00:00:00:10

RT_A_IP=${SEG_A}.1;      RT_A_MAC=02:00:00:00:00:01
RT_B_IP=${SEG_B}.1;      RT_B_MAC=02:00:00:00:00:02
RT_C_IP=${SEG_C}.1;      RT_C_MAC=02:00:00:00:00:03
CLI_IP=${SEG_C}.2;       CLI_MAC=02:00:00:00:00:04
BE1_IP=${SEG_A}.21;      BE1_MAC=02:00:00:00:00:21   # <- backend.mac for the L2 DSR backend
BE2_IP=${SEG_B}.22;      BE2_MAC=02:00:00:00:00:22   # <- backend.addr for the IPIP backend

BR_A=mbr-a
BR_B=mbr-b
NS_ALL=(mrt mcli mbe1 mbe2)

# The underlay carries the encapsulation overhead. docs/design/23-mtu.md's strategy
# is jumbo frames on the Marlin->backend path; client-facing ingress stays 1500, so
# the client segment is deliberately left alone. Set config.max_frame to this value.
# To exercise frame_too_big instead, lower it to 1500 and send a full-size packet.
MTU_UNDERLAY=1600

BPFFS=/sys/fs/bpf
PINDIR=${BPFFS}/marlin

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

# XDP cannot see GSO/CHECKSUM_PARTIAL skbs, which veth offers by default and
# drops rather than delivers. VLAN offload is off too: XDP must see the VLAN
# tag in the header, not out of band in the descriptor (xdp-tutorial testenv).
#
# One feature per invocation on purpose: several of these are fixed on veth, and a
# single ethtool call carrying an unsupported key applies *none* of the others.
noffl() {
	local ns=$1 dev=$2 k
	for k in tso gso gro tx rx rxvlan txvlan; do
		nsx "${ns}" ethtool -K "${dev}" "${k}" off >/dev/null 2>&1 || true
	done
}

mtu() { # underlay MTU; a bridge takes the minimum of its ports, so set every port
	local ns=$1; shift
	local d
	for d in "$@"; do nsx "${ns}" ip link set "${d}" mtu "${MTU_UNDERLAY}" || true; done
}

bpffs_mounted() { grep -q " ${BPFFS} bpf " /proc/mounts; }

# ---------------------------------------------------------------------------
# check — WSL2 preflight
# ---------------------------------------------------------------------------

check() {
	need_root
	local fail=0

	echo "kernel:  $(uname -r)"
	local kmaj kmin
	kmaj=$(uname -r | cut -d. -f1); kmin=$(uname -r | cut -d. -f2)
	if (( kmaj < 6 )); then
		echo "  FAIL  docs/design/01-scope.md requires kernel >= 6.0 (have ${kmaj}.${kmin})"
		fail=1
	else
		echo "  ok    >= 6.0"
	fi

	echo "tools:"
	for t in ip bpftool ethtool; do
		if command -v "${t}" >/dev/null; then
			echo "  ok    ${t}"
		else
			echo "  FAIL  ${t} not found"; fail=1
		fi
	done

	echo "kernel features:"
	if [[ -r /proc/config.gz ]]; then
		for c in CONFIG_BPF_SYSCALL CONFIG_BPF_JIT CONFIG_VETH CONFIG_BRIDGE \
		         CONFIG_DUMMY CONFIG_NET_IPIP CONFIG_IPV6_SIT CONFIG_NET_NS; do
			if zgrep -qE "^${c}=(y|m)$" /proc/config.gz; then
				echo "  ok    ${c}"
			else
				echo "  FAIL  ${c} not enabled"; fail=1
			fi
		done
	else
		echo "  ----  /proc/config.gz absent (CONFIG_IKCONFIG_PROC off); probing instead"
		for m in veth bridge dummy ipip sit; do
			if modprobe -q "${m}" 2>/dev/null || grep -qw "${m}" /proc/modules 2>/dev/null; then
				echo "  ok    ${m}"
			else
				echo "  WARN  ${m} not loadable — may be built in, will fail at 'up' if not"
			fi
		done
	fi

	echo "bpf filesystem:"
	if bpffs_mounted; then
		echo "  ok    ${BPFFS} mounted"
	elif mount -t bpf bpf "${BPFFS}" 2>/dev/null; then
		echo "  ok    ${BPFFS} mounted now"
	else
		echo "  FAIL  cannot mount bpffs at ${BPFFS}"; fail=1
	fi

	# Marlin does not use CO-RE (docs/REPO-STRUCTURE.md §3, "No vmlinux.h, no CO-RE
	# directory"), so a missing /sys/kernel/btf/vmlinux is not fatal — the object's
	# own BTF comes from clang -g. It is still worth knowing it is absent.
	if [[ -r /sys/kernel/btf/vmlinux ]]; then
		echo "  ok    /sys/kernel/btf/vmlinux present"
	else
		echo "  note  /sys/kernel/btf/vmlinux absent (CONFIG_DEBUG_INFO_BTF off)."
		echo "        Not required by Marlin; bpftool type-aware output is degraded."
	fi

	echo
	echo "native XDP on veth is not statically checkable — 'up' attempts a real"
	echo "xdpdrv attach, which must fail rather than degrade to SKB mode"
	echo "(docs/design/02-architecture.md)."

	return "${fail}"
}

# ---------------------------------------------------------------------------
# up
# ---------------------------------------------------------------------------

up() {
	need_root
	down_quiet

	modprobe -q veth   2>/dev/null || true
	modprobe -q bridge 2>/dev/null || true
	modprobe -q dummy  2>/dev/null || true
	modprobe -q ipip   2>/dev/null || true
	modprobe -q sit    2>/dev/null || true

	for ns in "${NS_ALL[@]}"; do ip netns add "${ns}"; done

	# --- root-ns bridges: the two broadcast domains ------------------------
	for br in "${BR_A}" "${BR_B}"; do
		ip link add "${br}" type bridge forward_delay 0 stp_state 0
		ip link set "${br}" up
	done

	# --- Marlin: root ns, on segment A ------------------------------------
	# Kept in the root namespace so bpftool, the pinned maps under /sys/fs/bpf
	# and the C# control plane all see one bpffs (docs/design/02-architecture.md).
	ip link add "${MARLIN_IF}" address "${MARLIN_MAC}" type veth peer name mlan0-br
	ip link set mlan0-br master "${BR_A}" up
	ip addr add "${MARLIN_IP}/24" dev "${MARLIN_IF}"
	ip link set "${MARLIN_IF}" up

	# --- router: three legs ------------------------------------------------
	ip link add rt-a address "${RT_A_MAC}" type veth peer name rt-a-br
	ip link add rt-b address "${RT_B_MAC}" type veth peer name rt-b-br
	ip link add rt-cli address "${RT_C_MAC}" type veth peer name cli0
	ip link set rt-a-br master "${BR_A}" up
	ip link set rt-b-br master "${BR_B}" up
	ip link set rt-a   netns mrt
	ip link set rt-b   netns mrt
	ip link set rt-cli netns mrt
	ip link set cli0   netns mcli

	ip netns exec mrt ip addr add "${RT_A_IP}/24" dev rt-a
	ip netns exec mrt ip addr add "${RT_B_IP}/24" dev rt-b
	ip netns exec mrt ip addr add "${RT_C_IP}/24" dev rt-cli
	ip netns exec mrt ip link set lo up
	ip netns exec mrt ip link set rt-a up
	ip netns exec mrt ip link set rt-b up
	ip netns exec mrt ip link set rt-cli up

	sc mrt net.ipv4.ip_forward=1
	# The VIP routes to Marlin over rt-a, but DSR replies carry the VIP as
	# *source* -- on rt-b for the IPIP backend, not the interface the VIP route
	# points at. Strict RPF drops that; it's a property of DSR, not the rig.
	sc mrt net.ipv4.conf.all.rp_filter=0
	sc mrt net.ipv4.conf.default.rp_filter=0
	sc mrt net.ipv4.conf.rt-a.rp_filter=0
	sc mrt net.ipv4.conf.rt-b.rp_filter=0
	# docs/design/15-nexthop-l2dsr.md: redirect generation should be suppressed
	# on the segment Marlin MAC-swaps back onto.
	sc mrt net.ipv4.conf.all.send_redirects=0
	sc mrt net.ipv4.conf.rt-a.send_redirects=0

	# Everything for the VIP goes to Marlin.
	ip netns exec mrt ip route add "${VIP}/32" via "${MARLIN_IP}" dev rt-a

	# --- client ------------------------------------------------------------
	ip netns exec mcli ip link set lo up
	ip netns exec mcli ip link set cli0 address "${CLI_MAC}"
	ip netns exec mcli ip addr add "${CLI_IP}/24" dev cli0
	ip netns exec mcli ip link set cli0 up
	ip netns exec mcli ip route add default via "${RT_C_IP}" dev cli0

	# --- backend 1: L2 DSR, on segment A -----------------------------------
	ip link add be1-0 address "${BE1_MAC}" type veth peer name be1-br
	ip link set be1-br master "${BR_A}" up
	ip link set be1-0 netns mbe1
	ip netns exec mbe1 ip link set lo up
	ip netns exec mbe1 ip addr add "${BE1_IP}/24" dev be1-0
	ip netns exec mbe1 ip link set be1-0 up
	ip netns exec mbe1 ip route add default via "${RT_A_IP}" dev be1-0
	backend_vip mbe1
	sc mbe1 net.ipv4.conf.all.rp_filter=0
	sc mbe1 net.ipv4.conf.be1-0.rp_filter=0

	# --- backend 2: IPIP, on segment B -------------------------------------
	ip link add be2-0 address "${BE2_MAC}" type veth peer name be2-br
	ip link set be2-br master "${BR_B}" up
	ip link set be2-0 netns mbe2
	ip netns exec mbe2 ip link set lo up
	ip netns exec mbe2 ip addr add "${BE2_IP}/24" dev be2-0
	ip netns exec mbe2 ip link set be2-0 up
	ip netns exec mbe2 ip route add default via "${RT_B_IP}" dev be2-0
	backend_vip mbe2

	# Protocol 4 — IPv4 inner. docs/design/14-forwarding-modes.md §7.2.
	ip netns exec mbe2 ip link add ipip0 type ipip \
		local "${BE2_IP}" remote "${MARLIN_IP}" ttl 64
	ip netns exec mbe2 ip link set ipip0 up
	# Protocol 41 — IPv6 inner over the IPv4 outer. §7.2: "A backend serving both
	# inner families needs both devices." Phase 2b, harmless before then.
	ip netns exec mbe2 ip link add sit-m type sit \
		local "${BE2_IP}" remote "${MARLIN_IP}" ttl 64 2>/dev/null || \
		echo "note: sit device not created (CONFIG_IPV6_SIT off) — IPv6 inner untestable"
	ip netns exec mbe2 ip link set sit-m up 2>/dev/null || true

	# The decapsulated packet is addressed to the VIP but sourced from the client,
	# whose route back is the default gateway on be2-0, not ipip0. Same rp_filter
	# problem as the router, same reason.
	sc mbe2 net.ipv4.conf.all.rp_filter=0
	sc mbe2 net.ipv4.conf.be2-0.rp_filter=0
	sc mbe2 net.ipv4.conf.ipip0.rp_filter=0

	# --- offloads ----------------------------------------------------------
	noffl -    "${MARLIN_IF}";  noffl - mlan0-br
	noffl -    rt-a-br;         noffl - rt-b-br
	noffl -    be1-br;          noffl - be2-br
	noffl mrt  rt-a;            noffl mrt rt-b;    noffl mrt rt-cli
	noffl mcli cli0
	noffl mbe1 be1-0
	noffl mbe2 be2-0

	# --- underlay MTU ------------------------------------------------------
	# Both encapsulated segments, and both bridges. The client link keeps 1500.
	mtu -    "${MARLIN_IF}" mlan0-br rt-a-br rt-b-br be1-br be2-br "${BR_A}" "${BR_B}"
	mtu mrt  rt-a rt-b
	mtu mbe1 be1-0
	mtu mbe2 be2-0

	bpffs_mounted || mount -t bpf bpf "${BPFFS}"
	mkdir -p "${PINDIR}"

	echo "topology up."
	echo
	summary
}

# VIP on a dummy device with ARP/NDP suppression. Required by L2 DSR
# (docs/design/14-forwarding-modes.md §7.1) and by VXLAN; harmless and correct
# for IPIP, whose inner packet also still carries the VIP (§7.2).
backend_vip() {
	local ns=$1
	ip netns exec "${ns}" ip link add vip0 type dummy
	ip netns exec "${ns}" ip addr add "${VIP}/32" dev vip0
	ip netns exec "${ns}" ip link set vip0 up
	sc "${ns}" net.ipv4.conf.all.arp_ignore=1
	sc "${ns}" net.ipv4.conf.all.arp_announce=2
	sc "${ns}" net.ipv4.conf.vip0.arp_ignore=1
	sc "${ns}" net.ipv4.conf.vip0.arp_announce=2
}

# ---------------------------------------------------------------------------
# status / down
# ---------------------------------------------------------------------------

summary() {
	cat <<EOF
Values this topology implies for the maps:

  config.tunnel_src            ${MARLIN_IP}
  config.max_frame             ${MTU_UNDERLAY}
  VIP                          ${VIP}
  L2 DSR backend  .addr        ${BE1_IP}
                  .mac         ${BE1_MAC}
                  MARLIN_BE_F_FIB clear, egress = ${MARLIN_IF}
  IPIP backend    .addr        ${BE2_IP}
                  .mac         unused (MAC swap, docs/design/15-nexthop-l2dsr.md)

Attach (must be xdpdrv, never a generic fallback):

  bpftool prog loadall data-plane/marlin.bpf.o ${PINDIR} pinmaps ${PINDIR}
  bpftool net attach xdpdrv pinned ${PINDIR}/xdp_marlin dev ${MARLIN_IF}

Drive it:

  ip netns exec mcli ping -c1 ${VIP}
  ip netns exec mcli curl -sS --max-time 2 http://${VIP}/

Watch it:

  ip netns exec mbe1 tcpdump -nei be1-0            # L2 DSR: VIP intact, MAC rewritten
  ip netns exec mbe2 tcpdump -nei be2-0 'proto 4'  # IPIP: outer ${MARLIN_IP} -> ${BE2_IP}
  ip netns exec mbe2 tcpdump -nei ipip0            # IPIP: after decapsulation
  bpftool map dump name drop_stats
EOF
}

status() {
	for ns in "${NS_ALL[@]}"; do
		ip netns list | grep -qw "${ns}" || { echo "topology is down"; return 1; }
	done
	echo "== root ns =="
	ip -br addr show "${MARLIN_IF}" 2>/dev/null || true
	ip -d link show "${MARLIN_IF}" | sed -n '2,3p'
	bridge link show 2>/dev/null | grep -E "${BR_A}|${BR_B}" || true
	for ns in "${NS_ALL[@]}"; do
		echo "== ns ${ns} =="
		ip netns exec "${ns}" ip -br addr
	done
}

down_quiet() {
	ip link set dev "${MARLIN_IF}" xdp off 2>/dev/null || true
	for ns in "${NS_ALL[@]}"; do ip netns del "${ns}" 2>/dev/null || true; done
	for d in "${MARLIN_IF}" mlan0-br rt-a-br rt-b-br be1-br be2-br "${BR_A}" "${BR_B}"; do
		ip link del "${d}" 2>/dev/null || true
	done
}

down() {
	need_root
	down_quiet
	rm -rf "${PINDIR}"
	echo "topology down."
}

# ---------------------------------------------------------------------------

help() {
	cat <<EOF
usage: $0 <command>

  check   preflight the host for WSL2/kernel prerequisites (kernel version,
          tools, kernel config, bpffs) without changing anything
  up      build the full integration topology: router, client, and both an
          L2 DSR and an IPIP backend
  status  show the topology's namespaces and root-ns attach state
  down    tear the topology down and remove its pins
  help    show this text
EOF
}

case "${1:-}" in
	check)          check ;;
	up)             up ;;
	status)         status ;;
	down)           down ;;
	help|-h|--help) help ;;
	*)
		echo "usage: $0 {check|up|status|down|help}" >&2
		echo "run '$0 help' for what each command does" >&2
		exit 2
		;;
esac
