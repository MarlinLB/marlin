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
# Usage:  sudo ./ipip_wsl.sh up | attach | seed | reload | detach | status | down
#                           | listen | trace | test_icmp_echo | test_http_get
#
#   up              build the topology (does not attach the program)
#   attach          load marlin.bpf.o, pin it, attach to ${MARLIN_IF}
#   seed            write config and backends[0]; nothing forwards until then
#   unseed          zero backends[0] again; the program stays attached
#   reload          after a rebuild: detach, unpin, load the new object, attach
#   detach          detach and remove the pins; the topology stays up
#   down            tear the topology down (implies detach)
#   listen          serve HTTP on the VIP from the backend namespace until ^C
#   trace           follow the kernel trace pipe — xdp_main's bpf_printk output
#   test_icmp_echo  ping the VIP from the client namespace
#   test_http_get   GET the VIP from the client namespace, against a throwaway
#                   listener started in the backend namespace
#
# The working order is up, attach, seed, listen. Seeding is not optional: BPF
# array maps come up zero-filled, and an all-zero backends[0] has
# MARLIN_BE_F_STATE clear, which xdp_interim_nexthop() (src/main.c) reads as
# "not mine" and passes. An attached program with unseeded maps forwards
# nothing and looks exactly like a broken datapath.
#
# Nothing is encapsulated yet. marlin_nexthop_encapsulate() (src/nexthop.c)
# MAC-swaps and XDP_TX's, and no bpf_xdp_adjust_head() exists anywhere in the
# datapath, so the packet reaches miprt-a with the client's own header intact.
# The router then routes the VIP back to Marlin and the frame circulates until
# its TTL runs out. Until the encapsulation lands (docs/PHASES.md, Phase 2b),
# this rig exercises the attach, the parse and the MAC swap; a completed GET is
# not among the things it can show, and drop_stats plus a tcpdump on miprt-a are
# where the evidence is.
#
# Overridable: MARLIN_OBJ, MARLIN_PINDIR, XDP_MODE, BPFTOOL.
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

HTTP_PORT=80                 # listen and test_http_get; no VIP lookup exists yet,
                             # so the port is the listener's alone (src/main.c)

# Root-namespace devices this script owns. down() deletes exactly these. The
# last two normally die with their namespaces; they are listed so that a run of
# up() that failed between creating a veth and moving it still cleans up.
ROOT_DEVS=("${MARLIN_IF}" "${BE_IF}" "${CLI_IF}")

# --- the BPF object, its pins, and the attach mode --------------------------
#
# Resolved from the script's own location, so the verbs work from any cwd. The
# build writes to data-plane/build/ (data-plane/Makefile: BUILD_DIR := build).
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
OBJ="${MARLIN_OBJ:-${SCRIPT_DIR}/../build/marlin.bpf.o}"

# Per-rig pin directory, not the /sys/fs/bpf/marlin default: this rig's
# namespaces/devices/MACs/VIP are disjoint from the other two rigs, so a shared
# pin dir would break that on first detach (DEPLOYMENT.md:62).
PINDIR="${MARLIN_PINDIR:-/sys/fs/bpf/mlipip}"

# bpftool pins each program under its C function name, not its section name --
# SEC("xdp") int xdp_main() pins as xdp_main (data-plane/src/main.c).
PROG=xdp_main

# xdpgeneric per this file's header; overridable to point at a native attach,
# which fails loudly rather than degrading (docs/design/02-architecture.md:31).
XDP_MODE="${XDP_MODE:-xdpgeneric}"
BPFFS=/sys/fs/bpf
BPFTOOL="${BPFTOOL:-bpftool}"

# The underlay carries the 20-byte outer header. docs/design/23-mtu.md's strategy
# is jumbo frames on the Marlin->backend path; the client link stays at 1500 and
# is deliberately left alone.
#
# config.max_frame is the *frame*, not the MTU: "egress MTU + ETH_HLEN"
# (docs/design/08-types.md, §1.7), so 1600 here means 1614 there. To exercise
# frame_too_big, drop MTU_UNDERLAY to 1500 and max_frame to 1514.
MTU_UNDERLAY=1600
MAX_FRAME=$((MTU_UNDERLAY + 14))

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

need_root() {
	[[ ${EUID} -eq 0 ]] || { echo "must run as root (sudo)" >&2; exit 1; }
}

# Fail by name, up front. Without this a missing ss or curl surfaces halfway
# through a verb, with a namespace already built and a listener already bound.
need_cmd() {
	local c
	for c in "$@"; do
		command -v "${c}" >/dev/null 2>&1 || {
			echo "${c} not found -- required by this verb" >&2; exit 1; }
	done
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
# ARP/NDP suppression isn't load-bearing here -- the backend shares no segment
# with anything that would ask for the VIP -- but it's the documented backend
# requirement (§7.1, inherited by §7.2), and omitting it teaches the wrong recipe.
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
	need_cmd ip ethtool
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
	# Static, because resolving ${MARLIN_IP} means ARPing *into* the XDP program:
	# whether the datapath passes non-IP ethertypes is what's under test, so a
	# rig whose first packet depends on it fails at ARP, not at forwarding.
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

Attach — ${XDP_MODE}, because WSL2 veth has no native XDP:

  sudo $0 attach          # load ${OBJ##*/}, pin under ${PINDIR}, attach
  sudo $0 reload          # after a rebuild: detach, unpin, load, attach
  sudo $0 detach          # detach and unpin; rig stays up

Seed — an attached program forwards nothing until backends[0] is written:

  sudo $0 seed            # write config and backends[0] with the values above
  sudo $0 unseed          # zero backends[0] again, to watch forwarding stop

Drive it — but see the file header: the encapsulation is not written yet, so a
completed request is not among the things this rig can show today.

  sudo $0 listen          # serve ${VIP}:${HTTP_PORT} from ns ${NS_BE} until ^C,
                          # bound to the VIP alone so only tunnelled packets arrive
  sudo $0 test_http_get   # one GET from ns ${NS_CLI} against a throwaway listener
  sudo $0 test_icmp_echo  # ping the VIP. No reply is the correct outcome: echo
                          # passes to the host stack (docs/design/13-icmp.md), so
                          # the evidence is icmp_echo moving in drop_stats

Watch it, in path order:

  sudo $0 trace                                         # ${PROG}'s bpf_printk output
  ip netns exec ${NS_RT} tcpdump -nei ${RT_A}            # in from client, back out encapsulated
  ip netns exec ${NS_BE} tcpdump -nei ${BE_IF} 'proto 4' # outer ${MARLIN_IP} -> ${BE_IP}
  ip netns exec ${NS_BE} tcpdump -nei ipip0              # after decapsulation, VIP intact
  ip -d link show ${MARLIN_IF} | grep prog/xdp           # expect "${XDP_MODE}"
  ${BPFTOOL} map dump pinned ${PINDIR}/drop_stats        # 'name drop_stats' would
                                                         # match every rig's map
EOF
}

status() {
	for ns in "${NS_ALL[@]}"; do
		ip netns list | grep -qw "${ns}" || { echo "ipip rig is down"; return 1; }
	done
	echo "== root ns =="
	ip -br addr show "${MARLIN_IF}" 2>/dev/null || true
	ip -d link show "${MARLIN_IF}" | sed -n '2,3p'
	echo "== xdp =="
	if xdp_attached; then
		ip -d link show dev "${MARLIN_IF}" | grep 'prog/xdp'
		echo "pins: ${PINDIR}"
		find "${PINDIR}" -mindepth 1 -maxdepth 1 -printf '  %f\n' 2>/dev/null || true
	else
		echo "  no program attached to ${MARLIN_IF} (run '$0 attach')"
	fi
	echo "== maps =="
	if [[ -e ${PINDIR}/backends ]]; then
		config_show || echo "  config not seeded (run '$0 seed')"
		backend_show || echo "  backends[0] not seeded (run '$0 seed')"
	else
		echo "  no pins under ${PINDIR} (run '$0 attach')"
	fi
	echo "== ns ${NS_BE} listeners =="
	nsx "${NS_BE}" ss -lnt 2>/dev/null || echo "  ss not available"
	for ns in "${NS_ALL[@]}"; do
		echo "== ns ${ns} =="
		ip netns exec "${ns}" ip -br addr
	done
	echo "== ns ${NS_BE} routes =="
	ip netns exec "${NS_BE}" ip route
}

# Idempotent: safe to run when nothing exists. up() calls it first.
down_quiet() {
	local ns d pids
	detach_quiet
	# `ip netns del` unlinks the name; the namespace itself lives on while a
	# process is attached, so a leftover listener survives a down/up cycle.
	# ${pids} is unquoted on purpose: it is a list.
	for ns in "${NS_ALL[@]}"; do
		pids=$(ip netns pids "${ns}" 2>/dev/null || true)
		if [[ -n ${pids} ]]; then kill ${pids} 2>/dev/null || true; fi
	done
	for ns in "${NS_ALL[@]}"; do ip netns del "${ns}" 2>/dev/null || true; done
	for d in "${ROOT_DEVS[@]}"; do ip link del "${d}" 2>/dev/null || true; done
}

down() {
	need_root
	down_quiet
	echo "ipip rig down."
}

# ---------------------------------------------------------------------------
# attach / detach / reload
# ---------------------------------------------------------------------------

ensure_bpffs() {
	mountpoint -q "${BPFFS}" && return 0
	mount -t bpf bpf "${BPFFS}" 2>/dev/null && return 0
	echo "cannot mount bpffs at ${BPFFS}" >&2
	return 1
}

# `ip -d` prints "prog/xdp id N ..." for an attached program regardless of mode.
# Plain `ip link show` prints "xdpgeneric/id:N", whose spelling has moved between
# iproute2 releases; the -d form has not.
xdp_attached() {
	ip -d link show dev "${MARLIN_IF}" 2>/dev/null | grep -q 'prog/xdp'
}

rig_up_or_die() {
	local ns
	ip link show "${MARLIN_IF}" >/dev/null 2>&1 || {
		echo "${MARLIN_IF} does not exist -- run '$0 up' first" >&2; exit 1; }
	for ns in "${NS_ALL[@]}"; do
		ip netns list | grep -qw "${ns}" || {
			echo "rig is incomplete (missing ns ${ns}) -- run '$0 up' first" >&2; exit 1; }
	done
}

# down_quiet(), detach() and reload() funnel through here for one definition
# of "cleaned up". A bare `xdp off` resolves to XDP_MODE_DRV and is NOT a
# substitute for the mode-specific forms -- it no-ops on a generic attach.
detach_quiet() {
	ip link set dev "${MARLIN_IF}" xdpgeneric off 2>/dev/null || true
	ip link set dev "${MARLIN_IF}" xdpdrv off 2>/dev/null || true
	ip link set dev "${MARLIN_IF}" xdp off 2>/dev/null || true
	rm -rf "${PINDIR}"
}

# The load-and-attach core, without the guards. attach() and reload() differ
# only in what they tolerate finding already in place.
do_attach() {
	need_cmd "${BPFTOOL}"
	[[ -f ${OBJ} ]] || {
		echo "no object at ${OBJ}" >&2
		echo "build it:  make -C ${SCRIPT_DIR}/.." >&2
		exit 1
	}
	ensure_bpffs || exit 1

	# Assert the interface is clear rather than letting the attach fail with
	# EBUSY. A detach that silently no-ops is the failure mode this catches --
	# see detach_quiet() for why that is not hypothetical.
	if xdp_attached; then
		echo "${MARLIN_IF} still has a program attached after detach:" >&2
		ip -d link show dev "${MARLIN_IF}" | grep 'prog/xdp' >&2 || true
		echo "clear it by hand, e.g. 'ip link set dev ${MARLIN_IF} xdpgeneric off'" >&2
		exit 1
	fi

	# PINDIR is this rig's alone, so clearing it cannot disturb another rig.
	# Without this, loadall fails with EEXIST against pins a previous run left
	# behind -- detached but never unpinned, or killed mid-run.
	rm -rf "${PINDIR}"
	mkdir -p "${PINDIR}"

	"${BPFTOOL}" prog loadall "${OBJ}" "${PINDIR}" pinmaps "${PINDIR}"
	"${BPFTOOL}" net attach "${XDP_MODE}" pinned "${PINDIR}/${PROG}" dev "${MARLIN_IF}"
}

attach() {
	need_root
	rig_up_or_die
	if xdp_attached; then
		echo "${MARLIN_IF} already has an XDP program attached." >&2
		echo "use '$0 reload' to replace it, or '$0 detach' first." >&2
		exit 1
	fi
	do_attach
	echo "attached ${PROG} to ${MARLIN_IF} (${XDP_MODE}), pinned under ${PINDIR}"
	echo "next: '$0 seed' -- until config and backends[0] are written, every packet passes"
}

detach() {
	need_root
	local was_attached=0
	# if/then, not `xdp_attached && was_attached=1`: under `set -e` an && list
	# whose left side fails is a trap worth not setting.
	if xdp_attached; then was_attached=1; fi
	detach_quiet
	if [[ ${was_attached} -eq 1 ]]; then
		echo "detached from ${MARLIN_IF}, pins under ${PINDIR} removed. Rig still up."
	else
		echo "nothing was attached to ${MARLIN_IF}; pins under ${PINDIR} removed anyway."
	fi
}

# The rebuild loop. Unpinning is the point: the pins hold the *old* program, so
# a bare re-attach would put the pre-rebuild object back on the interface.
reload() {
	need_root
	rig_up_or_die
	detach_quiet
	do_attach
	echo "reloaded ${PROG} onto ${MARLIN_IF} (${XDP_MODE}) from ${OBJ}"
}

# ---------------------------------------------------------------------------
# Map seeding
# ---------------------------------------------------------------------------
#
# What the C# service will write once it can (docs/design/19-control-plane.md).
# Until then manual map writes are the sanctioned route (docs/TESTING.md §10),
# and without them an attached program passes every packet.
#
# Both config and backends[0] are written here, unlike the L2 DSR rig: an
# encapsulating backend reads config.tunnel_src for the outer source and
# config.max_frame for the post-encapsulation size check.
#
# vip_map and fwd_table are not written, because nothing reads them yet --
# xdp_interim_nexthop() takes backends[0] directly (src/main.c). They become
# required when selection lands (docs/PHASES.md, Phase 2b).

ABI_HDR="${SCRIPT_DIR}/../include/marlin/abi/defines.h"

# One #define, read out of the ABI header at run time. Copying the values here
# would make this a third hand-written mirror of the ABI with nothing checking
# it against the other two.
abi_define() {
	local name=$1 v
	v=$(sed -n "s/^#define[[:space:]]\+${name}[[:space:]]\+\([0-9]\+\)[[:space:]]*\$/\1/p" "${ABI_HDR}")
	[[ -n ${v} ]] || { echo "cannot read ${name} from ${ABI_HDR}" >&2; exit 1; }
	echo "${v}"
}

# struct backend and struct marlin_config as byte lists `bpftool map update`
# takes. python3 rather than shell arithmetic: both mix network-order
# addresses with host-order words, and struct.pack states which is which.
pack_backend() {
	python3 - "$@" <<'PY'
import socket, struct, sys

addr, mac, flags = sys.argv[1], sys.argv[2], int(sys.argv[3])
mac_b = bytes(int(x, 16) for x in mac.split(":")) if mac else b"\0" * 6

raw = (socket.inet_aton(addr)     # __be32 addr
       + mac_b                    # __u8   mac[6]
       + struct.pack("!H", 0)     # __be16 encap_dport — IPIP has no outer port
       + struct.pack("B", flags)  # __u8   flags
       + b"\0" * 3                # __u8   pad[3]
       + struct.pack("=I", 0)     # __u32  egress_ifindex — 0 disables the check
       + struct.pack("=I", 0)     # __u32  vni
       + b"\0" * 6                # __u8   inner_mac[6]
       + b"\0" * 2)               # __u8   pad_end[2]

if len(raw) != 32:
    sys.exit("struct backend must pack to 32 bytes, got %d" % len(raw))

print(" ".join("0x%02x" % b for b in raw))
PY
}

pack_config() {
	python3 - "$@" <<'PY'
import socket, struct, sys

tunnel_src, max_frame = sys.argv[1], int(sys.argv[2])

raw = (socket.inet_aton(tunnel_src)      # __be32 tunnel_src
       + struct.pack("=I", 0)            # __u32  flags — ACL and RL off
       + struct.pack("=H", max_frame)    # __u16  max_frame
       + struct.pack("=H", 0)            # __u16  acl_lists
       + struct.pack("=I", 0)            # __u32  rl_refill
       + struct.pack("=I", 0))           # __u32  rl_burst

if len(raw) != 20:
    sys.exit("struct marlin_config must pack to 20 bytes, got %d" % len(raw))

print(" ".join("0x%02x" % b for b in raw))
PY
}

# Decode backends[0] as bpftool returns it, and exit non-zero when the entry is
# not seeded.
#
# The offsets below are a third mirror of struct backend
# (include/marlin/abi/types.h) that would drift silently -- named BTF fields
# are checked against them here rather than trusted.
backend_show() {
	local bit
	bit=$(abi_define MARLIN_BE_F_STATE_BIT)
	[[ -e ${PINDIR}/backends ]] || { echo "  no pins under ${PINDIR}"; return 1; }
	"${BPFTOOL}" -j map dump pinned "${PINDIR}/backends" 2>/dev/null | python3 -c '
import json, socket, struct, sys

state_bit = int(sys.argv[1])

try:
    entry = json.load(sys.stdin)[0]
except (ValueError, IndexError):
    print("  backends is unreadable -- is the object still loaded?")
    sys.exit(1)

raw = bytes(int(b, 16) for b in entry["value"])
addr, mac, flags = raw[0:4], raw[4:10], raw[12]

btf = entry.get("formatted", {}).get("value")
if btf is not None:
    if struct.pack("=I", btf["addr"] & 0xffffffff) != addr or int(btf["flags"]) != flags:
        print("  BTF disagrees with the offsets this script packs: struct backend moved",
              file=sys.stderr)
        sys.exit(2)

up = (flags >> state_bit) & 1
print("  addr   %s" % socket.inet_ntoa(addr))
print("  mac    %s" % ":".join("%02x" % b for b in mac))
print("  flags  0x%02x  mode %u, state %s" % (flags, flags & 0x0f, "UP" if up else "DOWN"))
sys.exit(0 if up else 1)
' "${bit}"
}

config_show() {
	[[ -e ${PINDIR}/config ]] || { echo "  no pins under ${PINDIR}"; return 1; }
	"${BPFTOOL}" -j map dump pinned "${PINDIR}/config" 2>/dev/null | python3 -c '
import json, socket, struct, sys

try:
    entry = json.load(sys.stdin)[0]
except (ValueError, IndexError):
    print("  config is unreadable -- is the object still loaded?")
    sys.exit(1)

raw = bytes(int(b, 16) for b in entry["value"])
tunnel_src = raw[0:4]
max_frame = struct.unpack("=H", raw[8:10])[0]

btf = entry.get("formatted", {}).get("value")
if btf is not None:
    if struct.pack("=I", btf["tunnel_src"] & 0xffffffff) != tunnel_src or int(btf["max_frame"]) != max_frame:
        print("  BTF disagrees with the offsets this script packs: struct marlin_config moved",
              file=sys.stderr)
        sys.exit(2)

print("  tunnel_src  %s" % socket.inet_ntoa(tunnel_src))
print("  max_frame   %u" % max_frame)
sys.exit(0 if tunnel_src != b"\0" * 4 else 1)
'
}

backend_seeded() {
	backend_show >/dev/null 2>&1
}

seed_or_die() {
	[[ -e ${PINDIR}/backends ]] || {
		echo "no pinned maps under ${PINDIR} -- run '$0 attach' first" >&2; exit 1; }
}

seed() {
	need_root
	need_cmd python3 "${BPFTOOL}"
	rig_up_or_die
	seed_or_die

	local mode bit flags value
	mode=$(abi_define MARLIN_MODE_IPIP)
	bit=$(abi_define MARLIN_BE_F_STATE_BIT)
	# MARLIN_BE_F_FIB stays clear, so the nexthop is the MAC swap back at the
	# router rather than a FIB lookup (docs/design/15-nexthop-l2dsr.md).
	flags=$(( mode | (1 << bit) ))

	# backend.mac stays zero: the encapsulating path swaps the frame's own
	# addresses and never reads it (src/nexthop.c).
	value=$(pack_backend "${BE_IP}" "" "${flags}")
	# Unquoted on purpose: bpftool takes the value as separate byte arguments.
	# shellcheck disable=SC2086
	"${BPFTOOL}" map update pinned "${PINDIR}/backends" key 0 0 0 0 value ${value}

	value=$(pack_config "${MARLIN_IP}" "${MAX_FRAME}")
	# shellcheck disable=SC2086
	"${BPFTOOL}" map update pinned "${PINDIR}/config" key 0 0 0 0 value ${value}

	echo "seeded config:"
	config_show
	echo "seeded backends[0]:"
	backend_show
}

unseed() {
	need_root
	need_cmd python3 "${BPFTOOL}"
	seed_or_die

	local value
	value=$(pack_backend 0.0.0.0 "" 0)
	# shellcheck disable=SC2086
	"${BPFTOOL}" map update pinned "${PINDIR}/backends" key 0 0 0 0 value ${value}
	echo "backends[0] zeroed; ${PROG} passes every packet again."
	echo "config left in place: it is read on every packet, before the backend lookup."
}

# ---------------------------------------------------------------------------
# trace
# ---------------------------------------------------------------------------
#
# xdp_main writes a bpf_printk line per packet (src/main.c), which lands in the
# kernel trace pipe and nowhere else.
trace() {
	need_root
	local p
	for p in /sys/kernel/tracing/trace_pipe /sys/kernel/debug/tracing/trace_pipe; do
		if [[ -r ${p} ]]; then exec cat "${p}"; fi
	done
	if mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null; then
		exec cat /sys/kernel/tracing/trace_pipe
	fi
	echo "no readable trace_pipe; mount tracefs at /sys/kernel/tracing" >&2
	exit 1
}

# ---------------------------------------------------------------------------
# Traffic
# ---------------------------------------------------------------------------
#
# Generators, not assertions. Each runs one client-side command and reports
# which drop_stats counters moved while it ran; the exit status is the
# command's own.

# Names for the counters, read from the header at run time rather than copied
# here. The enumerators are drop_stats indices from first release (CLAUDE.md),
# and a second hand-written mirror would drift with nothing to catch it.
RET_HDR="${SCRIPT_DIR}/../include/marlin/marlin.h"

# Emits "index name" per counted enumerator. The count isn't just the line
# number: MARLIN_OK (and maybe later enumerators) carries an explicit "= 0"
# in marlin.h, and an explicit value resets the count rather than being ignored.
ret_names() {
	[[ -f ${RET_HDR} ]] || return 0
	sed -n '/^enum marlin_ret {/,/^};/p' "${RET_HDR}" | awk '
		BEGIN { n = 0 }
		{ sub(/\/\*.*/, "") }
		match($0, /MARLIN_[A-Z0-9_]+/) {
			name = substr($0, RSTART, RLENGTH)
			if(name == "MARLIN_RET_MAX") next
			if(match($0, /=[[:space:]]*[0-9]+/))
				n = substr($0, RSTART + 1, RLENGTH - 1) + 0
			print n, name
			n++
		}'
}

# drop_stats is a per-CPU array keyed by enum marlin_ret, summed per index here.
# JSON stays stable across bpftool's plain-text format changes; a value comes
# back as a number with BTF or a little-endian byte array without it.
stats_read() {
	[[ -e ${PINDIR}/drop_stats ]] || return 1
	"${BPFTOOL}" -j map dump pinned "${PINDIR}/drop_stats" 2>/dev/null | python3 -c '
import json, sys

def num(v):
    if isinstance(v, list):
        return int("".join(b[2:] for b in reversed(v)), 16)
    return int(v)

for e in json.load(sys.stdin):
    print(num(e["key"]), sum(num(v["value"]) for v in e.get("values", [e])))
'
}

STATS_BEFORE=

stats_snapshot() {
	STATS_BEFORE=$(stats_read || true)
}

stats_report() {
	local after moved=0 i b a n
	if [[ -z ${STATS_BEFORE} ]]; then
		echo "drop_stats unreadable -- no pins under ${PINDIR} (run '$0 attach'), or no python3"
		return 0
	fi
	after=$(stats_read || true)
	local -A before=() name=()
	# if/then rather than an && list, for the reason in detach() above.
	while read -r i n; do if [[ -n ${i} ]]; then name[${i}]=${n}; fi; done < <(ret_names)
	while read -r i b; do if [[ -n ${i} ]]; then before[${i}]=${b}; fi; done <<<"${STATS_BEFORE}"
	echo "drop_stats:"
	while read -r i a; do
		[[ -n ${i} ]] || continue
		b=${before[${i}]:-0}
		(( a > b )) || continue
		moved=1
		printf '  %-32s +%s\n' "${name[${i}]:-index ${i}}" "$(( a - b ))"
	done <<<"${after}"
	(( moved )) || echo "  nothing moved"
}

# An echo request to a VIP is XDP_PASS by design (docs/design/13-icmp.md); the
# root namespace doesn't hold the VIP, so no reply is the correct outcome --
# the evidence is icmp_echo moving in drop_stats, not a reply.
test_icmp_echo() {
	need_root
	rig_up_or_die
	need_cmd ping
	stats_snapshot
	local rc=0
	# -W bounds the wait. Nothing answers the VIP until the datapath forwards,
	# and ping's default linger makes that look like a hang rather than a miss.
	nsx "${NS_CLI}" ping -c1 -W2 "${VIP}" || rc=$?
	echo
	stats_report
	echo "(no reply is expected: echo passes to the host stack, it is not forwarded)"
	return "${rc}"
}

be_port_busy() {
	local port=${1:-${HTTP_PORT}}
	nsx "${NS_BE}" ss -lnt "sport = :${port}" 2>/dev/null | grep -q LISTEN
}

# The encapsulation this rig exists to exercise does not exist yet; see the file
# header. Printed by listen() and test_http_get() rather than left for the reader
# to rediscover as a hung curl.
encap_caveat() {
	cat >&2 <<EOF
note: nothing is encapsulated yet -- marlin_nexthop_encapsulate() (src/nexthop.c)
      MAC-swaps without prepending an outer header, so the packet returns to
      ${RT_A} carrying the client's own header and the router sends it straight
      back to Marlin. Expect the request to fail; the evidence this rig can give
      today is in drop_stats and in a tcpdump on ${RT_A}.

EOF
}

# The listener argv, shared by listen() and test_http_get() so the two cannot
# come to disagree about what the backend serves or what it binds.
#
# --bind ${VIP} is load-bearing: the decapsulated packet still carries the VIP
# as destination (§7.2), and only a listener bound to the VIP on lo answers
# tunnelled traffic -- a wildcard bind would also answer ordinary routing.
#
# python3 -m http.server because it needs no configuration and is already the
# dependency stats_read() carries.
BE_HTTP_ARGV=()

be_http_argv() {
	BE_HTTP_ARGV=(python3 -m http.server "$1" --bind "${VIP}" --directory "$2")
}

# A document root whose index names the rig, so a reply identifies which backend
# answered rather than only that something did.
be_docroot() {
	local d
	d=$(mktemp -d)
	cat >"${d}/index.html" <<EOF
<!doctype html>
<title>marlin ipip rig</title>
<pre>
rig       ipip_wsl.sh (IPIP, docs/design/14-forwarding-modes.md 7.2)
backend   ns ${NS_BE}, ${BE_IF} ${BE_IP}, tunnel ipip0 local ${BE_IP} remote ${MARLIN_IP}
bound to  ${VIP} -- the VIP, on lo; reached only through the tunnel
</pre>
EOF
	echo "${d}"
}

# Held open until ^C, with each request logged as it arrives. The rig's own
# state is checked first, because an unattached or unseeded datapath presents
# exactly as a hung curl.
listen() {
	need_root
	rig_up_or_die
	need_cmd python3 ss
	local port=${1:-${HTTP_PORT}} root rc=0

	[[ ${port} =~ ^[0-9]+$ ]] || {
		echo "port must be a number, got '${port}'" >&2; exit 1; }

	if ! xdp_attached; then
		echo "note: nothing is attached to ${MARLIN_IF} -- run '$0 attach' then '$0 seed'," >&2
		echo "      or the client cannot reach ${VIP} at all." >&2
	elif ! backend_seeded; then
		echo "note: backends[0] is not seeded -- ${PROG} passes every packet" >&2
		echo "      (src/main.c). Run '$0 seed' in another terminal." >&2
	fi
	encap_caveat

	if be_port_busy "${port}"; then
		echo "port ${port} is already bound in ns ${NS_BE}:" >&2
		nsx "${NS_BE}" ss -lntp "sport = :${port}" >&2 || true
		echo "kill that process, then retry" >&2
		exit 1
	fi

	root=$(be_docroot)
	trap 'rm -rf "${root}"' EXIT
	be_http_argv "${port}" "${root}"

	cat <<EOF
listening on ${VIP}:${port} in ns ${NS_BE} -- ^C to stop.

Drive it from the client:

  ip netns exec ${NS_CLI} curl -sS --max-time 2 http://${VIP}:${port}/

Nothing else reaches it. ${BE_IP}:${port} is not bound, so a request that
arrived by ordinary routing rather than through the tunnel is refused.

Watch it, in path order:

  sudo $0 trace
  ip netns exec ${NS_RT} tcpdump -nei ${RT_A}             # in from the client, back out
  ip netns exec ${NS_BE} tcpdump -nei ${BE_IF} 'proto 4'  # outer ${MARLIN_IP} -> ${BE_IP}
  ip netns exec ${NS_BE} tcpdump -nei ipip0               # after decapsulation
  ${BPFTOOL} map dump pinned ${PINDIR}/drop_stats

EOF
	ip netns exec "${NS_BE}" "${BE_HTTP_ARGV[@]}" || rc=$?
	rm -rf "${root}"
	trap - EXIT
	# http.server exits 0 on ^C; 130 is the same interrupt seen through a shell
	# that did not install its own handler. Neither is a failure of the rig.
	if [[ ${rc} -eq 0 || ${rc} -eq 130 ]]; then
		echo "listener stopped."
		return 0
	fi
	return "${rc}"
}

# One GET against a throwaway instance of the same listener. Nothing here depends
# on what is served, only that the handshake completes from the backend namespace.
test_http_get() {
	need_root
	rig_up_or_die
	need_cmd python3 ss curl

	# Name the holder rather than guessing at it. A bind failure here is almost
	# always a listener from an earlier run, and "Address already in use" out of
	# a backgrounded process says nothing about whose.
	if be_port_busy; then
		echo "port ${HTTP_PORT} is already bound in ns ${NS_BE}:" >&2
		nsx "${NS_BE}" ss -lntp "sport = :${HTTP_PORT}" >&2 || true
		echo "kill that process, then retry" >&2
		exit 1
	fi

	local err pid root rc=0
	err=$(mktemp)
	root=$(be_docroot)
	be_http_argv "${HTTP_PORT}" "${root}"

	# ip netns exec directly rather than nsx(): backgrounding a shell function
	# makes $! the subshell's pid, and killing that leaves the python3 beneath
	# it alive and still holding the port.
	ip netns exec "${NS_BE}" "${BE_HTTP_ARGV[@]}" >/dev/null 2>"${err}" &
	pid=$!
	# The cleanup has to survive a failing curl, a ^C and set -e alike: a
	# listener that outlives the script holds the port and the next run cannot
	# bind.
	trap 'kill "${pid}" 2>/dev/null || true; rm -rf "${err}" "${root}"' EXIT

	# Poll rather than sleep a fixed interval, which either races the bind or
	# pads every run. A bind failure is immediate, so watch for the process
	# dying too and stop waiting on something that is already gone.
	local i
	for i in $(seq 1 50); do
		if be_port_busy; then break; fi
		if ! kill -0 "${pid}" 2>/dev/null; then break; fi
		sleep 0.1
	done

	if ! be_port_busy; then
		echo "listener did not come up in ns ${NS_BE}:" >&2
		cat "${err}" >&2
		exit 1
	fi

	if ! backend_seeded; then
		echo "note: backends[0] is not seeded -- expect this GET to time out" >&2
	fi
	encap_caveat

	stats_snapshot
	nsx "${NS_CLI}" curl -sS --max-time 2 "http://${VIP}/" || rc=$?
	echo
	stats_report

	kill "${pid}" 2>/dev/null || true
	wait "${pid}" 2>/dev/null || true
	rm -rf "${err}" "${root}"
	trap - EXIT
	return "${rc}"
}

# ---------------------------------------------------------------------------

help() {
	cat <<EOF
usage: $0 <command> [args]

  up              build the topology (router, client, backend); does not
                  attach the program
  attach          load marlin.bpf.o, pin it, and attach it to ${MARLIN_IF}
  seed            write config and backends[0]; nothing forwards until then
  unseed          zero backends[0] again; the program stays attached
  reload          rebuild loop: detach, unpin, load the new object, reattach
  detach          detach the program and remove its pins; topology stays up
  status          show the rig's namespaces, attach state and seeded maps
  down            tear the whole topology down (implies detach)
  listen [port]   serve HTTP on the VIP from the backend namespace until ^C
  trace           follow the kernel trace pipe for xdp_main's bpf_printk output
  test_icmp_echo  ping the VIP from the client namespace, report drop_stats
  test_http_get   GET the VIP from the client namespace, report drop_stats
  help            show this text

Typical order: up, attach, seed, listen -- but see the file header: the
encapsulation is not written yet, so a completed request is not among the
things this rig can show today.
EOF
}

case "${1:-}" in
	up)             up ;;
	attach)         attach ;;
	detach)         detach ;;
	reload)         reload ;;
	seed)           seed ;;
	unseed)         unseed ;;
	status)         status ;;
	down)           down ;;
	listen)         shift; listen "$@" ;;
	trace)          trace ;;
	test_icmp_echo) test_icmp_echo ;;
	test_http_get)  test_http_get ;;
	help|-h|--help) help ;;
	*)
		echo "usage: $0 {up|attach|seed|unseed|reload|detach|status|down|listen|trace|test_icmp_echo|test_http_get|help}" >&2
		echo "run '$0 help' for what each command does" >&2
		exit 2
		;;
esac
