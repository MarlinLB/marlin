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
# Usage:  sudo ./ipip_wsl.sh up | attach | reload | detach | status | down
#                           | test_icmp_echo | test_http_get
#
#   up              build the topology (does not attach the program)
#   attach          load marlin.bpf.o, pin it, attach to ${MARLIN_IF}
#   reload          after a rebuild: detach, unpin, load the new object, attach
#   detach          detach and remove the pins; the topology stays up
#   down            tear the topology down (implies detach)
#   test_icmp_echo  ping the VIP from the client namespace
#   test_http_get   GET the VIP from the client namespace, against a throwaway
#                   listener started in the backend namespace
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

HTTP_PORT=80                 # test_http_get; the VIP carries no port of its own

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

# Per-rig pin directory, not the /sys/fs/bpf/marlin default. This script's whole
# premise is that its namespaces, devices, MACs and VIP are disjoint from the
# other two rigs' so all three can be up at once; a shared pin directory would
# break that on the first detach. DEPLOYMENT.md:62 makes the path a default
# rather than an invariant, so this is in bounds.
PINDIR="${MARLIN_PINDIR:-/sys/fs/bpf/mlipip}"

# bpftool pins each program under its C function name, not its section name --
# SEC("xdp") int xdp_main() pins as xdp_main (data-plane/src/main.c).
PROG=xdp_main

# xdpgeneric for the reason in this file's header. Overridable so the rig can be
# pointed at a native attach on a kernel that has one; it will fail loudly there
# rather than degrade, which is the behaviour docs/design/02-architecture.md:31
# wants.
XDP_MODE="${XDP_MODE:-xdpgeneric}"
BPFFS=/sys/fs/bpf
BPFTOOL="${BPFTOOL:-bpftool}"

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

Attach — ${XDP_MODE}, because WSL2 veth has no native XDP:

  sudo $0 attach          # load ${OBJ##*/}, pin under ${PINDIR}, attach
  sudo $0 reload          # after a rebuild: detach, unpin, load, attach
  sudo $0 detach          # detach and unpin; rig stays up

Drive it:

  sudo $0 test_icmp_echo  # ip netns exec ${NS_CLI} ping -c1 ${VIP}
  sudo $0 test_http_get   # ip netns exec ${NS_CLI} curl -sS --max-time 2 http://${VIP}/
                          # ...against python3 -m http.server in ns ${NS_BE}

Watch it, in path order:

  ip netns exec ${NS_RT} tcpdump -nei ${RT_A}            # in from client, back out encapsulated
  ip netns exec ${NS_BE} tcpdump -nei ${BE_IF} 'proto 4' # outer ${MARLIN_IP} -> ${BE_IP}
  ip netns exec ${NS_BE} tcpdump -nei ipip0              # after decapsulation, VIP intact
  ip -d link show ${MARLIN_IF} | grep prog/xdp           # expect "${XDP_MODE}"
  bpftool map dump name drop_stats
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
	# `ip netns del` unlinks the name, but the namespace itself lives on while a
	# process is still attached to it. A leftover listener therefore survives a
	# down/up cycle with nothing to show for it but the next failed bind.
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

# No output, no root check, no failure. down_quiet(), detach() and reload() all
# funnel through here so there is one definition of "cleaned up".
#
# Every mode is cleared explicitly, and a bare `xdp off` is NOT a substitute for
# the mode-specific forms. dev_xdp_mode() in net/core/dev.c resolves a request
# carrying no mode flag to XDP_MODE_DRV on any device with ndo_bpf -- veth has
# it -- so `xdp off` targets the driver slot, finds it empty, and returns
# success without touching a generic-mode program. The next attach then fails
# with EBUSY "XDP program already attached", pointing at the wrong thing.
detach_quiet() {
	ip link set dev "${MARLIN_IF}" xdpgeneric off 2>/dev/null || true
	ip link set dev "${MARLIN_IF}" xdpdrv off 2>/dev/null || true
	ip link set dev "${MARLIN_IF}" xdp off 2>/dev/null || true
	rm -rf "${PINDIR}"
}

# The load-and-attach core, without the guards. attach() and reload() differ
# only in what they tolerate finding already in place.
do_attach() {
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

# Emits "index name" per counted enumerator. The running counter is not just the
# line number: MARLIN_OK carries an explicit "= 0" (marlin.h), and any later
# enumerator may too, so an explicit value resets the count rather than being
# ignored.
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

# drop_stats is a per-CPU array of __u64 keyed by enum marlin_ret, so a reading
# is the per-CPU values summed per index. The JSON form is what stays stable:
# bpftool's plain-text layout for per-CPU maps has moved between releases. A
# value comes back as a number when the object carries BTF and as a
# little-endian byte array when it does not; num() takes either.
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

test_icmp_echo() {
	need_root
	rig_up_or_die
	stats_snapshot
	local rc=0
	# -W bounds the wait. Nothing answers the VIP until the datapath forwards,
	# and ping's default linger makes that look like a hang rather than a miss.
	nsx "${NS_CLI}" ping -c1 -W2 "${VIP}" || rc=$?
	echo
	stats_report
	return "${rc}"
}

be_port_busy() {
	nsx "${NS_BE}" ss -lnt "sport = :${HTTP_PORT}" 2>/dev/null | grep -q LISTEN
}

# python3 -m http.server because it needs no configuration and is already the
# dependency stats_read() carries. Nothing here depends on what it serves, only
# that something completes the handshake from the backend namespace.
test_http_get() {
	need_root
	rig_up_or_die
	command -v python3 >/dev/null 2>&1 || {
		echo "python3 not found -- needed for the throwaway backend listener" >&2
		exit 1
	}

	# Name the holder rather than guessing at it. A bind failure here is almost
	# always a listener from an earlier run, and "Address already in use" out of
	# a backgrounded process says nothing about whose.
	if be_port_busy; then
		echo "port ${HTTP_PORT} is already bound in ns ${NS_BE}:" >&2
		nsx "${NS_BE}" ss -lntp "sport = :${HTTP_PORT}" >&2 || true
		echo "kill that process, then retry" >&2
		exit 1
	fi

	local err pid rc=0
	err=$(mktemp)

	# ip netns exec directly rather than nsx(): backgrounding a shell function
	# makes $! the subshell's pid, and killing that leaves the python3 beneath
	# it alive and still holding the port.
	ip netns exec "${NS_BE}" python3 -m http.server "${HTTP_PORT}" >/dev/null 2>"${err}" &
	pid=$!
	# The cleanup has to survive a failing curl, a ^C and set -e alike: a
	# listener that outlives the script holds the port and the next run cannot
	# bind.
	trap 'kill "${pid}" 2>/dev/null || true; rm -f "${err}"' EXIT

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

	stats_snapshot
	nsx "${NS_CLI}" curl -sS --max-time 2 "http://${VIP}/" || rc=$?
	echo
	stats_report

	kill "${pid}" 2>/dev/null || true
	wait "${pid}" 2>/dev/null || true
	rm -f "${err}"
	trap - EXIT
	return "${rc}"
}

# ---------------------------------------------------------------------------

case "${1:-}" in
	up)             up ;;
	attach)         attach ;;
	detach)         detach ;;
	reload)         reload ;;
	status)         status ;;
	down)           down ;;
	test_icmp_echo) test_icmp_echo ;;
	test_http_get)  test_http_get ;;
	*)
		echo "usage: $0 {up|attach|reload|detach|status|down|test_icmp_echo|test_http_get}" >&2
		exit 2
		;;
esac
