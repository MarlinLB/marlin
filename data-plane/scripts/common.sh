#!/usr/bin/env bash
#
# Marlin — shared helpers for the per-mode WSL2 development rigs
# (l2dsr_wsl.sh, ipip_wsl.sh, gue_wsl.sh, vxlan_wsl.sh).
#
# Not a standalone script. Sourced after a rig has set its own parameter
# block (VIP, namespace/device names, PINDIR, MTU_UNDERLAY/MAX_FRAME, RIG_NAME,
# NS_ALL, ROOT_DEVS, HTTP_PORT if overridden) and before it defines its own
# up(), seed(), summary(), status(), be_docroot(), verify() and help(). Every
# function here reads those as globals rather than taking them as arguments,
# the same way the four rigs already shared them by copy-paste.
#
# What stays out of here, and why: up()/seed()/summary()/status()/be_docroot()
# differ by topology and wire format, not by accident; verify() differs by
# what each mode's assertions are. help() and the values it prints differ
# enough per rig (mode-specific fields, mode-specific watch commands) that
# folding it in here would just move the per-rig text into a parameter, not
# remove it.

# --- the BPF object, its pins, and the attach mode --------------------------
#
# Identical for every rig: SCRIPT_DIR is set by the caller (its own
# BASH_SOURCE[0], before this file is sourced), so OBJ resolves the same way
# regardless of which rig sourced this file.
OBJ="${MARLIN_OBJ:-${SCRIPT_DIR}/../build/bpf/marlin.bpf.o}"

# bpftool pins each program under its C function name, not its section name --
# SEC("xdp") int xdp_main() pins as xdp_main (data-plane/bpf/main.c).
PROG=xdp_main

# xdpgeneric per every rig's header; overridable to point at a native attach,
# which fails loudly rather than degrading (docs/design/02-architecture.md:31).
XDP_MODE="${XDP_MODE:-xdpgeneric}"
BPFFS=/sys/fs/bpf
BPFTOOL="${BPFTOOL:-bpftool}"

HTTP_PORT="${HTTP_PORT:-80}" # listen, test_http_get, and half of vip_map's key
                             # (balancer.c) -- seed() and the listener must agree

ABI_HDR="${SCRIPT_DIR}/../include/marlin/abi/defines.h"
RET_HDR="${SCRIPT_DIR}/../include/marlin/marlin.h"

# Real backend and VIP identifiers, not the reserved sentinel: backends[0] is
# never allocated (docs/design/10-map-invariants.md) and vip_num 0 is simply
# this rig's own, only entry in fwd_table's row space. Every rig seeds
# exactly one backend and one VIP, so both are fixed here instead of per rig.
BACKEND_ID=1
BACKEND_KEY="${BACKEND_ID} 0 0 0" # little-endian __u32 array key -- these rigs are x86_64-only
VIP_NUM=0
IPPROTO_TCP=6

# vip_map and fwd_table are written by tools/marlin_seed, not by a
# python/bpftool packer like backends and config below: vip_key's zeroed
# union and fwd_table's TABLE_SIZE rows are exactly the case pack_backend's
# own comment warns against re-mirroring by hand.
SEEDER="${MARLIN_SEEDER:-${SCRIPT_DIR}/../build/tools/marlin_seed}"

# ---------------------------------------------------------------------------
# Basic helpers
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

# The VIP goes on lo, per docs/design/14-forwarding-modes.md: the *inner*
# packet retains the VIP (or, for L2 DSR, the packet was never rewritten), so
# the backend must still hold it locally. lo is per-namespace, so nothing
# leaks into the WSL2 host.
#
# ARP/NDP suppression is load-bearing for L2 DSR, whose client shares a
# broadcast domain with the backend, and harmless-but-documented for the
# encapsulating modes, which share no segment with anything that would ask.
backend_vip() {
	local ns=$1 dev=$2
	nsx "${ns}" ip addr add "${VIP}/32" dev lo
	sc "${ns}" net.ipv4.conf.all.arp_ignore=1
	sc "${ns}" net.ipv4.conf.all.arp_announce=2
	sc "${ns}" "net.ipv4.conf.${dev}.arp_ignore=1"
	sc "${ns}" "net.ipv4.conf.${dev}.arp_announce=2"
}

# ---------------------------------------------------------------------------
# down
# ---------------------------------------------------------------------------

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
	echo "${RIG_NAME} rig down."
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
	echo "next: '$0 seed' -- until vip_map and backends[${BACKEND_ID}] are written, every packet passes"
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
# vip_map and fwd_table are seeded through marlin_seed (below); backends and
# config keep the python/bpftool packers, since neither needs a struct key or
# a 65536-row table.

need_seeder() {
	[[ -x ${SEEDER} ]] || {
		echo "no seeder binary at ${SEEDER} -- build it: make -C ${SCRIPT_DIR}/.. tools" >&2
		exit 1
	}
}

# vip_num is always 0: every rig configures exactly one VIP, so its
# fwd_table block never collides with another rig's pins. flags defaults to
# 0 (no ACL/RL/hash/QUIC bits, no DSCP marking); set VIP_FLAGS in the
# environment to exercise a marking, e.g. VIP_FLAGS=$((46 << 16)) for EF.
vip_seed() {
	local backend_id=$1
	need_seeder
	"${SEEDER}" add "${PINDIR}" "${VIP}" "${HTTP_PORT}" "${IPPROTO_TCP}" "${VIP_NUM}" "${VIP_FLAGS:-0}" "${backend_id}"
}

# Deletes the vip_map entry rather than zeroing it: a *present* entry
# pointing fwd_table at backend 0 would drop as no_backend (bpf/balancer.c),
# not restore the pass-through unseed() promises.
vip_unseed() {
	need_seeder
	"${SEEDER}" del "${PINDIR}" "${VIP}" "${HTTP_PORT}" "${IPPROTO_TCP}" "${VIP_NUM}"
}

vip_seeded() {
	[[ -e ${PINDIR}/vip_map ]] || return 1
	"${BPFTOOL}" -j map dump pinned "${PINDIR}/vip_map" 2>/dev/null | python3 -c '
import json, sys

try:
    entries = json.load(sys.stdin)
except ValueError:
    sys.exit(1)

sys.exit(0 if entries else 1)
'
}

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
#
# id is a fourth, always-available argument -- every call site passes
# ${BACKEND_ID} explicitly, since it must match the array slot the bpftool
# key below writes (docs/design/10-map-invariants.md: a populated slot's
# struct backend.id equals its own index; index 0 is never allocated).
# encap_dport/vni/inner_mac stay an optional tail after it: a mode that does
# not use one of those fields omits it, rather than writing a value and
# relying on the datapath to ignore it. l2dsr_wsl.sh and ipip_wsl.sh call
# this with four arguments only.
pack_backend() {
	python3 - "$@" <<'PY'
import socket, struct, sys

def mac_bytes(s):
    return bytes(int(x, 16) for x in s.split(":")) if s else b"\0" * 6

if len(sys.argv) < 5:
    sys.exit("id is required (the array slot this value will be written to)")

addr, mac, flags = sys.argv[1], sys.argv[2], int(sys.argv[3])
be_id       = int(sys.argv[4])
encap_dport = int(sys.argv[5]) if len(sys.argv) > 5 else 0
vni         = int(sys.argv[6]) if len(sys.argv) > 6 else 0
inner_mac   = sys.argv[7] if len(sys.argv) > 7 else ""

if not 0 <= be_id <= 0xffff:
    sys.exit("id out of range: %d" % be_id)
if not 0 <= encap_dport <= 0xffff:
    sys.exit("encap_dport out of range: %d" % encap_dport)
# MARLIN_VNI_MASK (include/marlin/abi/defines.h): the VXLAN header carries 24
# bits and the reserved byte behind them must stay clear.
if vni & ~0x00ffffff:
    sys.exit("vni exceeds the 24 bits the VXLAN header carries: %d" % vni)

raw = (socket.inet_aton(addr)              # __be32 addr             0-3
       + mac_bytes(mac)                    # __u8   mac[6]           4-9
       + struct.pack("!H", encap_dport)    # __be16 encap_dport     10-11
       + struct.pack("B", flags)           # __u8   flags            12
       + b"\0" * 3                         # __u8   pad[3]          13-15
       + struct.pack("=I", 0)              # __u32  egress_ifindex  16-19, 0 disables the check
       + struct.pack("=I", vni)            # __u32  vni             20-23, host order (bpf/vxlan.c)
       + mac_bytes(inner_mac)              # __u8   inner_mac[6]    24-29
       + struct.pack("=H", be_id))         # __u16  id              30-31, host order

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

# Decode backends[id] as bpftool returns it, and exit non-zero when the entry
# is not seeded. id defaults to ${BACKEND_ID}: every rig seeds exactly one.
#
# backends is a plain ARRAY, so `map dump` returns all MAX_BACKENDS entries in
# index order -- selecting by decoded key rather than positionally is what
# makes this keep working now that the seeded slot is not index 0.
#
# The offsets below are a third mirror of struct backend
# (include/marlin/abi/types.h) that would drift silently -- named BTF fields
# are checked against them here rather than trusted. mac/inner_mac are not
# BTF-checked: bpftool's rendering of a __u8[6] is less stable than a scalar's.
backend_show() {
	local id=${1:-${BACKEND_ID}} bit
	bit=$(abi_define MARLIN_BE_F_STATE_BIT)
	[[ -e ${PINDIR}/backends ]] || { echo "  no pins under ${PINDIR}"; return 1; }
	"${BPFTOOL}" -j map dump pinned "${PINDIR}/backends" 2>/dev/null | python3 -c '
import json, socket, struct, sys

state_bit = int(sys.argv[1])
want_id = int(sys.argv[2])

def num(v):
    if isinstance(v, list):
        return int("".join(b[2:] for b in reversed(v)), 16)
    return int(v)

try:
    entries = json.load(sys.stdin)
    entry = next(e for e in entries if num(e["key"]) == want_id)
except (ValueError, StopIteration):
    print("  backends[%d] is unreadable -- is the object still loaded?" % want_id)
    sys.exit(1)

raw = bytes(int(b, 16) for b in entry["value"])
addr, mac, flags = raw[0:4], raw[4:10], raw[12]
dport = struct.unpack("!H", raw[10:12])[0]
vni = struct.unpack("=I", raw[20:24])[0]
inner_mac = raw[24:30]
be_id = struct.unpack("=H", raw[30:32])[0]

btf = entry.get("formatted", {}).get("value")
if btf is not None:
    if (struct.pack("=I", btf["addr"] & 0xffffffff) != addr
            or int(btf["flags"]) != flags
            or struct.pack("=H", btf["encap_dport"] & 0xffff) != raw[10:12]
            or int(btf["vni"]) != vni
            or int(btf["id"]) != be_id):
        print("  BTF disagrees with the offsets this script packs: struct backend moved",
              file=sys.stderr)
        sys.exit(2)

up = (flags >> state_bit) & 1
print("  addr   %s" % socket.inet_ntoa(addr))
print("  mac    %s" % ":".join("%02x" % b for b in mac))
print("  dport  %u%s" % (dport, "" if dport else "  (0 = the mode default the datapath fills in)"))
print("  vni    %u" % vni)
print("  inner  %s" % ":".join("%02x" % b for b in inner_mac))
print("  id     %u" % be_id)
print("  flags  0x%02x  mode %u, state %s" % (flags, flags & 0x0f, "UP" if up else "DOWN"))
sys.exit(0 if up else 1)
' "${bit}" "${id}"
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
	[[ -e ${PINDIR}/backends && -e ${PINDIR}/vip_map && -e ${PINDIR}/fwd_table ]] || {
		echo "no pinned maps under ${PINDIR} -- run '$0 attach' first" >&2; exit 1; }
}

# Removes the vip_map entry before zeroing the backend, not after: with the
# order reversed there is a window where the VIP still matches and
# fwd_table still names this backend, but the backend itself is DOWN, which
# drops as backend_down (bpf/balancer.c) instead of the pass-through this
# promises. Deleting the VIP entry is what actually restores it --
# marlin_balancer_admit() returns MARLIN_PASS_VIP_MISS on the miss, which
# main.c maps to XDP_PASS.
unseed() {
	need_root
	need_cmd python3 "${BPFTOOL}"
	seed_or_die

	vip_unseed

	local value
	value=$(pack_backend 0.0.0.0 "" 0 0)
	# shellcheck disable=SC2086
	"${BPFTOOL}" map update pinned "${PINDIR}/backends" key ${BACKEND_KEY} value ${value}
	echo "vip_map entry removed and backends[${BACKEND_ID}] zeroed; ${PROG} passes every packet again."
	if [[ -e ${PINDIR}/config ]]; then
		echo "config left in place: it is read on every packet, before the VIP lookup."
	fi
}

# ---------------------------------------------------------------------------
# trace
# ---------------------------------------------------------------------------
#
# xdp_main writes a bpf_printk line per packet (bpf/main.c), which lands in the
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
# command's own. See verify() (per rig) for byte-level assertions.

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

# The listener argv, shared by listen() and test_http_get() so the two cannot
# come to disagree about what the backend serves or what it binds.
#
# --bind ${VIP} is load-bearing: only a listener bound to the VIP answers
# traffic that actually went through the datapath -- a wildcard bind would
# also answer traffic that arrived by ordinary routing or skipped the program.
#
# python3 -m http.server because it needs no configuration and is already the
# dependency stats_read() carries.
BE_HTTP_ARGV=()

be_http_argv() {
	BE_HTTP_ARGV=(python3 -m http.server "$1" --bind "${VIP}" --directory "$2")
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
	elif ! vip_seeded || ! backend_seeded; then
		echo "note: vip_map or backends[${BACKEND_ID}] is not seeded -- ${PROG} passes every packet" >&2
		echo "      (bpf/balancer.c). Run '$0 seed' in another terminal." >&2
	fi

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

Nothing else reaches it. Watch it with 'sudo $0 status' or 'sudo $0 trace'.
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

	if ! vip_seeded || ! backend_seeded; then
		echo "note: vip_map or backends[${BACKEND_ID}] is not seeded -- expect this GET to time out" >&2
	fi

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
# verify — byte-level assertions (docs/design/24-testing.md, "Integration tests")
# ---------------------------------------------------------------------------
#
# test_icmp_echo/test_http_get are drop_stats generators, deliberately not
# assertions (see the comment above ret_names). verify() is the other half:
# it captures the frame Marlin actually emits and checks it byte-for-byte.
# Redefined by gue_wsl.sh and vxlan_wsl.sh; a rig that does not define its own
# (l2dsr, ipip) falls through to this stub.
verify() {
	echo "no verify assertions are defined for the ${RIG_NAME} rig." >&2
	echo "drop_stats deltas from test_http_get / test_icmp_echo are the evidence here." >&2
	exit 1
}

# Captures on ${RT_A} in ${NS_RT} -- the leg the router receives Marlin's
# emitted frame on -- for the duration of one test_http_get run, then hands
# the pcap to a python callback for decoding. Root privilege and the pcap file
# are the caller's problem before/after; this only owns the capture window.
#
# tcpdump's own startup race (a capture that starts after the first packet)
# is closed by polling for the pcap's global header rather than a fixed sleep.
verify_capture() {
	local pcap=$1 rc=0 tries
	need_cmd tcpdump python3
	rig_up_or_die

	nsx "${NS_RT}" tcpdump -w "${pcap}" -i "${RT_A}" -U >/dev/null 2>&1 &
	local tcpdump_pid=$!
	trap 'kill "${tcpdump_pid}" 2>/dev/null || true; wait "${tcpdump_pid}" 2>/dev/null || true' RETURN

	for tries in $(seq 1 50); do
		[[ -s ${pcap} ]] && break
		sleep 0.1
	done
	# The pcap header only proves the file is open, not that the capture
	# socket is already receiving: promiscuous mode on a veth takes a moment
	# to take effect after pcap_activate(), and this rig's whole SYN-to-FIN
	# exchange is a loopback path that completes in single-digit milliseconds
	# -- fast enough to run entirely inside that gap and leave the pcap with
	# nothing but its own header.
	sleep 0.3

	test_http_get >/dev/null 2>&1 || rc=$?
	sleep 0.2 # let tcpdump flush the last packet of the run
	kill "${tcpdump_pid}" 2>/dev/null || true
	wait "${tcpdump_pid}" 2>/dev/null || true
	trap - RETURN

	if [[ ${rc} -ne 0 ]]; then
		echo "test_http_get did not complete (rc=${rc}); nothing to verify" >&2
		return 1
	fi
	return 0
}
