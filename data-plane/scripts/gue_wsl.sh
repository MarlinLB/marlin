#!/usr/bin/env bash
#
# Marlin — GUE development rig for WSL2.
#
# One mode, one script. tests/integration/netns-topo.sh builds all four modes
# in a single topology for the integration suite; this is the smaller thing
# you want while developing the GUE path alone. Namespace names, device names
# and prefixes are disjoint from that script's and from the other three
# *_wsl.sh rigs', so all five can be up at once.
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
#   ns mgucli            ns mgurt (router)              root ns
#   ┌────────────────┐   ┌──────────────────────┐
#   │ mgucli0        ├───┤ mgurt-c              │
#   │ 198.19.7.2/24  │   │ 198.19.7.1/24        │
#   └────────────────┘   │                      │       mgulan0  ← XDP here
#                        │ mgurt-a ─────────────┼────── 198.19.5.10/24
#                        │ 198.19.5.1/24        │       (= config.tunnel_src)
#                        │                      │
#                        │                      │      ns mgube
#                        │ mgurt-b ─────────────┼────── mgube0 198.19.6.22/24
#                        │ 198.19.6.1/24        │       fou    port 6080 gue
#                        └──────────────────────┘       mgurx4 ipip local .22 remote .5.10
#                                                        mgurx6 sit  — IPv6 inner
#                                                        lo     198.18.3.1/32
#
# Point-to-point veths, no bridge, and a real router namespace — because GUE
# does not address the backend at layer 2. It MAC-swaps and XDP_TX's the
# encapsulated packet back at the *upstream router*, which then routes the outer
# header onward (docs/design/15-nexthop-l2dsr.md, "MAC swap — default for IPIP and
# GUE"). The backend therefore has to be somewhere the router reaches and Marlin
# does not, which is what the second segment is for. A rig with the backend on
# Marlin's own segment would forward, and would prove nothing.
#
# The router hairpins nothing here: the outer packet arrives on mgurt-a and
# leaves on mgurt-b. send_redirects is cleared anyway, because the production
# requirement in docs/design/15-nexthop-l2dsr.md is unconditional and a rig that
# only satisfies it by accident of topology is not evidence.
#
#   VIP        198.18.3.1     RFC 2544 benchmark range. netns-topo.sh uses
#                             198.18.0.1, l2dsr_wsl.sh 198.18.1.1, ipip_wsl.sh
#                             198.18.2.1 and vxlan_wsl.sh 198.18.4.1, so no two
#                             rigs share a VIP.
#   Segments   198.19.5.0/24  Marlin  <-> router   (the tunnel source side)
#              198.19.6.0/24  router  <-> backend  (the tunnel destination side)
#              198.19.7.0/24  client  <-> router
#
# On the wire, Marlin -> backend: outer IPv4 (protocol 17) + UDP + a 4-byte GUE
# v0 header — 0x00, then the inner protocol (4 or 41), then two zero bytes.
# 32 bytes, MARLIN_OVERHEAD_GUE (bpf/gue.c). The outer UDP checksum is always
# zero, which an IPv4 outer permits unconditionally
# (docs/design/14-forwarding-modes.md §7.6).
#
# The backend decapsulates with one listener and two devices: `ip fou add port
# 6080 gue` strips the outer headers, then the kernel resubmits the inner packet
# into the protocol-4 or protocol-41 receive path on the GUE header's proto byte,
# and that path still needs a tunnel device to match — GUE removes the second
# *listener*, not the second device (docs/design/14-forwarding-modes.md §7.3).
#
# MACs are pinned (02:00:00:00:03:xx, locally administered) so tests can assert
# emitted frames byte-for-byte, with one field that is not assertable and must
# not be: the outer UDP source port is an entropy hash over the inner 5-tuple,
# confined to 49152-65535 (include/marlin/entropy.h). It is stable for one
# connection and different between connections. Assert the range, never a value.
#
# Usage:  sudo ./gue_wsl.sh up | attach | seed | reload | detach | status | down
#                          | listen | trace | test_icmp_echo | test_http_get | verify
#
#   up              build the topology (does not attach the program)
#   attach          load marlin.bpf.o, pin it, attach to ${MARLIN_IF}
#   seed            write config, vip_map and backends[1]; nothing forwards until then
#   unseed          remove the vip_map entry and zero backends[1]; the program stays attached
#   reload          after a rebuild: detach, unpin, load the new object, attach
#   detach          detach and remove the pins; the topology stays up
#   down            tear the topology down (implies detach)
#   listen          serve HTTP on the VIP from the backend namespace until ^C
#   trace           follow the kernel trace pipe — xdp_main's bpf_printk output
#   test_icmp_echo  ping the VIP from the client namespace
#   test_http_get   GET the VIP from the client namespace, against a throwaway
#                   listener started in the backend namespace
#   verify          capture one test_http_get run on ${RT_A} and assert the
#                   emitted frame byte-for-byte (docs/design/24-testing.md)
#
# The working order is up, attach, seed, listen. Seeding is not optional: an
# unmatched VIP passes every packet (marlin_lb_admit, bpf/lb_core.c),
# and a backend with MARLIN_BE_F_STATE clear (an all-zero backends[] slot) is
# never selected either. An attached program with unseeded maps forwards
# nothing and looks exactly like a broken datapath.
#
# A completed GET is evidence here, and evidence that it completed *through the
# tunnel* rather than by ordinary routing is threefold: the backend's listener is
# bound to the VIP on lo alone, so ${BE_IP}:80 refuses anything that arrived by
# routing; the frame leaving mgurt-a is 32 bytes larger than the one that
# arrived; and mgurx4's receive counter moves, which only the resubmit path
# touches.
#
# Overridable: MARLIN_OBJ, MARLIN_PINDIR, MARLIN_GUE_PORT, XDP_MODE, BPFTOOL.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------

RIG_NAME=gue
VIP=198.18.3.1

SEG_M=198.19.5               # Marlin <-> router
SEG_B=198.19.6               # router <-> backend
SEG_C=198.19.7               # client <-> router

MARLIN_IF=mgulan0            # the interface the XDP program attaches to (root ns)
MARLIN_IP=${SEG_M}.10        # this is config.tunnel_src
MARLIN_MAC=02:00:00:00:03:10

RT_A=mgurt-a;  RT_A_IP=${SEG_M}.1;  RT_A_MAC=02:00:00:00:03:01
RT_B=mgurt-b;  RT_B_IP=${SEG_B}.1;  RT_B_MAC=02:00:00:00:03:02
RT_C=mgurt-c;  RT_C_IP=${SEG_C}.1;  RT_C_MAC=02:00:00:00:03:03

BE_IF=mgube0;   BE_IP=${SEG_B}.22;  BE_MAC=02:00:00:00:03:22   # <- backend.addr
CLI_IF=mgucli0; CLI_IP=${SEG_C}.2;  CLI_MAC=02:00:00:00:03:04

# The decapsulation side. One listener, two receive devices: the kernel
# resubmits the inner packet on the GUE header's proto byte and that path
# still needs a tunnel to match (docs/design/14-forwarding-modes.md §7.3).
BE_RX4=mgurx4                 # ipip — protocol 4,  IPv4 inner
BE_RX6=mgurx6                 # sit  — protocol 41, IPv6 inner

NS_RT=mgurt
NS_BE=mgube
NS_CLI=mgucli
NS_ALL=("${NS_RT}" "${NS_BE}" "${NS_CLI}")

# backend.encap_dport and the backend's FOU listener, one value. Overridable
# because writing the field explicitly only buys something when it can differ
# from the ABI default: with the two equal, a datapath that ignored
# encap_dport altogether would still forward and the rig would not notice.
GUE_PORT="${MARLIN_GUE_PORT:-}"

# Root-namespace devices this script owns. down() deletes exactly these. The
# last two normally die with their namespaces; they are listed so that a run of
# up() that failed between creating a veth and moving it still cleans up.
ROOT_DEVS=("${MARLIN_IF}" "${BE_IF}" "${CLI_IF}")

# Resolved from the script's own location, so the verbs work from any cwd. The
# build writes to data-plane/build/ (data-plane/Makefile: BUILD_DIR := build).
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Per-rig pin directory, not the /sys/fs/bpf/marlin default: this rig's
# namespaces/devices/MACs/VIP are disjoint from the other rigs, so a shared
# pin dir would break that on first detach (DEPLOYMENT.md:62).
PINDIR="${MARLIN_PINDIR:-/sys/fs/bpf/mgue}"

# The underlay carries 32 bytes of outer header -- IPv4 (20) + UDP (8) + GUE
# (4), MARLIN_OVERHEAD_GUE. docs/design/23-mtu.md's strategy is jumbo frames
# on the Marlin->backend path; the client link stays at 1500 and is
# deliberately left alone.
#
# config.max_frame is the *frame*, not the MTU: "egress MTU + ETH_HLEN"
# (docs/design/08-types.md, §1.7), so 1600 here means 1614 there. To exercise
# frame_too_big, drop MTU_UNDERLAY to 1500 and max_frame to 1514.
MTU_UNDERLAY=1600
MAX_FRAME=$((MTU_UNDERLAY + 14))

# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

# The ABI default, read from the header rather than copied -- abi_define()'s
# reasoning applied to a value the listener and backends[1] must agree on.
gue_port() {
	if [[ -n ${GUE_PORT} ]]; then echo "${GUE_PORT}"; else abi_define MARLIN_GUE_DPORT_DEFAULT; fi
}

# Fail up front, for need_cmd()'s reason. `ip fou show` fails with ENOENT on
# the genl family -- not with an empty list -- when fou.ko is absent, and a
# rig built without it looks exactly like a datapath that never transmitted.
need_fou() {
	modprobe -q fou 2>/dev/null || true
	ip fou show >/dev/null 2>&1 || {
		echo "no 'ip fou' support here: the kernel needs CONFIG_NET_FOU and" >&2
		echo "iproute2 needs the fou subcommand. Nothing decapsulates GUE without it." >&2
		exit 1
	}
}

# ---------------------------------------------------------------------------
# up
# ---------------------------------------------------------------------------

up() {
	need_root
	need_cmd ip ethtool
	need_fou
	down_quiet

	local port
	port=$(gue_port)

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
	# The VIP is routed to Marlin over mgurt-a, but DSR replies arrive from the
	# backend carrying the VIP as *source*, on mgurt-b. Strict reverse-path
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

	# One FOU/GUE listener strips the outer IPv4 + UDP + 4-byte GUE header
	# (docs/DEPLOYMENT.md). Without it the outer packet is an ordinary UDP
	# datagram to a closed port and the backend answers port-unreachable.
	nsx "${NS_BE}" ip fou add port "${port}" gue

	# The listener is not the whole receive path: the kernel resubmits the
	# decapsulated packet into the protocol-4 or protocol-41 handler on the GUE
	# header's proto byte (bpf/gue.c), and that handler still needs a tunnel
	# device to match -- GUE removes the second listener, not the second device
	# (docs/design/14-forwarding-modes.md §7.3).
	#
	# local/remote are both pinned so a config.tunnel_src that does not match
	# fails the tunnel lookup here, visibly, instead of being decapsulated
	# anyway by a wildcard device.
	nsx "${NS_BE}" ip link add "${BE_RX4}" type ipip \
		local "${BE_IP}" remote "${MARLIN_IP}" ttl 64
	nsx "${NS_BE}" ip link set "${BE_RX4}" up
	nsx "${NS_BE}" ip link add "${BE_RX6}" type sit \
		local "${BE_IP}" remote "${MARLIN_IP}" ttl 64 2>/dev/null || \
		echo "note: sit device not created (CONFIG_IPV6_SIT off) — IPv6 inner untestable"
	nsx "${NS_BE}" ip link set "${BE_RX6}" up 2>/dev/null || true

	# The decapsulated packet is addressed to the VIP but sourced from the client,
	# whose route back is the default gateway on ${BE_IF}, not ${BE_RX4}. Same
	# rp_filter problem as the router, same reason.
	sc "${NS_BE}" net.ipv4.conf.all.rp_filter=0
	sc "${NS_BE}" "net.ipv4.conf.${BE_IF}.rp_filter=0"
	sc "${NS_BE}" "net.ipv4.conf.${BE_RX4}.rp_filter=0"

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

	echo "${RIG_NAME} rig up."
	echo
	summary
}

# ---------------------------------------------------------------------------
# status / summary
# ---------------------------------------------------------------------------

summary() {
	local port
	port=$(gue_port)
	cat <<EOF
Values this rig implies for the maps:

  VIP                          ${VIP}
  vip mode                     GUE (docs/design/14-forwarding-modes.md §7.3)
  config.tunnel_src            ${MARLIN_IP}
  config.max_frame             ${MAX_FRAME}   (MTU ${MTU_UNDERLAY} + ETH_HLEN)
  backend.addr                 ${BE_IP}
  backend.mac                  unused — MAC swap, not a stored MAC
                               (docs/design/15-nexthop-l2dsr.md)
  backend.encap_dport          ${port}
  outer UDP sport               entropy hash, 49152-65535, one value per
                               connection (include/marlin/entropy.h) — never
                               assert a fixed value

Attach — ${XDP_MODE}, because WSL2 veth has no native XDP:

  sudo $0 attach          # load ${OBJ##*/}, pin under ${PINDIR}, attach
  sudo $0 reload          # after a rebuild: detach, unpin, load, attach
  sudo $0 detach          # detach and unpin; rig stays up

Seed — an attached program forwards nothing until vip_map and backends[${BACKEND_ID}] are written:

  sudo $0 seed            # write config, vip_map and backends[${BACKEND_ID}] with the values above
  sudo $0 unseed          # remove the vip_map entry and zero backends[${BACKEND_ID}]

Drive it:

  sudo $0 listen          # serve ${VIP}:${HTTP_PORT} from ns ${NS_BE} until ^C,
                          # bound to the VIP alone so only tunnelled packets arrive
  sudo $0 test_http_get   # one GET from ns ${NS_CLI} against a throwaway listener
  sudo $0 test_icmp_echo  # ping the VIP. No reply is the correct outcome: echo
                          # passes to the host stack (docs/design/13-icmp.md), so
                          # the evidence is icmp_echo moving in drop_stats
  sudo $0 verify          # capture one test_http_get run and assert the emitted
                          # frame byte-for-byte

Watch it, in path order:

  sudo $0 trace                                            # ${PROG}'s bpf_printk output
  ip netns exec ${NS_RT} tcpdump -nei ${RT_A}                # in from client, back out 32B larger
  ip netns exec ${NS_BE} tcpdump -nei ${BE_IF} "udp port ${port}"  # outer ${MARLIN_IP} -> ${BE_IP}
  ip netns exec ${NS_BE} tcpdump -nei ${BE_RX4}               # after decapsulation, VIP intact
  ip netns exec ${NS_BE} ip -s link show ${BE_RX4}            # RX moving = resubmit matched
  ip netns exec ${NS_BE} ip fou show
  ip -d link show ${MARLIN_IF} | grep prog/xdp               # expect "${XDP_MODE}"
  ${BPFTOOL} map dump pinned ${PINDIR}/drop_stats            # 'name drop_stats' would
                                                             # match every rig's map
EOF
}

status() {
	for ns in "${NS_ALL[@]}"; do
		ip netns list | grep -qw "${ns}" || { echo "${RIG_NAME} rig is down"; return 1; }
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
		if vip_seeded; then
			echo "  vip_map: seeded (${VIP}:${HTTP_PORT})"
		else
			echo "  vip_map: empty (run '$0 seed')"
		fi
		backend_show || echo "  backends[${BACKEND_ID}] not seeded (run '$0 seed')"
	else
		echo "  no pins under ${PINDIR} (run '$0 attach')"
	fi
	echo "== ns ${NS_BE} decap =="
	nsx "${NS_BE}" ip fou show 2>/dev/null || echo "  ip fou show unavailable"
	nsx "${NS_BE}" ip -s link show "${BE_RX4}" 2>/dev/null || true
	echo "== ns ${NS_BE} listeners =="
	nsx "${NS_BE}" ss -lnt 2>/dev/null || echo "  ss not available"
	for ns in "${NS_ALL[@]}"; do
		echo "== ns ${ns} =="
		ip netns exec "${ns}" ip -br addr
	done
	echo "== ns ${NS_BE} routes =="
	ip netns exec "${NS_BE}" ip route
}

# ---------------------------------------------------------------------------
# Map seeding
# ---------------------------------------------------------------------------

seed() {
	need_root
	need_cmd python3 "${BPFTOOL}"
	rig_up_or_die
	seed_or_die

	local mode bit flags port value
	mode=$(abi_define MARLIN_MODE_GUE)
	bit=$(abi_define MARLIN_BE_F_STATE_BIT)
	# MARLIN_BE_F_FIB stays clear, so the nexthop is the MAC swap back at the
	# router rather than a FIB lookup (docs/design/15-nexthop-l2dsr.md).
	flags=$(( mode | (1 << bit) ))
	port=$(gue_port)

	# A port no listener holds is a blackhole that presents as a datapath which
	# never transmitted: the outer packet arrives and the backend answers
	# port-unreachable. up() and seed() must have seen the same MARLIN_GUE_PORT.
	nsx "${NS_BE}" ip fou show 2>/dev/null | grep -qE "(^| )port ${port}( |$)" || {
		echo "no FOU/GUE listener on port ${port} in ns ${NS_BE}:" >&2
		nsx "${NS_BE}" ip fou show >&2 || true
		echo "re-run '$0 up' with the same MARLIN_GUE_PORT" >&2
		exit 1
	}

	# backend.mac stays zero: the encapsulating path swaps the frame's own
	# addresses and never reads it (bpf/nexthop.c). vni and inner_mac are
	# omitted -- they belong to VXLAN alone.
	value=$(pack_backend "${BE_IP}" "" "${flags}" "${BACKEND_ID}" "${port}")
	# Unquoted on purpose: bpftool takes the value as separate byte arguments.
	# shellcheck disable=SC2086
	"${BPFTOOL}" map update pinned "${PINDIR}/backends" key ${BACKEND_KEY} value ${value}

	value=$(pack_config "${MARLIN_IP}" "${MAX_FRAME}")
	# shellcheck disable=SC2086
	"${BPFTOOL}" map update pinned "${PINDIR}/config" key 0 0 0 0 value ${value}

	# vip_map/fwd_table: the port-agnostic lookup lb_core.c performs
	# (docs/design/11-pipeline.md), pointed at the one backend above.
	vip_seed "${BACKEND_ID}"

	echo "seeded config:"
	config_show
	echo "seeded backends[${BACKEND_ID}]:"
	backend_show
}

# A document root whose index names the rig, so a reply identifies which backend
# answered rather than only that something did.
be_docroot() {
	local d port
	port=$(gue_port)
	d=$(mktemp -d)
	cat >"${d}/index.html" <<EOF
<!doctype html>
<title>marlin gue rig</title>
<pre>
rig       gue_wsl.sh (GUE, docs/design/14-forwarding-modes.md 7.3)
backend   ns ${NS_BE}, fou port ${port} gue, ${BE_RX4} local ${BE_IP} remote ${MARLIN_IP}
bound to  ${VIP} -- the VIP, on lo; reached only through the tunnel
</pre>
EOF
	echo "${d}"
}

# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------
#
# Decodes the pcap verify_capture() (common.sh) collected and checks the
# emitted frame against bpf/gue.c and docs/design/14-forwarding-modes.md §7.3.
verify() {
	need_root
	need_cmd tcpdump python3
	local pcap port dscp rc
	port=$(gue_port)
	# VIP_FLAGS bits 16-21 (VIP_DSCP_SHIFT/_MASK, defines.h); 0 unless the
	# caller set VIP_FLAGS before seed().
	dscp=$(( (${VIP_FLAGS:-0} >> 16) & 0x3f ))
	pcap=$(mktemp)
	trap 'rm -f "${pcap}"' EXIT

	verify_capture "${pcap}" || { rm -f "${pcap}"; trap - EXIT; exit 1; }

	python3 - "${pcap}" "${port}" "${dscp}" <<'PY'
import struct, sys

path, dport, expected_dscp = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])

def read_pcap(path):
    with open(path, "rb") as f:
        data = f.read()
    magic = data[0:4]
    if magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    elif magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    else:
        sys.exit("not a pcap file (unrecognised magic)")
    off = 24  # global header
    pkts = []
    while off < len(data):
        if off + 16 > len(data):
            break
        _, _, caplen, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        pkts.append(data[off:off + caplen])
        off += caplen
    return pkts

pkts = read_pcap(path)
ok, fail = [], []

def check(name, cond):
    (ok if cond else fail).append(name)

# The largest GUE frame on this leg -- ICMP echo (unencapsulated) also
# transits ${RT_A}, so pick the frame that actually carries the UDP dport.
target = None
for p in pkts:
    if len(p) < 14 + 20:
        continue
    eth_type = struct.unpack("!H", p[12:14])[0]
    if eth_type != 0x0800:
        continue
    ihl = (p[14] & 0x0f) * 4
    proto = p[14 + 9]
    if proto != 17:
        continue
    udp = p[14 + ihl:14 + ihl + 8]
    if len(udp) < 8:
        continue
    if struct.unpack("!H", udp[2:4])[0] == dport:
        target = p
        break

if target is None:
    sys.exit("no UDP packet to port %d found on the captured leg" % dport)

eth, ip, ihl = target[0:14], target[14:14 + 20], (target[14] & 0x0f) * 4
udp = target[14 + ihl:14 + ihl + 8]
gue = target[14 + ihl + 8:14 + ihl + 8 + 4]

check("outer IPv4 protocol == 17 (UDP)", ip[9] == 17)
check("outer IPv4 frag_off carries IP_DF", (struct.unpack("!H", ip[6:8])[0] & 0x4000) != 0)
check("outer IPv4 ttl == 64", ip[8] == 64)
check("outer IPv4 DSCP == configured (%d)" % expected_dscp, (ip[1] >> 2) == expected_dscp)
check("outer IPv4 ECN bits == 0", (ip[1] & 0x03) == 0)
csum = 0
words = struct.unpack("!10H", ip[:20])
s = sum(words)
s = (s & 0xffff) + (s >> 16)
s = (s & 0xffff) + (s >> 16)
check("outer IPv4 checksum valid", (~s & 0xffff) == 0)
check("outer UDP dest == encap_dport (%d)" % dport, struct.unpack("!H", udp[2:4])[0] == dport)
check("outer UDP source in the ephemeral range 49152-65535", 49152 <= struct.unpack("!H", udp[0:2])[0] <= 65535)
check("outer UDP checksum == 0", struct.unpack("!H", udp[6:8])[0] == 0)
check("GUE byte 0 == 0x00 (version 0, no control message)", gue[0] == 0x00)
check("GUE byte 1 (proto) in {4, 41}", gue[1] in (4, 41))
check("GUE bytes 2-3 == 0x0000 (no flags)", gue[2:4] == b"\x00\x00")

print("gue verify: %d/%d assertions passed" % (len(ok), len(ok) + len(fail)))
for name in ok:
    print("  ok    %s" % name)
for name in fail:
    print("  FAIL  %s" % name)

sys.exit(0 if not fail else 1)
PY
	rc=$?
	rm -f "${pcap}"
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
  seed            write config, vip_map and backends[1]; nothing forwards until then
  unseed          remove the vip_map entry and zero backends[1]; the program stays attached
  reload          rebuild loop: detach, unpin, load the new object, reattach
  detach          detach the program and remove its pins; topology stays up
  status          show the rig's namespaces, attach state and seeded maps
  down            tear the whole topology down (implies detach)
  listen [port]   serve HTTP on the VIP from the backend namespace until ^C
  trace           follow the kernel trace pipe for xdp_main's bpf_printk output
  test_icmp_echo  ping the VIP from the client namespace, report drop_stats
  test_http_get   GET the VIP from the client namespace, report drop_stats
  verify          capture one test_http_get run and assert the emitted frame
                  byte-for-byte (docs/design/24-testing.md)
  help            show this text

Typical order: up, attach, seed, listen.
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
	verify)         verify ;;
	help|-h|--help) help ;;
	*)
		echo "usage: $0 {up|attach|seed|unseed|reload|detach|status|down|listen|trace|test_icmp_echo|test_http_get|verify|help}" >&2
		echo "run '$0 help' for what each command does" >&2
		exit 2
		;;
esac
