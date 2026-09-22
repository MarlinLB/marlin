#!/usr/bin/env bash
#
# Marlin — VXLAN development rig for WSL2.
#
# One mode, one script. tests/integration/netns-topo.sh builds all four modes
# in a single topology for the integration suite; this is the smaller thing
# you want while developing the VXLAN path alone. Namespace names, device
# names and prefixes are disjoint from that script's and from the other three
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
#   ns mvxcli            ns mvxrt (router)              root ns
#   ┌────────────────┐   ┌──────────────────────┐
#   │ mvxcli0        ├───┤ mvxrt-c              │
#   │ 198.19.10.2/24 │   │ 198.19.10.1/24       │
#   └────────────────┘   │                      │       mvxlan0  ← XDP here
#                        │ mvxrt-a ─────────────┼────── 198.19.8.10/24
#                        │ 198.19.8.1/24        │       (= config.tunnel_src)
#                        │                      │
#                        │                      │      ns mvxbe
#                        │ mvxrt-b ─────────────┼────── mvxbe0 198.19.9.22/24
#                        │ 198.19.9.1/24        │       mvxbr0 vxlan id 100 dstport 4789
#                        └──────────────────────┘              local .22
#                                                        lo     198.18.4.1/32
#
# Point-to-point veths, no bridge, and a real router namespace. VXLAN writes
# its own outer Ethernet header rather than going through the step-9 MAC swap
# (marlin_nexthop_encapsulate() returns immediately for MARLIN_MODE_VXLAN,
# bpf/nexthop.c), but it writes the *same* addresses the swap would have --
# outer dst = the arriving frame's source (the router), outer src = Marlin's
# own -- so the topology need is identical to IPIP/GUE's: a router the
# backend sits behind, on a second segment Marlin does not reach directly.
#
#   VIP        198.18.4.1     RFC 2544 benchmark range. netns-topo.sh uses
#                             198.18.0.1, l2dsr_wsl.sh 198.18.1.1, ipip_wsl.sh
#                             198.18.2.1 and gue_wsl.sh 198.18.3.1, so no two
#                             rigs share a VIP.
#   Segments   198.19.8.0/24  Marlin  <-> router   (the tunnel source side)
#              198.19.9.0/24  router  <-> backend  (the tunnel destination side)
#              198.19.10.0/24 client  <-> router
#
# On the wire, Marlin -> backend: a NEW outer Ethernet header, then outer IPv4
# (protocol 17) + UDP + an 8-byte VXLAN header, then the arriving frame's OWN
# Ethernet header (relocated, with its destination rewritten to
# backend.inner_mac and its source to Marlin's own MAC), then the arriving IP
# packet unchanged. 50 bytes of new header, MARLIN_OVERHEAD_VXLAN (bpf/vxlan.c).
# The outer UDP checksum is always zero, permitted unconditionally with an
# IPv4 outer (docs/design/14-forwarding-modes.md §7.6).
#
# The ordering inside vxlan.c is load-bearing (§7.4): both arriving MAC
# addresses are read and saved *before* bpf_xdp_adjust_head() invalidates the
# pointer that held them, because that adjust also relocates the arriving
# header to become the inner one. An implementation that rewrote the inner
# header first would destroy the addresses the outer header needs -- this is
# the one property no other mode's rig can exercise, because no other mode
# consumes the arriving header this way. See verify().
#
# The backend decapsulates with one device: a `vxlan` netdev with the matching
# VNI and dstport handles both inner families itself, since the family is
# carried in the inner EtherType, not chosen by the receiving device
# (docs/design/14-forwarding-modes.md §7.4). dstport must be given explicitly
# -- the Linux vxlan netdev's own default is 8472, not the IANA 4789 Marlin
# uses, and a device left at that default silently never matches.
#
# The VIP goes on lo, matching the other *_wsl.sh rigs, not on the vxlan
# device itself. Production placement is still open
# (docs/PHASES.md, "VXLAN backend VIP placement"); this rig assumes lo.
#
# MACs are pinned (02:00:00:00:04:xx, locally administered) so tests can assert
# emitted frames byte-for-byte, with one field that is not assertable and must
# not be: the outer UDP source port is an entropy hash over the inner 5-tuple,
# confined to 49152-65535 (include/marlin/entropy.h), the same value GUE uses.
# It is stable for one connection and different between connections. Assert
# the range, never a value.
#
# Usage:  sudo ./vxlan_wsl.sh up | attach | seed | reload | detach | status | down
#                            | listen | trace | test_icmp_echo | test_http_get | verify
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
# routing; the frame leaving mvxrt-a is 50 bytes larger than the one that
# arrived; and mvxbr0's receive counter moves, which only the decap path touches.
#
# Overridable: MARLIN_OBJ, MARLIN_PINDIR, MARLIN_VXLAN_PORT, MARLIN_VNI,
# MARLIN_INNER_MAC, XDP_MODE, BPFTOOL.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------

RIG_NAME=vxlan
VIP=198.18.4.1

SEG_M=198.19.8                # Marlin <-> router
SEG_B=198.19.9                # router <-> backend
SEG_C=198.19.10               # client <-> router

MARLIN_IF=mvxlan0            # the interface the XDP program attaches to (root ns)
MARLIN_IP=${SEG_M}.10        # this is config.tunnel_src
MARLIN_MAC=02:00:00:00:04:10

RT_A=mvxrt-a;  RT_A_IP=${SEG_M}.1;  RT_A_MAC=02:00:00:00:04:01
RT_B=mvxrt-b;  RT_B_IP=${SEG_B}.1;  RT_B_MAC=02:00:00:00:04:02
RT_C=mvxrt-c;  RT_C_IP=${SEG_C}.1;  RT_C_MAC=02:00:00:00:04:03

BE_IF=mvxbe0;   BE_IP=${SEG_B}.22;  BE_MAC=02:00:00:00:04:22   # <- backend.addr
CLI_IF=mvxcli0; CLI_IP=${SEG_C}.2;  CLI_MAC=02:00:00:00:04:04

# The decapsulation device and the inner destination MAC backend.inner_mac
# points at -- both pinned here, like every other MAC, so seed() and up() can
# never disagree about what the backend presents.
BE_VXDEV=mvxbr0
INNER_MAC="${MARLIN_INNER_MAC:-02:00:00:00:04:23}"

NS_RT=mvxrt
NS_BE=mvxbe
NS_CLI=mvxcli
NS_ALL=("${NS_RT}" "${NS_BE}" "${NS_CLI}")

# backend.vni and backend.encap_dport. Overridable for the same reason
# gue_wsl.sh's GUE_PORT is: with the ABI default and the wire value equal, a
# datapath that ignored either field would still forward undetected.
VNI="${MARLIN_VNI:-100}"
VXLAN_PORT="${MARLIN_VXLAN_PORT:-}"

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
PINDIR="${MARLIN_PINDIR:-/sys/fs/bpf/mvxlan}"

# The underlay carries 50 bytes of outer header -- Ethernet (14) + IPv4 (20) +
# UDP (8) + VXLAN (8), MARLIN_OVERHEAD_VXLAN. docs/design/23-mtu.md's strategy
# is jumbo frames on the Marlin->backend path; the client link stays at 1500
# and is deliberately left alone.
#
# config.max_frame is the *frame*, not the MTU: "egress MTU + ETH_HLEN"
# (docs/design/08-types.md, §1.7), so 1600 here means 1614 there. To exercise
# frame_too_big, drop MTU_UNDERLAY to 1500 and max_frame to 1514.
MTU_UNDERLAY=1600
MAX_FRAME=$((MTU_UNDERLAY + 14))

# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

# The ABI default, read from the header rather than copied -- abi_define()'s
# reasoning applied to a value the vxlan device and backends[1] must agree on.
vxlan_port() {
	if [[ -n ${VXLAN_PORT} ]]; then echo "${VXLAN_PORT}"; else abi_define MARLIN_VXLAN_DPORT_DEFAULT; fi
}

# ---------------------------------------------------------------------------
# up
# ---------------------------------------------------------------------------

up() {
	need_root
	need_cmd ip ethtool
	down_quiet

	local port
	port=$(vxlan_port)

	modprobe -q veth  2>/dev/null || true
	modprobe -q vxlan 2>/dev/null || true

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
	# The VIP is routed to Marlin over mvxrt-a, but DSR replies arrive from the
	# backend carrying the VIP as *source*, on mvxrt-b. Strict reverse-path
	# filtering drops exactly that. This is a property of DSR, not of the rig.
	sc "${NS_RT}" net.ipv4.conf.all.rp_filter=0
	sc "${NS_RT}" net.ipv4.conf.default.rp_filter=0
	sc "${NS_RT}" "net.ipv4.conf.${RT_A}.rp_filter=0"
	sc "${NS_RT}" "net.ipv4.conf.${RT_B}.rp_filter=0"
	# docs/design/15-nexthop-l2dsr.md's suppression requirement is unconditional;
	# vxlan.c writes the same addresses the MAC swap would have, so the same
	# rule applies on the segment those addresses point back at.
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

	# One device handles both inner families: the family is the inner
	# EtherType, which the arriving frame already set and vxlan.c leaves alone
	# (docs/design/14-forwarding-modes.md §7.4) -- unlike GUE, there is no
	# second receive device to add.
	#
	# dstport must be explicit: the vxlan netdev's own default is 8472, not the
	# IANA 4789 Marlin uses, and a device left at that default silently never
	# matches. `remote` takes an IP_ADDRESS, not `any` -- unlike ipip/sit, a
	# vxlan device omits it outright when there is no default FDB entry to give.
	nsx "${NS_BE}" ip link add "${BE_VXDEV}" type vxlan \
		id "${VNI}" dstport "${port}" local "${BE_IP}"
	nsx "${NS_BE}" ip link set "${BE_VXDEV}" address "${INNER_MAC}"
	nsx "${NS_BE}" ip link set "${BE_VXDEV}" up

	# The decapsulated packet is addressed to the VIP but sourced from the client,
	# whose route back is the default gateway on ${BE_IF}, not ${BE_VXDEV}. Same
	# rp_filter problem as the router, same reason.
	sc "${NS_BE}" net.ipv4.conf.all.rp_filter=0
	sc "${NS_BE}" "net.ipv4.conf.${BE_IF}.rp_filter=0"
	sc "${NS_BE}" "net.ipv4.conf.${BE_VXDEV}.rp_filter=0"

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
	port=$(vxlan_port)
	cat <<EOF
Values this rig implies for the maps:

  VIP                          ${VIP}
  vip mode                     VXLAN (docs/design/14-forwarding-modes.md §7.4)
  config.tunnel_src            ${MARLIN_IP}
  config.max_frame             ${MAX_FRAME}   (MTU ${MTU_UNDERLAY} + ETH_HLEN)
  backend.addr                 ${BE_IP}
  backend.mac                  unused — vxlan.c writes the outer header itself
                               (bpf/nexthop.c returns MARLIN_OK_TX immediately
                               for MARLIN_MODE_VXLAN)
  backend.encap_dport          ${port}
  backend.vni                  ${VNI}
  backend.inner_mac            ${INNER_MAC}   (= ${BE_VXDEV}'s own address)
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
                          # frame byte-for-byte, including the inner/outer
                          # Ethernet ordering (docs/design/24-testing.md)

Watch it, in path order:

  sudo $0 trace                                             # ${PROG}'s bpf_printk output
  ip netns exec ${NS_RT} tcpdump -nei ${RT_A}                 # in from client, back out 50B larger
  ip netns exec ${NS_BE} tcpdump -nei ${BE_IF} "udp port ${port}"  # outer ${MARLIN_IP} -> ${BE_IP}
  ip netns exec ${NS_BE} tcpdump -nei ${BE_VXDEV}             # after decapsulation, VIP intact
  ip netns exec ${NS_BE} ip -s link show ${BE_VXDEV}          # RX moving = decap matched
  ip -d link show ${MARLIN_IF} | grep prog/xdp                # expect "${XDP_MODE}"
  ${BPFTOOL} map dump pinned ${PINDIR}/drop_stats             # 'name drop_stats' would
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
	nsx "${NS_BE}" ip -d link show "${BE_VXDEV}" 2>/dev/null || echo "  ${BE_VXDEV} not present"
	nsx "${NS_BE}" ip -s link show "${BE_VXDEV}" 2>/dev/null || true
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
	mode=$(abi_define MARLIN_MODE_VXLAN)
	bit=$(abi_define MARLIN_BE_F_STATE_BIT)
	# MARLIN_BE_F_FIB stays clear: vxlan.c writes the outer header itself, so
	# neither the MAC swap nor the FIB lookup runs (bpf/nexthop.c).
	flags=$(( mode | (1 << bit) ))
	port=$(vxlan_port)

	nsx "${NS_BE}" ip -d link show "${BE_VXDEV}" 2>/dev/null | grep -q "vxlan id ${VNI} " || {
		echo "no vxlan device ${BE_VXDEV} with id ${VNI} in ns ${NS_BE}:" >&2
		nsx "${NS_BE}" ip -d link show "${BE_VXDEV}" >&2 || true
		echo "re-run '$0 up' with the same MARLIN_VNI" >&2
		exit 1
	}

	# backend.mac stays zero -- see summary() for why. inner_mac must match
	# what the backend's vxlan device presents, or the decapsulated frame
	# arrives addressed to a MAC the device does not answer to.
	value=$(pack_backend "${BE_IP}" "" "${flags}" "${BACKEND_ID}" "${port}" "${VNI}" "${INNER_MAC}")
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
	port=$(vxlan_port)
	d=$(mktemp -d)
	cat >"${d}/index.html" <<EOF
<!doctype html>
<title>marlin vxlan rig</title>
<pre>
rig       vxlan_wsl.sh (VXLAN, docs/design/14-forwarding-modes.md 7.4)
backend   ns ${NS_BE}, ${BE_VXDEV} vni ${VNI} dstport ${port} local ${BE_IP}
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
# emitted frame against bpf/vxlan.c and the assertion list at
# docs/design/24-testing.md ("VXLAN-specific assertions").
#
# Two assertions from that list are not reachable here and are not faked:
#   - a 50-byte headroom shortfall counted adjust_head_failed: generic XDP
#     guarantees XDP_PACKET_HEADROOM (256 bytes), so this rig cannot produce
#     the shortfall. It belongs to the packet tier or a native-driver rig.
#   - inner EtherType distinguishing IPv4 from IPv6 on one device: this rig's
#     client is IPv4-only. Already covered at the packet tier
#     (tests/packet/xdp_45_encap.c); a v6 client leg is a follow-up, not this rig.
verify() {
	need_root
	need_cmd tcpdump python3
	local pcap port dscp rc
	port=$(vxlan_port)
	# VIP_FLAGS bits 16-21 (VIP_DSCP_SHIFT/_MASK, defines.h); 0 unless the
	# caller set VIP_FLAGS before seed().
	dscp=$(( (${VIP_FLAGS:-0} >> 16) & 0x3f ))
	pcap=$(mktemp)
	trap 'rm -f "${pcap}"' EXIT

	verify_capture "${pcap}" || { rm -f "${pcap}"; trap - EXIT; exit 1; }

	python3 - "${pcap}" "${port}" "${RT_A_MAC}" "${MARLIN_MAC}" "${INNER_MAC}" "${VNI}" "${dscp}" <<'PY'
import struct, sys

path, dport, rt_a_mac, marlin_mac, inner_mac, vni, expected_dscp = sys.argv[1:8]
dport = int(dport)
vni = int(vni)
expected_dscp = int(expected_dscp)

def mac_bytes(s):
    return bytes(int(x, 16) for x in s.split(":"))

rt_a_mac, marlin_mac, inner_mac = mac_bytes(rt_a_mac), mac_bytes(marlin_mac), mac_bytes(inner_mac)

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
    off = 24
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

target = None
for p in pkts:
    if len(p) < 14 + 20 + 8:
        continue
    eth_type = struct.unpack("!H", p[12:14])[0]
    if eth_type != 0x0800:
        continue
    ihl = (p[14] & 0x0f) * 4
    if p[14 + 9] != 17:
        continue
    udp = p[14 + ihl:14 + ihl + 8]
    if len(udp) < 8:
        continue
    if struct.unpack("!H", udp[2:4])[0] == dport:
        target = p
        break

if target is None:
    sys.exit("no UDP packet to port %d found on the captured leg" % dport)

outer_eth = target[0:14]
ip = target[14:14 + 20]
ihl = (target[14] & 0x0f) * 4
udp = target[14 + ihl:14 + ihl + 8]
vxlan_hdr = target[14 + ihl + 8:14 + ihl + 8 + 8]
inner = target[14 + ihl + 8 + 8:]

check("outer Ethernet dst == the arriving frame's source (%s)" % rt_a_mac.hex(":"),
      outer_eth[0:6] == rt_a_mac)
check("outer Ethernet src == Marlin's own MAC", outer_eth[6:12] == marlin_mac)
check("outer IPv4 protocol == 17 (UDP)", ip[9] == 17)
check("outer IPv4 DSCP == configured (%d)" % expected_dscp, (ip[1] >> 2) == expected_dscp)
check("outer IPv4 ECN bits == 0", (ip[1] & 0x03) == 0)
check("outer UDP dest == encap_dport (%d)" % dport, struct.unpack("!H", udp[2:4])[0] == dport)
check("outer UDP source in the ephemeral range 49152-65535", 49152 <= struct.unpack("!H", udp[0:2])[0] <= 65535)
check("outer UDP checksum == 0", struct.unpack("!H", udp[6:8])[0] == 0)
check("VXLAN flags == 0x08 (I bit only)", vxlan_hdr[0] == 0x08)
check("VXLAN reserved0[1:3] == 0", vxlan_hdr[1:4] == b"\x00\x00\x00")
got_vni = (vxlan_hdr[4] << 16) | (vxlan_hdr[5] << 8) | vxlan_hdr[6]
check("VNI == %d in the header's 3-byte field" % vni, got_vni == vni)
check("VXLAN trailing reserved byte == 0", vxlan_hdr[7] == 0)

if len(inner) < 14:
    fail.append("inner Ethernet header present (frame too short)")
else:
    check("inner Ethernet dst == backend.inner_mac (%s)" % inner_mac.hex(":"), inner[0:6] == inner_mac)
    check("inner Ethernet src == Marlin's own MAC", inner[6:12] == marlin_mac)
    check("inner EtherType == ETH_P_IP (0x0800)", inner[12:14] == b"\x08\x00")

print("vxlan verify: %d/%d assertions passed" % (len(ok), len(ok) + len(fail)))
for name in ok:
    print("  ok    %s" % name)
for name in fail:
    print("  FAIL  %s" % name)
print()
print("not asserted here (see the comment above verify() in this script):")
print("  - 50-byte headroom shortfall -> adjust_head_failed (needs a native driver)")
print("  - inner EtherType distinguishing v4/v6 on one device (needs a v6 client leg)")

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
                  byte-for-byte, including inner/outer MAC ordering
                  (docs/design/24-testing.md)
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
