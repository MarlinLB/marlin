#!/usr/bin/env bash
#
# Marlin — IPIP development rig for WSL2.
#
# One mode, one script. tests/integration/netns-topo.sh builds all four modes
# in a single topology for the integration suite; this is the smaller thing
# you want while developing the IPIP path alone. Namespace names, device
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
#   VIP        198.18.2.1     RFC 2544 benchmark range. netns-topo.sh uses
#                             198.18.0.1, l2dsr_wsl.sh 198.18.1.1, gue_wsl.sh
#                             198.18.3.1 and vxlan_wsl.sh 198.18.4.1, so no two
#                             rigs share a VIP.
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
#
# The working order is up, attach, seed, listen. Seeding is not optional: an
# unmatched VIP passes every packet (marlin_lb_admit, bpf/lb_core.c),
# and a backend with MARLIN_BE_F_STATE clear (an all-zero backends[] slot) is
# never selected either. An attached program with unseeded maps forwards
# nothing and looks exactly like a broken datapath.
#
# marlin_nexthop_encapsulate() (bpf/nexthop.c) MAC-swaps the frame that
# marlin_ipip_encap_packet() (bpf/ipip.c) already wrapped in an outer IPv4
# header, so a completed GET is evidence here: the frame leaving miprt-a is 20
# bytes larger than the one that arrived, and ${BE_IP}:80 (unbound) refuses
# anything that arrived by ordinary routing rather than through ipip0.
#
# Overridable: MARLIN_OBJ, MARLIN_PINDIR, XDP_MODE, BPFTOOL.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------

RIG_NAME=ipip
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

# Resolved from the script's own location, so the verbs work from any cwd. The
# build writes to data-plane/build/ (data-plane/Makefile: BUILD_DIR := build).
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Per-rig pin directory, not the /sys/fs/bpf/marlin default: this rig's
# namespaces/devices/MACs/VIP are disjoint from the other rigs, so a shared
# pin dir would break that on first detach (DEPLOYMENT.md:62).
PINDIR="${MARLIN_PINDIR:-/sys/fs/bpf/mlipip}"

# The underlay carries the 20-byte outer header. docs/design/23-mtu.md's strategy
# is jumbo frames on the Marlin->backend path; the client link stays at 1500 and
# is deliberately left alone.
#
# config.max_frame is the *frame*, not the MTU: "egress MTU + ETH_HLEN"
# (docs/design/08-types.md, §1.7), so 1600 here means 1614 there. To exercise
# frame_too_big, drop MTU_UNDERLAY to 1500 and max_frame to 1514.
MTU_UNDERLAY=1600
MAX_FRAME=$((MTU_UNDERLAY + 14))

# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

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

	echo "${RIG_NAME} rig up."
	echo
	summary
}

# ---------------------------------------------------------------------------
# status / summary
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
#
# config and backends[${BACKEND_ID}] are both written here, unlike the L2 DSR
# rig: an encapsulating backend reads config.tunnel_src for the outer source
# and config.max_frame for the post-encapsulation size check.

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
	# addresses and never reads it (bpf/nexthop.c).
	value=$(pack_backend "${BE_IP}" "" "${flags}" "${BACKEND_ID}")
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
	help|-h|--help) help ;;
	*)
		echo "usage: $0 {up|attach|seed|unseed|reload|detach|status|down|listen|trace|test_icmp_echo|test_http_get|help}" >&2
		echo "run '$0 help' for what each command does" >&2
		exit 2
		;;
esac
