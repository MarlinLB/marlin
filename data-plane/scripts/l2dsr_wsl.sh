#!/usr/bin/env bash
#
# Marlin — L2 DSR development rig for WSL2.
#
# One mode, one script. tests/integration/netns-topo.sh builds all four modes
# in a single topology for the integration suite; this is the smaller thing
# you want while developing the L2 DSR path alone. Namespace names, device
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
#   VIP        198.18.1.1     RFC 2544 benchmark range. netns-topo.sh uses
#                             198.18.0.1, ipip_wsl.sh 198.18.2.1, gue_wsl.sh
#                             198.18.3.1 and vxlan_wsl.sh 198.18.4.1, so no two
#                             rigs share a VIP.
#   Segment    198.19.1.0/24  same range, deliberately not one of the
#                             documentation prefixes netns-topo.sh occupies.
#
# MACs are pinned (02:00:00:00:01:xx, locally administered) so tests can assert
# emitted frames byte-for-byte and so backend.mac can be configured by hand.
#
# Usage:  sudo ./l2dsr_wsl.sh up | attach | seed | reload | detach | status | down
#                            | listen | trace | test_icmp_echo | test_http_get
#
#   up              build the topology (does not attach the program)
#   attach          load marlin.bpf.o, pin it, attach to ${MARLIN_IF}
#   seed            write vip_map and backends[1]; nothing forwards until then
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
# Overridable: MARLIN_OBJ, MARLIN_PINDIR, XDP_MODE, BPFTOOL.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------

RIG_NAME=l2dsr
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

# Resolved from the script's own location, so the verbs work from any cwd. The
# build writes to data-plane/build/ (data-plane/Makefile: BUILD_DIR := build).
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Per-rig pin directory, not the /sys/fs/bpf/marlin default: this rig's
# namespaces/devices/MACs/VIP are disjoint from the other rigs, so a shared
# pin dir would break that on first detach (DEPLOYMENT.md:62).
PINDIR="${MARLIN_PINDIR:-/sys/fs/bpf/ml2dsr}"

# No MTU parameter: L2 DSR prepends nothing ("No packet growth",
# docs/design/14-forwarding-modes.md §7.1), so default 1500 is honest, and
# config.max_frame is not required with no encapsulating backend.

# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

# ---------------------------------------------------------------------------
# up
# ---------------------------------------------------------------------------

up() {
	need_root
	need_cmd ip ethtool
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
	# VIP is off-segment on purpose: on-link the client would ARP for it, which
	# backend_vip() suppresses; a host route addresses the frame to Marlin's MAC
	# instead, putting it in front of the XDP program.
	nsx "${NS_CLI}" ip route add "${VIP}/32" via "${MARLIN_IP}" dev "${CLI_IF}"
	# Static, because resolving ${MARLIN_IP} means ARPing *into* the XDP program:
	# whether the datapath passes non-IP ethertypes is what's under test, so a
	# rig whose first packet depends on it fails at ARP, not at forwarding.
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
	# Not strictly needed here (the reply's return path passes strict RPF), but
	# DSR replies are sourced from an address on no segment, and leaving the
	# check on hides that. Same reason netns-topo.sh clears it.
	sc "${NS_BE}" net.ipv4.conf.all.rp_filter=0
	sc "${NS_BE}" "net.ipv4.conf.${BE_IF}.rp_filter=0"

	# --- offloads ----------------------------------------------------------
	noffl -          "${MARLIN_IF}"
	noffl -          "${MARLIN_BR}"
	noffl -          "${CLI_BR}"
	noffl -          "${BE_BR}"
	noffl "${NS_CLI}" "${CLI_IF}"
	noffl "${NS_BE}"  "${BE_IF}"

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

Attach — ${XDP_MODE}, because WSL2 veth has no native XDP:

  sudo $0 attach          # load ${OBJ##*/}, pin under ${PINDIR}, attach
  sudo $0 reload          # after a rebuild: detach, unpin, load, attach
  sudo $0 detach          # detach and unpin; rig stays up

Seed — an attached program forwards nothing until vip_map and backends[${BACKEND_ID}] are written:

  sudo $0 seed            # write vip_map and backends[${BACKEND_ID}] with the values above
  sudo $0 unseed          # remove the vip_map entry and zero backends[${BACKEND_ID}]

Drive it:

  sudo $0 listen          # serve ${VIP}:${HTTP_PORT} from ns ${NS_BE} until ^C,
                          # bound to the VIP alone so only forwarded packets arrive
  sudo $0 test_http_get   # one GET from ns ${NS_CLI} against a throwaway listener
  sudo $0 test_icmp_echo  # ping the VIP. No reply is the correct outcome: echo
                          # passes to the host stack (docs/design/13-icmp.md), so
                          # the evidence is icmp_echo moving in drop_stats

Watch it:

  sudo $0 trace                                  # ${PROG}'s bpf_printk output
  ip netns exec ${NS_BE} tcpdump -nei ${BE_IF}   # VIP intact, dst MAC now ${BE_MAC}
  ip -d link show ${MARLIN_IF} | grep prog/xdp   # expect "${XDP_MODE}"
  ${BPFTOOL} map dump pinned ${PINDIR}/drop_stats
                                                 # 'name drop_stats' would match
                                                 # every rig's map, not this one's
EOF
}

status() {
	for ns in "${NS_ALL[@]}"; do
		ip netns list | grep -qw "${ns}" || { echo "${RIG_NAME} rig is down"; return 1; }
	done
	echo "== root ns =="
	ip -br addr show "${MARLIN_IF}" 2>/dev/null || true
	ip -d link show "${MARLIN_IF}" | sed -n '2,3p'
	bridge link show 2>/dev/null | grep -w "${BR}" || true
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
}

# ---------------------------------------------------------------------------
# Map seeding
# ---------------------------------------------------------------------------
#
# config's zero value already suits this rig: nothing here is encapsulated,
# so config.tunnel_src/max_frame are never read.

seed() {
	need_root
	need_cmd python3 "${BPFTOOL}"
	rig_up_or_die
	seed_or_die

	local mode bit flags value
	mode=$(abi_define MARLIN_MODE_L2DSR)
	bit=$(abi_define MARLIN_BE_F_STATE_BIT)
	# MARLIN_BE_F_FIB stays clear, so the stored MAC is the fast path and
	# bpf_fib_lookup() is not consulted (docs/design/15-nexthop-l2dsr.md).
	flags=$(( mode | (1 << bit) ))
	value=$(pack_backend "${BE_IP}" "${BE_MAC}" "${flags}" "${BACKEND_ID}")

	# Unquoted on purpose: bpftool takes the value as separate byte arguments.
	# shellcheck disable=SC2086
	"${BPFTOOL}" map update pinned "${PINDIR}/backends" key ${BACKEND_KEY} value ${value}

	# vip_map/fwd_table: the port-agnostic lookup lb_core.c performs
	# (docs/design/11-pipeline.md), pointed at the one backend above.
	vip_seed "${BACKEND_ID}"

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
<title>marlin l2dsr rig</title>
<pre>
rig       l2dsr_wsl.sh (L2 DSR, docs/design/14-forwarding-modes.md 7.1)
backend   ns ${NS_BE}, ${BE_IF} ${BE_IP} ${BE_MAC}
bound to  ${VIP} -- the VIP, on lo; reached only through ${PROG}
</pre>
EOF
	echo "${d}"
}

# ---------------------------------------------------------------------------

help() {
	cat <<EOF
usage: $0 <command> [args]

  up              build the topology (namespaces, veths, bridge); does not
                  attach the program
  attach          load marlin.bpf.o, pin it, and attach it to ${MARLIN_IF}
  seed            write vip_map and backends[1] so the attached program starts forwarding
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
