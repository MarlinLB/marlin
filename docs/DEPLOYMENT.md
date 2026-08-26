# Marlin — Deployment

This document answers two questions and nothing else:

1. How must the Marlin host be configured? (§1)
2. How must a backend node be configured? (§2, split per forwarding mode)

Everything else lives elsewhere: what Marlin does and why in `docs/design/`, what is in scope in
`PHASES.md`, what the counters mean in `docs/design/22-observability.md`, source filtering and
rate limiting in `docs/design/27-source-filtering.md` and `docs/design/28-rate-limiting.md`.

Shell samples illustrate the intent on a recent Linux distribution. Except for the two `bpftool`
commands in §1.2, no command below is specified by the design documents — device names, addresses,
table numbers and sysctl paths are examples. Marlin is pre-implementation, so none of them has been
run against a working system. Translate them; do not paste them.

Where a requirement is real but its mechanism is not settled, this document says so at the point it
would have to be applied rather than omitting it. Those places are §1.9, §1.10 and §2.2.

---

## 1. The Marlin host

### 1.1 Kernel and tooling

| Requirement | Value |
|---|---|
| Linux kernel | 6.0 or later (`docs/design/01-scope.md`) |
| `bpftool` | from the `linux-tools` package matching the running kernel, with `prog loadall` and `net attach` (`docs/design/29-versions.md`) |

`bpftool` is not built by Marlin; it comes from the distribution. Nothing else is needed on the
forwarding host — clang, libbpf and `bpftool gen object` are build-host requirements and produce
the single `marlin.bpf.o` that ships.

`docs/design/29-versions.md` lists the individual kernel features Marlin depends on and the
version each arrived in; all are below 6.0. That table exists for the case where the 6.0 floor is
challenged, not as an invitation to run below it.

### 1.2 BPF filesystem and pinning

Programs and maps are pinned, so they outlive the process that created them. The BPF filesystem
must be mounted before the loader runs:

```sh
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
```

The loader is `deploy/marlin-load.sh` and does exactly two things:

```sh
bpftool prog loadall marlin.bpf.o /sys/fs/bpf/marlin pinmaps /sys/fs/bpf/marlin
bpftool net attach xdpdrv pinned /sys/fs/bpf/marlin/xdp_marlin dev "$IFACE"
```

- There is no map pre-creation step. Every map is sized at compile time and created from its BTF
  declaration at load.
- `bpftool`, not `ip`: iproute2's libbpf linkage is distribution-dependent and its legacy loader
  handles BTF-defined maps and CO-RE poorly.
- The attach is a legacy netlink attach, not `bpf_link`, so the program stays attached with no
  process holding a file descriptor.

`IFACE` and the pin path come from `marlin.env.example`. `/sys/fs/bpf/marlin` is the default, not
an invariant — if you change it, the control plane's configuration must agree.

### 1.3 The XDP interface

**Native XDP is mandatory.** `xdpdrv` fails the attach outright rather than falling back to
generic/SKB mode. This is deliberate: a silent fallback would succeed at attach time and then cost
roughly an order of magnitude in throughput, presenting as a software fault rather than a hardware
one. Rule out the recoverable causes first — another XDP program already attached, an MTU above the
driver's XDP limit, insufficient queue memory — and if none apply, the card or driver cannot do
native XDP and the answer is different hardware, not a different flag.

**Hardware receive coalescing must be off.** LRO merges arriving frames in hardware, before XDP
sees them; the datapath assumes client-facing ingress is never larger than a standard frame and
does not handle multi-buffer packets. `lro` is not the only such feature — several drivers keep a
separate hardware-GRO toggle that survives `lro off`:

```sh
ethtool -K "$IFACE" lro off
ethtool -K "$IFACE" rx-gro-hw off   # not present on every driver; ignore a failure here
```

**The driver must leave headroom in front of each packet for encapsulation** — 20 bytes for
IP-in-IP, 32 for GUE. A driver that does not cannot be worked around from the datapath; the
failure counts as `adjust_head_failed`.

Two other properties of this interface are read by the control plane rather than configured:

- Its MTU is the source of `config.max_frame` (§1.7), refreshed on netlink link events.
- Its configured prefixes are what the control plane compares backend addresses against when
  deciding whether a backend is confirmed on-segment (§2.2).

### 1.4 Memory

Map memory is allocated at load, not as VIPs are configured.

| Map | Size |
|---|---|
| `fwd_table` | 100 × 65536 × 4 B = **26 MB, preallocated in full at load regardless of how many VIPs exist** |
| `ratelimit` | 262144 × 28 B = 7.3 MB of key and value data, plus allocator and bucket overhead that has not been measured |
| `backends` | 4096 × 20 B = 80 KB |
| `vip_map` | preallocated; at 100 entries `BPF_F_NO_PREALLOC` would only add cost |
| Source-filtering tries | proportional to populated rules — a binary trie with N leaves also holds up to N−1 internal nodes, so budget roughly 2× the rule count. Nothing when empty. |

No total is quoted for the rate limiter and none should be used operationally until it has been
measured (`docs/design/09-sizing.md`).

On kernels from 5.11 onwards — which is every supported kernel — this memory is charged to the
**memory control group**, not to `RLIMIT_MEMLOCK`. **Containerised deployments must size the
cgroup memory limit to include it.** A limit set without accounting for the 26 MB forwarding table
will refuse the load.

### 1.5 Capacity limits

Compile-time constants in `limits.h`. Nothing to configure; listed so a sizing exercise does not
have to read the design documents.

| Limit | Value | At the limit |
|---|---|---|
| VIPs | 100 | rejected by the control plane |
| Backends | 4096, **4095 usable** — identifier 0 is reserved and never allocated | rejected by the control plane |
| Egress interfaces registered for redirect | 64 — a capacity bound, not an index space; a host ifindex may exceed 64 | see §1.8 |
| Source-filtering rules | 65536 **per trie, and there are four** (allow/block × IPv4/IPv6) | no validation rule specified |
| Rate limiter entries | 262144 | least-recently-used eviction, which is what bounds its memory against a high-cardinality flood |

### 1.6 Privileges and service ordering

| Component | Capabilities | For |
|---|---|---|
| `marlin-load.sh` | `CAP_BPF`, `CAP_NET_ADMIN` | load, pin, attach |
| Control plane | `CAP_BPF`, `CAP_NET_ADMIN` | map I/O; maintaining kernel neighbour entries; binding probe sockets into the probe VRF |

No component needs `CAP_SYS_ADMIN`. The probe isolation in §1.9 uses a VRF rather than a network
namespace specifically to keep it that way.

One correction to that argument, which the design documents do not carry: binding a socket to a
device with `SO_BINDTODEVICE` gates on `CAP_NET_RAW`, which `CAP_NET_ADMIN` does not imply. The
control plane needs **`CAP_NET_RAW` as well** for §1.9 to work. The conclusion holds — this is
still short of `CAP_SYS_ADMIN` — but the capability set above is the design's, not a verified one.

The loader is a systemd **oneshot with `RemainAfterExit`, ordered before the control plane
service** — `deploy/marlin-load.service` before `deploy/marlin.service`. A pinned map does outlive
its creator, so the ordering is not a technical necessity; it exists so that exactly one component
owns map identity and sizing. The control plane opens pinned paths and performs I/O only. It never
loads a program and never creates a map, so restarting or upgrading it does not disturb forwarding
and does not drop connections. (Upgrading the datapath may.)

### 1.7 Instance configuration

Three per-instance values gate forwarding. All three are configuration the control plane reads,
not host state, but they are host-specific and easy to leave unset.

| Value | Requirement |
|---|---|
| `config.tunnel_src` | The outer IPv4 source address for encapsulated traffic. **Required if any backend is IP-in-IP or GUE**; the configuration is rejected without it. |
| `config.max_frame` | Egress MTU + `ETH_HLEN`. **Required if any backend is IP-in-IP or GUE**; the configuration is rejected without it, precisely because an unset value would be a silent loss of protection rather than a visible failure — zero disables the egress frame check in the datapath. Sourced from the attached interface's MTU. The check is **per-instance, not per-next-hop**, so an asymmetric-MTU fabric is only covered on the routing-table path. |
| `vip_meta.hash_key` | Exactly 16 bytes. Rejected at any other length. |

Where more than one Marlin instance serves the same VIP, **`hash_key` and `table_seed` must be
byte-identical on every instance**. They are distinct values with distinct effects and matching one
without the other buys nothing:

- `hash_key` acts in the datapath. Disagreement maps the same client to different table rows.
- `table_seed` acts in the control plane and never enters the datapath. Disagreement maps the same
  row to different backends.

Both are per-VIP secrets owned by the configuration store, established once at VIP creation and
supplied by the operator or generated there. **Neither is ever generated during reconciliation** —
a "generate if absent" fallback would have each instance invent a different value, which is
precisely the divergence the rule prevents. Absence at reconcile time is a hard error.

A mismatch has no symptom of its own: each instance independently shows healthy, well-distributed
backend counters, and nothing measures the correlation between instances. The per-VIP digest that
would detect it is a Phase 3 deliverable (`PHASES.md`); until it exists, the configuration store is
the only place to check.

Given both values agree, nothing else needs to. Marlin holds no per-flow state, so any instance can
handle any packet and upstream ECMP may rehash freely.

### 1.8 Routing state

**IPv4 forwarding must be enabled.** The datapath consults the kernel routing table for backends it
cannot reach directly on the ingress segment, and for L2 DSR backends carrying the reachability flag
or lacking a stored hardware address. Where the lookup happens with forwarding disabled, the packet
is dropped and counted `fib_fwd_disabled`.

Only IPv4 matters. The lookup destination is always `backend.addr`, which is IPv4 in every mode
including where the VIP is IPv6, so the lookup is `AF_INET` throughout and **no IPv6 forwarding
sysctl is ever needed**.

```sh
cat >/etc/sysctl.d/90-marlin.conf <<'EOF'
net.ipv4.ip_forward = 1
EOF
sysctl --system
```

Note that forwarding is also a per-device setting and the datapath's drop reflects the state of the
device the lookup resolves to. Writing the global knob above covers every existing device and the
default for devices created later, but a device with forwarding explicitly disabled stays disabled.

**Policy routing rules apply to the datapath lookup.** The datapath does not pass
`BPF_FIB_LOOKUP_DIRECT` today, so `ip rule` entries on the host change how backends resolve. There
is no configuration surface for this, and whether to expose one is an open decision recorded in
`PHASES.md` against `nexthop.c`. Until it closes, treat `ip rule` on the Marlin host as
forwarding-affecting state.

```sh
ip rule show    # anything here participates in backend resolution
```

**Egress interfaces are registered by the control plane, not by you.** Where a backend resolves out
an interface other than the ingress one, the datapath redirects by kernel ifindex, and the control
plane populates `tx_ports` with every ifindex it intends to redirect to. Your side of this is only
that the interfaces exist and the routing table resolves backends to them. An unregistered
interface produces a counted drop (`no_tx_port`), not a silent one. The ingress interface is
deliberately absent from the map — transmitting back out the ingress interface needs no devmap.

### 1.9 The health-probe VRF

**The most easily missed prerequisite in this document.** Without it, every probe fails against
every healthy backend and the whole fleet is marked down.

Health probes are addressed to the **VIP**, not to the backend's own address, and forced down the
path Marlin would use. That is the only way to detect a missing tunnel device, an absent FOU
listener, a VIP that was never put on loopback, or missing ARP suppression — a plain connection to
the backend's real address proves the backend is alive and proves nothing about whether it will
accept what Marlin sends it.

But a backend replying to a VIP-addressed probe sources that reply **from the VIP**, and the Marlin
host holds the VIP. The reply arrives claiming a source address the receiving host owns, the local
route discards it as a martian, and the probe fails. Source-address validation is applied per-VRF,
so inside a VRF that does not contain the VIP the same reply is ordinary traffic.

Provide **a VRF that does not contain the VIP**, holding a probe source address and the host-side
tunnel devices the probes traverse. Because the probe is addressed to the VIP, the route that
selects *which* backend it reaches lives in the VRF's table, so the state below is per backend, not
per instance:

```sh
BE=198.51.100.20            # backend.addr
VIP4=203.0.113.10
VIP6=2001:db8::10

ip link add vrf-probe type vrf table 100
ip link set vrf-probe up

# Probe source addresses inside the VRF, one per family. Without them the VRF
# cannot originate a probe, and an IPv6 VIP cannot be probed at all.
ip link add probe-src type dummy
ip link set probe-src master vrf-probe
ip link set probe-src up
ip addr add 198.51.100.250/32 dev probe-src
ip addr add 2001:db8:1::250/128 dev probe-src nodad

# One host tunnel device per mode *and* per inner address family. The device type
# fixes the inner family on the originating side, so four devices cover the two
# encapsulating modes.
ip link add probe-ipip type ipip  local 198.51.100.250 remote "$BE"     # IPIP, IPv4 inner
ip link add probe-sit  type sit   local 198.51.100.250 remote "$BE"     # IPIP, IPv6 inner
ip link add probe-gue4 type ipip  local 198.51.100.250 remote "$BE" \
    encap gue encap-dport 6080                                          # GUE,  IPv4 inner
ip link add probe-gue6 type sit   local 198.51.100.250 remote "$BE" \
    encap gue encap-dport 6080                                          # GUE,  IPv6 inner

for d in probe-ipip probe-sit probe-gue4 probe-gue6; do
    ip link set "$d" master vrf-probe
    ip link set "$d" up
done

# The VIP must route out the device for the mode being probed. One route per
# VIP per table, so a table cannot express two backends in the same mode.
ip route add "$VIP4" dev probe-ipip table 100
ip -6 route add "$VIP6" dev probe-sit table 100
```

For an L2 DSR backend there is no tunnel device; the probe is resolved statically instead, against
a VRF-enslaved device that reaches the segment:

```sh
ip neigh replace "$VIP4" lladdr 00:00:5e:00:53:01 dev <vrf-member> nud permanent
ip route add "$VIP4" dev <vrf-member> table 100
```

Per mode, what the probe needs:

| Mode | Requirement |
|---|---|
| L2 DSR | A static neighbour entry mapping the VIP to the backend's hardware address, and a route to the VIP out the device that entry is on |
| IP-in-IP | A host tunnel device matching the inner address family. **Both families where a backend serves both** — they are different devices |
| GUE | A host GUE tunnel device **per inner address family.** The single-listener property of GUE is a receiver property; on the originating side the device type still fixes the inner family |

The control plane binds its probe sockets into this VRF with `SO_BINDTODEVICE`. Health checking is
entirely control-plane work and the datapath is not involved.

A network namespace would work equally well but requires `CAP_SYS_ADMIN`; a VRF plus
`SO_BINDTODEVICE` stays within `CAP_NET_ADMIN` and `CAP_NET_RAW` (§1.6). `accept_local` is a smaller
change but IPv4-only, which would leave every IPv6 VIP unprobeable.

Two accepted blind spots:

- A host tunnel device does not reproduce the GUE entropy source port or the zero outer UDP
  checksum (§2.4). A backend that rejects those two things specifically still probes healthy.
- Under active/active, each instance probes independently and instances may briefly disagree about
  a backend. This is harmless — a row pointing at a backend one instance believes is down simply
  drops on that instance. Health state is not synchronised, by design.

**Two things this mechanism does not yet specify.** Both are load-bearing and neither is settled in
`docs/design/18-health.md`, which describes the VRF and its contents and stops there:

- **How the reply gets into the VRF.** The backend's reply is unencapsulated in every mode — VIP to
  probe address, plain IP — so it arrives on the Marlin host's physical interface, which is in the
  default VRF, where the VIP is local and the packet is a martian. Enslaving a dummy carries the
  probe address's local route into table 100 but does not move the ingress path there. Either the
  ingress path must be steered into the VRF (a veth pair with one end enslaved, or an explicit local
  route) or the premise needs restating.
- **How one VRF addresses more than one backend.** Probes are addressed to the VIP, so backend
  selection is expressed as route and neighbour state keyed on the VIP — one route per VIP per
  table, one neighbour entry per VIP per device. At 100 VIPs and 4095 backends a single table cannot
  express the fleet, and nothing says whether the intended shape is a table per backend, a device
  per backend, or something else.

### 1.10 The VIP on the Marlin host

§1.9 depends on the Marlin host holding the VIP: that is why a VIP-sourced reply is a martian and
why the probe VRF exists. The design documents assert this as a premise but never state where the
VIP is configured on the host or how it is advertised — the datapath does not need the address
present to forward, since VIP matching is a map lookup and not a local-delivery decision.

**This is undecided, not omitted.** Either the VIP must be configured on the host (and this
document must say on which interface, and how it is advertised to the fabric), or it must not be
(and §1.9's martian premise needs restating). Nothing else in this document resolves it.

### 1.11 The uplink

For IP-in-IP and GUE, the datapath's default next-hop behaviour is to swap the Ethernet source and
destination and send the encapsulated packet back out the interface it arrived on. The upstream
router then routes it onward using its own table. Three things must be true of that router:

- **It is on the same network segment as Marlin.** Normal in the BGP/ECMP anycast topology Marlin
  is designed for.
- **It forwards packets back out the interface they arrived on.** Standard for a routed interface —
  but **some switch SVIs restrict this and must be verified explicitly.**
- **ICMP redirect generation should be suppressed on that interface.** A router generates a redirect
  when the better next hop for a packet is on the segment the packet arrived from, which a
  hairpinned packet can satisfy. Whether it does depends on the topology; suppressing it removes the
  question.

On a Linux router the last of those is:

```sh
sysctl -w net.ipv4.conf.<uplink-to-marlin>.send_redirects=0
```

There is no reply path to arrange. Backends answer clients directly, so with multiple uplinks the
arrangement is naturally symmetric: an encapsulated packet leaves via whichever router delivered it.

---

## 2. A backend node

The forwarding mode is a property of the individual backend, so **one VIP may be served by
backends in all three modes simultaneously**. Provision each backend for the mode it is configured
with.

| Mode | Adds | Crosses routers? | Backend needs |
|---|---|---|---|
| L2 DSR (§2.2) | nothing | no | VIP on loopback or dummy, ARP/NDP suppression, directly attached segment |
| IP-in-IP (§2.3) | 20 bytes | yes | an `ipip` device, a `sit` device, or both |
| GUE (§2.4) | 32 bytes | yes | one FOU listener, plus the tunnel receive devices |

### 2.1 Every mode

**The backend must hold the VIP and accept traffic addressed to it.** In all three modes the packet
that reaches the application still carries the VIP as its destination, and that is what lets the
backend reply directly to the client with the correct source address. All three modes are Direct
Server Return; there is no mode that works against an unmodified server.

**The backend needs an IPv4 address of its own** — `backend.addr` — in every mode. It is the outer
destination for IP-in-IP and GUE, and the address whose neighbour entry is looked up for L2 DSR. It
is the only address the datapath ever resolves. A backend configured without it is rejected, and a
resolved hardware address does not substitute.

**Ports are not translated.** A VIP on port 443 reaches backends on port 443.

Two operational consequences worth knowing before you provision rather than after:

- **A backend is up or down.** There is no drain. Rows pointing at a backend marked down drop
  (`backend_down`); they are not migrated. Marking a backend down or back up changes no forwarding
  table rows and disrupts nothing else.
- **`mode`, `addr` and `gue_dport` cannot be edited in place.** Changing any of them means removing
  the backend and adding it under a new identifier. Removal costs only that backend's own
  connections, but the addition half resets approximately `1/(N+1)` of established connections **on
  healthy backends** — about 1.3% at 75 backends. Adding a backend to a live VIP costs the same.
  This is accepted design behaviour on the assumption that clients reconnect immediately; avoid it
  under load where that does not hold — long-lived sessions that are expensive to re-establish,
  connections mid-TLS-handshake or mid-upload, and non-idempotent requests in flight.

### 2.2 L2 DSR

Nothing is encapsulated. Marlin rewrites the destination hardware address and sends the frame on
unchanged.

**Put the VIP on a loopback or dummy interface, with ARP and NDP suppression.** The packet arrives
still addressed to the VIP, so the backend must own it — but every backend owns it, and if they
answer address resolution for it they will fight each other and the Marlin host.

```sh
ip link add vip0 type dummy
ip link set vip0 up
ip addr add 203.0.113.10/32 dev vip0

# IPv4: do not answer ARP for addresses that are not on the receiving interface
sysctl -w net.ipv4.conf.all.arp_ignore=1
sysctl -w net.ipv4.conf.all.arp_announce=2

# IPv6: stop duplicate address detection from disabling an address every backend holds.
ip addr add 2001:db8::10/128 dev vip0 nodad
```

**`nodad` is not NDP suppression** and this document cannot tell you what is. `nodad` stops the
backend from disabling its own VIP; it does nothing about neighbour advertisements for the VIP,
which every backend will answer and which is the IPv6 half of the requirement. There is no
`arp_ignore` equivalent for IPv6, and the design documents require "NDP suppression" without naming
a mechanism — so this is unresolved, not merely unwritten. An IPv6 VIP under L2 DSR cannot be
provisioned from this document alone.

**The backend must be on a directly attached segment** — not necessarily the one Marlin receives
client traffic on, but attached. Nothing is encapsulated, so a router in the path would see a packet
still addressed to the VIP, which is anycast to Marlin, and route it back: a loop bounded by the
TTL rather than a drop.

Marlin drops such a backend with `fib_gatewayed` rather than forwarding into the loop — **but only
for backends that take the routing-table path.** A backend with a stored hardware address that the
control plane believes is on the ingress segment never reaches that check; it is transmitted onto
the ingress segment and blackholes with every counter reading healthy. The control plane's defence
is to set the reachability flag `MARLIN_BE_F_FIB` on every backend it has not *positively confirmed*
on that segment, confirmation being that `backend.addr` falls inside a prefix configured on the
XDP-attached interface. Uncertainty is therefore slow rather than silent. The requirement stands
regardless.

**The backend needs an IPv4 address on that segment even when the VIP is IPv6.** That address is
what Marlin looks up to find the hardware address. It is not the VIP, and it is not used to address
the traffic — the packet carries the VIP throughout. The lookup is never on the VIP: every backend
owns the VIP and ARP/NDP is suppressed for it, so nothing would answer. An IPv4 neighbour entry
forwards an IPv6 flow perfectly well, and widening `backend.addr` to IPv6 would also cost 12 bytes
of the datapath's stack budget — the firmer of the two reasons (`docs/design/15-nexthop-l2dsr.md`).

**Neighbour entries must resolve on the Marlin host.** The datapath cannot trigger address
resolution — an XDP program has no way to send an ARP request and wait — so an unresolved neighbour
is a dropped packet, counted `fib_no_neigh`. This is the control plane's job, not yours: it keeps
these entries pinned (`nud permanent`) or probes them periodically, which reduces unresolved
neighbours to a startup transient. It matters most for a backend genuinely on a different segment
from the ingress interface, and for any backend deliberately configured with an address but no
hardware address.

**L2 DSR is not free of MTU exposure.** It adds nothing, but a backend reached over the routing-table
path is still checked against the egress MTU, so an L2 DSR backend behind a lower-MTU segment can
drop `frag_needed` where the stored-hardware-address path would have transmitted.

If you configure backends with addresses alone and no hardware addresses — a legitimate choice that
gives the control plane less to keep correct, at the price of a hard dependency on the kernel
neighbour table — accept two consequences deliberately rather than discover them:

- `mac_fallback` becomes the steady state and stops being a signal. Do not alert on it.
- `neigh_fallback` can never fire, because it answers from a stored hardware address and there is
  none. An unresolved neighbour becomes an unconditional drop, so pinning stops being advisory.

### 2.3 IP-in-IP

Marlin wraps the client's packet in a second IP header. The outer header is **always IPv4** —
source `config.tunnel_src` (§1.7), destination `backend.addr`. Overhead is **20 bytes**.

The backend needs a tunnel device matching the address family of the traffic **inside** the tunnel:

- **`ipip`** for IPv4 client traffic — IP protocol 4.
- **`sit`** for IPv6 client traffic — IP protocol 41.
- **Both, if the backend serves both.** One does not cover the other.

The kernel's automatic `tunl0` and `sit0` are devices of exactly these types and satisfy the
requirement — but **they are administratively down until something brings them up**, so their mere
existence is not enough. Create explicit devices where you want the endpoint pinned or the naming to
be obvious:

```sh
# IPv4 inner
ip link add ipip0 type ipip local 198.51.100.20 remote any
ip link set ipip0 up

# IPv6 inner
ip link add sit1 type sit local 198.51.100.20 remote any
ip link set sit1 up
```

**Relax reverse-path validation on the receive device.** After decapsulation the packet carries the
client's source address and arrives on the tunnel device, while the backend's route back to that
client is out its ordinary interface. Strict reverse-path filtering sees the asymmetry and drops it,
which presents as a backend that passes health checks and serves no traffic. This applies equally to
GUE, whose decapsulated packets land on the same devices.

```sh
sysctl -w net.ipv4.conf.ipip0.rp_filter=0
```

All traffic Marlin sends to one IP-in-IP backend shares a single outer address pair, so the network
cannot spread it across equal-cost paths and the backend's network card cannot spread it across
receive queues. That limitation is the reason GUE exists as a third mode; choose GUE where it
matters.

See §2.5 for packet size.

### 2.4 GUE

Like IP-in-IP with a UDP header in between: outer IPv4 (20) + UDP (8) + GUE header (4) =
**32 bytes**. The outer header is always IPv4.

The backend needs **one FOU listener** on the configured port — `backend.gue_dport`, or 6080 where
that is unset:

```sh
ip fou add port 6080 gue
```

A single listener covers both inner address families, because GUE carries the inner IP protocol
number in its own header. **The tunnel receive devices must still exist and be up**, however: the
kernel hands the decapsulated packet into the protocol-4 or protocol-41 receive path afterwards. The
kernel's automatic `tunl0` and `sit0` satisfy this, subject to the same caveat as §2.3 — they are
down by default. GUE removes the second listener, not the second device. Reverse-path validation on
those devices needs the same relaxation as §2.3.

Three things Marlin emits that a strict receiver may object to:

- **The outer UDP source port carries an entropy hash over the client's inner 5-tuple**, not a
  fixed value. This is what lets routers spread traffic across paths and the backend's card spread
  it across receive queues, while keeping any single connection on one path so its packets do not
  reorder. It is deliberately a different hash from the one used to select the backend, which uses
  the client address only — reusing that would collapse one client's connections onto a single path
  and a single queue.
- **Inner fragments carry no ports**, so fragments of one datagram hash differently and may spread
  across paths and arrive slightly reordered before the backend reassembles them. They always reach
  the same backend.
- **The outer UDP checksum is zero.** Unconditionally permitted with an IPv4 outer header; the
  receiver needs no configuration for it.

A backend that rejects the entropy source port or the zero checksum specifically will still pass
health checks, because the probe path cannot reproduce either (§1.9).

Changing a backend's `gue_dport` is a remove-and-re-add, not an edit (§2.1).

See §2.5 for packet size.

### 2.5 Packet size, for IP-in-IP and GUE

Marlin adds 20 bytes (IP-in-IP) or 32 bytes (GUE) on the path from Marlin to the backend. A
1500-byte client packet leaves as 1520 or 1532 bytes. Nothing is added on the return path, because
there is no return path — only client-to-backend is encapsulated. Two ways to accommodate it:

1. **Raise the MTU on the Marlin-to-backend path** so the encapsulated frame fits. The only option
   that covers all traffic.
2. **Reduce the MSS the backend advertises**, via `advmss` on the route or by setting the tunnel
   device MTU and letting the kernel derive the advertised value from it.

```sh
# Option 2, on the backend. advmss applies to the route toward the peer that receives
# the SYN-ACK — that is, toward clients. Not toward the VIP's own prefix.
ip route change default via 198.51.100.1 dev eth0 advmss 1400
```

**MSS clamping must happen on the backend, not on Marlin.** The encapsulated direction is
client-to-backend, so limiting it means reducing what the *backend* advertises in its SYN-ACK — and
under Direct Server Return that SYN-ACK never passes through Marlin. There is nothing for Marlin to
clamp.

What this leaves uncovered:

- MSS applies to TCP only. Large non-QUIC UDP is covered by raising the MTU and by nothing else.
- QUIC is unaffected in practice: its 1200-byte datagrams, with DPLPMTUD, sit below 1500 even with
  GUE's 32 bytes added.

Marlin does not generate "fragmentation needed" or "packet too big" errors; it forwards ones
generated elsewhere, steering them by the embedded header so that path MTU discovery works through
the encapsulation. Oversized frames are dropped and counted, which is what makes this diagnosable:

- `frag_needed` fires only on the routing-table path, against the egress MTU the lookup returns.
- `frame_too_big` covers the default path. Marlin's default next hop for both encapsulation modes
  is a hardware-address swap, which performs no routing-table lookup and so has no egress MTU to
  compare against; the datapath checks the emitted frame against `config.max_frame` instead. That
  is why there are two counters rather than one — and why `config.max_frame` being unset is a
  silent loss of protection (§1.7).
