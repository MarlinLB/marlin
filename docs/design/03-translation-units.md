# Marlin — Source Layout: Translation Units


### Translation units

Each `.c` compiles separately; the objects are linked with `bpftool gen object` into a
single `marlin.bpf.o`. Sources are `.c` and `.h`; only the linked object carries `.bpf.o`.

| File | Contents |
|---|---|
| `marlin.c` | XDP entry point. Zeroes `marlin_ctx`, takes the `config` snapshot, calls `marlin_parse()` then `marlin_balance()`, maps the returned `enum marlin_ret` onto an XDP action and a `drop_stats` index |
| `balancer.c` | `marlin_balance()` — the packet pipeline of `docs/design/11-pipeline.md`: VIP lookup, backend selection, mode dispatch |
| `parse.c` | L2/L3/L4 parsing, IPv6 extension-header walking, ICMP embedded-header parsing, `packet_tuple` construction |
| `ipip_encap.c` | IPIP encapsulation |
| `gue_encap.c` | GUE encapsulation |
| `vxlan_encap.c` | VXLAN encapsulation: the VNI, the inner Ethernet header rewrite, and the outer Ethernet header (`docs/design/14-forwarding-modes.md` §7.4) |
| `nexthop.c` | MAC swap, the L2 DSR MAC rewrite, `bpf_fib_lookup()`, `tx_ports` slot resolution |
| `marlin.h` | `marlin_ctx`, `enum marlin_ret`, every `marlin_*` prototype — internal, not an ABI |
| `types.h` | map key and value structs only; the map ABI the control plane mirrors |
| `maps.h` | single definition site for all maps |
| `csum.h` | checksum arithmetic |
| `entropy.h` | the outer UDP source port entropy hash, shared by `gue_encap.c` and `vxlan_encap.c` |
| `siphash.h` | SipHash-2-4 |
| `stats.h` | counter helpers |
| `acl.h` | `marlin_acl()` — the two trie lookups of `docs/design/27-source-filtering.md` |
| `ratelimit.h` | `marlin_ratelimit()` — the token bucket of `docs/design/28-rate-limiting.md` |

**Why `csum`, `siphash` and `stats` are headers rather than translation units.** A global
subprogram cannot take a packet pointer — the supported argument types are `PTR_TO_CTX`,
scalars and BTF struct pointers — so any function that must be *handed* a packet pointer has to
be `static __always_inline` in a header and inlined into the caller that owns it. A translation
unit may still walk packet bytes provided it re-derives `data` and `data_end` from `ctx` on
entry, which is what `nexthop.c` does.
`csum.h` is the case that forces the rule; `siphash.h` and `stats.h` are headers because an
extra call frame for a few dozen ALU operations is a poor trade. `acl.h` and `ratelimit.h` are
headers for the same reason: two map lookups and an unrolled arithmetic loop do not earn a
frame, and neither reads packet bytes. Both inline into `balancer.c`.

`entropy.h` passes the same test as `acl.h` and `ratelimit.h`, not the `csum.h` test: it hashes
`marlin_ctx.tuple`, a BTF struct pointer already resolved by the time either encapsulation unit
calls it, and reads no packet bytes at all — so nothing here forces it into a translation unit,
and a shared header is what `gue_encap.c` and `vxlan_encap.c` both calling the same few-ALU-op
hash actually requires. It moved out of `gue_encap.c` because GUE stopped being the only
consumer, not because its cost characteristics changed.

**Why `types.h` holds map structs only.** Everything in it is ABI the control plane has to
mirror by hand, so anything placed there becomes control-plane surface and another chance to
diverge. `marlin_ctx` and `enum marlin_ret` are datapath-internal and live in `marlin.h`.

**Where L2 DSR lives.** It is a destination-MAC rewrite, which is next-hop resolution (`docs/design/15-nexthop-l2dsr.md`),
so it belongs to `nexthop.c` rather than earning a file. `marlin_balance_encap()` has an
empty case for it.

### Linking

All inputs must carry BTF. Maps are deduplicated by name across objects.
