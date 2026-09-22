# Marlin — Source Layout: Translation Units


### Translation units

Each `.c` compiles separately; the objects are linked with `bpftool gen object` into a
single `marlin.bpf.o`. Sources are `.c` and `.h`; only the linked object carries `.bpf.o`.

| File | Contents |
|---|---|
| `marlin.c` | XDP entry point. Zeroes `marlin_ctx`, takes the `config` snapshot, calls `marlin_parse()` then `marlin_balance()`, maps the returned `enum marlin_ret` onto an XDP action and a `drop_stats` index |
| `lb_core.c` | `marlin_lb_process()` — the packet pipeline of `docs/design/11-pipeline.md`: VIP lookup, backend selection, mode dispatch |
| `parser.c` | L2/L3/L4 parsing, IPv6 extension-header walking, ICMP embedded-header parsing, `packet_tuple` construction |
| `ipip.c` | IPIP encapsulation |
| `gue.c` | GUE encapsulation |
| `vxlan.c` | VXLAN encapsulation: the VNI, the inner Ethernet header rewrite, and the outer Ethernet header (`docs/design/14-forwarding-modes.md` §7.4) |
| `nexthop.c` | MAC swap, the L2 DSR MAC rewrite, `bpf_fib_lookup()`, `tx_ports` slot resolution |
| `acl.c` | `marlin_acl_check()` — the two trie lookups of `docs/design/27-source-filtering.md` |
| `ratelimit.c` | `marlin_ratelimit()` — the token bucket of `docs/design/28-rate-limiting.md` |
| `marlin.h` | `marlin_ctx`, `enum marlin_ret`, every `marlin_*` prototype — internal, not an ABI |
| `types.h` | map key and value structs only; the map ABI the control plane mirrors |
| `maps.h` | single definition site for all maps |
| `csum.h` | checksum arithmetic |
| `entropy.h` | the outer UDP source port entropy hash, shared by `gue.c` and `vxlan.c` |
| `siphash.h` | SipHash-2-4 |
| `stats.h` | counter helpers |
| `acl.h` | `enum marlin_acl_verdict` and the `marlin_acl_check()` prototype |
| `ratelimit.h` | the `marlin_ratelimit()` prototype |

**Why `csum`, `siphash` and `stats` are headers rather than translation units.** A global
subprogram cannot take a packet pointer — the supported argument types are `PTR_TO_CTX`,
scalars and BTF struct pointers — so any function that must be *handed* a packet pointer has to
be `static __always_inline` in a header and inlined into the caller that owns it. A translation
unit may still walk packet bytes provided it re-derives `data` and `data_end` from `ctx` on
entry, which is what `nexthop.c` does.
`csum.h` is the case that forces the rule; `siphash.h` and `stats.h` are headers because an
extra call frame for a few dozen ALU operations is a poor trade.

**`acl.c` and `ratelimit.c` are translation units despite passing the same test.** `acl.c`,
written out rather than sketched, is family dispatch over two structurally distinct per-family
checks, each up to two conditional map lookups gated by `CFG_ACL_ENABLE` and `acl_lists` — more
than the "two map lookups" this section originally weighed against a frame. `nexthop.c` already
sets the precedent: a discrete pipeline stage living in its own translation unit with global
subprograms, even though several of its own helpers (`marlin_backend_mac_set()`,
`marlin_fib_onlink()`) are individually as small as the case above. Only `marlin_acl_check()`,
the family dispatch, is global; the two per-family checks stay `static __always_inline` inside
`acl.c` itself, unreachable from outside it.

`ratelimit.c`'s own arithmetic still passes the header test: `rl_spend()` reads no packet byte
and is a few dozen ALU operations, same as `stats.h`. `marlin_ratelimit()` around it does not —
three helper calls (`bpf_map_lookup_elem`, `bpf_map_update_elem`, `bpf_ktime_get_ns`), the
NULL/`CFG_RL_ENABLE`/allow-verdict gates of `docs/design/04-calling-convention.md` and
`docs/design/27-source-filtering.md`, and an unrolled retry loop around the compare-and-swap —
past what an inlined header buys back in call-frame cost. Splitting the arithmetic into its own
`static __always_inline` helper keeps it independently testable
(`docs/design/24-testing.md`) without also splitting the translation unit.

`entropy.h` passes the same test as `stats.h`, not the `csum.h` test: it hashes
`marlin_ctx.tuple`, a BTF struct pointer already resolved by the time either encapsulation unit
calls it, and reads no packet bytes at all — so nothing here forces it into a translation unit,
and a shared header is what `gue.c` and `vxlan.c` both calling the same few-ALU-op hash actually
requires. It moved out of `gue.c` because GUE stopped being the only consumer, not because its
cost characteristics changed.

**Why `types.h` holds map structs only.** Everything in it is ABI the control plane has to
mirror by hand, so anything placed there becomes control-plane surface and another chance to
diverge. `marlin_ctx` and `enum marlin_ret` are datapath-internal and live in `marlin.h`.

**Where L2 DSR lives.** It is a destination-MAC rewrite, which is next-hop resolution (`docs/design/15-nexthop-l2dsr.md`),
so it belongs to `nexthop.c` rather than earning a file. `marlin_balance_encapsulate()` has an
empty case for it.

### Linking

All inputs must carry BTF. Maps are deduplicated by name across objects.
