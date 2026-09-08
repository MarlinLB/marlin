# Marlin — Calling Convention

## Calling convention

Functions crossing a translation unit must be non-`static`, making them global subprograms.
Global subprograms are verified independently of their callers and are restricted to
**scalar return values on every kernel version**.

- **Prefix.** `marlin_*` marks a pipeline stage, not a linkage class. Every global
  subprogram carries it, and so do the `static` stage functions inside a unit —
  `marlin_balance_process_packet()`, `marlin_balance_encapsulate()`. Globals share one
  namespace across the linked object and the linker rejects duplicates.
- **Output parameters, not returns.** One per-packet context struct is allocated in the
  entry frame and threaded through as a pointer.

```c
struct marlin_ctx {          /* 104 bytes */
    struct packet_tuple tuple; /* 40 — written by parser.c, read by everything after */
    struct backend backend;  /* 32 — written by balancer.c, read by the encap units */
    struct marlin_config cfg;/* 20 — written by marlin.c, read by balancer.c and the encap units */
    __u32 flags;             /*  4 */
    __u16 l3_off;            /*  2 — parser.c's ingress value; an encap unit updates it to the outer offset */
    __u16 l4_off;            /*  2 */
    __u16 pkt_len;           /*  2 — parser.c's ingress value; an encap unit updates it to the emitted length */
    __u8  acl_verdict;       /*  1 — enum marlin_acl_verdict, docs/design/27-source-filtering.md */
    __u8  pad;               /*  1 */
};
```

```c
int marlin_balance(struct xdp_md *ctx, struct marlin_ctx *mctx);
```

The three encapsulation units share this shape and prefix pattern —
`marlin_nexthop_l2dsr()`/`marlin_nexthop_encapsulate()` (`include/marlin/nexthop.h:11-12`) are
the precedent already in the tree:

```c
int marlin_ipip_encap_packet(struct xdp_md *ctx, struct marlin_ctx *mctx);
int marlin_gue_encap_packet(struct xdp_md *ctx, struct marlin_ctx *mctx);
int marlin_vxlan_encap_packet(struct xdp_md *ctx, struct marlin_ctx *mctx);
```

Each returns `MARLIN_OK` on success — the caller then proceeds to next-hop resolution
(`docs/design/11-pipeline.md` step 9) — or a `MARLIN_DROP_*` reason: `MARLIN_DROP_FRAME_TOO_BIG`
from `mtu.h` (`docs/design/23-mtu.md`), or `MARLIN_DROP_ADJUST_HEAD` if
`bpf_xdp_adjust_head()` itself fails. **Each unit calls and owns its own `adjust_head`; there is
no shared call site for it**, because the three units disagree on both the byte count and on
whether the arriving Ethernet header must be copied first (`docs/design/14-forwarding-modes.md`
§7.2-7.4) — there is no common shape left to factor out once the disagreement is accounted for.

Every global subprogram that takes a pointer parameter — the three encapsulation units,
`marlin_parse()`, `marlin_nexthop_l2dsr()`, `marlin_nexthop_encapsulate()`, `marlin_acl_check()`,
and `marlin_ratelimit()`
— null-checks every pointer it receives and returns `MARLIN_ABORT_NULLREF` (`marlin_acl_check()`
returns `MARLIN_ACL_ABORT`, its own verdict type's spelling of the same outcome; see below). A NULL
argument to one of these is a caller bug, not a property of the packet, so it is distinct from
`MARLIN_DROP_PARSE_ERROR`, which stays reserved for a bounds check the packet itself can fail —
`marlin_parse_eth()` and `marlin_nexthop_eth()` returning NULL for a frame shorter than
`ETH_HLEN` is the one already in the tree. The check is unreachable in the compiled datapath: a
global subprogram's BTF struct-pointer argument is non-NULL by verifier contract, so the branch
is pruned at load. It exists for the native test tier, where the same source is compiled and
called directly on the host with no verifier to make the argument's non-nullness a precondition
(`docs/design/24-testing.md`). `static __always_inline` helpers — `mtu.h`, `entropy.h`, `csum.h`,
`stats.h` — are exempt: they are verified in the caller's frame and always called with the
address of a local, never a pointer that could be NULL.

- **`marlin_ctx` carries what crosses a translation unit boundary, plus one stage boundary.**
  `vip_num` and `backend_id` are not members: nothing outside `balancer.c` reads them, and the
  statistics they key are bumped in the frame that derives them. State that never leaves a
  frame is a local, not context.

  `acl_verdict` is the one exception and does not cross a translation unit boundary either.
  `docs/design/11-pipeline.md` splits the two filtering steps around the VIP lookup — the ACL at step 3, its verdict
  consumed by the metering gate at step 5 — so the verdict must survive step 4. Carrying it
  here costs a byte of existing padding and keeps the step 4-8 stage function's signature about
  the packet pipeline rather than about a filtering result it never reads. It is `__u8` and not
  `enum marlin_acl_verdict` because `acl.h` includes `marlin.h` and not the reverse; a zeroed
  `marlin_ctx` reads as `MARLIN_ACL_NONE`, which is the safe default — no allow, so no metering
  exemption.

  `enum marlin_acl_verdict` carries a fourth member, `MARLIN_ACL_ABORT`, for a NULL `mctx` —
  `marlin_acl_check()`'s signature returns the verdict enum directly rather than a `marlin_ret`
  and an output parameter, so it has no other channel for the NULL-argument convention above.
  The caller (`main.c`) checks for `MARLIN_ACL_ABORT` before the store into `mctx->acl_verdict`
  and maps it to `MARLIN_ABORT_NULLREF`, so the field itself never holds it and `MARLIN_ACL_NONE`
  staying `0` is unaffected.

- **`cfg` is the per-packet configuration snapshot, taken once in `marlin.c`.** It qualifies by
  the same test as everything else here: four units read it — `balancer.c` for `flags` and
  `max_frame`, `ipip.c`, `gue.c` and `vxlan.c` for `tunnel_src` (`docs/design/14-forwarding-modes.md`). No unit other
  than `marlin.c` looks the `config` map up.

  Two things follow from taking it once rather than per unit. **One generation per packet:** the
  control plane rewrites `marlin_config` whole while packets are in flight
  (`docs/design/17-reconfiguration.md`), so independent
  lookups could observe a field either side of a write within a single packet — `flags` read as
  ACL-off in one stage and RL-on in another is the combination `docs/design/20-configuration-validation.md` rejects at configuration
  time, reconstructed at runtime. **Less stack, not more:** the budget below is combined across
  the call chain, and the frames of `xdp_marlin`, `marlin_balance()` and an encapsulation unit
  coexist on it, so a local copy per unit costs 20 bytes *per unit* where this costs 20 bytes
  once. Threading it as an extra argument to each global subprogram costs the same 20 bytes as
  this does and adds a parameter to every signature (`docs/design/25-rejected.md`).

  The copy is not atomic — a 20-byte read cannot be in BPF — so it narrows cross-field mixing to
  the instant of the copy rather than eliminating it. `docs/design/08-types.md` says the rest.

- **`l3_off` and `pkt_len` hold the ingress values through parsing, and an encapsulation unit
  updates both to the post-encapsulation values before returning.** Nothing downstream reads
  either today — `nexthop.c`'s `fib.tot_len` re-derives its length from `ctx->data_end -
  ctx->data` rather than from `pkt_len` — so the choice is not forced by an existing reader; it
  is made now so a future reader finds `marlin_ctx` describing the frame as it will actually be
  transmitted, not the frame that arrived. `mtu.h`'s `frame_too_big` check
  (`docs/design/23-mtu.md`) is the one caller that needs the *ingress* value, which is why it
  runs before either field is updated, not after.

- **`marlin_ctx` must be fully zeroed before the first `marlin_*` call.** For a BTF
  struct-pointer argument the verifier requires the pointed-to stack memory to be
  initialised; the "each stage fills in its part" pattern otherwise fails with
  `invalid indirect read from stack`.
- **`static` for pointer freedom.** Static functions are verified in the caller's context
  and may return pointers or aggregates, including pointers into map values. The
  scalar-only restriction binds global subprograms alone, so a `static` helper may return
  a `struct vip_key` by value. Only the global boundary needs the output-parameter
  convention.
- **No packet pointer may be held across a `marlin_*` call.** Each global subprogram
  re-derives `data` and `data_end` from `ctx` on entry. The verifier's tracking of whether a
  called subprogram invalidates packet pointers was added in December 2024, so on the older
  half of the supported kernel range a stale pointer is accepted and unsafe, and on the
  newer half the same source is rejected at load. Re-deriving on entry makes the question
  moot on every supported kernel. See also `docs/design/11-pipeline.md`, "Pointer invalidation".
