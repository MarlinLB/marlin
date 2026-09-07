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
    __u16 l3_off;            /*  2 */
    __u16 l4_off;            /*  2 */
    __u16 pkt_len;           /*  2 */
    __u8  acl_verdict;       /*  1 — enum marlin_acl_verdict, docs/design/27-source-filtering.md */
    __u8  pad;               /*  1 */
};
```

```c
int marlin_balance(struct xdp_md *ctx, struct marlin_ctx *mctx);
```

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
