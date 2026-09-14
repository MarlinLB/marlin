# Marlin — Stack and Verifier Budgets

## Stack budget

`MAX_BPF_STACK` is **512 bytes combined across the entire call chain**, not per frame.
`MAX_CALL_FRAMES` limits nesting to 8. `marlin_ctx` therefore consumes budget that every
callee shares.

Target: `marlin_ctx` ≤ 108 bytes, leaving ≳400 bytes for the call chain. This is a hard
constraint on how much per-packet state may be threaded, and is the reason `marlin_ctx`
holds a resolved copy of `struct backend` (32 bytes) rather than accumulating scratch.

**104 of the 108 are used**, sixteen of them spent widening `struct backend` for
`egress_ifindex`, `vni` and `inner_mac` (`docs/design/16-fib-lookup.md`, `docs/design/08-types.md`).
The remaining four are not spare capacity: `nexthop.c`'s
`struct bpf_fib_lookup` is 64 bytes of the chain's share on its own. The
target was raised from 96 to 108 by decision, not by measurement — the project owner's explicit
sanction for `struct backend`'s growth to carry VXLAN's overlay identity — and that is the honest
description of it rather than a justification worked backward from the number. Raising it further
is still a decision to be made against a measured chain depth, not to absorb the next field someone
wants to thread. Both aggregate members earn their place by being read in a unit other than the one
that writes them — `backend` by the encapsulation units and `nexthop.c`, `cfg` by
`balancer.c` and the encapsulation units — and that is the test any addition has to pass.

**Measured, not estimated.** `make verifier-stats` (`data-plane/tools/verifier_stats.c`, which loads
`marlin.bpf.o` through libbpf directly — no `bpftool`, no bpffs pin, since some hosts' LSM
policy blocks bpffs writes even under root) reports the worst combined stack depth across
everything `xdp_main` reaches, against the 512-byte limit. The figure moves whenever a unit's
frame does, so it is read from the build rather than quoted here; CI records it as the
regression signal (`docs/design/24-testing.md`).

The kernel's own verifier log states this as one figure per BPF-to-BPF-callable function, joined
with `+` — "stack depth 144+72+24+32+..." — and that display reads exactly like a sum to add up,
which it is not: each figure is already that function's own worst case if execution starts
there, with no call-graph information attached, in an order that carries no names. Neither the
sum nor the maximum of that flat list is what `MAX_BPF_STACK` is checked against — what is
checked is the deepest **root-to-leaf sum along the real call graph**, each frame rounded up to
16 bytes (`round_up_stack_depth()`, kernel-JIT builds — the default, `bpf_jit_enable=1`) or 32
bytes (interpreted builds).

This is not one of Marlin's units calling another as a byte-for-byte coincidence: `balancer.c`
calls seven of the other nine global subprograms directly, so `xdp_main → marlin_balancer_process
→ marlin_vxlan_encap_packet` is a real three-frame chain, not three siblings. `verifier_stats.c`
reconstructs that call graph from the linked object's own `R_BPF_64_32` relocations — the
BPF-to-BPF call sites `bpftool gen object` leaves for libbpf to resolve — pairs it with each
function's own decoded stack depth, and walks it depth-first from `xdp_main` to report the worst
chain by name, under both roundings. The kernel's anonymous per-function list is still printed
alongside for cross-checking, but it is no longer what the tool's answer is derived from.

`balancer.c` does not appear as a figure of its own: its stage functions are `static
__always_inline` (see Verifier budget, below), so their cost lands in the frame of whichever
caller reaches them rather than in a callee's. Editing them moves a number that is not labelled
with their name, which is the second reason the depth is read from the build rather than
recorded here.

**This budget, not map memory, is what bounds `struct backend`.** `backends` holds 4096 entries
and costs 128 KB against `fwd_table`'s 26 MB (`docs/design/09-sizing.md`, "Memory"), so a field added there is invisible
in map terms and immediate here. Any future widening is a stack decision.

## Verifier budget

Independent verification of global subprograms is the mitigation for the verifier's
processed-instruction budget (`BPF_COMPLEXITY_LIMIT_INSNS`, 1,000,000 processed
instructions — distinct from the 1M maximum *program size*). Four modes across two inner
families in one monolithic program is where path explosion would appear; separately
verified global subprograms keep it tractable.

The unit of independent verification is the translation unit boundary, not every named
function. Inside `balancer.c` only `marlin_balance()` is global; its stage functions are
`static __always_inline` and are verified as one body with it. That is deliberate — the
selection path is branch-light, and factoring it into global subprograms would have cost a
call frame and the output-parameter convention for no reduction in path count. What remains
independently verified is where the explosion actually lives: `parser.c`, the three
encapsulation units, and `nexthop.c` with its seven FIB return codes and its two next-hop
paths, one of which branches again on whether the MAC-swap default applies
(`docs/design/15-nexthop-l2dsr.md`).

**Fallback if the budget is still exceeded:** move mode dispatch to a `PROG_ARRAY` with one
program per mode — a fourth program under this fallback, making the case for it slightly
stronger than with three. Three consequences, recorded so they are not rediscovered under
pressure:

1. A tail call replaces the caller's frame, so the stack-allocated `marlin_ctx` does not
   survive dispatch. The output-parameter convention would have to move to a per-CPU scratch
   map.
2. Programs mixing tail calls with BPF-to-BPF calls are capped at 256 bytes of accumulated
   stack — the fallback tightens the stack budget rather than preserving it.
3. Tail calls do not return to the caller.

With NAT removed, verifier pressure is substantially lower than originally estimated, and this
is now measured rather than assumed: the same `make verifier-stats` run cited under Stack
budget, above, reports **15,155 processed instructions against the 1,000,000 limit** — under
2% of budget — for the same reachable set (`parser.c`, `acl.c`, all three encapsulation units,
both `nexthop.c` entry points). This fallback is not needed today. The kernel's log reports one
aggregate instruction count for the whole verification pass, not a per-subprogram breakdown, so
"complexity per unit" is not separable from this figure — the aggregate is what the 1,000,000
limit is checked against regardless, and is the number that matters for this criterion.
