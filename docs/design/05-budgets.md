# Marlin — Stack and Verifier Budgets

## Stack budget

`MAX_BPF_STACK` is **512 bytes combined across the entire call chain**, not per frame.
`MAX_CALL_FRAMES` limits nesting to 8. `marlin_ctx` therefore consumes budget that every
callee shares.

Target: `marlin_ctx` ≤ 96 bytes, leaving ≳400 bytes for the call chain. This is a hard
constraint on how much per-packet state may be threaded, and is the reason `marlin_ctx`
holds a resolved copy of `struct backend` (20 bytes) rather than accumulating scratch.

**92 of the 96 are used**, four of them spent widening `struct backend` for
`egress_ifindex` (`docs/design/16-fib-lookup.md`). The remaining four are not spare capacity: `nexthop.c`'s
`struct bpf_fib_lookup` is 64 bytes of the chain's share on its own, and `parse.c`'s
extension-header walk and the GUE entropy hash have not been written. Raising the target is a
decision to be made against a measured chain depth, not to absorb the next field someone wants
to thread. Both aggregate members earn their place by being read in a unit other than the one
that writes them — `backend` by the encapsulation units and `nexthop.c`, `cfg` by
`balancer.c` and the encapsulation units — and that is the test any addition has to pass.

**This budget, not map memory, is what bounds `struct backend`.** `backends` holds 4096 entries
and costs 80 KB against `fwd_table`'s 26 MB (`docs/design/09-sizing.md`, "Memory"), so a field added there is invisible
in map terms and immediate here. Any future widening is a stack decision.

## Verifier budget

Independent verification of global subprograms is the mitigation for the verifier's
processed-instruction budget (`BPF_COMPLEXITY_LIMIT_INSNS`, 1,000,000 processed
instructions — distinct from the 1M maximum *program size*). Three modes across two inner
families in one monolithic program is where path explosion would appear; separately
verified global subprograms keep it tractable.

The unit of independent verification is the translation unit boundary, not every named
function. Inside `balancer.c` only `marlin_balance()` is global; its stage functions are
`static __always_inline` and are verified as one body with it. That is deliberate — the
selection path is branch-light, and factoring it into global subprograms would have cost a
call frame and the output-parameter convention for no reduction in path count. What remains
independently verified is where the explosion actually lives: `parse.c`, the two
encapsulation units, and `nexthop.c` with its seven FIB return codes and three mode paths.

**Fallback if the budget is still exceeded:** move mode dispatch to a `PROG_ARRAY` with one
program per mode. Three consequences, recorded so they are not rediscovered under pressure:

1. A tail call replaces the caller's frame, so the stack-allocated `marlin_ctx` does not
   survive dispatch. The output-parameter convention would have to move to a per-CPU scratch
   map.
2. Programs mixing tail calls with BPF-to-BPF calls are capped at 256 bytes of accumulated
   stack — the fallback tightens the stack budget rather than preserving it.
3. Tail calls do not return to the caller.

With NAT removed, verifier pressure is substantially lower than originally estimated and
this fallback is unlikely to be needed.
