# Marlin — The Map ABI is Hand-Written on Both Sides

## The map ABI is hand-written on both sides

`types.h` is the single source of truth for map key and value layouts. The control plane's
C# equivalents are **hand-written to match it**, not generated. `[StructLayout]` is
`Sequential` for every struct except `vip_key`, whose anonymous union (`docs/design/08-types.md`) requires
`Explicit` with both arms at `FieldOffset(0)`. Fixed-size array members — `vip_meta.hash_key`,
`backend.mac`, `backend.inner_mac`, the `addr[4]` fields and every `pad` — are `[InlineArray]` or `fixed` buffers,
never managed arrays.

**The accepted risk.** A divergence between the two declarations is silent memory corruption,
not an exception, and nothing in the build detects it. This is accepted: the struct set is
small, closed, and changes rarely, and no BTF-to-C# generator exists to be adopted — the
transformation would have had to be written and maintained as project-specific tooling.

**What the discipline is instead.** Any change to a struct in `types.h` is incomplete until
the C# declaration changes in the same commit. Byte offsets are stated in comments on both
sides — `marlin_config` (`docs/design/08-types.md`) already carries them — so a review can check parity by reading,
which is the only mechanism there is.
