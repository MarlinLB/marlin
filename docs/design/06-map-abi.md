# Marlin — The Map ABI is Hand-Written on Both Sides

## The map ABI is hand-written on both sides

`types.h` is the single source of truth for map key and value layouts. The control plane's
C# equivalents are **hand-written to match it**, not generated. `[StructLayout]` is
`Explicit` for **every** struct, with `[FieldOffset]` stated on every field — not `Sequential`
with `vip_key` as the lone exception. `vip_key`'s anonymous union puts both arms at
`FieldOffset(0)`; every other struct's fields simply carry the offset `types.h` assigns them.
Fixed-size array members — `vip_meta.hash_key`, `backend.mac`, `backend.inner_mac`, the
`addr[4]` fields and every `pad` — are `[InlineArray]` or `fixed` buffers, never managed
arrays.

**Why every struct is `Explicit`, not only `vip_key`.** Under `Sequential`, a byte-offset
comment is asserted by the author and checked by a reader; under `Explicit`, the offset is
part of the declaration and the CLR refuses to load a struct whose fields do not fit the
stated `Size`. This turns a category of drift — a field dropped, widened, or measured against
the wrong `Size` — from something a reviewer must notice into something the runtime refuses to
run. It does not require generation: the offsets are still hand-copied from `types.h`, just
copied into an attribute instead of a comment.

**The accepted risk, narrowed.** A CLR-enforced offset does not check itself against
`types.h` — the offsets are still transcribed by hand, so a mistranscription that is
internally consistent (every field moved to make room for one at the wrong place) loads
without error. Nor can it catch a reordering of two same-sized fields, or a value that is
laid out correctly but wrong in kind — host order stored where network order is read,
or a scaling factor applied on one side and not the other. That residue is still silent
memory corruption or misinterpretation, not an exception, and nothing in the build detects
it. This is accepted for the same reason as before: the struct set is small, closed, and
changes rarely, and no BTF-to-C# generator exists to be adopted — the transformation would
have had to be written and maintained as project-specific tooling. Whether a mechanical check
against the compiled BTF is worth adding to close the reordering gap is undecided
(`docs/REPO-STRUCTURE.md` §7.7).

**What the discipline is instead.** Any change to a struct in `types.h` is incomplete until
the C# declaration changes in the same commit. Byte offsets are stated as `[FieldOffset]` on
the C# side and in comments on the C side — `marlin_config` (`docs/design/08-types.md`)
already carries them — so a review can check parity by reading, which is the primary
mechanism for what `Explicit` layout does not already enforce.
