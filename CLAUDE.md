# Marlin — agent guidance

eBPF/XDP layer-4 load balancer. Datapath is C compiled with clang and attached as native XDP;
control plane is C#/.NET 10. Design is settled and pre-implementation.

**Read `PHASES.md` before deciding something is in scope.**

## Documents, in the order they answer questions

| Question | Document |
|---|---|
| How does it work, and why that way? | `docs/design/README.md` (revision 6, split into per-topic files) |
| Is this in scope now, and what is still undecided? | `PHASES.md` |
| Where does this file go? | `REPO-STRUCTURE.md` |
| What must the integrator provide? | `DEPLOYMENT.md` |
| Source filtering and rate limiting | `docs/design/27-source-filtering.md`, `docs/design/28-rate-limiting.md` |

## Rules

- **Re-read the tree before answering or editing.** Files change outside the session; assume
  your mental model is stale.
- **Answer the exact question, with file-and-line citations.** Do not restate the question.
- **Be concise and list-based.** Walls of text will be called out.
- **Present decisions as options** — concise, clearly worded, with pros and cons.
- **Once a scope decision is made, write it into the documents and stop re-litigating it.**
- **Report documentation drift; do not silently fix it.**
- **Name an undecided thing where the decision lives** — in the section whose argument it
  interrupts, or at the line that would have to change — and add it to `PHASES.md`'s open-decision
  table with the phase that must close it. There is no separate gaps document.
- **Remove unverifiable figures, do not hedge them.** If a number cannot be derived from
  source material, omit it.
- **Check prior art** — GitHub's GLB and Meta's Katran — before adopting a novel mechanism.
- **Run an adversarial verification pass** over your own output before presenting it, for
  anything non-trivial.

## Code comments

- **File header:** one short paragraph at the top of the file, no more.
- **No phase/plan narration in code** — no "In phase 2b: ...", "this part handles ...", or
  similar. That belongs in `PHASES.md`, not the source.
- **Comment only what isn't self-explanatory**, and then explain *why* the code exists (the
  constraint, bug, or requirement behind it), not what it does — the code already says that.
- When editing existing code, remove comments that violate the above instead of leaving them.

## Traps specific to this codebase

- `types.h` is ABI. The C# mirror is hand-written and nothing checks that the two agree, so a
  divergence is silent memory corruption. Change both in the same commit.
- `enum marlin_ret` values are `drop_stats` indices from first release. Append, never reorder.
- The BPF stack is 512 bytes **combined across the whole call chain**. `marlin_ctx` is 92.
- Never hold a packet pointer across a `marlin_*` call, and re-read `data`/`data_end` after
  every `bpf_xdp_adjust_head()`.
- Every source file is tab-indented while `.clang-format` and `.editorconfig` mandate spaces.
  Do not resolve this incidentally — it is a Phase 1 decision in `PHASES.md`.
