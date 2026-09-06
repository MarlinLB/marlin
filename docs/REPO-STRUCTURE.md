# Marlin — Repository Structure

**Status:** proposed, pending the open decisions in §7
**Reconciled against:** `docs/design/README.md` revision 6, post-ABI-change
(`docs/design/06-map-abi.md`, "The map ABI is hand-written on both sides")

`docs/design/03-translation-units.md` names the datapath translation units but places them in
no directory. This file places every file in the repository and states why. It is a layout
document only: where a placement implies a change to `docs/design/03-translation-units.md`,
that change is listed in §8 as proposed, not applied.

---

## 1. Principles

The rules the layout follows, stated so a new file can be placed without re-deriving them.

1. **One repository.** Three built artefacts (`docs/design/02-architecture.md`) sharing one ABI
   whose two halves must change in the same commit (`docs/design/06-map-abi.md`). A repository
   boundary between them would put that commit across two histories.
2. **A directory per deployed piece**, not a flat tree. The pieces are independent artefacts
   with different toolchains, not one program.
3. **The map ABI is a delimited surface.** Nothing in the build detects a divergence between
   `types.h` and its C# mirror, and review by reading is the only mechanism
   (`docs/design/06-map-abi.md`). Both halves therefore live in directories whose entire
   content is ABI, so the review is a two-directory diff.
4. **Nothing depends on the interop layer for a type.** `Marlin.Abi` carries no project or
   package references, so every other project can depend on it without acquiring libbpf.
5. **Tests are siblings of what they test, not children.** `docs/design/24-testing.md` makes
   packet-level tests a phase-0 artefact; nesting them under `data-plane/` invites treating
   them as build scaffolding.
   **Exception: native C unit tests of a single translation unit.** `data-plane/tests/` holds
   tests that `#include` a `data-plane/src/*.c` file directly to reach its `static` helpers —
   they cannot be moved out of that tree without losing that access, so this principle applies
   above the translation-unit level (`tests/packet/`, `tests/integration/`) and not below it.

---

## 2. Tree

```none
marlin/
├── README.md
├── CLAUDE.md                         # agent guidance; stays at the root, where tooling finds it
├── LICENSE
├── Makefile                          # data-plane → control-plane → tests
├── .editorconfig                     # cross-language only, see §5
├── .gitattributes
├── .gitignore
│
├── docs/                             # see §6 on migrating the existing documents
│   ├── design/                       # README.md plus 29 numbered per-topic files, replacing DESIGN.md
│   ├── DEPLOYMENT.md
│   ├── PHASES.md
│   └── REPO-STRUCTURE.md
│
├── data-plane/
│   ├── Makefile                      # clang -target bpf; bpftool gen object; compile_commands.json
│   ├── .clang-format
│   ├── .clang-tidy
│   ├── src/
│   │   ├── main.c                  # XDP entry point
│   │   ├── balancer.c                # marlin_balance()
│   │   ├── parser.c
│   │   ├── ipip_encap.c
│   │   ├── gue_encap.c
│   │   ├── vxlan_encap.c
│   │   └── nexthop.c
│   ├── include/
│   │   ├── marlin.h                  # marlin_ctx, enum marlin_ret, marlin_* prototypes
│   │   └── marlin/
│   │       ├── abi/                  # every file here has a C# counterpart. Nothing else does.
│   │       │   ├── types.h           # map key and value structs
│   │       │   ├── limits.h          # docs/design/09-sizing.md constants — not in docs/design/03-translation-units.md, see §8
│   │       │   └── enums.h           # modes, states, drop reasons, flag bits — see §8
│   │       ├── maps.h
│   │       ├── csum.h
│   │       ├── entropy.h             # outer UDP source port entropy hash, shared by gue_encap.c and vxlan_encap.c
│   │       ├── siphash.h
│   │       ├── stats.h
│   │       ├── acl.h
│   │       └── ratelimit.h
│   └── tests/                       # native unit tests, `make tests` — Principle 5's exception
│       ├── parser_test.c            # #includes src/parser.c to reach its static helpers
│       ├── packet.h                 # packet builder, reusable by tests/packet/ once that lands
│       └── harness.h
│
├── deploy/
│   ├── marlin-load.sh                # the two commands of docs/design/02-architecture.md
│   ├── marlin-load.service           # oneshot, RemainAfterExit, before marlin.service
│   ├── marlin.service                # the control plane
│   ├── marlin.env.example            # IFACE, pin path
│   └── .shellcheckrc
│
├── control-plane/
│   ├── Marlin.sln
│   ├── Directory.Build.props          # TreatWarningsAsErrors, AnalysisLevel
│   ├── Directory.Packages.props       # central package management
│   ├── .editorconfig                  # all C# rules, see §5
│   ├── Marlin.Abi/                    # hand-written mirror of include/marlin/abi/. Nothing else.
│   │   └── .editorconfig              # narrow exceptions for InlineArray / fixed / unsafe
│   ├── Marlin.Bpf/                    # open pinned paths, map I/O only (docs/design/19-control-plane.md)
│   ├── Marlin.Core/                   # reconciliation, fwd_table generation, ACL/RL conversion
│   ├── Marlin.Health/                 # VRF-bound probers (docs/design/18-health.md)
│   ├── Marlin.Netlink/                # neighbour and link events (docs/design/15-nexthop-l2dsr.md, docs/design/19-control-plane.md)
│   └── Marlin.Api/                    # ASP.NET Core host; configuration and status APIs
│
├── tests/
│   ├── packet/                        # bpf_prog_test_run, exact output bytes (docs/design/24-testing.md)
│   ├── integration/                   # netns, veth, real ipip/sit/FOU/vxlan devices
│   └── unit/
│       ├── Marlin.Core.Tests/
│       ├── Marlin.Health.Tests/
│       └── .editorconfig
│
└── .github/workflows/
    ├── build.yml
    ├── verifier.yml                   # load gate + complexity trend (docs/design/24-testing.md)
    └── style.yml                      # clang-format, clang-tidy, dotnet format, shellcheck
```

---

## 3. Datapath placement

- **`src/` and `include/` split.** `docs/design/03-translation-units.md` compiles each `.c`
  separately and links with `bpftool gen object`, so the source set is a flat list of peers with
  no hierarchy to express. The split exists to keep the compiled inputs visually distinct from
  the headers, many of which are inlined code rather than declarations
  (`docs/design/03-translation-units.md`).
- **`marlin.h` sits above `marlin/`, and is not an umbrella.** `docs/design/03-translation-units.md`
  assigns it exact contents: `marlin_ctx`, `enum marlin_ret`, and the `marlin_*` prototypes. Making it
  include the `marlin/` headers would contradict that and hide which translation unit
  depends on what. Each `.c` includes the specific `marlin/…` headers it uses.
- **The prototypes in `marlin.h` are the global subprogram set.** `docs/design/03-translation-units.md`
  compiles each unit separately and `docs/design/04-calling-convention.md`'s calling convention
  requires anything crossing a unit boundary to be non-`static`, so the declaration must be
  visible at the call site. Only `marlin_balance()` is named in `docs/design/04-calling-convention.md`;
  the rest are unnamed — see §7.
- **`abi/` is a subdirectory, not a naming convention.** `docs/design/03-translation-units.md`
  says anything placed in `types.h` becomes control-plane surface and another chance to
  diverge. A directory answers "which headers oblige a matching C# change in this commit" by
  containment rather than by a sentence someone has to remember.
- **No `vmlinux.h`, no CO-RE directory.** The datapath uses `xdp_md` and `bpf_fib_lookup`,
  which are UAPI, not vmlinux BTF. `docs/design/02-architecture.md` already dropped the C loader
  that CO-RE would have justified.
- **`nexthop.c` holds the L2 DSR MAC rewrite** and no file exists for L2 DSR, per
  `docs/design/03-translation-units.md`.

---

## 4. Control-plane placement

**Project boundaries follow the responsibility list in `docs/design/19-control-plane.md`**, with
two that are boundaries for a reason beyond tidiness:

- **`Marlin.Abi` is separate from `Marlin.Bpf`** because four projects need the struct
  vocabulary — `Core` for `fwd_table` generation (`docs/design/12-selection.md`) and validation,
  `Health` to write `backend.state`, `Api` for the flag bits and drop-reason labels that
  `docs/design/08-types.md` calls part of the control-plane API surface, and `Bpf` for map I/O.
  Merging the two would make all three others reference the interop project to see a struct
  definition, pulling libbpf P/Invoke and syscall marshalling into projects that should
  never hold a file descriptor.
- **`Marlin.Abi` carries no references at all.** That is what makes it safe as a universal
  dependency, and it is enforceable by reading one `.csproj`.
- **`Marlin.Bpf` performs I/O and never creates a map or loads a program.**
  `docs/design/02-architecture.md` confines map creation to `deploy/marlin-load.sh` so there is
  exactly one owner of map identity and sizing. The project boundary is where that rule is
  visible.
- **`Marlin.Health` is separate** because `docs/design/18-health.md` gives it a socket-binding
  and privilege story no other component has: it is the only code that touches a VRF.
- **`Marlin.Api` hosts the rest.** `Core`, `Health` and `Netlink` run under it as background
  services. `docs/design/19-control-plane.md`'s "expose configuration and status APIs" is the
  project's whole job.

`deploy/marlin.service` keeps its name rather than becoming `marlin-api.service`: it is the
single long-running Marlin process an operator manages, and a qualified name would imply
siblings that do not exist.

**`Marlin.Abi` needs `<AllowUnsafeBlocks>`.** `docs/design/06-map-abi.md` requires
`[InlineArray]` or `fixed` buffers for every fixed-size array member and prohibits managed
arrays. That is design-mandated, so the analyzer exceptions are scoped to that one directory
(§5) rather than relaxed solution-wide.

---

## 5. Style and lint files

| Path | Owns |
|---|---|
| `/.editorconfig` | charset, EOL, final newline, trailing whitespace, indent for md/yml/json/sh. **Sets no indent for `*.c`/`*.h`** — see the conflict note below |
| `/.gitattributes` | EOL normalisation; `deploy/*.sh` must stay LF on Windows checkouts |
| `/data-plane/.clang-format` | the only definition of C formatting |
| `/data-plane/.clang-tidy` | C checks |
| `/control-plane/.editorconfig` | all C#: naming, file-scoped namespaces, `dotnet_diagnostic.*` severities |
| `/control-plane/Marlin.Abi/.editorconfig` | narrow exceptions for `[InlineArray]`, `fixed`, `unsafe` |
| `/tests/unit/.editorconfig` | test method naming, magic numbers permitted |
| `/tests/packet/.clang-format`, `.clang-tidy` | only if the harness is C — §7 |
| `/deploy/.shellcheckrc` | `marlin-load.sh` is a shipped artefact (`docs/design/02-architecture.md`) |

Three practical points:

- **`.clang-format` belongs in `data-plane/`, not at the root.** clang-format searches
  upward from the file being formatted, so this scopes the datapath rules without reaching
  `tests/packet/`, which normally wants a longer line limit than production C.
- **`.clang-tidy` is inert without a compile database.** `data-plane/Makefile` must emit
  `compile_commands.json` — concatenated `clang -MJ` fragments, or `bear --`. Without it
  clang-tidy cannot resolve `-target bpf` or the BPF headers, and every file fails to parse
  instead of reporting findings.
- **Root `.editorconfig` and `data-plane/.clang-format` both want C indentation.**
  clang-format wins, because it rewrites the file. Either omit `[*.{c,h}]` indent keys from
  the root file or keep them numerically identical, or IDEs will fight the formatter.

Analyzer severity lives in `control-plane/.editorconfig`, paired with
`TreatWarningsAsErrors` in `Directory.Build.props`. `style.yml` runs `clang-format
--dry-run -Werror`, `clang-tidy` over the compile database, `dotnet format
--verify-no-changes`, and `shellcheck`.

---

## 6. Build flow

```none
make            → data-plane/  clang -target bpf -g   (BTF on every input, docs/design/03-translation-units.md)
                             → bpftool gen object → marlin.bpf.o
                             → compile_commands.json
                → control-plane/  dotnet build
                → tests/          packet, unit
```

No codegen stage. `docs/design/26-superseded.md` records the BTF-to-C# step as superseded on
feasibility: `bpftool btf dump` emits raw, JSON or C, never C#, so the step named a source
and a prohibition but no mechanism.

**Migrating the existing docs.** `DESIGN.md` has already been split into `docs/design/` (a
`README.md` plus 29 numbered per-topic files); the remaining three — `DEPLOYMENT.md`,
`PHASES.md` and `REPO-STRUCTURE.md` — are still at the repository root today,
and the tree puts them in `docs/`. They reference each other by bare filename throughout, which
continues to resolve only if all three move in one commit. `DEVELOPMENT.md` has been deleted
rather than migrated. `CLAUDE.md` stays at the root, where the tooling expects it.

---

## 7. Open decisions

Recorded rather than defaulted, because each changes a directory that is expensive to
rename later.

**7.1 `data-plane/` versus `datapath/`.** The design documents say *datapath*, one word,
throughout — `docs/design/README.md`, `docs/design/02-architecture.md`'s artefact table and
`docs/design/03-translation-units.md`, among others — and never "data plane". They say *control
plane*, two words. `data-plane/` + `control-plane/` reads as a pair and diverges from the
design's vocabulary; `datapath/` + `control-plane/` matches it and reads as mismatched. If
`data-plane/` stands, the design documents need a terminology pass in the same change rather
than the repository and the design disagreeing from the first commit.

**7.2 Packet-harness language.** Decides whether `tests/packet/` needs its own clang files.

| Option | For | Against |
|---|---|---|
| C + libbpf | shortest path to exact-byte assertions | a second test runner in CI |
| C# P/Invoke | one runner; seeds maps through the hand-written structs, so a wrong offset fails a forwarding assertion instead of corrupting production | marshalling a syscall the control plane never makes |
| Python + ctypes | fastest packet crafting | a third language in the tree |

A related, narrower decision already has code waiting on it: whether `data-plane/tests/`
(native C, landed ahead of this one — see Principle 5's exception) joins `make format`/`make tidy`
against the root `.clang-format`/`.clang-tidy`, or takes its own, on the same reasoning this
section already gives for `tests/packet/` wanting a longer `ColumnLimit`.

**7.3 `Marlin.Bpf` interop.** libbpf P/Invoke matches the function names in
`docs/design/19-control-plane.md` and gets `bpf_map_lookup_batch` for free; a raw `bpf()`
syscall wrapper drops the native dependency and costs a few hundred lines of marshalling.

**7.4 `include/marlin/abi/` versus flattening it.** The subdirectory delimits the review
surface by containment. Flattening to `include/marlin/{types,limits,enums}.h` matches
`docs/design/03-translation-units.md`'s file table more literally and moves that delimitation
into a sentence.

**7.5 clang-format base style.** Kernel style — tabs, 8 wide, 80 columns — matches the BPF
samples anyone reading `parser.c` will have read. `BasedOnStyle: LLVM` matches nothing else in
the repository but is less hostile to deep nesting.

**7.6 The unnamed global subprograms.** `docs/design/04-calling-convention.md` names only
`marlin_balance()`. The entries for `parser.c`, `ipip_encap.c`, `gue_encap.c`, `vxlan_encap.c`
and `nexthop.c` are the file-to-file contract and are unspecified; `nexthop.c` may be one or two.
Left silent, the first person to write `parser.c` picks them.

**7.7 An ABI parity test.** A `Marlin.Abi.Tests/` asserting `Marshal.SizeOf` and
`Marshal.OffsetOf` against the byte offsets `docs/design/06-map-abi.md` requires in comments
would catch size and offset drift, though not a reordering of two same-sized fields. It is
absent from §2 deliberately: `docs/design/06-map-abi.md` states that nothing in the build
detects divergence and that review is the only mechanism, so adding it contradicts the design
as written and requires that `docs/design/06-map-abi.md` change first.

---

## 8. Amendments this implies to `docs/design/03-translation-units.md`

Proposed, not applied. Its file table is the authority on datapath file contents; these
are gaps in it that the layout exposed.

1. **`limits.h` is not in the table.** The `docs/design/09-sizing.md` constants — `MAX_VIPS`,
   `TABLE_SIZE`, `MAX_BACKENDS`, `MAX_TX_PORTS`, `MAX_ACL_ENTRIES`, `MAX_RL_ENTRIES`,
   `RL_CAS_RETRIES`, `RL_TOKEN_SHIFT`, `MAX_EXT_HDRS`, `DROP_REASON_MAX` — have no named home,
   yet `maps.h` cannot declare `max_entries` without them and
   `docs/design/20-configuration-validation.md` validates configuration against `MAX_VIPS` and
   `MAX_BACKENDS`. They are therefore control-plane surface, and `types.h` is restricted to map
   structs by `docs/design/03-translation-units.md`.
2. **`enums.h` is not in the table.** `MARLIN_MODE_*`, `MARLIN_UP`/`MARLIN_DOWN`, the flag
   bits of `docs/design/08-types.md` and `docs/design/22-observability.md`'s drop-reason
   enumeration are all control-plane surface, but `docs/design/03-translation-units.md` places
   `enum marlin_ret` in `marlin.h` as datapath-internal and names no home for the rest.
3. **Plain `#define` is now sufficient for the constants.** An earlier draft required an
   anonymous `enum` so `bpftool btf dump` could see them. Nothing reads BTF since
   `docs/design/26-superseded.md`, so that constraint is void.

Items 1 and 2 are the kind of thing that should simply be folded into
`docs/design/03-translation-units.md`'s table, and Phase 2a is where it is settled.
