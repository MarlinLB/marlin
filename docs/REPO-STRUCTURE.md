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
3. **The map ABI is a delimited surface.** `Explicit` layout with `[FieldOffset]` on every
   C# field lets the CLR catch a struct whose fields no longer fit, but a mistranscription
   from `types.h`, a reordering of two same-sized fields, or a value correct in layout but
   wrong in kind (host order for network order, an unapplied scale) is still undetected by
   the build, and review by reading is the mechanism for that residue
   (`docs/design/06-map-abi.md`). Both halves therefore live in directories whose entire
   content is ABI, so the review is a two-directory diff.
4. **Nothing depends on the interop layer for a type.** `Marlin.Abi` carries no project or
   package references, so every other project can depend on it without acquiring libbpf.
5. **Tests are siblings of what they test, not children.** `docs/design/24-testing.md` makes
   packet-level tests a phase-0 artefact; nesting them under `data-plane/` invites treating
   them as build scaffolding.
   **Exception: native C unit tests of a single translation unit, and the packet-level harness
   that reuses them.** `data-plane/tests/` holds tests that `#include` a `data-plane/bpf/*.c`
   file directly to reach its `static` helpers — they cannot be moved out of that tree without
   losing that access. `data-plane/tests/stubs/` is a third thing living there for a related but
   distinct reason: it is neither a test file nor shared with `tests/packet/`, which must keep
   the real libbpf headers to link `-lbpf` — it exists only to give the native tier's map-reading
   and helper-calling translation units (`acl.c`, `ipip.c`) something to `#include` in place of
   libbpf's own `<bpf/bpf_helpers.h>`. `data-plane/tests/packet/` (§7.2) extends the exception for a narrower
   reason: it reuses that tree's `packet.h` and `harness.h` as-is and shares its Makefile, not
   because it needs the same `#include` access. `tests/integration/` has neither reason and
   stays outside `data-plane/`, at the repo root.

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
│   ├── design/                       # README.md plus 30 numbered per-topic files, replacing DESIGN.md
│   ├── DEPLOYMENT.md
│   ├── PHASES.md
│   └── REPO-STRUCTURE.md
│
├── data-plane/
│   ├── Makefile                      # clang -target bpf; bpftool gen object; compile_commands.json
│   ├── VERSION                       # marlin.bpf.o + marlind's shared version; sources include/marlin/version.h (generated)
│   ├── CHANGELOG.md                  # datapath changelog; root CHANGELOG.md is the per-component index
│   ├── .clang-format
│   ├── .clang-tidy
│   ├── bpf/
│   │   ├── main.c                  # XDP entry point
│   │   ├── balancer.c                # marlin_balance()
│   │   ├── parser.c
│   │   ├── ipip.c
│   │   ├── gue.c
│   │   ├── vxlan.c
│   │   ├── nexthop.c
│   │   ├── acl.c                    # marlin_acl_check()
│   │   └── ratelimit.c              # marlin_ratelimit()
│   ├── include/
│   │   ├── marlin.h                  # marlin_ctx, enum marlin_ret, marlin_* prototypes
│   │   ├── marlin/
│   │   │   ├── abi/                  # every file here has a C# counterpart. Nothing else does.
│   │   │   │   ├── types.h           # map key and value structs
│   │   │   │   ├── limits.h          # docs/design/09-sizing.md constants — not in docs/design/03-translation-units.md, see §8
│   │   │   │   └── enums.h           # modes, states, drop reasons, flag bits — see §8
│   │   │   ├── maps.h
│   │   │   ├── build.h               # struct marlin_build, embedded in .rodata.marlin_version (bpf/main.c)
│   │   │   ├── csum.h
│   │   │   ├── entropy.h             # outer UDP source port entropy hash, shared by gue.c and vxlan.c
│   │   │   ├── siphash.h
│   │   │   ├── stats.h
│   │   │   ├── acl.h
│   │   │   └── ratelimit.h          # marlin_ratelimit() prototype
│   │   └── marlind/                  # marlind's own headers — host-only, never reachable from a -target bpf TU (§3)
│   │       ├── marlind.h             # struct config, EXIT_*, MARLIN_PROG_NAME, MARLIN_VERSION (via marlin/version.h), load_config()
│   │       ├── build.h               # marlin_build_from_object(), marlin_find_build_map() -- shared with tools/verifier_stats.c
│   │       ├── log.h                 # logmsg(), die(), notify()
│   │       ├── preflight.h           # preflight()
│   │       ├── bpf_load.h            # load_and_pin_maps(), pin_version(), pin_program(), attach_link()
│   │       └── cmd.h                 # attach_probe(), cmd_attach(), cmd_status(), cmd_unpin()
│   ├── tests/                       # native unit tests, `make tests` — Principle 5's exception
│   │   ├── parser_test.c            # #includes bpf/parser.c to reach its static helpers
│   │   ├── acl_test.c               # #includes bpf/acl.c; map lookups answered by stubs/ below
│   │   ├── ipip_test.c              # #includes bpf/ipip.c; bpf_xdp_adjust_head() answered by stubs/ below
│   │   ├── nexthop_test.c           # #includes bpf/nexthop.c; NULL-argument aborts only
│   │   ├── ratelimit_test.c         # #includes bpf/ratelimit.c; hash map + clock answered by stubs/ below
│   │   ├── csum_test.c              # <marlin/csum.h>, header-only
│   │   ├── mtu_test.c               # <marlin/mtu.h>, header-only
│   │   ├── entropy_test.c           # <marlin/entropy.h>, header-only
│   │   ├── packet.h                 # packet builder, shared with tests/packet/ below
│   │   ├── harness.h                # shared with tests/packet/ below
│   │   ├── stubs/                   # shadows <bpf/bpf_helpers.h> for the native tier only
│   │   │   ├── map_stub.h           # host LPM trie answering bpf_map_lookup_elem
│   │   │   ├── hash_stub.h          # host hash map (exact key, no eviction) for the ratelimit map
│   │   │   ├── xdp_stub.h           # headroom bounds + shadow diff answering bpf_xdp_adjust_head
│   │   │   ├── time_stub.h          # settable clock answering bpf_ktime_get_ns
│   │   │   └── bpf/
│   │   │       └── bpf_helpers.h    # SEC/__uint/__type/__always_inline + the map/adjust_head/clock stubs
│   │   └── packet/                  # bpf_prog_test_run, exact bytes — §7.2: landed here, not the repo root
│   │       ├── xdp_test.c           # cases + main()
│   │       ├── prog.h               # load/run wrapper over libbpf
│   │       ├── maps.h               # map fd lookup, seeding, drop_stats reads
│   │       └── fib.h                # veth + real routes/neighbours for nexthop.c's bpf_fib_lookup() cases
│   ├── tools/                       # dev-only, `make tools` — never installed
│   │   └── verifier_stats.c        # loads marlin.bpf.o via libbpf; verifier insn/stack report
│   └── marlind/                     # the loader; built by data-plane/Makefile's `marlind` target
│       ├── main.c                   # getopt_long: --attach | --status | --unpin
│       ├── log.c                    # logmsg(), die(), notify()
│       ├── config.c                 # load_config()
│       ├── preflight.c              # preflight() -- host-state checks, docs/design/02-architecture.md
│       ├── bpf_load.c               # load, pin, attach -- the map/program/link creation
│       ├── cmd_attach.c             # cmd_attach(): netlink/signalfd watch + epoll loop
│       ├── cmd_status.c             # cmd_status(), attach_probe() (also used by cmd_unpin.c)
│       └── cmd_unpin.c              # cmd_unpin()
│
├── deploy/
│   ├── marlind.service                # Type=notify, before marlin.service
│   ├── marlin.service                 # the control plane
│   └── marlin.env.example             # IFACE, pin path
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
├── tests/                             # packet/ lives at data-plane/tests/packet/ instead (§7.2)
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

**`data-plane/marlind/` is not `data-plane/tools/` and not `deploy/`.** `data-plane/tools/` is
scoped to dev-only tooling (`verifier_stats.c` is never installed); `marlind/`'s sources build a shipped
artefact that runs on every forwarding host, so it belongs beside the other deployed pieces, not among
diagnostics. It is not under `deploy/` either — that directory holds configuration and unit
files, not source that a C toolchain compiles.

`tools/verifier_stats.c` including `include/marlind/build.h` reads as a boundary crossing, but the
directory's actual contract (§3) is host-only, not marlind-only — `data-plane/Makefile`'s tools
rule already passes `-I$(INC_DIR)`, so the include costs nothing to satisfy — and this is the one
piece of logic both binaries would otherwise duplicate.

**`marlind/` sits inside `data-plane/`, not beside it, and has no makefile of its own.** The
loader shares the datapath's host toolchain end to end — the same `clang`, the same
`clang-format`/`clang-tidy` configuration, the same `-lbpf` link — and the two ship together, so
one build per *toolchain* serves Principle 2 better than one per artefact. `data-plane/Makefile`
builds both: `bpf` for `marlin.bpf.o` alone, `marlind` for the loader alone, `all` for both. This
is the one directory in the tree holding two build targets, and that is deliberate: it is also
the one place two deployed artefacts share every tool that produces them.

**`include/marlind/` is host-only and is never reachable from a `-target bpf` TU.** It holds
`marlind/`'s own headers (`struct config`, the CLI exit codes, and the prototypes each `marlind/*.c`
crosses to reach another). It sits beside `include/marlin/`, not inside it, because `include/marlin/`
is the datapath's own namespace (§3) and a header full of glibc/libbpf assumptions must not become
reachable from a BPF TU by accident; `marlind.h` also `#error`s under `__bpf__` as a second line of
defence. `.clang-tidy`'s `HeaderFilterRegex` and `make format`'s `$(HDRS)` cover both directories.

---

## 3. Datapath placement

- **`bpf/` and `include/` split.** `docs/design/03-translation-units.md` compiles each `.c`
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
  `Health` to write the state bit of `backend.flags`, `Api` for the flag bits and drop-reason labels that
  `docs/design/08-types.md` calls part of the control-plane API surface, and `Bpf` for map I/O.
  Merging the two would make all three others reference the interop project to see a struct
  definition, pulling libbpf P/Invoke and syscall marshalling into projects that should
  never hold a file descriptor.
- **`Marlin.Abi` carries no references at all.** That is what makes it safe as a universal
  dependency, and it is enforceable by reading one `.csproj`.
- **`Marlin.Bpf` performs I/O and never creates a map or loads a program.**
  `docs/design/02-architecture.md` confines map creation to `data-plane/marlind/bpf_load.c` so there is
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
| `/.gitattributes` | EOL normalisation; `data-plane/scripts/*.sh` must stay LF on Windows checkouts |
| `/data-plane/.clang-format` | the only definition of C formatting |
| `/data-plane/.clang-tidy` | C checks |
| `/control-plane/.editorconfig` | all C#: naming, file-scoped namespaces, `dotnet_diagnostic.*` severities |
| `/control-plane/Marlin.Abi/.editorconfig` | narrow exceptions for `[InlineArray]`, `fixed`, `unsafe` |
| `/tests/unit/.editorconfig` | test method naming, magic numbers permitted |
| `/data-plane/tests/packet/.clang-format`, `.clang-tidy` | only if `data-plane/tests/` takes its own rather than joining the root's — open, `docs/PHASES.md` |

Three practical points:

- **`.clang-format` belongs in `data-plane/`, not at the root.** clang-format searches
  upward from the file being formatted, so this scopes the datapath rules without reaching
  `data-plane/tests/packet/`, which normally wants a longer line limit than production C.
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

**7.2 Packet-harness language: C + libbpf.** Settled at `data-plane/tests/packet/`, not the
repo root's `tests/packet/` — `data-plane/tests/` had already landed there (Principle 5's
exception) by the time this decision closed, and a second Makefile plus a
`../data-plane/include` reach-around bought nothing. It `#include`s the native tier's `packet.h`
and `harness.h` directly and links `-lbpf`, which the other two options could not do:

| Option | For | Against |
|---|---|---|
| C + libbpf (chosen) | shortest path to exact-byte assertions; reuses `data-plane/tests/packet.h` and `harness.h` as-is | a second test runner in CI alongside the native one |
| C# P/Invoke | one runner; seeds maps through the hand-written structs, so a wrong offset fails a forwarding assertion instead of corrupting production | marshalling a syscall the control plane never makes; discards `packet.h` |
| Python + ctypes | fastest packet crafting | a third language in the tree; discards `packet.h` |

A related, narrower decision still has code waiting on it: whether `data-plane/tests/`
(native C, landed ahead of this one — see Principle 5's exception) joins `make format`/`make tidy`
against the root `.clang-format`/`.clang-tidy`, or takes its own — on the same reasoning this
section gave for `tests/packet/` wanting a longer `ColumnLimit`, now extending to
`data-plane/tests/packet/` as well. `acl_test.c` and `data-plane/tests/stubs/` add two more files
to that undecided set, and `ipip_test.c` plus `stubs/xdp_stub.h` add two more again; `make
format`/`make tidy` operate on `$(SRCS)`/`$(HDRS)` only
(`data-plane/Makefile`), so none of it is tool-enforced either way until the decision closes.

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
`marlin_balance()`. The entries for `parser.c`, `ipip.c`, `gue.c`, `vxlan.c` and `nexthop.c` are
the file-to-file contract and are unspecified; `nexthop.c` may be one or two. Left silent, the
first person to write `parser.c` picks them.

**7.7 An ABI parity test.** `docs/design/06-map-abi.md` now requires every mirrored struct to
be `[StructLayout(Explicit)]` with `[FieldOffset]` per field, so the CLR already refuses a
struct whose fields do not fit its declared `Size` — the size/offset-drift class a
`Marlin.Abi.Tests/` asserting `Marshal.SizeOf`/`Marshal.OffsetOf` would have caught. What no
runtime check catches is a reordering of two same-sized fields on the C side with the C# side
left unchanged, since the C# offsets are transcribed by hand and a self-consistent
mistranscription loads without error. Closing that gap needs an oracle outside both
hand-written declarations — a CI step comparing `bpftool btf dump`'s member offsets against
the C# `[FieldOffset]` set, in both directions — and is undecided (`docs/PHASES.md`'s
open-decision table, phase 2a). It is not the BTF-to-C# generation `docs/design/26-superseded.md`
rejects: a two-column offset comparison models no C# syntax and emits no code, where
generation would have to model both.

**7.8 Netns integration rigs: `tests/integration/` versus `data-plane/scripts/`.** Principle 5
places netns/veth integration tests at the repo root, outside `data-plane/`, on the same
reasoning that carves out `data-plane/tests/` — neither exception applies to a shell script
that drives `ip`/`bpftool` against a built `marlin.bpf.o`, so `tests/integration/` is what this
document specifies. In practice, all five per-mode rigs (`l2dsr_wsl.sh`, `ipip_wsl.sh`,
`gue_wsl.sh`, `vxlan_wsl.sh`, and the multi-backend `netns-topo.sh`) live at
`data-plane/scripts/` instead, and each carries a header comment asserting the
`tests/integration/` placement this section describes — a claim about their own location that
has been wrong since the first of them landed. Left unresolved: whether to move the five
scripts to `tests/integration/` (closing the gap this document describes) or to amend this
document and Principle 5's exception list to admit `data-plane/scripts/` as a third exception,
on the grounds that a rig which only means anything next to the `Makefile` that builds the
object it attaches is closer to `data-plane/tests/`'s reasoning than to a standalone test tree
(`docs/PHASES.md`'s open-decision table, phase 2b).

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
