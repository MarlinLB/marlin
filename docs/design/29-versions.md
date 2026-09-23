# Marlin — Version Requirements

Inbound floors this project depends on -- kernel and toolchain. Marlin's own version is unrelated,
and is not one number: `marlin.bpf.o` and `marlind` version independently, in
`data-plane/bpf/VERSION` and `data-plane/marlind/VERSION` (`docs/PHASES.md`'s open-decision table,
`data-plane/include/marlin/build.h`). "marlind's floor on marlin.bpf.o" below covers the one place
the two meet: the minimum `marlin.bpf.o` version `marlind` will attach.

## Kernel

All below Marlin's 6.0 minimum. Listed for the case where the floor is challenged.

| Feature | Minimum |
|---|---|
| `bpf_fib_lookup()` in XDP | 4.18 |
| Global subprograms (scalar and `PTR_TO_CTX` args) | 5.5 |
| Struct pointer arguments to global subprograms | 5.13 |
| BPF memory charged to the memory cgroup | 5.11 |
| `bpf_map_lookup_batch` | 5.6 |
| `DEVMAP_HASH` | 5.4 |
| `bpf_map_get_next_key` on `LPM_TRIE` | 4.20 |
| `BPF_ATOMIC \| BPF_CMPXCHG` — `ratelimit.c`'s compare-and-swap | 5.12 |
| `bpf_link` for XDP (`BPF_LINK_CREATE` with `attach_type = BPF_XDP`) | 5.9 |

`ARRAY_OF_MAPS`, `DEVMAP`, `LPM_TRIE`, `LRU_HASH`, `PERCPU_ARRAY`, `bpf_csum_diff()` and
`bpf_xdp_adjust_head()` all predate 4.18.

`LPM_TRIE` requires `BPF_F_NO_PREALLOC` and a `max_prefixlen` that is a multiple of 8 between 8
and 2048; `docs/design/08-types.md`'s ACL keys use 32 and 128.

Global subprogram return values are restricted to scalars on all versions, including current
mainline. The restriction is structural: global subprograms are verified independently of their
callers, so there is no caller context in which to establish a returned pointer's provenance,
bounds or lifetime.

## Toolchain

| Requirement | Minimum |
|---|---|
| clang with BPF target and BTF emission | 12 |
| clang `-mcpu=v3`, for `BPF_ATOMIC \| BPF_CMPXCHG` | required, no version floor of its own |
| libbpf with `bpf_linker` (BPF static linking) | 0.4 |
| `bpftool` with `gen object` | from `linux-tools` matching the kernel, build host only — `data-plane/marlind/` replaces its `prog loadall`/`net attach` use on the forwarding host |

`data-plane/marlind/` links against the same libbpf and uses no API newer than the `bpf_linker` floor above.

## marlind's floor on marlin.bpf.o

`marlin.bpf.o` and `marlind` version independently (above), so their two version numbers are
expected to differ -- what `marlind` enforces instead is a minimum supported `marlin.bpf.o`
version, `MARLIND_MIN_BPF_VERSION` in `data-plane/include/marlind/compat.h`. Hand-maintained, not
generated: it is a compatibility claim about other builds, not a fact about this one. Checked in
preflight before `--attach` loads or pins anything (`docs/design/02-architecture.md`); `--version`
runs the same check but only reports it (`docs/DEPLOYMENT.md` §1.2).

The comparator (`marlind_version_cmp()`, same file) is a reduced form of SemVer 2.0.0 precedence:

- `major.minor.patch` compared numerically, never lexicographically (`1.10.0` > `1.9.0`).
- Build metadata (`+...`) is ignored (SemVer §10).
- A pre-release (`-...`) orders below its own release with the same triple (SemVer §11.3).
- Narrowed from full SemVer §11.4 in exactly one place: two pre-releases of the same triple
  compare **equal** rather than being ordered by dot-separated identifier. This cannot misorder
  any version this project has produced, and the one case it under-distinguishes -- two distinct
  pre-releases of one triple -- has never occurred here. Documented as a limitation, not hedged
  away, so that adopting full §11.4 precedence later is a decision, not an accidental fix.
- An unparseable version, on either side, is a distinct outcome, never coerced to "older": a floor
  exists to refuse objects that are genuinely old, not ones this comparator merely failed to read.

**The floor is weak protection, and only in one direction.** It bounds how old an object may be;
nothing bounds how new one may be. A renamed `xdp_main`, a changed map definition, or a changed
`struct marlin_build` layout already fail loudly elsewhere -- the pinned-program lookup, libbpf's
map-reuse error, and `marlin_find_build_map()`'s exact-size match, respectively -- but an object
with identical names and definitions and a *newer*, incompatible meaning (a new `cfg.flags` bit, a
reordered `enum marlin_ret`) attaches without complaint. Whether `marlind` should also carry a
ceiling is an open decision (`docs/PHASES.md`).

The floor is also weak protection **during `0.x`**: SemVer §4 makes every `0.y` bump potentially
breaking, so a floor of `0.1.0` does not stop `0.2.0` from breaking `marlind` -- the floor becomes
a meaningful guarantee only once both sides commit to `1.0.0`. Packaging exists now (`packaging/`,
`docs/DEPLOYMENT.md` §1.2), so what remains is a release decision, not a build one -- see
`docs/PHASES.md`'s open-decision table.
