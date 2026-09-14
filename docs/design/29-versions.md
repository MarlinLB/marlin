# Marlin — Version Requirements


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
| `bpftool` with `gen object` | from `linux-tools` matching the kernel, build host only — `data-plane/marlind/main.c` replaces its `prog loadall`/`net attach` use on the forwarding host |

`data-plane/marlind/main.c` links against the same libbpf and uses no API newer than the `bpf_linker` floor above.
