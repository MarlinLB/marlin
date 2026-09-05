# Marlin — Architecture Overview


Four deployed pieces, three of which Marlin builds:

| Piece | Built | Role |
|---|---|---|
| `marlin.bpf.o` | yes | XDP datapath |
| `marlin-load.sh` + systemd unit | yes | loads, pins, attaches |
| Marlin control plane (C#) | yes | configuration, health, reconciliation |
| `bpftool` | no | supplied by `linux-tools` |

## Load sequence

```sh
bpftool prog loadall marlin.bpf.o /sys/fs/bpf/marlin \
    pinmaps /sys/fs/bpf/marlin

bpftool net attach xdpdrv pinned /sys/fs/bpf/marlin/xdp_main dev "$IFACE"
```

Two commands. All maps are sized at compile time (`docs/design/09-sizing.md`), so no map is pre-created and no
`map name … pinned …` reuse is needed. Run as a systemd oneshot with `RemainAfterExit`,
ordered before the control plane service.

Rationale:

- **`bpftool`, not `ip`.** iproute2 may or may not be linked against libbpf depending on
  the distribution, and its legacy internal loader handles BTF-defined maps and CO-RE
  poorly. `bpftool` ships with `linux-tools` and is libbpf-based.
- **`xdpdrv`, not `xdpgeneric`.** Driver mode fails the attach outright if the NIC cannot
  support native XDP. Silent degradation to SKB mode would satisfy the attach while costing
  an order of magnitude in throughput, and would present as a software fault.
- **Legacy netlink attach rather than `bpf_link`.** The attachment must persist with no
  process holding a file descriptor. That is what the netlink attach does; a `bpf_link`
  would require its own pin to survive.
- **No C loader component.** Load-time map sizing was the only thing that would have
  justified one, and compile-time sizing removes the need. See `docs/design/25-rejected.md`.

## Object lifetime

Maps and programs are pinned under `/sys/fs/bpf/marlin/`, so they persist independently of
any process. The control plane opens pinned paths and performs map I/O only; it never
creates maps.

This is an ownership and ordering rule, not a technical necessity — a pinned map does
outlive its creator. Confining creation to the load script means there is exactly one
owner of map identity and sizing, and the control plane can be restarted or upgraded
without any interaction with the datapath.

## Privileges

| Component | Capabilities | Why |
|---|---|---|
| `marlin-load.sh` | `CAP_BPF`, `CAP_NET_ADMIN` | load, pin, attach XDP |
| Control plane | `CAP_BPF`, `CAP_NET_ADMIN` | map I/O; plus neighbour entries (`docs/design/16-fib-lookup.md`) and probe tunnel interfaces (`docs/design/18-health.md`) |

On kernels ≥ 5.11 BPF memory is charged to the memory cgroup rather than
`RLIMIT_MEMLOCK`, so containerised deployments must size the cgroup limit to include map
memory (`docs/design/09-sizing.md`).
