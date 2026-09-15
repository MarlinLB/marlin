# Marlin — Architecture Overview


Three deployed pieces, all built by Marlin:

| Piece | Built | Role |
|---|---|---|
| `marlin.bpf.o` | yes | XDP datapath |
| `marlind` + systemd unit | yes | loads, pins, attaches, holds the `bpf_link` |
| Marlin control plane (C#) | yes | configuration, health, reconciliation |

`bpftool` is a build-host requirement only — `bpftool gen object` links the per-unit `.o` files
into `marlin.bpf.o` (`docs/design/29-versions.md`). The forwarding host does not need it.

## Attach sequence

`marlind --attach`, in order:

1. Preflight: refuses rather than configures (§1.3 of `docs/DEPLOYMENT.md`).
2. Opens `marlin.bpf.o`, sets a pin path on every user-defined map, and loads it. libbpf reuses
   whatever is already pinned under `/sys/fs/bpf/marlin/` and creates the rest — the program
   always loads fresh, but map contents and VIP configuration survive both a restart and a
   datapath upgrade, provided no map's definition changed. Internal maps (`.rodata`, `.bss`, …)
   are excluded: their libbpf-derived names contain a `.`, which bpffs refuses to look up, and
   reusing one across an upgrade would silently keep its old contents — wrong by construction for
   `.rodata.marlin_version`, the build-version global this object carries, on the one upgrade that
   changes it.
3. Pins the program, replacing any stale pin from a previous run — and, the same way, pins the
   version global under `<pin_dir>/version`, so `marlind --status` and `bpftool map dump pinned`
   both see the version of what actually loaded.
4. Calls `bpf_link_create()` on the program against the interface's ifindex with
   `XDP_FLAGS_DRV_MODE`, and holds the resulting link for as long as it runs.
5. Reports readiness to systemd and blocks — woken only by `SIGTERM`/`SIGINT`, or by a netlink
   `RTM_DELLINK` for the interface it is attached to.

Rationale:

- **`XDP_FLAGS_DRV_MODE`, not mode-unspecified.** `bpf_link_create()` with no mode flag lets the
  kernel silently fall back to generic/SKB mode when the driver lacks native XDP support —
  exactly the order-of-magnitude throughput regression this line exists to refuse. It must fail
  the attach, not degrade it.
- **A libbpf call, not a shelled-out tool.** Attaching directly through the syscalls avoids
  parsing another program's output and lets this process hold the resulting file descriptor,
  which the next point depends on.
- **`bpf_link`, not a legacy netlink attach.** A link-owned attach cannot be replaced or removed
  by `ip link set … xdp off` or `bpftool net detach` — both fail `EBUSY` against it — and it
  dies with the process that created it. That is deliberate: it is what makes systemd's view of
  the unit (`active (running)` or not) equal to the kernel's view of the attach, which a
  `RemainAfterExit` oneshot holding no link cannot express (`docs/DEPLOYMENT.md` §1.2).
- **A libbpf loader, not `bpftool`.** `bpftool link` has no `create` verb and `bpftool net attach`
  is netlink-only, so a `bpf_link` attachment requires libbpf code to exist somewhere.
  `docs/design/25-rejected.md` records the load-time map sizing and CO-RE grounds on which a
  general-purpose C loader was rejected; those do not apply here — this component exists only to
  attach, pin, and hold the link.

## Object lifetime

Maps are pinned under `/sys/fs/bpf/marlin/` and persist independently of any process — the
loader's own map-pin reuse (above) is what makes that persistence useful across restarts. The
program's attach does not persist the same way: it lives exactly as long as the loader process
holding its `bpf_link`, which is what ties "the unit is running" to "the datapath is attached"
with no gap for either to go stale.

The control plane opens pinned paths and performs map I/O only; it never creates a map, loads a
program, or touches the link. Restarting or upgrading it does not disturb forwarding.

## Privileges

| Component | Capabilities | Why |
|---|---|---|
| `marlind` | `CAP_BPF`, `CAP_NET_ADMIN` | load, pin, attach XDP |
| Control plane | `CAP_BPF`, `CAP_NET_ADMIN` | map I/O; plus neighbour entries (`docs/design/16-fib-lookup.md`) and probe tunnel interfaces (`docs/design/18-health.md`) |

On kernels ≥ 5.11 BPF memory is charged to the memory cgroup rather than
`RLIMIT_MEMLOCK`, so containerised deployments must size the cgroup limit to include map
memory (`docs/design/09-sizing.md`).
