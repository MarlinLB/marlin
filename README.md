# Marlin

A stateless eBPF/XDP layer-4 load balancer. The datapath is C, compiled with clang and
attached as native-mode XDP; the control plane is a C#/.NET 10 service.

**Status:** design settled, pre-implementation.

---

## What it does

Four forwarding modes, all Direct Server Return — backends reply to clients without
traversing Marlin, and Marlin holds no per-flow state.

| Mode | Inner families | Outer family | Backend requirement |
|---|---|---|---|
| L2 DSR | IPv4, IPv6 | n/a | VIP on loopback, ARP/NDP suppression, same L2 segment |
| IPIP | IPv4, IPv6 | IPv4 | `ipip` and/or `sit` tunnel device |
| GUE | IPv4, IPv6 | IPv4 | one FOU/GUE listener |
| VXLAN | IPv4, IPv6 | IPv4 | a `vxlan` device with the matching VNI and dstport |

Mode is a property of the individual backend — a single VIP may be served by backends
running different modes at once.

### Targets

- Up to 100 VIPs, compile-time maximum.
- Close to line rate with minimum added latency. Native XDP is mandatory, not preferred.
- Minimum kernel 6.0.

### Non-goals

L3 NAT, L4-granular or stateful filtering, userspace attack classification, L7 processing,
IPv6 underlay, and port translation are explicitly out of scope, with the reasoning for each
recorded in `docs/design/01-scope.md`.

---

## Architecture

Three deployed pieces, all built by Marlin:

| Piece | Built | Role |
|---|---|---|
| `marlin.bpf.o` | yes | XDP datapath |
| `marlin-dataplane` + systemd unit | yes | loads, pins, attaches, holds the `bpf_link` |
| Marlin control plane (C#) | yes | configuration, health, reconciliation |

`bpftool` is a build-host requirement only (`bpftool gen object`); the forwarding host does not
need it.

## Repository layout

See `REPO-STRUCTURE.md` for the full tree and the reasoning behind each placement.

## Documentation map

| Question | Document |
|---|---|
| How does it work, and why that way? | `docs/design/README.md` |
| Is this in scope now, and what is still undecided? | `PHASES.md` |
| Where does this file go? | `REPO-STRUCTURE.md` |
| What must the integrator provide? | `DEPLOYMENT.md` |

## Build and load

| Requirement | Minimum |
|---|---|
| Linux kernel | 6.0 |
| clang, BPF target, BTF emission | 12 |
| libbpf with `bpf_linker` | 0.4 |
| `bpftool` (build host only — `gen object`) | matching the running kernel |
| .NET | 10 |

The forwarding host runs one binary:

```sh
marlin-dataplane attach
```

It loads `marlin.bpf.o`, pins it under `/sys/fs/bpf/marlin`, attaches natively to `$IFACE`, and
holds the resulting `bpf_link` for as long as it runs — see `docs/design/02-architecture.md`.

## Deployment

Marlin is delivered as software. It does not configure the network it runs in or the
servers it forwards traffic to — both are the integrator's responsibility. See
`DEPLOYMENT.md` for everything that must be true before Marlin will forward a packet
correctly.

## License

Apache License 2.0. See `LICENSE` for details.