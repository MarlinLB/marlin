# Marlin — Control Plane


## Responsibilities

- Own the configuration of record and reconcile the maps to it.
- Generate `fwd_table` per VIP from the stored `table_seed` and member set, and write it.
- **Write `backend.id` equal to the slot it is writing to, on every add.** The array slot is
  already the backend's identity (`docs/design/07-maps.md`); this makes the value carry it too, and
  a mismatch is a control-plane bug the reconciler asserts against at the write site
  (`docs/design/20-configuration-validation.md`), not something the datapath can catch.
- Health-check backends and maintain the `MARLIN_BE_F_STATE` bit of `backend.flags`.
- Populate and refresh `backend.mac` from the kernel neighbour table.
- **Populate `backend.vni` and `backend.inner_mac` for every VXLAN backend, from configuration.**
  Unlike `backend.mac`, these come from the operator's configuration store, never from the
  kernel neighbour table — `inner_mac` is an overlay address, and the overlay is not a network
  the underlay neighbour table has any knowledge of. This is the whole reason D-B gave VXLAN a
  separate field rather than overloading `backend.mac` to carry it: `backend.mac` has a
  neighbour-table source of truth to refresh from, and an overlay MAC does not.
- Keep outer next-hop neighbour entries fresh (`nud permanent` or periodic probing).
- **Keep the neighbour entry for `backend.addr` fresh for every L2 DSR backend that is genuinely
  off-segment, and for every backend configured without a `backend.mac`.** Those are the cases
  `docs/design/16-fib-lookup.md`'s `neigh_fallback` cannot cover: the fallback answers `RET_NO_NEIGH` from the stored MAC
  only when the FIB names the ingress interface *and* a MAC is present. A flagged backend that
  really is on another segment, or any backend deliberately configured with addresses alone, has
  nothing to fall back to and drops `fib_no_neigh`.
- Maintain `config.max_frame` from the attach interface's MTU, refreshed on netlink link
  events, and populate `tx_ports` with every egress ifindex it intends to redirect to.
- Reconcile the four ACL tries to the configured rule set and maintain `config.acl_lists`
  (`docs/design/27-source-filtering.md`).
- Convert the operator's tokens-per-second and burst-in-packets into `config.rl_refill` and the
  scaled `config.rl_burst` (`docs/design/28-rate-limiting.md`). The datapath performs no unit conversion.
- **Never write `ratelimit`.** It is datapath-owned; the control plane reads it for diagnostics
  only.
- Bind health probes in a VRF that does not contain the VIP (`docs/design/18-health.md`).
- Expose configuration and status APIs.
- Validate configuration and reject impossible combinations.

There is no sweep, no expiry and no per-flow bookkeeping.

## Map access

The control plane opens pinned paths and performs I/O only:

| Operation | Use |
|---|---|
| `bpf_obj_get(path)` | open a pinned map |
| `bpf_map_update_elem` | all writes |
| `bpf_map_lookup_elem` | reads |
| `bpf_map_delete_elem` | `vip_map` and the ACL tries |
| `bpf_map_get_next_key` | ACL reconciliation |
| `bpf_map_lookup_batch` | bulk stats collection |

`bpf_map_delete_elem` works on `vip_map` because it is a `HASH`, and on the ACL tries because
`LPM_TRIE` supports deletion. It returns `-EINVAL` on an `ARRAY`, so removing a backend or a
table row is a zero-write instead (`docs/design/10-map-invariants.md`) — the sentinel discipline described there therefore does not extend
to the ACL, whose rules are genuinely deleted. Structs are hand-written to match `types.h`,
with `docs/design/06-map-abi.md`'s parity discipline and its accepted risk.

Per-CPU maps are read as an array of values sized to possible-CPUs, each element padded to
8-byte alignment, and summed.

## Restart and reconciliation

The configuration store is authoritative; the maps are not. On startup the control plane reads
its store and reconciles the maps to it idempotently. Reading maps as truth is ambiguous after
a partially applied write.

Because the maps are pinned, a restart does not disturb the datapath and does not drop
connections.

## Reachability is asserted opt-out

`MARLIN_BE_F_FIB` is set on every backend the control plane has **not positively confirmed on
the ingress segment**, and cleared only where it has. Confirmation means the backend's `addr`
falls in a prefix configured on the XDP-attached interface — the same netlink data the control
plane already reads to populate `backend.mac`, so the flag and the MAC derive from one source
and cannot disagree.

The polarity matters because the two errors are not symmetric. A backend wrongly *flagged* costs
one `bpf_fib_lookup()` and forwards correctly. A backend wrongly *unflagged* takes the stored
MAC, `XDP_TX`s onto the ingress segment, and blackholes with every counter healthy. Defaulting
to the flag makes uncertainty slow instead of silent — the same argument `docs/design/15-nexthop-l2dsr.md` makes for the
`mac_fallback` path, applied to the interface question rather than the MAC question.

Where the control plane knows which interface it expects the FIB to choose, it records that in
`backend.egress_ifindex`; `docs/design/16-fib-lookup.md` checks it and counts `egress_mismatch`. This is the diagnostic that
makes a wrongly-set flag visible, so it should be populated wherever the reachability
determination produced an interface at all.
