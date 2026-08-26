# Marlin — Map Invariants

## Sentinel: backend_id 0 is never allocated

`ARRAY` maps do not support deletion — `bpf_map_delete_elem()` returns `-EINVAL`. Removal is
therefore a zero-write, and index 0 is reserved so that a zeroed value is unambiguously
invalid:

- `backends[0]` is never allocated. Real backend IDs start at 1.
- A `fwd_table` row holding 0 means "no backend" and drops with reason `no_backend`.
- Removing a backend means writing a zeroed `backends[id]` **and** rewriting every row that
  referenced it to 0.
- `MARLIN_UP` is non-zero, so a zeroed slot also reads as not-UP.

## Zero the whole key before a hash lookup

HASH keys are compared byte-exact. On an IPv4 lookup the unused 12 bytes of the `vip_key`
union must be zeroed, or lookups miss intermittently and present as packet loss. All structs
above are laid out to have no implicit padding for the same reason; where padding is needed
it is explicit.

## `vip_meta.hash_key` is the packet hashing key

Not the table generation seed. `table_seed` is control-plane only and never enters the
datapath. They are distinct concerns and must be distinct values in the configuration
schema; conflating them will cause confusion.

Both are per-VIP secrets owned by the configuration store, established **once at VIP
creation** — supplied by the operator, or generated there. Neither is ever generated during
reconciliation: under the active/active model (`docs/design/21-active-active.md`) each instance
runs its own control plane against the shared store, so a reconcile-time "generate if absent"
fallback would have each instance invent a different value, which is exactly the divergence that
document exists to prevent. At reconcile time an
absent `hash_key` or `table_seed` is a hard error, not a prompt to create one.
