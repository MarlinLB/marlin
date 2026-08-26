# Marlin — Active/Active

## Active/active

**Two configuration values must be identical on every instance serving a VIP:
`hash_key` and `table_seed`.** They fail differently and both fail silently.

| Value | Where it acts | Effect of a mismatch |
|---|---|---|
| `vip_meta.hash_key` | datapath, `docs/design/12-selection.md` | instances map the same client to different *rows* |
| `table_seed` | control plane, `docs/design/12-selection.md` | instances map the same *row* to different backends |

Matching one without the other buys nothing: a client that reaches the same row on two
instances is still forwarded to two different backends if their tables were generated under
different seeds. Both must match, and affinity is lost before any of `docs/design/17-reconfiguration.md`'s failure modes
apply if either does not.

Both come from the configuration store, established once at VIP creation (`docs/design/10-map-invariants.md`). Marlin does
not distribute them between instances and does not verify agreement, so a mismatch has no
symptom of its own: each instance independently shows well-distributed `backend_stats` (`docs/design/22-observability.md`),
and what is broken is only the correlation *between* instances, which nothing measures. A
non-reversible digest of each value, exposed per VIP through the status API, is the cheapest
thing that makes divergence detectable without transporting the values.

Given both agree, nothing else needs to. Marlin holds no per-flow state, so any instance can
handle any packet, upstream ECMP may rehash freely, and instance loss costs only the
connections whose backend selection is unaffected — that is, none.
