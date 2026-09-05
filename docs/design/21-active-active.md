# Marlin — Active/Active

## Active/active

**Three configuration values must be identical on every instance serving a VIP:
`hash_key`, `table_seed` and the `VIP_HASH_5TUPLE` bit of `vip_meta.flags`.** They fail
differently and all three fail silently.

| Value | Where it acts | Effect of a mismatch |
|---|---|---|
| `vip_meta.hash_key` | datapath, `docs/design/12-selection.md` | instances map the same client to different *rows* |
| `table_seed` | control plane, `docs/design/12-selection.md` | instances map the same *row* to different backends |
| `VIP_HASH_5TUPLE` | datapath, `docs/design/12-selection.md` | instances hash different *fields*, so the same client reaches different rows — and one instance drops the VIP's fragments while another forwards them |

Matching one without the others buys nothing: a client that reaches the same row on two
instances is still forwarded to two different backends if their tables were generated under
different seeds, and a client that would reach the same row under one hash input reaches a
different one under the other. All three must match, and affinity is lost before any of
`docs/design/17-reconfiguration.md`'s failure modes apply if any does not.

`VIP_HASH_5TUPLE` joins the list on the general principle `docs/design/12-selection.md` states
for hash input: the generation is deterministic in the seed, the member set and the hash input,
and nothing else. A flag bit that selects the hash input is therefore the same class of value as
the key itself, not a per-instance tuning knob. It differs from the other two in one respect
worth stating — a mismatch has a partial symptom, because the instance with the bit set counts
`frag_unsupported` and the instance without it does not, so a fragmenting VIP will show the
divergence even though a non-fragmenting one will not.

Both come from the configuration store, established once at VIP creation (`docs/design/10-map-invariants.md`). Marlin does
not distribute them between instances and does not verify agreement, so a mismatch has no
symptom of its own: each instance independently shows well-distributed `backend_stats` (`docs/design/22-observability.md`),
and what is broken is only the correlation *between* instances, which nothing measures. A
non-reversible digest of each value, exposed per VIP through the status API, is the cheapest
thing that makes divergence detectable without transporting the values.

Given both agree, nothing else needs to. Marlin holds no per-flow state, so any instance can
handle any packet, upstream ECMP may rehash freely, and instance loss costs only the
connections whose backend selection is unaffected — that is, none.
