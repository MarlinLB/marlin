# Marlin — Source Filtering


Allow and block listing of source addresses and ranges. Rules match an address or prefix and
nothing else; L4 granularity is out of scope (`docs/design/01-scope.md`) and its cost is recorded in `docs/design/25-rejected.md`.

## What is matched

**`packet_tuple.src`, and nothing else.** `tuple.proto`, `tuple.dport` and `tuple.sport` are not
read.

`packet_tuple` is the tuple of the connection, not of the arriving packet (`docs/design/08-types.md`), and for an ICMP
error `parser.c` reconstructs it from the embedded header (`docs/design/13-icmp.md`). `tuple.src` is therefore the
**client**, and the transit router that emitted the packet appears nowhere. The ACL consequently
filters the connection an error concerns, not the sender of the error. This is correct:

- For TCP, UDP and SCTP, `tuple.src` **is** the on-the-wire source, so the distinction is
  invisible.
- Blocking the router would be wrong. Routers are not the traffic being filtered, and PMTUD for
  every other client depends on their errors being processed (`docs/design/13-icmp.md`).
- A blocked client's ICMP errors are suppressed along with its traffic, which is what blocking a
  client should mean.
- ICMP echo never reaches the ACL; it is `XDP_PASS` before selection (`docs/design/13-icmp.md`).

Neither the ACL nor the rate limiter reads packet bytes, so `docs/design/04-calling-convention.md`'s prohibition on holding a packet
pointer across a `marlin_*` call and `docs/design/11-pipeline.md`'s pointer-invalidation hazard are inapplicable to both.

## Keys and prefixes

One trie per list per family (`docs/design/07-maps.md`). Stored `prefixlen` is the CIDR prefix length directly — a `/8`
stores 8, a host route stores 32 or 128. Lookups present the family's full width and the trie
returns the longest match, so a `/32` block inside a `/8` block behaves as an operator expects.

Addresses are stored and matched in network order, which is already most-significant-byte-first,
so a CIDR prefix maps onto the trie's bit prefix with no transformation.

**Bits beyond `prefixlen` must be zero**, and `docs/design/20-configuration-validation.md` rejects rules where they are not. The kernel
compares only the first `prefixlen` bits, so `10.1.2.3/8` and `10.0.0.0/8` are the *same key*:
inserting the second silently replaces the first rather than adding a rule. The validation
prevents a lost rule, not merely a confusing one.

**The families are not merged.** Encoding IPv4 as `::ffff:a.b.c.d` in the IPv6 tries would halve
the map count and add 96 trie levels to every IPv4 lookup (`docs/design/25-rejected.md`).

**Value:** a `__u32` rule id in both lists. The map identity encodes the verdict, so the value is
otherwise free; carrying the control plane's rule identity is what makes `get_next_key`
reconciliation possible, since a key alone cannot be attributed back to a configuration object.

## Precedence: an allow match wins unconditionally

Over every block entry, at any relative specificity, and over the rate limiter. `10.0.0.0/8`
allowed beats `10.1.2.3/32` blocked.

This is not longest-prefix-wins, and it is deliberately unlike the
port-specific-beats-port-agnostic precedence of `docs/design/11-pipeline.md`. The reason to accept the inconsistency is
`docs/design/11-pipeline.md`'s: the allowlist is what guarantees an operator cannot be locked out by their own blocklist,
and a guarantee that a sufficiently specific block can override is not a guarantee.

**The precedence rule is why allow and block are separate maps.** A trie returns exactly one
match — the most specific. A single trie per family with the verdict in the value would give
longest-prefix-wins, contradicting the above. Two maps per family is a consequence of the
precedence rule, not an independent choice.

## Evaluation and enforcement

A packet is one family, so at most two lookups: allow, then block. Evaluation yields a verdict and
nothing else. Where the verdict is acted on is `docs/design/11-pipeline.md` step 4, after the VIP
lookup, and what happens there depends on what the packet was addressed to:

- a VIP carrying `VIP_ACL` — an allow admits, skipping step 5 but continuing through the rest of
  the pipeline; a block drops with `acl_blocked`; neither consults the other list;
- a VIP without it — the verdict is discarded, and the packet is treated as though no rule
  matched;
- no VIP at all — a block drops instance-wide, there being no VIP to take the bit from.

**Three gates, and no two of them are the same mechanism.**

- `CFG_ACL_ENABLE` is instance-wide operator intent, and lets the rule set stop being evaluated
  without being deleted. Clear, neither lookup runs and no packet carries a verdict at all.
- `VIP_ACL` is operator intent per VIP, acting one step later: the verdict is computed either way
  and discarded at step 4 when the bit is clear. It exempts one VIP's traffic and nothing else.
- `acl_lists` is control-plane-derived and exists to avoid a lookup against an empty map.

`CFG_ACL_ENABLE` dominates: `VIP_ACL` set while it is clear is inert. The instance-against-per-VIP
split is `CFG_RL_ENABLE` against `VIP_RATELIMIT`, one step further down the pipeline. `VIP_ACL` is
set-means-enforced like every other bit in `docs/design/08-types.md`'s tables, which is also what
lets it take over a bit that was reserved-must-be-zero: a `flags` word written before the bit
existed reads as not opted in. **A clear bit is not an ACL that is off**, though — step 4's
host-bound arm takes no bit from any VIP, so the rule set is still enforced against traffic
addressed to the host.

`VIP_ACL` is enforcement policy rather than hash input, so `docs/design/21-active-active.md`'s
cross-instance agreement requirement does not bind it as it binds `VIP_HASH_5TUPLE`. Divergence is
still observable: instances serving one VIP that disagree on the bit block a source on some ECMP
paths and admit it on others.

**Wherever the verdict does not reach, nothing is allowlisted.** That has two levels, and the
rate limiter is what is exposed by both:

- `CFG_ACL_ENABLE` clear. No lookup runs, so no packet carries an allow verdict, and the rate
  limiter — if enabled — would meter management prefixes with no escape hatch.
- `VIP_ACL` clear on a VIP carrying `VIP_RATELIMIT`. The verdict exists but is discarded, so that
  metered VIP has the same missing escape hatch.

`docs/design/20-configuration-validation.md` rejects both combinations. The second is what lets
the metering gate read `acl_verdict` without a `VIP_ACL` test of its own: any VIP that reaches
`marlin_ratelimit()` carries `VIP_ACL` by construction.

## Fragments are fully enforced

A non-first fragment carries no L4 header, so any port-granular rule would have been
unenforceable on it. The source address is in every fragment, so address-only matching has no
fragment-shaped hole and needs no counter to measure one. This is the principal operational
benefit of dropping L4 granularity, not the reduced map count.

**The rule itself has no fragment-shaped hole; which enforcement arm applies to a fragment
tail can still differ from its head's.** `VIP_ACL` is read from the `vip_map` hit
(`docs/design/11-pipeline.md`), and a tail's parsed destination port is always zero
(`docs/design/12-selection.md`, "Hash input"), so a tail can miss the VIP its head hit, or hit
a different one. A blocked source's tail then enforces against the instance-wide arm — or a
different VIP's `VIP_ACL` bit — rather than against the head's, even though the same rule
matched the same address in both.

## `acl_lists` write ordering

- Adding the first rule to a list: **set** the bit, **then** write the rule.
- Removing the last rule from a list: **delete** the rule, **then** clear the bit.

This is the reverse of `docs/design/12-selection.md`'s ordering for `backends`/`fwd_table`, and deliberately so: the two
mechanisms guard against opposite failures. `docs/design/12-selection.md`'s row is a reference the datapath follows to reach
data, so it must never point at a slot that is not populated yet. The `acl_lists` bit is not a
reference the datapath follows — it is a hint that gates whether a lookup runs at all — so the
failure to avoid here is the bit claiming "no rules" while a rule that should still be enforced is
actually present. Ordered as above, the bit is wrong only in the safe direction: it can cause one
extra lookup against a list that turns out to have nothing for that packet, never a skipped lookup
against a list that does.

## Operator lockout

The host-bound path of `docs/design/11-pipeline.md` step 4 enforces a block instance-wide, so the
ACL filters host-bound traffic too. A blocklist entry can therefore lock an operator out of the
host; **clearing `VIP_ACL` is not a way back in**, since the path that locked them out takes its
verdict from no VIP. Unconditional allow precedence is what contains it: management and
routing-peer prefixes must be allowlisted before the first blocklist rule.
The control plane cannot validate this — it does not know which prefixes are management — so it is
an integrator prerequisite in `DEPLOYMENT.md`.

**Allowlists are spoofable** without ingress source-address validation, since Marlin cannot
distinguish a forged source from a genuine one. BCP38 or unicast RPF on the ingress path is a
matching prerequisite, and there is no forwarding-path mitigation; `DEPLOYMENT.md` §4.3 states
it as an integrator requirement.
