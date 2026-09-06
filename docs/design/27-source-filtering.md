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

- For TCP and UDP, `tuple.src` **is** the on-the-wire source, so the distinction is invisible.
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

## Evaluation

A packet is one family, so at most two lookups: allow, then block. An allow hit admits and
suppresses the rate limiter; a block hit drops with `acl_blocked`; neither continues.

**When the ACL is disabled, nothing is allowlisted.** `CFG_ACL_ENABLE` clear means neither lookup
runs, so no packet carries an allow verdict and the rate limiter — if enabled — would meter
management prefixes with no escape hatch. `docs/design/20-configuration-validation.md` rejects that combination.

`CFG_ACL_ENABLE` and `acl_lists` are not the same mechanism. `acl_lists` is control-plane-derived
and exists to avoid a lookup against an empty map; `CFG_ACL_ENABLE` is operator intent, and lets
enforcement be suspended without deleting the rule set. The same split applies to
`CFG_RL_ENABLE` against `VIP_RATELIMIT`.

## Fragments are fully enforced

A non-first fragment carries no L4 header, so any port-granular rule would have been
unenforceable on it. The source address is in every fragment, so address-only matching has no
fragment-shaped hole and needs no counter to measure one. This is the principal operational
benefit of dropping L4 granularity, not the reduced map count.

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

The ACL precedes the VIP lookup, so it filters host-bound traffic too (`docs/design/11-pipeline.md`). A blocklist entry can
therefore lock an operator out of the host, and unconditional allow precedence is what contains
it: management and routing-peer prefixes must be allowlisted before the first blocklist rule.
The control plane cannot validate this — it does not know which prefixes are management — so it is
an integrator prerequisite in `DEPLOYMENT.md`.

**Allowlists are spoofable** without ingress source-address validation, since Marlin cannot
distinguish a forged source from a genuine one. BCP38 or unicast RPF on the ingress path is a
matching prerequisite, and there is no forwarding-path mitigation; `DEPLOYMENT.md` §4.3 states
it as an integrator requirement.
