# Marlin — ICMP

## ICMP

ICMP requires its own path; hashing the packet's own source address is wrong, because the
source of an ICMP error is the intermediate router that generated it, not the client.

**ICMP errors** (v4 types 3, 11, 12; v6 types 1, 2, 3, 4) arriving for a VIP were generated
in response to a *backend → client* packet, since backends source from the VIP. The embedded
offending header therefore has the VIP as its source and **the client as its destination**.

Both the VIP lookup and the hash must come from the embedded header, because the ICMP packet's
own addresses describe the router and ICMP carries no ports at all:

| Needed | Taken from |
|---|---|
| `vip_key.addr` | embedded **source** address |
| `vip_key.port` | embedded **source** port |
| `vip_key.proto` | embedded protocol |
| selection hash input | embedded **destination** address, and its port under `VIP_HASH_5TUPLE` |

**`parser.c` must recover the embedded destination port into `tuple.sport`, not only the source
port.** Address-only selection never needed it, so the requirement is new with
`VIP_HASH_5TUPLE` (`docs/design/12-selection.md`): on a flagged VIP the hash covers `sport`, and
an ICMP error carrying zero there hashes to a different row than the flow it belongs to, sending
the error to the wrong backend and breaking path MTU discovery for the encapsulation modes
precisely where it is load-bearing. With both ports recovered the normalised tuple is the
offending flow's own tuple, so the error hashes to the flow's row under either hash input.

This moves the truncation threshold below: reaching the embedded destination port needs four
bytes of embedded L4 header rather than two.

**The fragment flags describe the ICMP packet, not the embedded header.** `MARLIN_CTX_F_FRAG`
and `MARLIN_CTX_F_FRAG_FIRST` (`marlin.h`) qualify the packet being forwarded. An ICMP error is
a whole packet with a fully populated tuple, so neither bit is set even when the datagram it
reports on was itself fragmented — routers generate the error from the first fragment, which
carries the ports. Deriving the bits from the embedded header instead would have a
`VIP_HASH_5TUPLE` VIP drop precisely the `frag_needed` errors that path MTU discovery depends
on, which is the opposite of the intent.

**The same reasoning extends from the flags to the fragment/extension-header refusal of
`docs/design/11-pipeline.md`.** That refusal exists because a head and a tail of the packet
Marlin forwards can resolve `tuple.proto` differently when a Fragment header is immediately
followed by another extension header. A quoted first fragment has no such head/tail split —
it is embedded whole inside one ICMP packet — so `marlin_parse_icmp()` does not apply the
refusal to it: a quote shaped `Fragment → Destination Options → UDP`, with ports past both,
still recovers a tuple, the same way an unfragmented quote does. Refusing it would drop
exactly the `frag_needed`/Packet Too Big errors the paragraph above already argues path MTU
discovery depends on.

**A fragmented ICMP packet is a separate case, and only its first fragment reaches the branch
above.** A non-first fragment carries no ICMP header at all, so it is classifiable as neither an
error nor an echo and there is no embedded header to recover a tuple from. It passes to the host
stack as `not_forwarded`, which is where a fragmented echo request must arrive for the host to
reassemble it; counting it `icmp_unparseable` would attribute ordinary reassembly traffic to the
counter `docs/design/22-observability.md` reads as PMTUD errors being dropped. The first fragment
takes the branch above unchanged and keeps `MARLIN_CTX_F_FRAG_FIRST`, because the bit describes
the ICMP packet, which is genuinely fragmented.

The embedded source is the VIP and its service port; the embedded destination is the client, so
hashing it reproduces the original selection and steers the error to the backend that sent the
offending packet. This is what makes path MTU discovery work for the encapsulation modes.

The ICMP branch therefore **replaces step 2** of `docs/design/11-pipeline.md` rather than
following it, and rejoins at step 3.

It replaces step 2 only. The VIP lookup is **not** branched: `parser.c` normalises both paths to
one orientation, as below, so step 3 onward is a single shared path reached by ICMP and by
TCP, UDP and SCTP alike (`docs/design/32-sctp.md`). Every stage after parsing therefore has
exactly one call site — which is what
makes the ACL of `docs/design/27-source-filtering.md` a single evaluation rather than one per path, and what keeps a future stage
placed between parsing and selection from having to be duplicated.

**`parser.c` owns the reversal, and normalises both paths to one orientation.** `packet_tuple`
is always oriented client → VIP: `key.dst` is the VIP and `key.dport` its service port, `key.src`
is the client. For an ICMP error `parser.c` fills them from the embedded header per the table
above — embedded source into `key.dst`, embedded destination into `key.src`. Everything after
parsing therefore reads one shape, and neither the VIP lookup nor the selection hash needs an
ICMP branch.

Errors that cannot be parsed — truncated payload, embedded header too short to reach the
destination port, nested tunnel, unrecognised inner protocol — drop with reason
`icmp_unparseable`. The threshold is the destination port rather than the source port because
`VIP_HASH_5TUPLE` hashes `tuple.sport`, and an error parsed only as far as the source port would
carry a zero there and hash to the wrong row. Applying the wider threshold unconditionally keeps
parsing free of a per-VIP branch, at the cost of dropping errors on unflagged VIPs that the
narrower threshold would have admitted — errors truncated between the two offsets, which
requires an embedded header cut to an odd two-byte boundary.

**ICMP echo** request and reply are not errors and are not load-balanced: `XDP_PASS` to the
local stack.
