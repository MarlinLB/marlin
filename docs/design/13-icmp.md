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
| selection hash input | embedded **destination** address |

The embedded source is the VIP and its service port; the embedded destination is the client, so
hashing it reproduces the original selection and steers the error to the backend that sent the
offending packet. This is what makes path MTU discovery work for the encapsulation modes.

The ICMP branch therefore **replaces step 2** of `docs/design/11-pipeline.md` rather than
following it, and rejoins at step 3.

It replaces step 2 only. The VIP lookup is **not** branched: `parse.c` normalises both paths to
one orientation, as below, so step 3 onward is a single shared path reached by ICMP and by
TCP/UDP alike. Every stage after parsing therefore has exactly one call site — which is what
makes the ACL of `docs/design/27-source-filtering.md` a single evaluation rather than one per path, and what keeps a future stage
placed between parsing and selection from having to be duplicated.

**`parse.c` owns the reversal, and normalises both paths to one orientation.** `packet_tuple`
is always oriented client → VIP: `key.dst` is the VIP and `key.dport` its service port, `key.src`
is the client. For an ICMP error `parse.c` fills them from the embedded header per the table
above — embedded source into `key.dst`, embedded destination into `key.src`. Everything after
parsing therefore reads one shape, and neither the VIP lookup nor the selection hash needs an
ICMP branch.

Errors that cannot be parsed — truncated payload, embedded header too short to reach the source
port, nested tunnel, unrecognised inner protocol — drop with reason `icmp_unparseable`.

**ICMP echo** request and reply are not errors and are not load-balanced: `XDP_PASS` to the
local stack.
