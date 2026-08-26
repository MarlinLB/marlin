# Marlin — Configuration Validation

## Configuration validation

Rejected at configuration time rather than allowed to fail per packet:

- A VIP with no `hash_key`, or a `hash_key` that is not exactly 16 bytes.
- A VIP with no `table_seed`. Both it and `hash_key` are established at VIP creation (`docs/design/10-map-invariants.md`);
  absence at reconcile time is an error, never a prompt to generate one.
- A VIP with no backends in `MARLIN_UP` state — accepted with a warning, not rejected, since
  it is reachable transiently.
- A backend with no `addr`, in any mode. It is the only address the datapath ever looks up
  (`docs/design/15-nexthop-l2dsr.md`); under L2 DSR it is the backend's address on the attached segment, and a backend whose
  `mac` is currently resolved still needs it for the fallback.
- A backend with `mode` IPIP or GUE while `config.tunnel_src` is unset.
- A backend with `mode` IPIP or GUE while `config.max_frame` is unset. Zero disables the
  egress-MTU check in the datapath (`docs/design/23-mtu.md`), so an unset value is a silent loss of protection
  rather than a failure.
- An in-place `mode`, `addr` or `gue_dport` edit on an existing backend ID (`docs/design/17-reconfiguration.md`) — the API
  requires remove-then-add.
- A backend with `egress_ifindex` naming an interface that is neither the XDP-attached
  interface nor present in `tx_ports`. The ingress device is deliberately *not* in `tx_ports` —
  `XDP_TX` needs no devmap, and a deployment where every backend is on the ingress segment never
  populates that map at all — so it must be an accepted expectation, and the check is
  "reachable", not "redirectable". An ifindex in neither set names an interface the datapath
  could never legitimately select.
- A backend ID of 0 (`docs/design/10-map-invariants.md`).
- More than `MAX_BACKENDS - 1` backends, or more than `MAX_VIPS` VIPs.
- An ACL allow rule for `0.0.0.0/0` or `::/0`. Under `docs/design/27-source-filtering.md`'s precedence it nullifies the
  blocklist and the rate limiter entirely, and no operator means it.
- An ACL prefix whose host bits are set. `10.1.2.3/8` and `10.0.0.0/8` are the same trie key, so
  accepting the former silently replaces the latter instead of adding a rule (`docs/design/27-source-filtering.md`).
- An ACL prefix length exceeding the family's address width.
- `VIP_RATELIMIT` on any VIP while `rl_refill` is zero: the bucket never refills and the VIP
  black-holes after its initial burst.
- `rl_burst` of zero, or a burst exceeding 2^24 − 1 packets, which overflows the scaled token
  field (`docs/design/28-rate-limiting.md`).
- `CFG_RL_ENABLE` set while `CFG_ACL_ENABLE` is clear. Without the ACL no packet carries an
  allow verdict, so the rate limiter would meter management prefixes with no escape hatch (`docs/design/27-source-filtering.md`).
- Any reserved flag bit set (`docs/design/08-types.md`).

Accepted with a warning:

- An ACL block rule wholly covered by an allow rule, and therefore dead. Legitimate while a
  broad allow is temporary, usually a mistake.
- `CFG_RL_ENABLE` with no VIP carrying `VIP_RATELIMIT`.
- An ACL allow rule broader than `/8` for IPv4 or `/32` for IPv6.
