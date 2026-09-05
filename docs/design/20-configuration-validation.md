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
- A backend with `mode` IPIP, GUE or VXLAN while `config.tunnel_src` is unset.
- A backend with `mode` IPIP, GUE or VXLAN while `config.max_frame` is unset. Zero disables the
  egress-MTU check in the datapath (`docs/design/23-mtu.md`), so an unset value is a silent loss of protection
  rather than a failure.
- A VXLAN backend with `vni` unset, or with `vni & 0xFF000000` non-zero. `vni` is a host-order
  24-bit value (`docs/design/08-types.md`), so this is the *value's* high byte rather than a byte
  position in the struct, and a non-zero one can only be a value that was never a valid VNI. It
  would also collide with the shift `vxlan_encap.c` applies to reach wire order
  (`docs/design/14-forwarding-modes.md` §7.4), landing operator data in the VXLAN header's
  reserved byte.
- A VXLAN backend with an all-zero `inner_mac`. This is unlike `backend.mac`
  (`docs/design/15-nexthop-l2dsr.md`, "`backend.mac` is optional"): there is no
  resolve-via-`bpf_fib_lookup()` fallback for an overlay address, because there is nothing in the
  underlay for the FIB to resolve it from, so absence here is an error rather than a defined
  state.
- A non-VXLAN backend with `vni` or `inner_mac` set. Rejected, not merely warned: neither field
  means anything outside VXLAN, and accepting one silently on, say, a GUE backend would let a
  future mode change re-interpret bytes the operator never meant to set, rather than surfacing
  the mismatch at the point the backend was configured.
- An in-place `mode`, `addr` or `encap_dport` edit on an existing backend ID (`docs/design/17-reconfiguration.md`) — the API
  requires remove-then-add. `vni` and `inner_mac` require the same: both are identity for the
  purposes of `docs/design/12-selection.md`'s score, exactly as `addr` is.
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

Explicitly **not** validated:

- `VIP_HASH_5TUPLE` set on a VIP whose traffic fragments. Whether traffic fragments is not a
  property of the configuration, so nothing at configuration time can distinguish the intended
  use from the mistake. The flag's cost is therefore visible only in `frag_unsupported`
  (`docs/design/22-observability.md`), and this is recorded here so its absence is not read as
  an oversight (`docs/design/12-selection.md`).
- Agreement of `VIP_HASH_5TUPLE` between instances serving one VIP. Marlin does not verify
  `hash_key` or `table_seed` agreement either, and the flag is the same class of value
  (`docs/design/21-active-active.md`).

Accepted with a warning:

- An ACL block rule wholly covered by an allow rule, and therefore dead. Legitimate while a
  broad allow is temporary, usually a mistake.
- `CFG_RL_ENABLE` with no VIP carrying `VIP_RATELIMIT`.
- An ACL allow rule broader than `/8` for IPv4 or `/32` for IPv6.
