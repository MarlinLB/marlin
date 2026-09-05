# Marlin — Health Checking


The control plane performs active probes and drives `backend.state`. The datapath has no
health logic.

**Probes must exercise the forwarding path, not bypass it.** A TCP connect to a backend's real
address proves the backend is alive but says nothing about whether the configuration Marlin
depends on is correct — and every mode has a silent failure of exactly that kind:

| Mode | Silent failure | Probe |
|---|---|---|
| IPIP | tunnel device missing or wrong type for the inner family | probe the VIP over a matching host tunnel device |
| GUE | FOU listener absent, wrong port, or receive device missing | probe the VIP over a host GUE tunnel device |
| VXLAN | `vxlan` device missing, wrong VNI, or wrong dstport | probe the VIP over a host `vxlan` device with the matching VNI and dstport |
| L2 DSR | VIP not on loopback, or ARP/NDP suppression missing | probe the VIP with a static neighbour entry pointing at the backend's MAC |

In each case the probe is addressed to the **VIP**, not the backend address, and forced down
the path Marlin would use. That is what distinguishes "the backend is up" from "the backend
will accept what Marlin sends it".

## The prober must not share a routing domain with the VIP

Backends source from the VIP, so a backend's reply to a VIP-addressed probe carries the VIP as
its source and the Marlin host as its destination — and the Marlin host holds that VIP. The
reply arrives claiming a source address the receiving host owns, is discarded as a martian by
the local route, and every probe fails against a healthy backend. Left unhandled this marks the
entire fleet `MARLIN_DOWN`, which is worse than the failures this section exists to detect.

**The probe socket is therefore bound to a VRF that does not contain the VIP**, together with
the host tunnel devices the IPIP, GUE and VXLAN probes traverse. Source-address validation is
per-VRF, so inside it the reply is ordinary traffic.

- **No new privilege.** A VRF device and `SO_BINDTODEVICE` are within the `CAP_NET_ADMIN` the
  control plane already holds (`docs/design/02-architecture.md`). A network namespace would serve equally but needs
  `CAP_SYS_ADMIN`, so the VRF is preferred on privilege grounds alone.
- **No datapath involvement.** Health checking is entirely control-plane (above); this changes
  where its socket is bound and nothing else.
- **`accept_local` is not sufficient.** Setting it on the probe interface is a smaller change
  but is IPv4-only, so it would leave IPv6 VIPs unprobeable.
- The VRF, its probe address, and the host tunnel devices inside it are integrator
  prerequisites; see `DEPLOYMENT.md`.

An earlier design resolved the martian problem by probing the backend's own address instead.
That works but cannot detect a wrong VIP-on-loopback or missing ARP/NDP suppression, because the
probe never carries the VIP. Isolating the prober keeps the detection and removes the conflict;
`docs/design/26-superseded.md` records the earlier answer as superseded.

Two limitations, stated rather than papered over:

- A host tunnel device does not reproduce everything Marlin emits — notably the entropy source
  port and the zero UDP checksum that GUE and VXLAN both use. A backend that rejects those
  specifically will still probe healthy.
- The IPIP probe must cover both inner families separately if the backend serves both, since
  they use different tunnel devices. This is where VXLAN costs less than what it replaces: one
  `vxlan` device covers both inner families (`docs/design/14-forwarding-modes.md` §7.4), so a
  VXLAN backend needs one probe device where an IPIP backend needs two.

**Under active/active**, each instance probes independently and may briefly disagree. Harmless
given drop-on-down (`docs/design/17-reconfiguration.md`). Health state is not synchronised between instances.
