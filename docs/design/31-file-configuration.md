# Marlin — File Configuration

**Status:** implemented in `marlind`. §11 records the outcome of each open decision; the ones
still open are also carried in `PHASES.md`'s open-decision table.
**Reconciled against:** `docs/design/README.md` revision 14, `data-plane/marlind/` as it stands.

**The default path is `/etc/marlind/marlin.conf`, not `/etc/marlin/marlin.toml`** — §4's example
below is corrected to match. `deploy/marlin.conf.example` is the shipped, fully worked example.

`marlind` today loads, pins, attaches and holds the link, and writes no map data at all — the
only element-level map call in the tree's loader is a read (`marlind/cmd_status.c:119`). Every
map value is the control plane's. This document specifies a second, mutually exclusive
arrangement: **`marlind` reads a TOML file and reconciles the maps to it**, and the control
plane is reduced to reading stats.

It is a deployment-simplification mechanism, not a replacement for
`docs/design/19-control-plane.md`. §3 states exactly what it gives up, because five of that
document's responsibilities are not expressible in a file at all.

---

## 1. Why a file, and why in `marlind`

- `marlind` already parses configuration (`marlind/config.c`), already refuses rather than
  configures (`marlind/preflight.c`), and already owns map identity and sizing
  (`marlind/bpf_load.c:81-97`). A file-managed mode is its existing job with a wider input.
- It is the only component that must exist. `docs/DEPLOYMENT.md` §1.6 orders `marlind` before
  the control plane because the control plane has nothing to open until the loader has attached;
  a deployment that configures from a file therefore needs one process, not two.
- The reconcile insertion point is exact: after `load_and_pin_maps()`
  (`marlind/cmd_attach.c:143`) and **before** `attach_link()` (`:146`). Maps survive restarts by
  design (`docs/design/02-architecture.md`), so they may hold the previous generation's contents;
  attaching first would forward under stale configuration for the length of the reconcile.
- `control-plane/` holds one `.editorconfig` and no `.cs` file, so nothing is being displaced.

**What it does not change.** No map is created by anything but `marlind` (unchanged), and the
datapath is untouched — no `types.h` field, flag bit or counter is added by anything in this
document except the §2 interlock, if that option is taken.

The kernel surface is `docs/design/19-control-plane.md`'s map-access table, with one addition:
`bpf_map_update_batch`, for writing a `TABLE_SIZE`-row `fwd_table` block in one call.
`tools/marlin_seed.c` already uses it against a pinned object and
`data-plane/tests/packet/maps.c:373`'s `xdp_fwd_write_block()` against an in-process one
(`tools/marlin_seed.c:117`), so it is an omission from that table rather than a new dependency —
see §12.

---

## 2. Exactly one writer, chosen at startup

**The file and the control plane must never both write.** This is the whole risk of the feature.
Two writers against `backends` and `fwd_table` do not merely disagree, they violate
`docs/design/12-selection.md`'s write ordering: one writer's row rewrite can land between the
other's `backends[id]` write and its rows, and the invariant that no row references an
unpopulated slot is a property of a single ordered sequence.

Prior art is unambiguous on both halves:

- **Envoy** makes a resource either static (`static_resources` in the bootstrap file) or dynamic
  (delivered by xDS), never both.
- **HAProxy** allows both and pays for it: Runtime API changes are held in memory and lost on
  reload, and `server-state-file` is a bolt-on that does not persist everything (port changes
  among the gaps).

So: mode is fixed for the lifetime of the attach, selected by whether `marlind` was started with
a configuration file, and the control plane must be able to observe it before writing.

**Decided: documented exclusivity only** (D-F2). Of the three mechanisms considered —

| Mechanism | For | Against |
|---|---|---|
| A `CFG_FILE_MANAGED` bit in `marlin_config.flags` | visible to anything that reads the map, `bpftool` included; no new file, no new path; the control plane's check is one map read it already makes | it is ABI, so it must land in Phase 2a with the rest of the freeze, and it spends one of `flags` bits 2–31 on something the datapath never reads |
| A marker file written by `marlind` under a `RuntimeDirectory` | no ABI change | `deploy/marlind.service:24` sets `ProtectSystem=strict` with no `ReadWritePaths`, so the unit must gain a writable path; and it is advisory — nothing stops a writer that does not look |
| **Documented exclusivity only** | nothing to build | the failure is silent, intermittent and indistinguishable from a reconciliation bug |

— the third was taken, on the grounds that this document's scope is `marlind` alone: the other
two both reach outside it (an ABI change with a same-commit C# mirror, or a unit-file change
whose other half is the control plane observing it). `deploy/marlind.service` and
`deploy/marlin.conf.example` both state the exclusivity rule; nothing enforces it. Revisiting
this is D-F2's residual entry in `PHASES.md`, to be taken up once the control plane exists to
observe either mechanism.

The control plane's file-managed posture is read-only regardless: stats maps by
`bpf_map_lookup_batch`, `config`/`vip_map`/`backends` for labels, and no write anywhere.

---

## 3. What a file cannot express

Five of `docs/design/19-control-plane.md`'s responsibilities are continuous reactions to kernel
state, not values. A file mode either drops them, restates them statically, or reimplements the
control plane in C.

| Responsibility | Source today | In file-managed mode |
|---|---|---|
| `MARLIN_BE_F_STATE` | active VIP-addressed probes from a VRF (`docs/design/18-health.md`) | **not performed.** `state` is whatever the file says |
| `backend.mac` | kernel neighbour table, refreshed on netlink churn | either written in the file, or left absent so the datapath resolves per packet (below) |
| `MARLIN_BE_F_FIB` | asserted opt-out from the attach interface's prefixes | operator-stated per backend, defaulting to set wherever a `mac` is stated |
| `backend.egress_ifindex` | the same reachability determination | operator-stated; absent means zero, and zero skips the check (`docs/design/16-fib-lookup.md:38`) |
| `config.max_frame` | attach interface MTU, refreshed on netlink link events | derived at load from the attach interface; whether the refresh survives is §11's D-F5 |

### 3.1 The two postures for next-hop resolution

**Nothing new is needed here: `docs/design/15-nexthop-l2dsr.md` already sanctions the posture
file-managed mode wants.** Its "`backend.mac` is optional" section says so directly — an
operator content to let the kernel resolve every next hop may configure backends with addresses
alone. The three combinations the file can express are its steps 1–3 unchanged:

| `mac` | `fib` | Path | Cost |
|---|---|---|---|
| stated | clear | stored MAC, no lookup (step 2) | a MAC change needs a file edit and a reload |
| stated | set | lookup first, stored MAC as the L2 DSR `NO_NEIGH` fallback (step 1; `docs/design/16-fib-lookup.md`'s `neigh_fallback` row) | one lookup per packet; no `mac_fallback` counted |
| absent | either | lookup, `mac_fallback` counted when `fib` is clear (step 3) | the kernel keeps neighbours fresh without `marlind`'s help |

The default is `fib` set wherever a `mac` is stated, which is
`docs/design/19-control-plane.md`'s polarity applied to a file: uncertainty made slow rather
than silent, with the stored MAC still there as a fallback. Clearing it is the explicit request
for the zero-lookup fast path.

Two costs to accept rather than discover, both already written down:

- **`mac_fallback` stops being a signal** on any backend configured with addresses alone.
  `docs/design/22-observability.md` reads it as "the control plane is not maintaining
  `backend.mac`", which is true of this deployment by construction
  (`docs/design/15-nexthop-l2dsr.md`, "`backend.mac` is optional").
- **Neighbour freshness has no owner.** XDP cannot trigger ARP or NDP, so an unresolved
  neighbour is `fib_no_neigh`, and `docs/design/16-fib-lookup.md:69-72` assigns keeping those
  neighbours pinned or probed to the control plane. In file-managed mode nothing does, so it
  becomes an integrator prerequisite — `nud permanent` entries for backend addresses and outer
  next hops — belonging in `docs/DEPLOYMENT.md` §1.8 rather than in `marlind`.

### 3.2 Health

**File-managed mode has no health checking.** Stated plainly because the failure is a
blackhole: a dead backend stays `MARLIN_UP`, its rows keep pointing at it, and
`backend_stats` keeps counting packets that no longer arrive anywhere.

GLB's answer is the cheapest one available and needs no `marlind` code: its
`glb-healthcheck` companion reads the operator's `forwarding_table.src.json`, writes a derived
`forwarding_table.checked.json` with a health state per backend, and runs a reload command. The
same shape works here — a companion writes a derived file and sends `SIGHUP` — and it keeps
probing out of a process that must not die (§7). Whether Marlin ships that companion, defers to
the C# `Marlin.Health` project over a narrow write path, or accepts static state, is D-F1.

---

## 4. The file

One file, **`/etc/marlind/marlin.conf`** by default, selected by `marlind --config <path>`.
`marlind/main.c`'s option table gained `--config <path>` (`required_argument`) and `--check`
alongside the existing `no_argument` flags; the leading `+` and the `optind != argc` operand
check are unaffected.

**Decided (D-F3): the file replaces the environment input entirely, not a precedence order.**
With `--config`, `[instance]` is the only source of `interface`/`object`/`pin_dir`, and
`IFACE`/`MARLIN_OBJ`/`MARLIN_PIN_DIR` are ignored, with a warning logged if any is set. Without
`--config`, `marlind/config.c`'s existing environment path is untouched. A precedence order
(file overrides env, env is a fallback) was rejected: it would make the effective interface
depend on two files at once, exactly the ambiguity §2's single-writer rule exists to avoid one
level up.

```toml
[instance]
interface  = "eth0"                     # replaces IFACE
object     = "/usr/lib/marlin/marlin.bpf.o"
pin_dir    = "/sys/fs/bpf/marlin"
tunnel_src = "203.0.113.10"             # config.tunnel_src; required if any backend encapsulates
tx_ports   = ["eth1", "eth2"]           # resolved to ifindex; DEVMAP_HASH key == value
# max_frame = 1514                      # omit to derive from the attach interface's MTU + ETH_HLEN

[acl]                                   # CFG_ACL_ENABLE
enabled = true
allow   = ["192.0.2.0/24", "2001:db8:ffff::/48"]
block   = ["198.51.100.0/24"]

[ratelimit]                             # CFG_RL_ENABLE
enabled        = false
tokens_per_sec = 5000                   # operator units; scaled into config.rl_refill
burst_packets  = 10000                  # operator units; scaled into config.rl_burst

[[backend]]
name        = "web-01"                  # file-local identity, referenced by [[vip]].members
id          = 1                         # backends[] slot; never 0
addr        = "10.0.0.11"
mode        = "l2dsr"                   # l2dsr | ipip | gue | vxlan
state       = "up"                      # up | down — static; see §3.2
mac         = "52:54:00:ab:cd:01"       # omit to let the kernel resolve every packet
fib         = false                     # MARLIN_BE_F_FIB; defaults to true when mac is stated
egress      = "eth0"                    # optional; omit for no expectation
# encap_dport = 0                       # omit for the per-mode default
# vni       = 4242                      # VXLAN only
# inner_mac = "52:54:00:00:00:01"       # VXLAN only

[[vip]]
addr        = "203.0.113.1"              # or ["203.0.113.1", "2001:db8::1"] -- an address group
port        = 443                       # 0 = any port
proto       = "tcp"                     # "tcp" | "udp" | "sctp"
hash_key    = "00112233445566778899aabbccddeeff"   # 32 hex digits, 16 bytes
table_seed  = "ffeeddccbbaa99887766554433221100"   # 32 hex digits, 16 bytes
acl         = true                      # VIP_ACL
ratelimit   = false                     # VIP_RATELIMIT
hash_5tuple = false                     # VIP_HASH_5TUPLE
hash_ports  = false                     # VIP_HASH_PORTS; SCTP-only, landed in revision 14
                                         #   (docs/design/32-sctp.md), after this document's first draft
quic        = false                     # VIP_QUIC
# quic_cid_len = 8                      # VIP_QUIC_CID_LEN, 7–20; required when quic = true
# dscp        = 46                      # VIP_DSCP, 0–63; landed in revision 13, after this
                                         #   document's first draft -- outer header only
members = [
    { backend = "web-01", weight = 100 },
    { backend = "web-02", weight = 50 },
]
```

**`addr` accepts a string or an array of strings** (`docs/design/32-sctp.md`), the latter an
address group: every address becomes its own `vip_map` key, and all of them share this entry's
`port`, `proto`, `hash_key`, `table_seed`, flags and `members` — one `vip_num`, one `fwd_table`
block, one `vip_stats` counter. `docs/design/20-configuration-validation.md` carries the group
rules SCTP needs.

Five shape decisions, each forced rather than chosen:

- **Backends are global and referenced by name, not nested under a VIP.** `backends` is one
  `ARRAY` over a single dense ID space (`docs/design/07-maps.md`) and one backend may serve
  several VIPs. Nesting would duplicate a backend per VIP and make `marlind` deduplicate to
  allocate an ID. GLB nests because each of its tables is independent; Keepalived nests
  `real_server` for the same reason. HAProxy's named-backend-plus-reference form is the one that
  fits a shared ID space.
- **`weight` is per membership, not per backend.** The score `u^(1/w_b)` is evaluated during
  per-VIP generation (`docs/design/12-selection.md`) and weight never enters a map, so per-VIP
  weight is strictly more expressive at no cost.
- **`id` is explicit.** Three reasons: `VIP_QUIC` puts it on the wire
  (`docs/design/30-quic.md`), so an ID that moves when a `[[backend]]` block is inserted routes
  deterministically to the wrong backend; `docs/design/12-selection.md`'s retire-don't-recycle
  rule needs an authority that outlives one reconcile; and a `marlind`-allocated ID would need
  state persisted outside the file, which `ProtectSystem=strict` refuses without a new writable
  path. Stating it in the file makes the file the allocation authority and settles
  `PHASES.md`'s open row on ID authority *for this mode only* — every instance reads the same
  file content and therefore agrees.
- **`hash_key` and `table_seed` are required hex strings, never generated.**
  `docs/design/10-map-invariants.md` makes reconcile-time generation a hard error precisely
  because each instance would invent a different value. GLB requires the identical thing —
  `hash_key` and `seed`, 32 hex digits each, operator-generated and shared across director
  nodes — which is direct confirmation rather than a coincidence. Generation belongs in a
  separate, explicitly invoked step (D-F7).
- **`max_frame` is omitted rather than zeroed to mean "derive".** Zero is the ABI's own value
  for *unset, check disabled* (`abi/types.h`'s `marlin_config`), and
  `docs/design/20-configuration-validation.md` rejects an encapsulating backend against it. A
  file key whose `0` produced a non-zero map value would be the one place the schema and the ABI
  disagree about what zero means.

Reserved flag bits are unrepresentable by construction: there is no key that reaches
`vip_meta.flags` bits 4–7 or 13–31, or `marlin_config.flags` bits 2–31. That makes
`docs/design/20-configuration-validation.md`'s "any reserved flag bit set" rule a property of
the schema rather than a check.

---

## 5. What `marlind` derives

| Derived | From | Note |
|---|---|---|
| `vip_meta.vip_num` | allocated over `MAX_VIPS` blocks, one per `[[vip]]` entry regardless of how many addresses it holds (`docs/design/32-sctp.md`) | a surviving entry prefers a block one of its addresses already holds, read back from `vip_map`; new entries take free numbers. Cyclic regrouping may change that preference to an unreferenced final block. `data-plane/marlind/vip_alloc.c` computes assignments, safe write order and the release set before map writes |
| `fwd_table` block | `table_seed`, members, weights (`docs/design/12-selection.md`) | `TABLE_SIZE` rows per VIP; `tools/marlin_seed.c:117` already writes a whole block with one `bpf_map_update_batch()` |
| `config.rl_refill`, `config.rl_burst` | `tokens_per_sec`, `burst_packets` | the scaling of `docs/design/28-rate-limiting.md`; the datapath performs no unit conversion |
| `config.acl_lists` | which of the four lists are non-empty | bit index `(list << 1) \| family` (`docs/design/08-types.md`) |
| `config.max_frame` | attach interface MTU + `ETH_HLEN` | unless stated |
| `vip_key.family`, `proto` | the parsed address and `proto` string | |
| ACL trie values | rule position within its list | **a divergence to confirm.** `docs/design/27-source-filtering.md` makes the `__u32` the control plane's rule identity, on the grounds that `get_next_key` reconciliation cannot attribute a bare key to a configuration object. File mode does not need that: the desired key set is fully computable from the file, so reconciliation is a set difference and the value is a diagnostic label |

Two dependencies this adds to `marlind`, whose link line is `-lbpf` alone
(`data-plane/Makefile`):

- **SipHash-2-4, and it cannot be the datapath's copy.** Two independent obstacles, either
  sufficient on its own. `include/marlin/siphash.h` pulls in the real `<bpf/bpf_helpers.h>`,
  which cannot coexist in one translation unit with the userspace `<bpf/bpf.h>` that libbpf map
  I/O needs — the constraint `data-plane/tests/packet/xdp_siphash.h:6-10` already hit and
  answered with a from-scratch transcription. And `marlin_siphash()` accepts only input lengths
  that are a multiple of eight (`include/marlin/siphash.h:4-7`), while generation hashes a row
  index and a three-field backend identity whose widths sum to neither on their own (fixed by
  §6's byte encoding below, which pads both to a multiple of eight instead).

  **Correction:** this document previously called `data-plane/tests/packet/xdp_siphash.c`'s
  `sip_hash64()` "general-length". It is not — its own header comment says "Whole 8-byte blocks
  only, matching `marlin_siphash()`'s length contract" — so promoting it would not have removed
  the packing requirement below regardless.

  **Decided (D-F6): a third transcription, in `data-plane/marlind/hash.c`.** Same algorithm,
  same byte-wise little-endian load as the other two, carrying the same multiple-of-eight
  contract; trustworthy only because `data-plane/tests/fwd_gen_test.c` asserts the published
  vectors against it, as `xdp_50_siphash.c` does for the packet tier. Reworking
  `include/marlin/siphash.h` to drop the BPF-only include and accept arbitrary lengths was
  rejected: the datapath's own call sites are exactly the fixed, compile-time-constant lengths
  the current macro exists to enforce (`marlin_siphash()`'s `_Static_assert`s), and a
  general-length rework would weaken that guarantee for every existing caller to serve one new
  one outside the datapath entirely.
- **`-lm`**, for the weighted score. Comparing `ln(u)/w` instead of `u^(1/w)` preserves the
  ordering and avoids `pow()`, but still wants `log()`. `marlind/fwd_gen.c` skips even that when
  every member of a VIP shares one weight — the common case — since a constant weight does not
  reorder the comparison and the raw digest can be compared directly.

---

## 6. A second table generator

**This is the largest cost of the feature and it is not the file format.** `fwd_table`
generation would exist twice: in C in `marlind`, and in C# in `Marlin.Core`.
`docs/design/12-selection.md` already names the hazard for the cross-version case — "every
instance must run generation logic that hashes the same fields, or two instances score the same
VIP differently from identical `table_seed` and member-set inputs" — and two implementations in
two languages inside one repository is that hazard with a shorter fuse. It is the same class of
unchecked-duplicate risk as the hand-written map ABI (`docs/design/06-map-abi.md`), including
the part where the build catches none of it.

**The inputs' byte encoding is not specified anywhere, which makes the hazard concrete rather
than theoretical.** `docs/design/12-selection.md` gives the algorithm as
`siphash(row_index, table_seed)` and `siphash(row_seed, b.addr, b.vni, b.inner_mac)`, and
states neither field width, nor byte order, nor concatenation order, nor padding to
`marlin_siphash()`'s multiple-of-eight length. Two implementations reading that text agree on
the algorithm and disagree on the digest. The datapath's own packet hash is not exposed to this:
`include/marlin/siphash.h:36-39` fixes a byte-wise little-endian load specifically so every
instance computes the same row, and the generation side has no equivalent sentence.

Two mitigations, and they are complementary rather than alternatives:

- **Specify the encoding** in `docs/design/12-selection.md`, at the algorithm it already
  states. Nothing can be tested against an unwritten contract.
- **A committed fixture** of `table_seed` plus member set plus expected block digest, asserted
  by both implementations' test suites. It is the cross-language oracle
  `docs/REPO-STRUCTURE.md` §7.7 wishes it had for struct offsets, and it is easier here because
  the output is deterministic bytes. `xdp_50_siphash.c` is the precedent: a transcription is
  trustworthy only because a vector case asserts it.

Deferring generation to the control plane instead is not available: that is the component
file-managed mode exists to make optional.

---

## 7. Reload

- **`SIGHUP`, added to `open_signal_fd()`'s mask** (`marlind/cmd_attach.c:91-93`). The epoll
  loop already multiplexes a `signalfd` and a netlink socket (`:151-173`), so the reload path is
  a third branch, not a new mechanism. `signalfd` also means the reload runs in the main loop
  rather than in a handler, so nothing needs to be async-signal-safe.
- **Validate the whole file, then apply.** Parse into a complete in-memory model and run every
  check in §8 against it before the first `bpf_map_update_elem()`. A file that fails validation
  is never partially applied.
- **A failed reload must not exit.** The attach is `bpf_link`-owned and dies with the process
  (`docs/design/02-architecture.md`; `marlind/cmd_attach.c:165`), so exiting on a bad file stops
  forwarding — the worst possible response to a typo. Log, keep the last applied model as the
  reconcile baseline, and stay attached. This is the opposite of `--attach`'s startup posture,
  where a bad file must refuse before anything is attached.
- **`[instance]` keys are restart-only.** `interface`, `object` and `pin_dir` determine the
  attach and map identity. A reload that finds any of them changed logs and refuses that key
  rather than silently ignoring it. GLB splits this by file — `/etc/default/glb-director` needs a
  restart, the forwarding table reloads — and the split is the same one whether it is expressed
  as two files or two sections.
- **A new exit code.** `deploy/marlind.service` sets `Restart=on-failure` with
  `RestartPreventExitStatus=5`, and `die()` exits `EXIT_USAGE` (1)
  (`marlind/log.c`, `include/marlind/marlind.h:25-29`). A malformed file is "unfixable by
  retrying, only by replacing a file" — exactly the comment `marlind.service:16-17` gives for
  code 5 — so it needs its own code, added to `RestartPreventExitStatus`, or startup loops.
- **`marlind --check [--config <path>]`**, exiting non-zero on any rejection, with no privilege
  and no map access. It is what makes `ExecReload=` safe to wire and what lets CI validate an
  integrator's file.

### 7.1 File permissions

`open_conf_file()` (`marlind/conf.c`) checks the file on the fd it is about to parse, not by path
beforehand, so there is no TOCTOU gap between the check and the read.

- **Group- or world-writable is refused on `--attach` and SIGHUP-reload**, and only warned on
  `--check` -- the same `enforce_perms` split as every other check in this document, driven by
  `--check` being deliberately runnable unprivileged and against a file the caller does not
  control the layout of.
- **World-readable is always a warning, never a rejection**, in both modes: the file holds every
  VIP's `hash_key` and `table_seed`.
- **Ownership is not checked.** A config owned by someone other than root that is *not*
  group/world-writable is accepted. The write-mode check already covers the case that matters --
  an unprivileged user rewriting a file marlind trusts with real map writes -- for any config
  that lives in a directory that user cannot write to. Checking ownership on top of that would
  also refuse a config a developer owns outright in their own tree (a netns integration rig's
  config, for instance), for no corresponding gain: nothing stops that same developer from
  `chown`-ing the file to themselves and passing the write-mode check regardless.

---

## 8. Validation and write ordering

Validation is `docs/design/20-configuration-validation.md` unchanged — every rule there applies,
and none of them is weakened by the input being a file. The schema makes reserved-bit violations
and `backends[i].id != i` unrepresentable (§4); everything else is a check.

Additions the file form introduces:

- A `members` entry naming a `[[backend]]` that does not exist, and a duplicate `name` or `id`.
- `tx_ports` naming an interface that does not resolve, and `egress` naming one that is neither
  the attach interface nor in `tx_ports` — the existing rule, now checkable by name.
- More than `MAX_VIPS` VIP **addresses** across every `[[vip]]` entry, or `MAX_BACKENDS - 1`
  `[[backend]]` blocks (`abi/defines.h:25-26`). An address group (`docs/design/32-sctp.md`) is
  one entry but several `vip_map` keys, so the bound is on keys, the map's real capacity, not on
  entries. Reading the limits from the header rather than restating them is the discipline
  `data-plane/scripts/common.sh`'s `abi_define()` already follows.
- Two VIP addresses identical in address, port and protocol, whether in the same entry (a
  duplicate inside a group) or in two different ones (`docs/design/32-sctp.md`).

Write ordering is `docs/design/12-selection.md`'s and `docs/design/27-source-filtering.md`'s,
plus **one rule neither states, because neither has a component that allocates `vip_num`**,
extended to entries with several addresses:

> Delete keys absent from the desired configuration first. Before overwriting an entry's
> destination block, move every surviving key belonging to another entry away from that block.
> Write the complete destination block, then publish **every one of its** entry's keys.
> Zero released blocks only after every surviving key has moved to its final destination.

It is `docs/design/12-selection.md`'s reasoning one level up — `vip_num` is a reference the
datapath follows to reach data, exactly as a row is — and without it a VIP moved between blocks
forwards into another VIP's member set for the length of the rewrite. Delaying zeroing alone
does not prevent this: a new entry can overwrite an absorbed block before a merge moves its
remaining address, and a split can rewrite the retained shared block before its other address
moves out.

`data-plane/marlind/vip_alloc.c` simulates these references and returns a deterministic write
order as well as assignments and a release set. If regrouping creates a dependency cycle, it
assigns an entry an unreferenced, otherwise-unassigned final block to break the cycle. This is
automatic, not an operator-managed sequence of reloads, and reserves no permanent spare.
The affected group's `vip_num`, and therefore statistics-slot identity, may change; ordinary
non-conflicting reloads retain the existing assignment preference.

The reconciler requires a complete baseline read and a successful plan before any map write.
A table or key write failure stops execution before dependent entries can reuse the block; a
retry plans from the actual maps. These are ordering guarantees between operations, not an
atomic reload or a new guarantee for packets already holding a previous map value.

**A second rule this document did not originally state either, found implementing it: `config.acl_lists`
needs the same "reference before referent" treatment as `vip_num`, one level further out.**
`docs/design/27-source-filtering.md` calls `acl_lists` "control-plane-derived and exists to
avoid a lookup against an empty map" — but that also means a clear bit is licence for the
datapath to skip a trie's lookup *entirely*, not merely an optimisation. Reconciling a
previously-empty trie by inserting its rows first and writing the bit second leaves a window,
for as long as that insert loop runs, where a newly added rule is present but silently
unenforced — worst on a newly added `block` rule, where the packets it exists to stop pass
through unaffected. `marlind/reconcile.c` avoids this the same way §8's `vip_num` rule does,
generalised: write `config.acl_lists` as `old_bits | final_bits` *before* touching any trie, so
a bit is never clear while its trie is non-empty; do the trie inserts and deletes; then write
`config` a second time, narrowing `acl_lists` down to exactly the final population. The
`vip_num`/`fwd_table` ordering above needs no equivalent second pass because nothing reads
`vip_num` as a bit deciding whether to trust `fwd_table` — a stale-but-still-valid `vip_num`
only ever points at a correctly-populated block, never at a "trust this less" signal the way a
clear `acl_lists` bit does.

---

## 9. Prior art

| System | Configuration surface | Bearing here |
|---|---|---|
| GLB (`glb-director`) | JSON forwarding table with `hash_key`, `seed`, `binds` and `backends`; per-host `director.conf` separate; `systemctl reload` applies the table | the model this design follows: required operator-generated keys shared across nodes, health merged in by a companion writing a derived file, static host config needing a restart |
| Katran | thrift/gRPC services over the library, driven by a Go client | no file surface for VIPs or reals was found in the tree; the position file-managed mode departs from |
| Envoy | `static_resources` **or** xDS per resource | the exclusivity rule of §2 |
| HAProxy | config file plus Runtime API, both writing | the counterexample: runtime changes lost on reload, `server-state-file` an incomplete retrofit |
| Keepalived | `real_server` nested in `virtual_server`, `SIGHUP` reload | nesting works where pools are per-VIP; §4 explains why Marlin's shared ID space rules it out |

---

## 10. What this costs, summarised

- No health checking, no neighbour maintenance, no reachability determination (§3).
- A second `fwd_table` generator with no oracle unless one is built (§6).
- `hash_key`, `table_seed` and `id` become operator bookkeeping, and the file holds secrets.
- `marlind` gains a TOML parser — new attack surface in a process that runs as root on every
  forwarding host, where the input surface today is four `getenv()` calls — plus `-lm`.
- The open decision on whether the control plane runs as a non-root user
  (`docs/DEPLOYMENT.md` §1.6) gets heavier, not lighter: a metrics-only reader is the case most
  likely to want to be unprivileged against `0600` pins.

---

## 11. Open decisions

Each is carried at the line or section it affects, per this repository's convention. Eight of
the ten are now closed, by implementation; the remaining two are carried forward into
`PHASES.md`'s open-decision table since they bind more than this document.

| Decision | Outcome |
|---|---|
| D-F1 — health in file-managed mode | **Closed: static `state` only.** `marlind` performs no health checking; §7's `SIGHUP` reload is what makes a GLB-style companion addable later with no `marlind` code change. |
| D-F2 — the write interlock | **Closed: documented exclusivity only** (§2). |
| D-F3 — `--config` versus the environment input | **Closed: replacement, not precedence** (§4). |
| D-F4 — the TOML parser | **Closed: vendored.** `data-plane/vendor/tomlc17/` (`cktan/tomlc17`, MIT), pinned at a tagged commit — see `vendor/README.md`. Hand-writing a restricted subset was rejected: TOML's string-escaping and array-of-tables rules are easy to get subtly wrong against root-parsed, untrusted input, and `tomlc17` is one translation unit with no dependency beyond the C standard library. |
| D-F5 — whether `config.max_frame` tracks netlink link events | **Still open** — carried in `PHASES.md`. `marlind` derives it once, at reconcile time, from `SIOCGIFMTU`; it does not yet subscribe the existing netlink socket to MTU changes. |
| D-F6 — where the generation-side SipHash lives | **Closed: a third transcription**, `data-plane/marlind/hash.c` (§5). |
| D-F7 — where key generation lives | **Closed: documented `openssl rand -hex 16`.** No `marlind` subcommand; `deploy/marlin.conf.example`'s header and `docs/DEPLOYMENT.md` carry the command. A generator subcommand was rejected as unnecessary surface: the two secrets are opaque 16-byte values with no structure a purpose-built generator would validate. |
| D-F8 — `port == 0` companion schema sugar | **Still open** — carried in `PHASES.md`, blocked on the same fragment-tail admission decision it always was. The machinery it would need already exists: `docs/design/32-sctp.md`'s address groups (`addr` as an array, `vip_alloc.c`) give one `[[vip]]` entry several `vip_map` keys sharing one `vip_meta`, the same shape a `ports` list needs — but D-F8 stays blocked on the fragment-tail decision regardless. |
| D-F9 — the ACL trie value | **Closed: rule ordinal within its list** (§5), a diagnostic label. |
| D-F10 — the byte encoding of `fwd_table` generation's hash inputs | **Closed: pinned in §5's derivation table** and restated here for visibility, since `docs/design/12-selection.md` is the document that should have stated it and did not. Both hashes are keyed by the VIP's `table_seed`. `row_seed = siphash(row_index as little-endian u32, padded to 8 bytes; table_seed)`. `score_input = siphash(row_seed as little-endian u64 (8B) ++ backend.addr exactly as stored, network order (4B) ++ backend.vni as little-endian u32 (4B) ++ backend.inner_mac (6B) ++ two zero pad bytes; table_seed)`, 24 bytes total. Little-endian for host-order scalars matches the datapath's own convention (`include/marlin/siphash.h:36-39`); network order for `addr` makes the buffer a direct copy of the ABI field. `data-plane/tests/fwd_gen_test.c` carries a computed vector over this encoding — not yet an external oracle, since no second implementation exists to check it against, but the concrete number a future `Marlin.Core` port must reproduce. |

---

## 12. Documentation drift this design exposed

Reported, not fixed. Only the items this document depends on; each is pre-existing.

- **`docs/design/19-control-plane.md`'s map-access table omits `bpf_map_update_batch`.** It is
  already used in two places (`tools/marlin_seed.c:117`,
  `data-plane/tests/packet/maps.c:373`), and a per-VIP `fwd_table` block is exactly the write it
  exists for. §1 treats the table as authoritative on the kernel surface, so the omission reads
  as a prohibition it is not.
- **`docs/design/12-selection.md` specifies table generation's algorithm but not its hash-input
  encoding.** Covered as D-F10; recorded here because it is a gap in an existing document rather
  than a decision this one introduces, and it binds `Marlin.Core` today whether or not
  file-managed mode is ever built.
- **`docs/REPO-STRUCTURE.md` §2 lists `include/marlin/abi/` as `types.h`, `limits.h` and
  `enums.h`.** The tree has `types.h` and `defines.h`, with `defines.h` holding what §8 of that
  document proposed splitting across the other two. §8 of this document cites
  `abi/defines.h:25-26` for `MAX_VIPS` and `MAX_BACKENDS`, so the two documents disagree about
  where a validator reads its limits from.
- **`docs/REPO-STRUCTURE.md` §2 lists `data-plane/tools/` as holding `verifier_stats.c`
  alone.** `marlin_seed.c` is also there, and this document leans on it twice — as the batch-write
  precedent above, and as the existing proof that a C binary can write `vip_map` and `fwd_table`
  through `abi/types.h` without a third hand-written mirror.
