# Marlin — Types and Flag Bits

## Types

```c
struct vip_key {              /* 20 bytes, no implicit padding */
    union {
        __be32 addr4;
        __be32 addr6[4];
    };
    __be16 port;
    __u8   proto;
    __u8   family;            /* AF_INET | AF_INET6 */
};

struct vip_meta {             /* 24 bytes */
    __u32 vip_num;            /* block index into fwd_table */
    __u32 flags;
    __u8  hash_key[16];       /* packet hashing key */
};

struct backend {              /* 20 bytes */
    __be32 addr;              /* the backend's own address, IPv4; required in every mode (docs/design/16-fib-lookup.md) */
    __u8   mac[6];            /* next-hop MAC; all-zero = resolve via bpf_fib_lookup */
    __be16 gue_dport;         /* 0 = default 6080 */
    __u8   mode;              /* MARLIN_MODE_{L2DSR,IPIP,GUE} */
    __u8   state;             /* MARLIN_UP | MARLIN_DOWN */
    __u8   flags;             /* MARLIN_BE_F_FIB */
    __u8   pad;
    __u32  egress_ifindex;    /* expected FIB egress interface, validation only (docs/design/16-fib-lookup.md) */
};

struct packet_tuple {         /* 40 bytes */
    __be32 src[4];            /* client; IPv4 in src[0], src[1..3] zero */
    __be32 dst[4];            /* VIP;    IPv4 in dst[0], dst[1..3] zero */
    __be16 sport;
    __be16 dport;
    __u8   proto;
    __u8   family;            /* AF_INET | AF_INET6 */
    __u8   pad[2];
};

struct stats {                /* 16 bytes */
    __u64 packets;
    __u64 bytes;
};

struct marlin_config {        /* 20 bytes */
    __be32 tunnel_src;        /* 0-3   IPv4 outer source address */
    __u32  flags;             /* 4-7 */
    __u16  max_frame;         /* 8-9   egress MTU + ETH_HLEN; 0 = unset */
    __u16  acl_lists;         /* 10-11 which ACL lists are non-empty (docs/design/27-source-filtering.md) */
    __u32  rl_refill;         /* 12-15 scaled tokens per timestamp tick (docs/design/28-rate-limiting.md) */
    __u32  rl_burst;          /* 16-19 bucket capacity, scaled tokens (docs/design/28-rate-limiting.md) */
};

struct acl_key4 {             /* 8 bytes, no implicit padding */
    __u32  prefixlen;
    __be32 addr;
};

struct acl_key6 {             /* 20 bytes, no implicit padding */
    __u32  prefixlen;
    __be32 addr[4];
};

struct rl_key {               /* 20 bytes, no implicit padding */
    __be32 addr[4];           /* tuple.src; IPv4 in addr[0], addr[1..3] zero */
    __u8   family;
    __u8   pad[3];
};

struct rl_bucket {            /* 8 bytes */
    __u64 state;              /* [63:32] coarse timestamp, [31:0] tokens, 8-bit fraction */
};
```

**Four fields of `marlin_config` change at runtime**, spanning both 8-byte words:
`max_frame` from the attach interface's MTU on netlink link events, `acl_lists` as rule lists
become empty or populated, and `rl_refill`/`rl_burst` on configuration change. Every field is
independently 2-byte or 4-byte aligned, so a torn read yields each field's old or new value and
never a mixture *within* a field. The control plane's obligation is set out in
`docs/design/17-reconfiguration.md`: every update is a read-modify-write of the complete struct.

**What the datapath does about the fields that are interpreted together.** `rl_refill` and
`rl_burst` are — the refill computed from one is clamped against the other on every metered
packet — and they sit at offsets 12 and 16, on opposite sides of the word boundary, so
per-field alignment is not on its own sufficient. `marlin.c` performs exactly one lookup of
this map per packet and copies the value onto `marlin_ctx.cfg` (`docs/design/04-calling-convention.md`); every reader in every
translation unit reads that copy. No field can therefore be observed with two values within one
packet's evaluation, and no two units can disagree about the generation they are reading. The
copy is not atomic, so cross-field mixing is narrowed to the instant of the copy rather than
eliminated.

`acl_key4` and `acl_key6` are the canonical `struct bpf_lpm_trie_key` shape — a `__u32
prefixlen` followed by the address bytes. Both are naturally aligned with no implicit padding,
so neither needs packing to keep an alignment hole out of the bit string the trie compares.

`struct backend` is 20 bytes: sixteen for the original layout — the outer family is IPv4 only
(`docs/design/01-scope.md`), so the tunnel destination is 4 bytes rather than 16 — plus the four of `egress_ifindex`
(`docs/design/16-fib-lookup.md`). Note that `marlin_ctx` embeds a `backend` by value, so every byte
added here is also a byte of the shared `MAX_BPF_STACK` budget (`docs/design/05-budgets.md`) — which is what bounds the
struct now that map memory does not (`docs/design/09-sizing.md`, "Memory": 80 KB against `fwd_table`'s 26 MB).

`packet_tuple` is IPv6-capable because inner traffic
may be either family. It is the single normalised description of the connection being load
balanced, with three consumers: the `vip_key` construction of `docs/design/11-pipeline.md`, the selection hash of `docs/design/12-selection.md` —
which reads `src` only, never the 5-tuple — and the GUE entropy hash of `docs/design/14-forwarding-modes.md`. It is not a key
or value of any map, so it lives in `marlin.h` rather than `types.h` and has no C#
counterpart.

**It is deliberately not called `flow_key`.** It keys nothing, and Marlin holds no per-flow
state — a flow cache was considered and rejected (`docs/design/25-rejected.md`). A name implying one would describe
machinery that does not exist. It is also the tuple of the *connection*, not of the arriving
packet: for an ICMP error it is reconstructed from the embedded header.

## Flag bits

`marlin_config.flags`:

| Bit | Meaning |
|---|---|
| 0 | `CFG_ACL_ENABLE` — evaluate the ACL (docs/design/27-source-filtering.md) |
| 1 | `CFG_RL_ENABLE` — evaluate the rate limiter (docs/design/28-rate-limiting.md) |
| 2–31 | reserved, must be zero |

`vip_meta.flags`:

| Bit | Meaning |
|---|---|
| 0 | reserved, must be zero |
| 1 | `VIP_RATELIMIT` — meter sources addressing this VIP (docs/design/28-rate-limiting.md) |
| 2–31 | reserved, must be zero |

`backend.flags`:

| Bit | Meaning |
|---|---|
| 0 | `MARLIN_BE_F_FIB` — resolve the next hop with `bpf_fib_lookup()` rather than the mode's zero-lookup path (docs/design/16-fib-lookup.md) |
| 1–7 | reserved, must be zero |

Bits are defined here as they are introduced rather than left to implementation, because all
three fields are part of the control-plane API surface.

`marlin_config.acl_lists` bit index `(list << 1) | family`, with `list` 0 for allow and 1 for
block, `family` 0 for IPv4 and 1 for IPv6 — four bits of sixteen. Bits 4–15 reserved, must be
zero.
