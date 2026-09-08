# Marlin — Rate Limiting


A token bucket per source address in one LRU hash map, evaluated in the datapath with no
control-plane involvement. A source over its rate is dropped while it remains over, and recovers
without intervention.

Off by default. `CFG_RL_ENABLE` is the instance switch, `VIP_RATELIMIT` the per-VIP opt-in.
Defaulting off is what keeps `docs/design/24-testing.md`'s determinism intact for all existing coverage.

## Both bucket fields in one word

A token bucket needs a token count and a timestamp, updated together. BPF has no 128-bit
compare-and-swap, so two 64-bit fields cannot be updated atomically. Packing both into one
`__u64` (`struct rl_bucket`, `docs/design/08-types.md`) makes a single `__sync_val_compare_and_swap` sufficient, and
removes any dependency on `bpf_spin_lock` support in `LRU_HASH` values.

`struct rl_key`'s `family` member is load-bearing. With IPv4 in `addr[0]` and the remaining words
zeroed, `10.1.2.3` produces the same sixteen address bytes as the IPv6 address `0a01:0203::`;
without `family` the two would share a bucket. The prefix is unassigned and the collision
improbable, but improbability is not a key design. `docs/design/10-map-invariants.md`'s rule also binds: the whole 20-byte key
must be zeroed before an IPv4 lookup.

## Timestamp and refill

`bpf_ktime_get_ns() >> RL_TICK_SHIFT` (`RL_TICK_SHIFT` = 20, `docs/design/09-sizing.md`) — units of 1.048576 ms, avoiding
a division. Thirty-two bits of that unit wrap after roughly 52 days of uptime, or the clock can
step backwards; either yields a negative elapsed time. **The bucket resyncs to full rather than
crediting no refill.** Clamping elapsed to zero instead would leave the stale future timestamp in
place — a drained bucket never reaches the compare-and-swap that would overwrite it, since the
`tokens < ONE_TOKEN` test in "Update" below returns first — so the source would stay dropped
until `now` caught back up to the stale value, on the order of the wrap period itself rather than
one refill interval.

**Refill is pre-scaled by the control plane.** There are 953.67 ticks per second — not an integer
and not a shift — so converting an operator-facing tokens-per-second figure in the datapath would
need a division per packet. `config.rl_refill` holds scaled tokens per tick, computed once as
`rate << RL_TOKEN_SHIFT` divided by 953. Tokens per second is an API unit and never enters a map.
Rounding down puts the enforced rate at most one part in 953 below the configured one, and floors
it entirely below roughly 3.73 tokens/sec, where `rate << RL_TOKEN_SHIFT` divided by 953 rounds to
zero — a permanently empty bucket. `docs/design/20-configuration-validation.md`'s `rl_refill == 0`
rejection is what keeps that floor from reaching the datapath as a silent lockout.

`config.rl_burst` is stored scaled — `packets << RL_TOKEN_SHIFT` — so the datapath compares it
against the token field without shifting. At `RL_TOKEN_SHIFT` of 8 the 32-bit token field holds
at most 2^24 − 1 whole packets, which bounds the configurable burst (`docs/design/20-configuration-validation.md`).

## Update

```
if mctx == NULL                      → abort, nullref
if CFG_RL_ENABLE clear               → admit, unmetered
if acl_verdict == ALLOW              → admit, unmetered (docs/design/27-source-filtering.md)

now = bpf_ktime_get_ns() >> RL_TICK_SHIFT
b   = lookup(key)
if miss:
    rc = spend(old=now<<32|burst_scaled, now, rl_refill, burst_scaled) → next
    if rc != OK                      → drop, ratelimited (no insert)
    insert(key, next); update failure → admit anyway, count rl_insert_failed
    → admit

old = READ_ONCE(b->state)
unrolled RL_CAS_RETRIES times:
    rc = spend(old, now, rl_refill, burst_scaled) → next
    if rc != OK                      → drop, ratelimited
    prev = cmpxchg(&b->state, old, next)
    if prev == old                   → admit
    old = prev

retries exhausted → admit, count rl_cas_exhausted

spend(old, now, rate, burst) -> next:
    elapsed = now - (old >> 32)                                  /* signed */
    refill  = burst                                     if elapsed < 0     /* resync, see above */
            = min((__u64)elapsed * rate, burst)          otherwise         /* 64-bit, then clamped */
    tokens  = min((old & 0xffffffff) + refill, burst)
    if tokens < ONE_TOKEN                                → drop, ratelimited
    next    = (now << 32) | (tokens - ONE_TOKEN)          → OK
```

**The refill product is computed in 64 bits and clamped before the add.** `elapsed` is unbounded
in practice — an idle bucket surviving eviction for days yields a large tick delta — so
`elapsed * rl_refill` overflows 32 bits long before the sum does. Clamping the product first
makes the arithmetic exact for every reachable input, and is free: a bucket idle long enough to
overflow is a full bucket either way.

The loop is `#pragma unroll` over a compile-time constant, so it is bounded independently of the
verifier's bounded-loop support.

**Exhaustion admits, and cannot be driven by an attacker.** Retry exhaustion requires
`RL_CAS_RETRIES` competing exchanges to succeed in between, and each of those spent a token. Once
a bucket is drained the `tokens < ONE_TOKEN` test precedes the exchange, so a drained bucket drops
with **no** compare-and-swap attempt and no possibility of exhaustion. The packets a contending
source can admit through exhaustion are bounded by its burst, not by its packet rate.
`rl_cas_exhausted` rising is a signal to raise `RL_CAS_RETRIES`, not a bypass.

A compare-and-swap loop is also the right shape for the contention pattern: a single source at
line rate across all receive queues contends one cacheline, and a failed exchange retries locally
rather than serialising the CPUs behind a lock.

**The miss path is the expensive one, and an attacker controls it.** A spoofed high-cardinality
flood misses on every packet, so every packet performs an insert and an LRU eviction rather than a
lookup and an exchange — the limiter's cost peaks under one of the attacks it exists to answer.
Bounded memory is achieved; bounded cost is not, and is unmeasured. `PHASES.md` Phase 4 makes
that measurement a condition of enabling the limiter, and requires the mitigation to be chosen
on the measurement rather than ahead of it.

**An insert failure admits the packet.** Fail-closed here would let a control plane starving the
map of memory — the same condition an attacker's flood produces — become a denial of service in
its own right. The failure is still counted (`rl_insert_failed`), since otherwise it is invisible
and is exactly the signal the insert-cost measurement above needs.

## Scope

**One bucket per source, shared across every VIP that source addresses.** Per-VIP buckets would
multiply the map by the VIP count and need a composite key, and the rate a source may send at is
a property of the source — the argument `docs/design/17-reconfiguration.md` makes against a per-VIP down-set (`docs/design/25-rejected.md`).

`VIP_RATELIMIT` gates the call, not the bucket: it decides whether a given packet's VIP invokes
`marlin_ratelimit()` at all (`docs/design/11-pipeline.md` step 5), not which bucket a packet
charges. A source addressing both a metered and an unmetered VIP spends tokens only on the
metered VIP's packets, from the one bucket above — the unmetered VIP's packets to that same
source never reach the token check and never spend one.

An allowlisted source is never metered (`docs/design/27-source-filtering.md`), which is what keeps the management-prefix escape
hatch intact when rate limiting is enabled.
