# Changelog

All notable changes to `marlin.bpf.o` will be documented in this file. Versioned in
`data-plane/bpf/VERSION`. See the root `CHANGELOG.md` for how this fits the other components.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.3] - 2026-09-16

- Replace the rate-limit clock-skew tolerance in the rate limiter with reading bucket state before
  sampling time on every CAS attempt, closing the same bypass without a fixed skew window.

## [0.0.2] - 2026-09-16

- Fix a rate-limit bucket refilling to burst when a losing CAS retry's clock sample read
  slightly behind a concurrent CPU's winning exchange; the loser now re-samples the clock per
  retry and tolerates the resulting skew instead of treating it as a 32-bit wrap.
- Drop ESP and AH non-first fragments as `unsupported_proto` in both families, matching the
  unfragmented head instead of admitting the tail.

## [0.0.1] - 2026-09-16

- Implement DSR load balancing mechanism.
- Implement support for the following forwarding modes:
  - GUE;
  - IP in IP;
  - VXLAN;
  - L2 DSR.
- Implement traffic control via IP based ACL.
- Prevent DDoS via rate limiting.
