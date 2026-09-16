# Changelog

All notable changes to `marlin.bpf.o` will be documented in this file. Versioned in
`data-plane/bpf/VERSION`. See the root `CHANGELOG.md` for how this fits the other components.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- QUIC classification (`parser.c`) no longer reads a UDP datagram's declared payload; it now
  bounds the header-form byte against `udp->len`, not merely `data_end`, so a header-only
  datagram's Ethernet padding can no longer be misread as a QUIC short header.
- QUIC connection-ID decoding (`balancer.c`) no longer reads past a UDP datagram's declared
  length; it now bounds the connection ID against `marlin_ctx.udp_payload_len` before loading it,
  so bytes physically present past the declared datagram can no longer be read as CID entropy.
