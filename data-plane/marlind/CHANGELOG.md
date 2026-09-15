# Changelog

All notable changes to `marlind` will be documented in this file. Versioned in
`data-plane/marlind/VERSION`. See the root `CHANGELOG.md` for how this fits the other components;
`data-plane/bpf/CHANGELOG.md` covers the datapath object, versioned separately.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project will adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once released.

## [Unreleased]

### Added

- Pins `marlin.bpf.o`'s embedded build version under `<pin_dir>/version` on attach and reports it
  from `--status` and `--version`.
- A hand-maintained minimum supported `marlin.bpf.o` version (`include/marlind/compat.h`).
  `--attach` refuses, before loading or pinning anything, an object below that floor or one that
  carries no build version at all; `--version` reports the same check but always exits `0`. A
  refusal exits `EXIT_INCOMPATIBLE` (5), excluded from systemd's `Restart=on-failure` retries
  (`deploy/marlind.service`) since it is not fixable by retrying.
- `marlin.bpf.o` and `marlind` now version independently (`data-plane/bpf/VERSION`,
  `data-plane/marlind/VERSION`); a mismatch between the two is expected, not a build error.

### Fixed

- `marlind --attach` no longer sets a pin path on internal maps (`.rodata`, `.bss`, ...). Their
  libbpf-derived names contain a `.`, which the kernel's bpffs rejects on lookup (`EPERM` --
  "reserved for future extensions"), and reuse across an upgrade would have kept an internal
  map's old contents regardless.
