# Changelog

All notable changes to the Marlin datapath (`marlin.bpf.o` and `marlind`) will be documented in
this file. They share one version, in `data-plane/VERSION`. See the root `CHANGELOG.md` for how
this fits the other components; `data-plane/tools/verifier_stats.c` versions itself and is not
covered here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project will adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once released.

## [Unreleased]

### Added

- `marlin.bpf.o` embeds its build version in a `const volatile struct marlin_build`
  (`include/marlin/build.h`, `SEC(".rodata.marlin_version")`), sourced from `VERSION` at build
  time by a generated `include/marlin/version.h`. `marlind` pins it under `<pin_dir>/version` on
  attach and reports it from `--status` and `--version`; `verifier_stats` reads it directly from
  an object file, no attach required.

### Fixed

- `marlind --attach` no longer sets a pin path on internal maps (`.rodata`, `.bss`, ...). Their
  libbpf-derived names contain a `.`, which the kernel's bpffs rejects on lookup (`EPERM` --
  "reserved for future extensions"), and reuse across an upgrade would have kept an internal
  map's old contents regardless.
