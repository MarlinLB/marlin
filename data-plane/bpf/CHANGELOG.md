# Changelog

All notable changes to `marlin.bpf.o` will be documented in this file. Versioned in
`data-plane/bpf/VERSION`. See the root `CHANGELOG.md` for how this fits the other components;
`data-plane/marlind/CHANGELOG.md` covers the loader, versioned separately; `data-plane/tools/
verifier_stats.c` versions itself and is not covered here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project will adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once released.

## [Unreleased]

### Added

- Embeds its build version in a `const volatile struct marlin_build`
  (`include/marlin/build.h`, `SEC(".rodata.marlin_version")`), sourced from `bpf/VERSION` at build
  time by a generated `include/marlin/version.h`. Read from the object file, no attach required, by
  `marlind` (`--status`, `--version`, and the version floor in `include/marlind/compat.h`) and by
  `verifier_stats`.
