# Changelog

All notable changes to Marlin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project will adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once released.

Versioned per component, each against its own number. `marlin.bpf.o` and `marlind` are separate
artefacts with separate release cadences -- a loader fix should not restamp the datapath object,
and vice versa -- so each carries its own `VERSION` and changelog. They ship as the
`marlinlb-xdp` and `marlinlb-daemon` .deb packages (`packaging/`, `docs/DEPLOYMENT.md` §1.2); the
`marlinlb` meta package pins a tested pair of the two and versions independently again, since it
records a release of the combination rather than of either component.

| Component | Version | Changelog |
|---|---|---|
| Datapath object (`marlin.bpf.o`) | `data-plane/bpf/VERSION` | `data-plane/bpf/CHANGELOG.md` |
| Loader (`marlind`) | `data-plane/marlind/VERSION` | `data-plane/marlind/CHANGELOG.md` |
| Packaging (`marlinlb` meta package) | `packaging/VERSION` | `packaging/CHANGELOG.md` |
| Control plane (C#) | not yet versioned | — |

`data-plane/tools/verifier_stats.c` is dev-only (`docs/REPO-STRUCTURE.md`), never installed, and
versions itself in its own source; it carries no changelog and does not enforce `marlind`'s
minimum-`marlin.bpf.o`-version floor (`data-plane/include/marlind/compat.h`).

This file is the index. Entries live next to the file that carries the version number they
describe, not here.
