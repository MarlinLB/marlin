# Changelog

All notable changes to Marlin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project will adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once released.

Versioned per component, each against its own number. `marlin.bpf.o` and `marlind` are separate
artefacts with separate release cadences -- a loader fix should not restamp the datapath object,
and vice versa -- so each carries its own `VERSION` and changelog even though neither ships
independently yet: no packaging exists (`docs/DEPLOYMENT.md` §1.2), so today they are still built
and deployed together. The split is preparation for that, not a description of current practice.

| Component | Version | Changelog |
|---|---|---|
| Datapath object (`marlin.bpf.o`) | `data-plane/bpf/VERSION` | `data-plane/bpf/CHANGELOG.md` |
| Loader (`marlind`) | `data-plane/marlind/VERSION` | `data-plane/marlind/CHANGELOG.md` |
| Control plane (C#) | not yet versioned | — |

`data-plane/tools/verifier_stats.c` is dev-only (`docs/REPO-STRUCTURE.md`), never installed, and
versions itself in its own source; it carries no changelog and does not enforce `marlind`'s
minimum-`marlin.bpf.o`-version floor (`data-plane/include/marlind/compat.h`).

This file is the index. Entries live next to the file that carries the version number they
describe, not here.
