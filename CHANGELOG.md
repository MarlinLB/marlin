# Changelog

All notable changes to Marlin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project will adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once released.

Versioned per component, each against its own number, since the datapath and the control plane
ship and change independently:

| Component | Version | Changelog |
|---|---|---|
| Datapath (`marlin.bpf.o` + `marlind`) | `data-plane/VERSION` | `data-plane/CHANGELOG.md` |
| Control plane (C#) | not yet versioned | — |

`data-plane/tools/verifier_stats.c` is dev-only (`docs/REPO-STRUCTURE.md`), never installed, and
versions itself in its own source; it carries no changelog.

This file is the index. Entries live next to the file that carries the version number they
describe, not here.
