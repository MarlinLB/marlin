# Changelog

All notable changes to `marlind` will be documented in this file. Versioned in
`data-plane/marlind/VERSION`. See the root `CHANGELOG.md` for how this fits the other components.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project will adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once released.

## [Unreleased]

### Added

- File-managed configuration (`docs/design/31-file-configuration.md`): `--config <path>`
  selects a mode where `marlind` reads a TOML file (default
  `/etc/marlind/marlin.conf`), validates it, and reconciles every map to it
  itself, with the control plane reduced to reading stats. `[instance]`
  replaces the environment input entirely when `--config` is given.
- `--check [--config <path>]`, validating a file with no privilege and no
  map access -- makes `ExecStartPre=` safe and lets CI validate a file
  before it is installed.
- `SIGHUP` reloads the active `--config` file in place; a rejected reload
  logs and keeps the previous generation attached rather than exiting.
- `EXIT_CONFIG` (6): a malformed or rejected configuration file. Added to
  `deploy/marlind.service`'s `RestartPreventExitStatus`.
- Vendored `tomlc17` (`data-plane/vendor/tomlc17/`, see `vendor/README.md`)
  and a third host-only SipHash-2-4 transcription
  (`data-plane/include/marlind/hash.h`) for `fwd_table` generation.
