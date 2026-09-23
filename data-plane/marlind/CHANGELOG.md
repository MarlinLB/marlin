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
- `--xdp-mode <native|generic>` on `--attach` (`docs/design/02-architecture.md`). `native` is the
  default and unchanged: refuse rather than silently degrade if the driver lacks native XDP
  support. `generic` is an explicit, logged-on-attach exception for a host whose native XDP_TX is
  broken outright rather than merely absent -- found on this repo's own netns rigs under a WSL2
  kernel, where native XDP_TX silently drops any frame grown by `bpf_xdp_adjust_head()`
  (`ethtool -S`'s `xdp_tx_errors`, invisible to the BPF program and to `drop_stats`).

### Changed

- The config file permission check no longer requires root ownership; a
  group- or world-writable file is still refused on `--attach`/SIGHUP (and
  warned on `--check`), but who owns the file is no longer examined
  (`docs/design/31-file-configuration.md` §7.1). This unblocks running
  `--config` against a config owned by the invoking user, as the netns
  integration rigs under `data-plane/scripts/` do.
