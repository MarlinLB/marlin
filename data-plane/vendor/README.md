# Vendored third-party sources

Not authored here. Each subdirectory is dropped in from upstream at a pinned
version, kept out of `make format`/`make tidy` (`docs/REPO-STRUCTURE.md`), and
updated by re-fetching the pin, never by hand-editing.

## tomlc17

- **Upstream:** https://github.com/cktan/tomlc17
- **Pinned tag:** `R20260515` (commit `a06e8ad3c5a348ba3f2e8989574361bddeaf3356`)
- **Files:** `tomlc17/tomlc17.c`, `tomlc17/include/tomlc17.h`, `tomlc17/LICENSE`
- **Licence:** MIT — this repository is GPL-2.0-only OR BSD-2-Clause
  (`data-plane/LICENSE`, `data-plane/LICENSE-BSD-2-Clause`), so `tomlc17/LICENSE`
  must stay alongside the source it covers and must be named wherever the
  built `marlind` binary's licensing is documented.
- **Why vendored, not packaged:** `marlind` is parsed and run as root on every
  forwarding host with no packaging pipeline yet (`docs/DEPLOYMENT.md` §1.2),
  so there is no dependency manager to defer to. `docs/design/31-file-configuration.md`
  D-F4 chose vendoring a small, auditable parser over hand-writing a TOML
  subset, on the grounds that TOML's escaping and table/array-of-tables rules
  are easy to get subtly wrong against untrusted input.
- **Why this library:** single translation unit, single header, no
  dependencies beyond the C standard library, MIT licence, and it compiles
  warning-clean under `-std=c17 -Wall -Wextra`.

To move the pin: re-fetch `src/tomlc17.c`, `src/tomlc17.h` and `LICENSE` from
the new tag, update the tag/commit above, and re-run `data-plane/tests/conf_test.c`
— a parser behaviour change is exactly what that suite exists to catch.
