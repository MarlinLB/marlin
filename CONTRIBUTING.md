# Marlin — Contributing

**Status:** first revision
**Companion documents:** `PHASES.md` (what's currently in scope), `REPO-STRUCTURE.md`
(where a file goes), `docs/design/README.md` (how Marlin works and why)

This document gets you from a clean machine to an open pull request.

For what's currently in scope and which decisions are still open, see `PHASES.md`. That list
moves as work lands, so it isn't repeated here.

---

## 1. Development environment

Marlin has two halves with different host requirements: the eBPF/XDP datapath needs a Linux
kernel and the BPF toolchain, and the control plane needs the .NET SDK. On Windows, that means
one half runs under WSL2 and the other runs natively.

### 1.1 Data plane (C, eBPF/XDP) — VS Code + WSL2

The data plane requires WSL2 on Windows machines for development, since the datapath compiles
with a BPF-target clang and loads through `bpftool`/kernel BPF syscalls, and neither exists on
Windows itself.

Install WSL2 with an Ubuntu distribution if you don't already have one (`wsl --install -d
Ubuntu-24.04` from an elevated Windows terminal), and clone the repository inside the WSL2
filesystem — `~/src/marlin`, say — rather than under `/mnt/c/...`, since cross-filesystem access
from WSL2 to Windows-mounted paths is much slower and mishandles Linux file permissions and
symlinks, both of which matter for a C toolchain.

From the WSL2 shell, install the toolchain from `apt`:

```sh
sudo apt update
sudo apt install -y \
  build-essential git pkg-config \
  clang lld llvm clang-format clang-tidy \
  libbpf-dev libelf-dev zlib1g-dev
```

### bpftool on WSL2 — build from source

No apt package resolves a working `bpftool` on WSL2: `linux-tools-generic`/`linux-tools-common`
install tooling matched to an Ubuntu kernel flavor (e.g. `6.8.0-138-generic`), but WSL2 runs a
Microsoft-built kernel (`*-microsoft-standard-WSL2`) with no corresponding `linux-tools-<version>`
package, so the installed `bpftool` dispatcher can never find a match — confirmed on this machine
(`apt install bpftool` fails outright; a manual symlink into the mismatched `linux-tools-6.8.0-138`
directory still failed the kernel-version check). `bpftool` itself is also a virtual package with
no installation candidate on this distro.

Build-only dependencies (additional to the block above; not needed for anything else in the C
toolchain):

```sh
sudo apt install -y libcap-dev bison flex
```

Build and install:

```sh
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src
make -j"$(nproc)"
sudo install -m 0755 bpftool /usr/local/sbin/bpftool
```

Verify:

```sh
hash -r
which bpftool
bpftool version
```

This is a WSL2-specific exception to the general rule stated elsewhere (`README.md`'s build
table, `DEPLOYMENT.md` §1.1) that `bpftool` comes from `linux-tools` matching the running kernel —
that rule holds on a standard Linux host, just not under WSL2.

If your machine already has `linux-tools-generic`/`linux-tools-common` installed from before this
fix, purge them so the broken dispatcher script doesn't shadow the source-built binary on PATH:

```sh
sudo apt purge -y linux-tools-generic linux-tools-common
sudo apt autoremove -y
```

Check the installed versions against `docs/design/29-versions.md`'s toolchain table, and if your
release's default packages are older than what it pins, install the versioned package name
instead (`clang-format-19`, say) rather than a second toolchain. Check the kernel version too —
`docs/design/29-versions.md` states the minimum Marlin supports — with `uname -r`, and update it via `wsl
--update` on the Windows side if it falls short.

WSL2 has one standing limitation worth planning around: compiling, static analysis, and any test
tier that runs a BPF program without a real network interface all work fine under it, but
anything that attaches to a NIC in native XDP mode needs a driver that supports it, and WSL2's
virtual adapter doesn't. Keep a real Linux host or VM on hand for that tier and for netns-based
integration testing, and use WSL2 for everything else.

Install VS Code on Windows along with the WSL extension (`ms-vscode-remote.remote-wsl`), then
open the clone from inside the WSL2 shell with `code .` — this brings up a VS Code window
running inside WSL2. Inside that window, install clangd (`llvm-vs-code-extensions.vscode-clangd`)
so intellisense and diagnostics come from the same compile database the build generates
(`REPO-STRUCTURE.md` §5) and `clang-tidy` reads in CI, and EditorConfig for VS Code so the
repository's `.editorconfig` is honoured.

### 1.2 Control plane (C#/.NET) — Windows

The control plane needs no WSL2 — run it wherever you'd run any .NET project. Install the [.NET
SDK](https://dotnet.microsoft.com/download) — version 10, per `README.md`'s build table — on Windows, then
work in either VS Code with the C# Dev Kit extension or JetBrains Rider, and open the
control-plane solution there.

### 1.3 Working across both halves

`docs/design/06-map-abi.md` requires the datapath's ABI headers and their hand-written C# mirror to
change in the same commit. In practice that means two editor windows open at once: the
WSL2-connected VS Code window for the datapath side, and a Windows VS Code/Rider window for the
control-plane side. Editing the Windows side against the `\\wsl.localhost\...` UNC path also
works if you'd rather have one window, at the cost of slower file I/O.

---

## 2. Building and testing

Build with the project's `make` target at the repository root, which builds the datapath, then
the control plane, then the test suites, in that order (`REPO-STRUCTURE.md` §6). The three test
tiers — packet-level, integration, and control-plane unit tests (`REPO-STRUCTURE.md` §2) — have
the first two described in `docs/design/24-testing.md`; run the tier closest to what you changed
before opening a PR, and all of them before merging anything that touches the datapath.

---

## 3. Style

Formatting and lint rules are defined in `.clang-format`, `.clang-tidy`, and `.editorconfig` —
see those files for specifics. Run the formatter and linter before pushing rather than relying on
CI to catch it.

---

## 4. Submitting a change

- One logical change per pull request. A change to the shared packet/map ABI and its C# mirror
  is one commit, not two.
- If you find a document disagreeing with the code, or with another document, say so in the PR
  description rather than silently fixing it (`CLAUDE.md`'s rules) — that includes drift you find
  outside the lines you're changing.
- If your change closes an entry in `PHASES.md`'s open-decision table, write the decision into
  the document that table names, in the same PR, not just in code.

---

## 5. Getting help

Open an issue in this repository. There's no separate chat channel or mailing list on record to
point you to.
