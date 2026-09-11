#
# Marlin — root build
#

DATA_PLANE_DIR := data-plane
LOADER_DIR := loader

# Recursive $(MAKE) -C calls below would otherwise print "Entering/Leaving
# directory" around every sub-make; propagates to the child via MAKEFLAGS.
MAKEFLAGS += --no-print-directory

.DEFAULT_GOAL := all

.PHONY: all data-plane loader check-toolchain ci format tidy clean tests packet-tests verifier-stats help

all: data-plane loader

## Build the eBPF/XDP data plane (data-plane/Makefile's default target).
data-plane:
	@$(MAKE) -C $(DATA_PLANE_DIR) all

## Build the data-plane loader (loader/Makefile's default target).
loader:
	@$(MAKE) -C $(LOADER_DIR) all

## Verify the data-plane toolchain (clang, bpftool, clang-format, clang-tidy versions).
check-toolchain:
	@$(MAKE) -C $(DATA_PLANE_DIR) check-toolchain

## Run what CI runs: check-toolchain (strict), a full build, then the unit tests.
ci:
	@$(MAKE) -C $(DATA_PLANE_DIR) ci

## Run the native unit tests over the data plane (not part of `all`).
tests:
	@$(MAKE) -C $(DATA_PLANE_DIR) tests

## Run bpf_prog_test_run tests against the real marlin.bpf.o. Needs root (or
## CAP_BPF+CAP_NET_ADMIN+CAP_PERFMON); not part of `tests` or `all`.
packet-tests:
	@$(MAKE) -C $(DATA_PLANE_DIR) packet-tests

## Report verifier processed-instructions and per-subprogram stack depth for
## marlin.bpf.o (docs/design/05-budgets.md). Needs root (or CAP_BPF+CAP_SYS_ADMIN);
## not part of `tests`, `packet-tests` or `ci`.
verifier-stats:
	@$(MAKE) -C $(DATA_PLANE_DIR) verifier-stats

## Rewrite the data plane's .c/.h in place with clang-format (repo-root .clang-format).
format:
	@$(MAKE) -C $(DATA_PLANE_DIR) format

## Run clang-tidy over the data plane (repo-root .clang-tidy; builds its own compile database).
tidy:
	@$(MAKE) -C $(DATA_PLANE_DIR) tidy

## Remove data-plane build artefacts.
clean:
	@$(MAKE) -C $(DATA_PLANE_DIR) clean
	@$(MAKE) -C $(LOADER_DIR) clean

## List available targets.
help:
	@echo "Marlin top-level targets:"
	@echo "  all             Build everything"
	@echo "  data-plane      Build the eBPF/XDP data plane"
	@echo "  loader          Build the data-plane loader"
	@echo "  check-toolchain Verify the data-plane toolchain is present and correct"
	@echo "  ci              check-toolchain + a full build, the way CI runs it"
	@echo "  format          Rewrite data-plane C sources/headers with clang-format"
	@echo "  tidy            Run clang-tidy over the data-plane C sources"
	@echo "  clean           Remove data-plane build artefacts"
	@echo "  tests           Run the native unit tests over the data plane"
	@echo "  packet-tests    Run bpf_prog_test_run tests over marlin.bpf.o (needs root)"
	@echo "  verifier-stats  Report verifier insn/stack budgets for marlin.bpf.o (needs root)"
	@echo "  help            Show this message"
	@echo ""
	@echo "control-plane is not yet wired in here."
