#
# Marlin — root build
#

DATA_PLANE_DIR := data-plane

# Recursive $(MAKE) -C calls below would otherwise print "Entering/Leaving
# directory" around every sub-make; propagates to the child via MAKEFLAGS.
MAKEFLAGS += --no-print-directory

.DEFAULT_GOAL := all

.PHONY: all data-plane bpf marlind version check-toolchain ci format format-check tidy clean tests packet-tests verifier-stats tools help

all: data-plane

## Build everything under data-plane/: marlin.bpf.o and marlind (data-plane/Makefile's `all`).
data-plane:
	@$(MAKE) -C $(DATA_PLANE_DIR) all

## Build only the eBPF/XDP datapath object (data-plane/Makefile's `bpf`).
bpf:
	@$(MAKE) -C $(DATA_PLANE_DIR) bpf

## Build only the data-plane loader (data-plane/Makefile's `marlind`).
marlind:
	@$(MAKE) -C $(DATA_PLANE_DIR) marlind

## Print marlin.bpf.o's and marlind's versions (data-plane/bpf/VERSION, data-plane/marlind/VERSION).
version:
	@$(MAKE) -C $(DATA_PLANE_DIR) version

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

## Build every dev tool under data-plane/tools/ (data-plane/Makefile's `tools`).
tools:
	@$(MAKE) -C $(DATA_PLANE_DIR) tools

## Rewrite the data plane's .c/.h in place with clang-format (repo-root .clang-format).
format:
	@$(MAKE) -C $(DATA_PLANE_DIR) format

## Check the data plane's .c/.h formatting without rewriting (clang-format --dry-run -Werror).
format-check:
	@$(MAKE) -C $(DATA_PLANE_DIR) format-check

## Run clang-tidy over the data plane (repo-root .clang-tidy; builds its own compile database).
tidy:
	@$(MAKE) -C $(DATA_PLANE_DIR) tidy

## Remove data-plane build artefacts.
clean:
	@$(MAKE) -C $(DATA_PLANE_DIR) clean

## List available targets.
help:
	@echo "Marlin top-level targets:"
	@echo "  all             Build everything"
	@echo "  data-plane      Build everything under data-plane/ (marlin.bpf.o and marlind)"
	@echo "  bpf             Build only the eBPF/XDP datapath object"
	@echo "  marlind         Build only the data-plane loader"
	@echo "  version         Print marlin.bpf.o's and marlind's versions"
	@echo "  check-toolchain Verify the data-plane toolchain is present and correct"
	@echo "  ci              check-toolchain + a full build, the way CI runs it"
	@echo "  format          Rewrite data-plane C sources/headers with clang-format"
	@echo "  format-check    Check data-plane C sources/headers are clang-format clean (no rewrite)"
	@echo "  tidy            Run clang-tidy over the data-plane C sources"
	@echo "  clean           Remove data-plane build artefacts"
	@echo "  tests           Run the native unit tests over the data plane"
	@echo "  packet-tests    Run bpf_prog_test_run tests over marlin.bpf.o (needs root)"
	@echo "  verifier-stats  Report verifier insn/stack budgets for marlin.bpf.o (needs root)"
	@echo "  tools           Build every dev tool under data-plane/tools/"
	@echo "  help            Show this message"
	@echo ""
	@echo "control-plane is not yet wired in here."
