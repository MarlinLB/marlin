#
# Marlin — root build
#

DATA_PLANE_DIR := data-plane

# Recursive $(MAKE) -C calls below would otherwise print "Entering/Leaving
# directory" around every sub-make; propagates to the child via MAKEFLAGS.
MAKEFLAGS += --no-print-directory

.DEFAULT_GOAL := all

.PHONY: all data-plane check-toolchain ci format tidy clean help

all: data-plane

## Build the eBPF/XDP data plane (data-plane/Makefile's default target).
data-plane:
	@$(MAKE) -C $(DATA_PLANE_DIR) all

## Verify the data-plane toolchain (clang, bpftool, clang-format, clang-tidy versions).
check-toolchain:
	@$(MAKE) -C $(DATA_PLANE_DIR) check-toolchain

## Run what CI runs: check-toolchain (strict) followed by a full build.
ci:
	@$(MAKE) -C $(DATA_PLANE_DIR) ci

## Rewrite the data plane's .c/.h in place with clang-format (repo-root .clang-format).
format:
	@$(MAKE) -C $(DATA_PLANE_DIR) format

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
	@echo "  data-plane      Build the eBPF/XDP data plane"
	@echo "  check-toolchain Verify the data-plane toolchain is present and correct"
	@echo "  ci              check-toolchain + a full build, the way CI runs it"
	@echo "  format          Rewrite data-plane C sources/headers with clang-format"
	@echo "  tidy            Run clang-tidy over the data-plane C sources"
	@echo "  clean           Remove data-plane build artefacts"
	@echo "  help            Show this message"
	@echo ""
	@echo "control-plane and tests are not yet wired in here (no control-plane tree or test"
	@echo "harness exists yet per docs/PHASES.md Phase 1's entry state)."
