# Marlin data-plane build: the XDP datapath object and the marlind loader
# that attaches it, one host toolchain shared by both.

SRC_DIR   := bpf
INC_DIR   := include
BUILD_DIR := build
TEST_DIR  := tests
TOOLS_DIR := tools

# --- Overridable tools --------------------------------------------------------
# CI pins versions; check-toolchain's tests inject stubs through these vars.
CLANG        ?= clang
BPFTOOL      ?= bpftool
READELF      ?=
CLANG_FORMAT ?= clang-format
CLANG_TIDY   ?= clang-tidy

# Host code, not BPF: defaults separately from CLANG so a cross-compiling
# CI job can still run tests natively.
HOST_CC       ?= $(CLANG)
# parser.c overlays wire structs unaligned by construction (kernel does the
# same); only UBSan's alignment check is disabled, ASan/UBSan stay on.
TEST_SANITIZE ?= -fsanitize=address,undefined -fno-sanitize=alignment
TEST_CFLAGS   ?= -std=gnu11 -g -O1 -Wall -Wextra -Werror -fno-omit-frame-pointer

# The shipped loader binary. Deliberately not derived from TEST_CFLAGS: tests
# carry sanitizers, this artefact must not.
HOST_CFLAGS ?= -std=gnu11 -O2 -Wall -Wextra -Werror -fno-omit-frame-pointer

# MARLIN_DEBUG=1 compiles in main.c's per-packet bpf_printk trace, read from
# trace_pipe by the dev rigs' `trace` subcommand. Not tracked as a dependency:
# toggling it needs `make clean` to take effect.
BPF_CFLAGS ?= -target bpf -mcpu=v3 -g -O2 -Wall -Wextra
ifeq ($(MARLIN_DEBUG),1)
BPF_CFLAGS += -DMARLIN_DEBUG
endif

include mk/toolchain.mk

.DEFAULT_GOAL := all

MULTIARCH_TRIPLET := $(shell dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null \
	|| gcc -print-multiarch 2>/dev/null \
	|| echo "$$(uname -m)-linux-gnu")

INCLUDES := -I$(INC_DIR) -I$(BUILD_DIR)/include
ifneq ($(MULTIARCH_TRIPLET),)
MULTIARCH_INC := /usr/include/$(MULTIARCH_TRIPLET)
ifneq ($(wildcard $(MULTIARCH_INC)),)
INCLUDES += -I$(MULTIARCH_INC)
else
$(warning data-plane/Makefile: no directory at $(MULTIARCH_INC) -- pass MULTIARCH_TRIPLET=<dir under /usr/include> explicitly if <asm/types.h> fails to resolve)
endif
endif

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/bpf/%.o,$(SRCS))

# Recursive: include/marlin/ already nests (abi/types.h) and gains more
# subdirectories (limits.h, enums.h) as more lands.
HDRS := $(shell find $(INC_DIR) -name '*.h')

# Each .c compiles separately; bpftool gen object links them, BTF included,
# into one marlin.bpf.o. Own build subdirectory, same as marlind/ and tools/ below.
MARLIN_OBJ := $(BUILD_DIR)/bpf/marlin.bpf.o

# marlind: the host-compiled loader that attaches marlin.bpf.o. Shares this
# makefile because it shares the host toolchain (clang, clang-format,
# clang-tidy) and the -lbpf link, not because it is BPF.
MARLIND_DIR  := marlind
MARLIND_SRCS := $(wildcard $(MARLIND_DIR)/*.c)
MARLIND_OBJS := $(patsubst $(MARLIND_DIR)/%.c,$(BUILD_DIR)/marlind/%.o,$(MARLIND_SRCS))
MARLIND_BIN  := $(BUILD_DIR)/marlind/marlind
MARLIND_LIBS := -lbpf

# marlin.bpf.o and marlind version independently (bpf/CHANGELOG.md,
# marlind/CHANGELOG.md): the loader and the datapath object are separate
# artefacts with separate release cadences. The oldest marlin.bpf.o a given
# marlind will attach is a hand-maintained literal in
# include/marlind/compat.h, not a generated file: it is a compatibility
# claim about other builds, not a fact about this one. verifier_stats
# versions itself in tools/verifier_stats.c and reads neither.
BPF_VERSION_FILE     := $(SRC_DIR)/VERSION
BPF_VERSION_H        := $(BUILD_DIR)/include/marlin/version.h
MARLIND_VERSION_FILE := $(MARLIND_DIR)/VERSION
MARLIND_VERSION_H    := $(BUILD_DIR)/include/marlind/version.h

# Host-compiled diagnostic utilities (verifier_stats.c and friends); see the
# comment above the verifier-stats target below for why they run offline.
TOOL_SRCS := $(wildcard $(TOOLS_DIR)/*.c)
TOOL_OBJS := $(patsubst $(TOOLS_DIR)/%.c,$(BUILD_DIR)/tools/%.o,$(TOOL_SRCS))
TOOL_BINS := $(patsubst $(TOOLS_DIR)/%.c,$(BUILD_DIR)/tools/%,$(TOOL_SRCS))
VERIFIER_STATS_BIN := $(BUILD_DIR)/tools/verifier_stats

# clang-tidy is inert without a compile database, built by concatenating each
# TU's -MJ fragment into a JSON array (trailing comma stripped from the last).
CC_JSON := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/bpf/%.o.json,$(SRCS)) \
	$(patsubst $(MARLIND_DIR)/%.c,$(BUILD_DIR)/marlind/%.o.json,$(MARLIND_SRCS)) \
	$(patsubst $(TOOLS_DIR)/%.c,$(BUILD_DIR)/tools/%.o.json,$(TOOL_SRCS))
COMPILE_COMMANDS := $(BUILD_DIR)/compile_commands.json

# Native unit tests over parser.c. Deliberately not part of $(SRCS): that
# wildcard compiles -target bpf; these are host binaries #include-ing the source.
TEST_SRCS := $(wildcard $(TEST_DIR)/*.c)
TEST_HDRS := $(wildcard $(TEST_DIR)/*.h) $(wildcard $(TEST_DIR)/stubs/*.h) $(wildcard $(TEST_DIR)/stubs/bpf/*.h)
TEST_OBJS := $(patsubst $(TEST_DIR)/%.c,$(BUILD_DIR)/tests/%.o,$(TEST_SRCS))

# One binary per test .c: harness.h's case registry is file-static per TU by
# design, and each test file defines its own main().
TEST_BINS := $(patsubst $(TEST_DIR)/%.c,$(BUILD_DIR)/tests/%,$(TEST_SRCS))

# tests/stubs shadows <bpf/bpf_helpers.h> (whose real version declares each
# helper as a function pointer, unusable natively); packet tier needs the real headers.
TEST_INCLUDES := -I$(TEST_DIR)/stubs $(INCLUDES)

# bpf_prog_test_run tests over the real marlin.bpf.o. Needs root (or
# CAP_BPF+CAP_NET_ADMIN+CAP_PERFMON) to load a program, so kept separate from `tests`.
PACKET_TEST_DIR  := $(TEST_DIR)/packet
PACKET_TEST_SRCS := $(wildcard $(PACKET_TEST_DIR)/*.c)
PACKET_TEST_HDRS := $(wildcard $(PACKET_TEST_DIR)/*.h)
PACKET_TEST_OBJS := $(patsubst $(PACKET_TEST_DIR)/%.c,$(BUILD_DIR)/tests/packet/%.o,$(PACKET_TEST_SRCS))
PACKET_TEST_BIN  := $(BUILD_DIR)/tests/packet/marlin_packet_tests
PACKET_TEST_LIBS := -lbpf

.PHONY: all
all: bpf marlind tools

.PHONY: bpf
bpf: $(MARLIN_OBJ)

.PHONY: version
version:
	@printf 'marlin.bpf.o  %s\n' "$$(cat $(BPF_VERSION_FILE))"
	@printf 'marlind       %s\n' "$$(cat $(MARLIND_VERSION_FILE))"

# Regenerated whenever the source VERSION changes; cmp -s || mv leaves the
# file (and its mtime) alone otherwise, so an unchanged version does not
# force a rebuild -- see docs/PHASES.md's decision on why these are
# checked-in files, not `git describe`. Each header is a prerequisite of
# its own %.o pattern rule only below, not the other's, so bumping one
# version does not rebuild the other artefact. A direct prerequisite
# rather than relying solely on -MMD because the header must already
# exist the first time either rule runs.
$(BPF_VERSION_H): $(BPF_VERSION_FILE)
	@mkdir -p $(dir $@)
	@{ \
		echo '#pragma once'; \
		printf '#define MARLIN_BPF_VERSION "%s"\n' "$$(cat $<)"; \
	} > $@.tmp
	@cmp -s $@.tmp $@ 2>/dev/null && rm -f $@.tmp || mv $@.tmp $@

$(MARLIND_VERSION_H): $(MARLIND_VERSION_FILE)
	@mkdir -p $(dir $@)
	@{ \
		echo '#pragma once'; \
		echo '#if defined(__bpf__)'; \
		echo '#error "include/marlind/ is host-only; do not include it from BPF sources"'; \
		echo '#endif'; \
		printf '#define MARLIND_VERSION "%s"\n' "$$(cat $<)"; \
	} > $@.tmp
	@cmp -s $@.tmp $@ 2>/dev/null && rm -f $@.tmp || mv $@.tmp $@

# -MMD/-MP plus the -include below give the bpf side real header tracking:
# previously this rule tracked no header at all (bpftool gen object has no
# equivalent of a .d file), so editing e.g. include/marlin/acl.h silently
# left a stale build/bpf/*.o in place. $(BPF_VERSION_H) stays a direct
# prerequisite too, for the first build, before any .d exists.
$(BUILD_DIR)/bpf/%.o: $(SRC_DIR)/%.c $(BPF_VERSION_H)
	@mkdir -p $(BUILD_DIR)/bpf
	@echo "compile $(notdir $<)"
	@$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -MJ $(BUILD_DIR)/bpf/$*.o.json -MMD -MP -c -o $@ $<

-include $(OBJS:.o=.d)

$(MARLIN_OBJ): $(OBJS)
	@echo "linking $(notdir $@)"
	@$(BPFTOOL) gen object $@ $(OBJS)

$(COMPILE_COMMANDS): $(OBJS) $(MARLIND_OBJS) $(TOOL_OBJS)
	@echo "generate $(notdir $@)"
	@{ echo '['; cat $(CC_JSON) | sed '$$s/,$$//'; echo ']'; } > $@

# Host compile, not -target bpf: main.c needs libbpf's syscall wrappers and
# system headers, neither of which the bpf target's include search covers.
$(BUILD_DIR)/marlind/%.o: $(MARLIND_DIR)/%.c $(MARLIND_VERSION_H)
	@mkdir -p $(BUILD_DIR)/marlind
	@echo "compile $(notdir $<)"
	@$(HOST_CC) $(HOST_CFLAGS) -I$(INC_DIR) -I$(BUILD_DIR)/include -MJ $(BUILD_DIR)/marlind/$*.o.json -MMD -MP -c -o $@ $<

$(MARLIND_BIN): $(MARLIND_OBJS)
	@echo "linking $(notdir $@)"
	@$(HOST_CC) $(HOST_CFLAGS) -o $@ $(MARLIND_OBJS) $(MARLIND_LIBS)

-include $(MARLIND_OBJS:.o=.d)

.PHONY: marlind
marlind: $(MARLIND_BIN)

# Depends on every header/source since a pattern rule can't name which one a
# test #includes; -MMD narrows this from the second build onward.
$(BUILD_DIR)/tests/%.o: $(TEST_DIR)/%.c $(TEST_HDRS) $(SRCS) $(HDRS)
	@mkdir -p $(BUILD_DIR)/tests
	@echo "compile $(notdir $<)"
	@$(HOST_CC) $(TEST_CFLAGS) $(TEST_SANITIZE) $(TEST_INCLUDES) -MMD -MP -c -o $@ $<

$(BUILD_DIR)/tests/%: $(BUILD_DIR)/tests/%.o
	@echo "linking $(notdir $@)"
	@$(HOST_CC) $(TEST_CFLAGS) $(TEST_SANITIZE) -o $@ $<

# Without this the .o files above are chained intermediates: make would
# delete each one -- and stop regenerating its .d -- after every link.
.SECONDARY: $(TEST_OBJS)

.PHONY: tests
tests: $(TEST_BINS)
	@fail=0; for t in $(TEST_BINS); do \
		echo "run $$(basename $$t)"; \
		$$t || fail=1; \
	done; \
	exit $$fail

-include $(TEST_OBJS:.o=.d)

# Links against libbpf and loads marlin.bpf.o rather than #include-ing
# parser.c. TEST_SANITIZE is left off: LeakSanitizer flags libbpf's own allocations.
$(BUILD_DIR)/tests/packet/%.o: $(PACKET_TEST_DIR)/%.c $(PACKET_TEST_HDRS) $(TEST_HDRS) $(HDRS)
	@mkdir -p $(BUILD_DIR)/tests/packet
	@echo "compile $(notdir $<)"
	@$(HOST_CC) $(TEST_CFLAGS) $(INCLUDES) -MMD -MP -c -o $@ $<

$(PACKET_TEST_BIN): $(PACKET_TEST_OBJS)
	@echo "linking $(notdir $@)"
	@$(HOST_CC) $(TEST_CFLAGS) -o $@ $(PACKET_TEST_OBJS) $(PACKET_TEST_LIBS)

-include $(PACKET_TEST_OBJS:.o=.d)

# Needs root (or CAP_BPF+CAP_NET_ADMIN+CAP_PERFMON) to load an XDP program;
# not a `tests` prerequisite for that reason.
.PHONY: packet-tests
packet-tests: $(MARLIN_OBJ) $(PACKET_TEST_BIN)
	@$(PACKET_TEST_BIN) $(MARLIN_OBJ)

# Verifier processed-instructions and worst combined stack depth
# (docs/design/05-budgets.md). tools/verifier_stats.c loads marlin.bpf.o
# via libbpf directly and pins nothing: bpftool prog load/loadall's pin step
# needs bpffs write access, which this host's LSM policy denies even under
# root (confirmed: mkdir, and even mktemp -u's stat, both EPERM on
# /sys/fs/bpf here) -- an unrelated bpf-type mount already visible in
# /proc/mounts suggests an EDR agent hooking bpffs writes for its own
# self-protection. Needs root (or CAP_BPF+CAP_SYS_ADMIN) regardless, to load
# the program at all; not a `tests`/`ci` prerequisite for that reason, same
# as packet-tests. verifier_stats.c parses the kernel's own log and prints a
# labelled report instead of relaying it raw -- the kernel's "stack depth"
# line lists one figure per function, not a chain to sum, and reads exactly
# like one if left as-is.
$(BUILD_DIR)/tools/%.o: $(TOOLS_DIR)/%.c
	@mkdir -p $(BUILD_DIR)/tools
	@echo "compile $(notdir $<)"
	@$(HOST_CC) $(HOST_CFLAGS) -I$(INC_DIR) -MJ $(BUILD_DIR)/tools/$*.o.json -MMD -MP -c -o $@ $<

$(BUILD_DIR)/tools/%: $(BUILD_DIR)/tools/%.o
	@echo "linking $(notdir $@)"
	@$(HOST_CC) $(HOST_CFLAGS) -o $@ $< -lbpf -lelf

-include $(TOOL_OBJS:.o=.d)

# Without this the .o files above are chained intermediates: make would
# delete each one -- and stop regenerating its .d -- after every link.
.SECONDARY: $(TOOL_OBJS)

.PHONY: tools
tools: $(TOOL_BINS)

.PHONY: verifier-stats
verifier-stats: $(MARLIN_OBJ) $(VERIFIER_STATS_BIN)
	@$(VERIFIER_STATS_BIN) $(MARLIN_OBJ)

.PHONY: ci
ci:
	$(MAKE) check-toolchain
	$(MAKE) all
	$(MAKE) tests
	@if [ "$$(id -u)" = "0" ]; then \
		$(MAKE) packet-tests; \
	else \
		echo "skip packet-tests: needs root (or CAP_BPF+CAP_NET_ADMIN+CAP_PERFMON) to load an XDP program -- run 'sudo make packet-tests' directly"; \
	fi

# Invoked as a recursive $(MAKE), not a prerequisite: only a literal, separate
# check-toolchain invocation makes Group B (format/tidy) fatal here.

.PHONY: format
format:
	$(MAKE) check-toolchain
	@$(CLANG_FORMAT) -i --style=file:$(MARLIN_REPO_ROOT)/.clang-format $(SRCS) $(HDRS) $(MARLIND_SRCS)

# Not one invocation over $(SRCS) $(MARLIND_SRCS): clang-tidy sharing one
# process across a -target bpf TU and a host TU corrupts clang-analyzer-valist's
# state, producing "uninitialized va_list" false positives in the host TU that
# do not reproduce when either file set is checked alone. The same corruption
# also appears *within* $(MARLIND_SRCS) once it holds more than one host TU
# that touches a va_list (log.c's logmsg()/die()/notify(), checked alongside
# config.c and main.c) -- so each marlind file gets its own process too.
.PHONY: tidy
tidy:
	@$(MAKE) $(COMPILE_COMMANDS)
	@$(CLANG_TIDY) --config-file=$(MARLIN_REPO_ROOT)/.clang-tidy -p $(BUILD_DIR) $(SRCS)
	@for f in $(MARLIND_SRCS); do \
		$(CLANG_TIDY) --config-file=$(MARLIN_REPO_ROOT)/.clang-tidy -p $(BUILD_DIR) $$f || exit 1; \
	done

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
