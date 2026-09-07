# Marlin data-plane build

SRC_DIR   := src
INC_DIR   := include
BUILD_DIR := build
TEST_DIR  := tests

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

include mk/toolchain.mk

.DEFAULT_GOAL := all

MULTIARCH_TRIPLET := $(shell dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null \
	|| gcc -print-multiarch 2>/dev/null \
	|| echo "$$(uname -m)-linux-gnu")

INCLUDES := -I$(INC_DIR)
ifneq ($(MULTIARCH_TRIPLET),)
MULTIARCH_INC := /usr/include/$(MULTIARCH_TRIPLET)
ifneq ($(wildcard $(MULTIARCH_INC)),)
INCLUDES += -I$(MULTIARCH_INC)
else
$(warning data-plane/Makefile: no directory at $(MULTIARCH_INC) -- pass MULTIARCH_TRIPLET=<dir under /usr/include> explicitly if <asm/types.h> fails to resolve)
endif
endif

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

# Recursive: include/marlin/ already nests (abi/types.h) and gains more
# subdirectories (limits.h, enums.h) as more lands.
HDRS := $(shell find $(INC_DIR) -name '*.h')

# Each .c compiles separately; bpftool gen object links them, BTF included,
# into one marlin.bpf.o.
MARLIN_OBJ := $(BUILD_DIR)/marlin.bpf.o

# clang-tidy is inert without a compile database, built by concatenating each
# TU's -MJ fragment into a JSON array (trailing comma stripped from the last).
CC_JSON := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o.json,$(SRCS))
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
all: $(MARLIN_OBJ)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	@echo "compile $(notdir $<)"
	@$(CLANG) -target bpf -mcpu=v3 -g -O2 -Wall -Wextra $(INCLUDES) -MJ $(BUILD_DIR)/$*.o.json -c -o $@ $<

$(MARLIN_OBJ): $(OBJS)
	@echo "link $(notdir $@)"
	@$(BPFTOOL) gen object $@ $(OBJS)

$(COMPILE_COMMANDS): $(OBJS)
	@echo "generate $(notdir $@)"
	@{ echo '['; cat $(CC_JSON) | sed '$$s/,$$//'; echo ']'; } > $@

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
	@$(CLANG_FORMAT) -i --style=file:$(MARLIN_REPO_ROOT)/.clang-format $(SRCS) $(HDRS)

.PHONY: tidy
tidy:
	@$(MAKE) $(COMPILE_COMMANDS)
	@$(CLANG_TIDY) --config-file=$(MARLIN_REPO_ROOT)/.clang-tidy -p $(BUILD_DIR) $(SRCS)

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
