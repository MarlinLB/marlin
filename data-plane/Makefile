# Marlin data-plane build

SRC_DIR   := src
INC_DIR   := include
BUILD_DIR := build

# --- Overridable tools --------------------------------------------------------
# CI pins versions here; check-toolchain's own tests inject stubs through
# these same variables (see data-plane/mk/toolchain.mk).
CLANG        ?= clang
BPFTOOL      ?= bpftool
READELF      ?=
CLANG_FORMAT ?= clang-format
CLANG_TIDY   ?= clang-tidy

include mk/toolchain.mk

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

.PHONY: all
all: $(OBJS)

# check-toolchain is an order-only prerequisite (the "|"): it gates whether
# the recipe below is allowed to run at all, but touching it never makes an
# object stale, which matches "no cache, no stamp file" -- the gate itself
# has no output to be stale.
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | check-toolchain
	@mkdir -p $(BUILD_DIR)
	$(CLANG) -target bpf -mcpu=v3 -g -O2 -I$(INC_DIR) -c -o $@ $<

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
