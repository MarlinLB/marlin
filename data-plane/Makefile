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

.DEFAULT_GOAL := all

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

.PHONY: all
all: $(OBJS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CLANG) -target bpf -mcpu=v3 -g -O2 -I$(INC_DIR) -c -o $@ $<

.PHONY: ci
ci:
	$(MAKE) check-toolchain
	$(MAKE) all

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
