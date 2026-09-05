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

# docs/design/03-translation-units.md "Linking": each .c compiles separately;
# bpftool gen object links the objects, BTF included, into one marlin.bpf.o.
MARLIN_OBJ := $(BUILD_DIR)/marlin.bpf.o

.PHONY: all
all: $(MARLIN_OBJ)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	@echo "compile $(notdir $<)"
	@$(CLANG) -target bpf -mcpu=v3 -g -O2 $(INCLUDES) -c -o $@ $<

$(MARLIN_OBJ): $(OBJS)
	@echo "link $(notdir $@)"
	@$(BPFTOOL) gen object $@ $(OBJS)

.PHONY: ci
ci:
	$(MAKE) check-toolchain
	$(MAKE) all

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
