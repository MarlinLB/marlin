# Marlin data-plane loader build

BUILD_DIR := build
BIN       := $(BUILD_DIR)/marlin-dataplane

HOST_CC      ?= clang
CFLAGS       ?= -std=gnu11 -g -O1 -Wall -Wextra -Werror -fno-omit-frame-pointer
LDLIBS       := -lbpf

.PHONY: all
all: $(BIN)

$(BIN): main.c
	@mkdir -p $(BUILD_DIR)
	@echo "compile $(notdir $<)"
	@$(HOST_CC) $(CFLAGS) -o $@ $< $(LDLIBS)

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
