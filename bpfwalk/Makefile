# SPDX-License-Identifier: LGPL-2.1-or-later
#
# bpfwalk - in-kernel traversal offload for drgn helpers.
#
# Build flow:
#   bpf/<x>.bpf.c --clang--> build/<x>.bpf.o        (loaded generically at runtime)
#   src/bpfwalk.c --cc----> build/libbpfwalk.so     (the cursor API for bindings)
# The .bpf.o objects sit beside the .so; the library finds them via dladdr().

CLANG      ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL    ?= bpftool
CC         ?= gcc

# BTF source used to generate the vmlinux.h that the BPF walkers compile
# against. CO-RE relocates onto other kernels at load, so building against the
# local kernel's BTF is fine. Point at a vmlinux ELF to build offline.
BTF_SRC ?= /sys/kernel/btf/vmlinux

INCLUDE := include
SRCDIR  := src
BPFDIR  := bpf
BUILD   := build

ARCH := $(shell uname -m | sed \
	-e 's/x86_64/x86/' -e 's/aarch64/arm64/' -e 's/armv7l/arm/' \
	-e 's/ppc64le/powerpc/' -e 's/mips.*/mips/' -e 's/s390x/s390/')

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS   := $(shell pkg-config --libs   libbpf 2>/dev/null || echo -lbpf)

BPF_SRCS := $(wildcard $(BPFDIR)/*.bpf.c)
BPF_OBJS := $(BPF_SRCS:$(BPFDIR)/%.bpf.c=$(BUILD)/%.bpf.o)

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
	      -I$(BUILD) -I$(INCLUDE) -Wno-unknown-attributes $(LIBBPF_CFLAGS)
LIB_CFLAGS := -g -O2 -Wall -Wextra -fPIC -D_GNU_SOURCE \
	      -I$(INCLUDE) $(LIBBPF_CFLAGS)

.PHONY: all
all: $(BUILD)/libbpfwalk.so $(BPF_OBJS)

# vmlinux.h from BTF (kept out of the tree; regenerated as needed).
$(BUILD)/vmlinux.h: | $(BUILD)
	$(BPFTOOL) btf dump file $(BTF_SRC) format c > $@

# BPF object: compile, then strip DWARF but keep BTF (needed for CO-RE).
$(BUILD)/%.bpf.o: $(BPFDIR)/%.bpf.c $(BUILD)/vmlinux.h | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

$(BUILD)/libbpfwalk.so: $(SRCDIR)/bpfwalk.c $(INCLUDE)/bpfwalk.h \
			$(INCLUDE)/bpfwalk_abi.h | $(BUILD)
	$(CC) $(LIB_CFLAGS) -shared $(SRCDIR)/bpfwalk.c -o $@ \
		$(LIBBPF_LIBS) -lelf -lz -ldl

$(BUILD):
	mkdir -p $@

.PHONY: clean
clean:
	rm -rf $(BUILD)
