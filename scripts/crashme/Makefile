# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

# Makefile used to generate tests/resources/crashme*

.PHONY: all cores clean

.DELETE_ON_ERROR:

EXECUTABLES := crashme crashme_pie crashme_static crashme_static_pie
CORES := $(addsuffix .core, $(EXECUTABLES)) $(addsuffix _no_headers.core, $(EXECUTABLES))
BINARIES := crashme.so $(EXECUTABLES) crashme.dwz crashme.so.dwz crashme.alt
ZSTD_BINARIES := $(addsuffix .zst, $(BINARIES))
ZSTD_CORES := $(addsuffix .zst, $(CORES))

all: $(BINARIES) cores $(ZSTD_BINARIES) $(ZSTD_CORES)

clean:
	rm -f $(BINARIES) $(CORES) $(ZSTD_BINARIES) $(ZSTD_CORES)

crashme.so: crashme.c common.c
	gcc -g -Os -fpic -shared $^ -o $@

crashme: main.c common.c crashme.so
	gcc -g -Os -fno-pie -no-pie $(filter-out crashme.so,$^) -o $@ -L . -l:crashme.so -Wl,-rpath,$(CURDIR)

crashme_pie: main.c common.c crashme.so
	gcc -g -Os -fpie -pie $(filter-out crashme.so,$^) -o $@ -L . -l:crashme.so -Wl,-rpath,$(CURDIR)

crashme_static: main.c common.c crashme.c
	musl-gcc -g -Os -fno-pie -static $^ -o $@

crashme_static_pie: main.c common.c crashme.c
	musl-gcc -g -Os -fpie -static-pie $^ -o $@

crashme.dwz crashme.so.dwz crashme.alt &: crashme crashme.so
	cp crashme crashme.dwz
	cp crashme.so crashme.so.dwz
	dwz -m crashme.alt -r crashme.dwz crashme.so.dwz

cores: $(CORES)

.NOTPARALLEL: cores

define CORE_COMMAND
flock /proc/sys/kernel/core_pattern sh -e -c '\
ulimit -c unlimited; \
echo "$$COREDUMP_FILTER" > /proc/$$$$/coredump_filter; \
old_pattern=$$(cat /proc/sys/kernel/core_pattern); \
restore_core_pattern() { \
	echo "$$old_pattern" > /proc/sys/kernel/core_pattern; \
}; \
trap restore_core_pattern EXIT; \
echo "$$PWD/core.%p" > /proc/sys/kernel/core_pattern; \
su "$$SUDO_USER" -c "env -i sh -l -c \"exec ./$<\" & wait; mv core.\$$! $@"'
endef

%.core: %
	sudo env COREDUMP_FILTER=0x33 $(CORE_COMMAND)

%_no_headers.core: %
	sudo env COREDUMP_FILTER=0x23 $(CORE_COMMAND)

%.zst: %
	zstd -19 $< -o $@
