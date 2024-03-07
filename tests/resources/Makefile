# Copyright (c) 2024 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

# Builds test resources for the CTF tests. Please note that due to the logic in
# drgn.tests.resources, the test framework will regenerate the compressed files
# whenever they are out-of-date compared to the decompressed files, and the
# makefile will do the reverse.

TARGETS := test.zst core.zst test.ctf.zst test.dwarf2ctf.zst
DOCKER := podman
IMAGE := "container-registry.oracle.com/os/oraclelinux:7"

.PHONY: all
all: $(TARGETS)

.PHONY: clean
clean:
	rm -f $(TARGETS)

test: test.c
	gcc -g -o test test.c

core: test
	ulimit -c unlimited; ./test; coredumpctl dump >core
	touch core

test.ctf: test.c
	gcc -gctf -Wl,--ctf-variables -o test.ctf test.c

%.zst: %
	zstd --compress --quiet --force --stdout $< >$@

test.dwarf2ctf: test.c build_dwarf2ctf.sh
	$(DOCKER) run -it \
	    --volume "$(shell pwd)":/io \
	    --workdir /io \
	    --hostname drgn \
	    --rm \
	    --pull always \
	    $(IMAGE) \
	    /io/build_dwarf2ctf.sh test.c test.dwarf2ctf
