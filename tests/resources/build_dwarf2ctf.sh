#!/bin/bash
# Copyright (c) 2024 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euxo pipefail

# Drop into a shell if something fails.
trap 'if [ $? -ne 0 ]; then exec bash -i; fi' EXIT

yum-config-manager --enable ol7_UEKR5
yum install -y \
	gcc \
	pkgconfig \
	elfutils{,-libelf}-devel \
	glib2-devel \
	libdtrace-ctf-devel \
	zlib-devel \
	wget

cd /tmp
wget https://github.com/oracle/linux-uek/raw/uek5/u5/scripts/dwarf2ctf/dwarf2ctf.c \
     https://github.com/oracle/linux-uek/raw/uek5/u5/scripts/eu_simple.{c,h}


CFLAGS="-I. `pkg-config --cflags glib-2.0`"
LDLIBS="-ldtrace-ctf -lelf -ldw `pkg-config --libs glib-2.0` -lz"

gcc $CFLAGS -o dwarf2ctf dwarf2ctf.c eu_simple.c $LDLIBS
gcc -g -o tmp /io/$1
mkdir output
./dwarf2ctf output -e <(echo tmp)
cp output/tmp.mod.ctf.new /io/$2
