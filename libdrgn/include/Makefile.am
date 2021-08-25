# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

# "Install" the elfutils headers to the build directory.

BUILT_SOURCES = elfutils/elf-knowledge.h \
		elfutils/libasm.h \
		elfutils/libdw.h \
		elfutils/libdwelf.h \
		elfutils/libdwfl.h \
		elfutils/version.h \
		gelf.h \
		libelf.h \
		nlist.h

elfutils/elf-knowledge.h: ../velfutils/libelf/elf-knowledge.h
elfutils/libasm.h: ../velfutils/libasm/libasm.h
elfutils/libdw.h: ../velfutils/libdw/libdw.h
elfutils/libdwelf.h: ../velfutils/libdwelf/libdwelf.h
elfutils/libdwfl.h: ../velfutils/libdwfl/libdwfl.h
elfutils/version.h: ../velfutils/version.h
gelf.h: ../velfutils/libelf/gelf.h
libelf.h: ../velfutils/libelf/libelf.h
nlist.h: ../velfutils/libelf/nlist.h

AM_V_CP = $(am__v_CP_@AM_V@)
am__v_CP_ = $(am__v_CP_@AM_DEFAULT_V@)
am__v_CP_0 = @echo "  CP      " $@;
am__v_CP_1 =

$(BUILT_SOURCES):
	$(AM_V_at)mkdir -p $$(dirname $@)
	$(AM_V_CP)cp $< $@
