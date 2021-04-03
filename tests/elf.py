# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import enum


class ET(enum.IntEnum):
    NONE = 0
    REL = 1
    EXEC = 2
    DYN = 3
    CORE = 4


class PT(enum.IntEnum):
    NULL = 0
    LOAD = 1
    DYNAMIC = 2
    INTERP = 3
    NOTE = 4
    SHLIB = 5
    PHDR = 6
    TLS = 7


class SHT(enum.IntEnum):
    NULL = 0
    PROGBITS = 1
    SYMTAB = 2
    STRTAB = 3
    RELA = 4
    HASH = 5
    DYNAMIC = 6
    NOTE = 7
    NOBITS = 8
    REL = 9
    SHLIB = 10
    DYNSYM = 11
    INIT_ARRAY = 14
    FINI_ARRAY = 15
    PREINIT_ARRAY = 16
    GROUP = 17
    SYMTAB_SHNDX = 18
