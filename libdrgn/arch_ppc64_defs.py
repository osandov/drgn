# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

REGISTERS = [
    *[DrgnRegister(f"r{i}") for i in range(32)],
    DrgnRegister("lr"),
    *[DrgnRegister(f"cr{i}") for i in range(8)],
]

# There are two conflicting definitions of DWARF register numbers after 63. The
# original definition appears to be "64-bit PowerPC ELF Application Binary
# Interface Supplement" [1]. The GNU toolchain instead uses its own that was
# later codified in "Power Architecture 64-Bit ELF V2 ABI Specification" [2].
# We use the latter.
#
# 1: https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi.html
# 2: https://openpowerfoundation.org/specifications/64bitelfabi/
REGISTER_LAYOUT = [
    DrgnRegisterLayout("lr", size=8, dwarf_number=65),
    *[DrgnRegisterLayout(f"r{i}", size=8, dwarf_number=i) for i in range(32)],
    *[DrgnRegisterLayout(f"cr{i}", size=8, dwarf_number=68 + i) for i in range(8)],
]
