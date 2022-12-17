# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

REGISTERS = [
    *[DrgnRegister(f"r{i}") for i in range(16)],
    *[DrgnRegister(f"a{i}") for i in range(16)],
    DrgnRegister("pswm"),
    DrgnRegister("pswa"),
]

REGISTER_LAYOUT = [
    # Callee-saved registers and return address (r14).
    *[DrgnRegisterLayout(f"r{i}", size=8, dwarf_number=i) for i in range(6, 16)],
    # Caller-saved registers.
    *[DrgnRegisterLayout(f"r{i}", size=8, dwarf_number=i) for i in range(6)],
    # These are typically only used for interrupted frames.
    DrgnRegisterLayout("pswm", size=8, dwarf_number=64),
    DrgnRegisterLayout("pswa", size=8, dwarf_number=65),
    # Access control registers (ACRs) are only used in userspace,
    # and not present in struct pt_regs.
    *[DrgnRegisterLayout(f"a{i}", size=4, dwarf_number=48 + i) for i in range(16)],
]

STACK_POINTER_REGISTER = "r15"
