# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

REGISTERS = [
    DrgnRegister("rax"),
    DrgnRegister("rdx"),
    DrgnRegister("rcx"),
    DrgnRegister("rbx"),
    DrgnRegister("rsi"),
    DrgnRegister("rdi"),
    DrgnRegister("rbp"),
    DrgnRegister("rsp"),
    DrgnRegister("r8"),
    DrgnRegister("r9"),
    DrgnRegister("r10"),
    DrgnRegister("r11"),
    DrgnRegister("r12"),
    DrgnRegister("r13"),
    DrgnRegister("r14"),
    DrgnRegister("r15"),
    DrgnRegister("rip"),
    DrgnRegister("rflags"),
    DrgnRegister("es"),
    DrgnRegister("cs"),
    DrgnRegister("ss"),
    DrgnRegister("ds"),
    DrgnRegister("fs"),
    DrgnRegister("gs"),
    DrgnRegister("fs.base"),
    DrgnRegister("gs.base"),
]

REGISTER_LAYOUT = [
    # The psABI calls this the return address (RA) register.
    DrgnRegisterLayout("rip", size=8, dwarf_number=16),
    DrgnRegisterLayout("rsp", size=8, dwarf_number=7),
    # General-purpose registers in the same order as struct pt_regs (which has
    # callee-saved registers first).
    DrgnRegisterLayout("r15", size=8, dwarf_number=15),
    DrgnRegisterLayout("r14", size=8, dwarf_number=14),
    DrgnRegisterLayout("r13", size=8, dwarf_number=13),
    DrgnRegisterLayout("r12", size=8, dwarf_number=12),
    DrgnRegisterLayout("rbp", size=8, dwarf_number=6),
    DrgnRegisterLayout("rbx", size=8, dwarf_number=3),
    DrgnRegisterLayout("r11", size=8, dwarf_number=11),
    DrgnRegisterLayout("r10", size=8, dwarf_number=10),
    DrgnRegisterLayout("r9", size=8, dwarf_number=9),
    DrgnRegisterLayout("r8", size=8, dwarf_number=8),
    DrgnRegisterLayout("rax", size=8, dwarf_number=0),
    DrgnRegisterLayout("rcx", size=8, dwarf_number=2),
    DrgnRegisterLayout("rdx", size=8, dwarf_number=1),
    DrgnRegisterLayout("rsi", size=8, dwarf_number=4),
    DrgnRegisterLayout("rdi", size=8, dwarf_number=5),
    # Segment and flags registers in the same order as struct user_regs_struct
    # (except for orig_rax, rip, and rsp).
    # orig_rax and rip are here in struct user_regs_struct.
    DrgnRegisterLayout("cs", size=8, dwarf_number=51),
    DrgnRegisterLayout("rflags", size=8, dwarf_number=49),
    # rsp is here in struct user_regs_struct.
    DrgnRegisterLayout("ss", size=8, dwarf_number=52),
    DrgnRegisterLayout("fs_base", size=8, dwarf_number=58),
    DrgnRegisterLayout("gs_base", size=8, dwarf_number=59),
    DrgnRegisterLayout("ds", size=8, dwarf_number=53),
    DrgnRegisterLayout("es", size=8, dwarf_number=50),
    DrgnRegisterLayout("fs", size=8, dwarf_number=54),
    DrgnRegisterLayout("gs", size=8, dwarf_number=55),
]

STACK_POINTER_REGISTER = "rsp"
