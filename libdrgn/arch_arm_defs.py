# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

REGISTERS = [
    DrgnRegister(["r0", "a1"]),
    DrgnRegister(["r1", "a2"]),
    DrgnRegister(["r2", "a3"]),
    DrgnRegister(["r3", "a4"]),
    DrgnRegister(["r4", "v1"]),
    DrgnRegister(["r5", "v2"]),
    DrgnRegister(["r6", "v3"]),
    DrgnRegister(["r7", "v4"]),
    DrgnRegister(["r8", "v5"]),
    DrgnRegister(["r9", "v6", "sb"]),
    DrgnRegister(["r10", "v7", "sl"]),
    DrgnRegister(["r11", "v8", "fp"]),
    DrgnRegister(["r12", "ip"]),
    DrgnRegister(["r13", "sp"]),
    DrgnRegister(["r14", "lr"]),
    DrgnRegister(["r15", "pc"]),
]

REGISTER_LAYOUT = [
    DrgnRegisterLayout("r13", size=4, dwarf_number=13),
    DrgnRegisterLayout("r14", size=4, dwarf_number=14),
    # Callee-saved registers.
    *[DrgnRegisterLayout(f"r{i}", size=4, dwarf_number=i) for i in range(4, 12)],
    # Caller-saved registers.
    *[DrgnRegisterLayout(f"r{i}", size=4, dwarf_number=i) for i in range(4)],
    DrgnRegisterLayout("r12", size=4, dwarf_number=12),
    DrgnRegisterLayout("r15", size=4, dwarf_number=15),
    DrgnRegisterLayout("cpsr", size=4, dwarf_number=None),
]

STACK_POINTER_REGISTER = "r13"
