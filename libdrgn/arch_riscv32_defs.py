# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

REGISTERS = [
    DrgnRegister(["x0", "zero"]),
    DrgnRegister(["x1", "ra"]),
    DrgnRegister(["x2", "sp"]),
    DrgnRegister(["x3", "gp"]),
    DrgnRegister(["x4", "tp"]),
    *[DrgnRegister([f"x{i+5}", f"t{i}"]) for i in range(3)],
    DrgnRegister(["x8", "fp", "s0"]),
    DrgnRegister(["x9", "s1"]),
    *[DrgnRegister([f"x{i+10}", f"a{i}"]) for i in range(8)],
    *[DrgnRegister([f"x{i+18}", f"s{i+2}"]) for i in range(0, 10)],
    *[DrgnRegister([f"x{i+28}", f"t{i+3}"]) for i in range(0, 3)],
    DrgnRegister("pc"),
]

REGISTER_LAYOUT = [
    *[DrgnRegisterLayout(f"x{i}", size=4, dwarf_number=i) for i in range(0, 32)],
    DrgnRegisterLayout("pc", size=4, dwarf_number=None),
]

STACK_POINTER_REGISTER = "x2"
