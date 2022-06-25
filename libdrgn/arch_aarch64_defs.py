# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

REGISTERS = [
    *[DrgnRegister(f"x{i}") for i in range(29)],
    DrgnRegister(["x29", "fp"]),
    DrgnRegister(["x30", "lr"]),
    DrgnRegister("sp"),
    DrgnRegister("pstate"),
]

REGISTER_LAYOUT = [
    DrgnRegisterLayout("ra_sign_state", size=8, dwarf_number=34),
    DrgnRegisterLayout("sp", size=8, dwarf_number=31),
    # Callee-saved registers.
    *[DrgnRegisterLayout(f"x{i}", size=8, dwarf_number=i) for i in range(19, 31)],
    # Caller-saved registers.
    *[DrgnRegisterLayout(f"x{i}", size=8, dwarf_number=i) for i in range(19)],
    # This pc register is only used for interrupted frames.
    DrgnRegisterLayout("pc", size=8, dwarf_number=32),
    DrgnRegisterLayout("pstate", size=8, dwarf_number=None),
]
