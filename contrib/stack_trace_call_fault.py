#!/usr/bin/env drgn
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Get a stack trace from a call to an invalid address on x86-64 or AArch64. drgn
should do this automatically eventually.
"""

import drgn
from drgn import Object
from drgn.helpers.common.prog import takes_program_or_default


def pt_regs_members_from_stack_frame(prog, frame):
    regs = frame.registers()
    if prog.platform.arch == drgn.Architecture.X86_64:
        return {
            "r15": regs.get("r15", 0),
            "r14": regs.get("r14", 0),
            "r13": regs.get("r13", 0),
            "r12": regs.get("r12", 0),
            "bp": regs.get("rbp", 0),
            "bx": regs.get("rbx", 0),
            "r11": regs.get("r11", 0),
            "r10": regs.get("r10", 0),
            "r9": regs.get("r9", 0),
            "r8": regs.get("r8", 0),
            "ax": regs.get("rax", 0),
            "cx": regs.get("rcx", 0),
            "dx": regs.get("rdx", 0),
            "si": regs.get("rsi", 0),
            "di": regs.get("rdi", 0),
            "orig_ax": -1,
            "ip": regs.get("rip", 0),
            "cs": regs.get("cs", 0),
            "flags": regs.get("rflags", 0),
            "sp": regs.get("rsp", 0),
            "ss": regs.get("ss", 0),
        }
    elif prog.platform.arch == drgn.Architecture.AARCH64:
        try:
            pc = frame.pc
        except LookupError:
            pc = 0
        return {
            "regs": [regs.get(f"x{i}", 0) for i in range(31)],
            "sp": regs.get("sp", 0),
            "pc": pc,
            "pstate": regs.get("pstate", 0),
        }
    else:
        raise NotImplementedError()


@takes_program_or_default
def call_fault_stack_trace(prog):
    pt_regs_members = pt_regs_members_from_stack_frame(
        prog, prog.crashed_thread().stack_trace()[0]
    )

    if prog.platform.arch == drgn.Architecture.X86_64:
        pt_regs_members["ip"] = prog.read_word(pt_regs_members["sp"]) - 1
        pt_regs_members["sp"] += 8
    elif prog.platform.arch == drgn.Architecture.AARCH64:
        pt_regs_members["pc"] = pt_regs_members["regs"][30] - 4
    else:
        raise NotImplementedError()

    return prog.stack_trace(Object(prog, "struct pt_regs", pt_regs_members))


if __name__ == "__main__":
    trace = call_fault_stack_trace(prog)
    print(trace)
