# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Stack
-----

The ``drgn.helpers.common.stack`` module provides helpers for working with
stack traces.
"""

from typing import Any, Dict

from drgn import Architecture, FaultError, PlatformFlags, Program, StackTrace
from drgn.helpers.common.memory import identify_address
from drgn.helpers.common.prog import takes_program_or_default

__all__ = (
    "print_annotated_stack",
    "print_registers",
)


def print_annotated_stack(trace: StackTrace) -> None:
    """
    Print the contents of stack memory in a stack trace, annotating values that
    can be identified.

    Currently, this will identify any addresses on the stack with
    :func:`~drgn.helpers.common.memory.identify_address()`.

    See :func:`~drgn.helpers.common.memory.print_annotated_memory()` for a
    similar function that annotates arbitrary memory ranges.

    >>> print_annotated_stack(stack_trace(1))
    STACK POINTER     VALUE
    [stack frame #0 at 0xffffffff8dc93c41 (__schedule+0x429/0x488) in context_switch at ./kernel/sched/core.c:5209:2 (inlined)]
    [stack frame #1 at 0xffffffff8dc93c41 (__schedule+0x429/0x488) in __schedule at ./kernel/sched/core.c:6521:8]
    ffffa903c0013d28: ffffffff8d8497bf [function symbol: __flush_tlb_one_user+0x5]
    ffffa903c0013d30: 000000008d849eb5
    ffffa903c0013d38: 0000000000000001
    ffffa903c0013d40: 0000000000000004
    ffffa903c0013d48: efdea37bb7cb1f00
    ffffa903c0013d50: ffff926641178000 [slab object: task_struct+0x0]
    ffffa903c0013d58: ffff926641178000 [slab object: task_struct+0x0]
    ffffa903c0013d60: ffffa903c0013e10
    ffffa903c0013d68: ffff926641177ff0 [slab object: mm_struct+0x70]
    ffffa903c0013d70: ffff926641178000 [slab object: task_struct+0x0]
    ffffa903c0013d78: ffff926641178000 [slab object: task_struct+0x0]
    ffffa903c0013d80: ffffffff8dc93d29 [function symbol: schedule+0x89]
    ...

    :param trace: Stack trace to print.
    """
    prog = trace.prog

    # platform must be known if there is a stack trace
    assert prog.platform is not None

    if prog.platform.flags & PlatformFlags.IS_LITTLE_ENDIAN:
        byteorder = "little"
    else:
        byteorder = "big"

    word_size = prog.address_size()
    if word_size == 8:
        line_format = "{:016x}: {:016x}{}"
        print("STACK POINTER     VALUE")
    else:
        line_format = "{:08x}: {:08x}{}"
        print("STACK     VALUE\nPOINTER")

    cache: Dict[Any, Any] = {}
    start = 0
    while start < len(trace):
        # Find the bounds of this stack. Our heuristics for the end of the
        # stack are:
        #
        # 1. An interrupted frame.
        # 2. A frame with a stack pointer less than the previous frame's stack
        #    pointer (since the stack grows down in all of the architectures we
        #    support).
        # 3. A frame with a stack pointer much greater than the previous
        #    frame's stack pointer. Our arbitrary threshold is 128 MB. (Linux
        #    kernel stacks are at most 16 KB as of Linux 6.8, and userspace
        #    stacks are limited to 8 MB by default, so this threshold could be
        #    adjusted if needed.)
        end = start + 1
        while (
            end < len(trace)
            and not trace[end].interrupted
            and 0 <= trace[end].sp - trace[end - 1].sp <= 128 * 1024 * 1024
        ):
            end += 1

        # Gather the frames for this stack.
        frames = [trace[i] for i in range(start, end)]
        frames_addrs = [frame.sp for frame in frames]

        start_addr = frames_addrs[0]
        end_addr = frames_addrs[-1] + word_size - 1
        stack_size = end_addr - start_addr + 1

        try:
            stack_bytes = prog.read(start_addr, stack_size)
        except FaultError:
            # Couldn't read the stack. Just print the frames.
            for frame in frames:
                print(f"[stack frame {frame}]")

            start = end
            continue

        frame_ind = 0

        for offset in range(0, len(stack_bytes), word_size):
            addr = start_addr + offset

            word_bytes = stack_bytes[offset : offset + word_size]
            word_val = int.from_bytes(
                word_bytes,
                # The byteorder parameter is annotated as
                # Literal['little', 'big'], but mypy infers that our byteorder
                # variable is str.
                byteorder=byteorder,  # type: ignore[arg-type]
            )

            # There may be multiple frames matching this address (usually
            # because of inline frames).
            while frame_ind < len(frames_addrs) and addr == frames_addrs[frame_ind]:
                frame = frames[frame_ind]
                print(f"[stack frame {frame}]")
                frame_ind += 1

            identified = identify_address(prog, word_val, cache=cache)
            if identified is None:
                identified = ""
            else:
                identified = f" [{identified}]"
            print(line_format.format(addr, word_val, identified))

        start = end


@takes_program_or_default
def print_registers(prog: Program, regs: Dict[str, int], indent: str = "    ") -> None:
    """
    Print a CPU register dump, in a format similar to that of
    :manpage:`crash(8)`

    :param regs: a dictionary of registers, named in a similar way to the
      dictionary returned by :py:meth:`drgn.StackTrace.registers()`.
    :param indent: a string prepended to each line of output
    """
    if not prog.platform:
        raise RuntimeError("Unknown platform & architecture")

    widths = {}
    formats = {}
    if prog.platform.arch == Architecture.X86_64:
        rows = [
            ("rip", "rsp", "rflags"),
            ("rax", "rbx", "rcx"),
            ("rdx", "rsi", "rdi"),
            ("rbp", "r8", "r9"),
            ("r10", "r11", "r12"),
            ("r13", "r14", "r15"),
            ("cs", "ss"),
        ]
        widths = {"cs": 4, "ss": 4, "rflags": 8}
    elif prog.platform.arch == Architecture.AARCH64:
        rows = [
            ("pc", "lr", "sp"),
            ("x29", "x28", "x27"),
            ("x26", "x25", "x24"),
            ("x23", "x22", "x21"),
            ("x20", "x19", "x18"),
            ("x17", "x16", "x15"),
            ("x14", "x13", "x12"),
            ("x11", "x10", "x9"),
            ("x8", "x7", "x6"),
            ("x5", "x4", "x3"),
            ("x2", "x1", "x0"),
        ]
    elif prog.platform.arch == Architecture.ARM:
        rows = [
            ("pc", "lr", "sp", "fp"),
            ("r10", "r9", "r8"),
            ("r7", "r6", "r5", "r4"),
            ("r3", "r2", "r1", "r0"),
        ]
    elif prog.platform.arch == Architecture.S390X:
        rows = [
            ("pswm", "pswa", "r0"),
            ("r1", "r3", "r3"),
            ("r4", "r5", "r6"),
            ("r7", "r8", "r9"),
            ("r10", "r11", "r12"),
            ("r13", "r14", "r15"),
        ]
    elif prog.platform.arch == Architecture.PPC64:
        rows = [
            ("r0", "r1", "r2"),
            ("r3", "r4", "r5"),
            ("r6", "r7", "r8"),
            ("r9", "r10", "r11"),
            ("r12", "r13", "r14"),
            ("r15", "r16", "r17"),
            ("r18", "r19", "r20"),
            ("r21", "r22", "r23"),
            ("r24", "r25", "r26"),
            ("r27", "r28", "r29"),
            ("r30", "r31"),
            # This departs from the crash format significantly. Crash recovers
            # registers like CTR, XER, LR, and a few others. However, drgn
            # doesn't provide these in stack frame registers. They are available
            # in struct pt_regs.
            ("cr0", "cr1", "cr2", "cr3"),
            ("cr4", "cr5", "cr6", "cr7"),
        ]
        widths = {f"cr{i}": 4 for i in range(8)}
        formats = {f"cr{i}": "b" for i in range(8)}
    else:
        raise RuntimeError(f"Unsupported architecture: {prog.platform.arch}")

    default_width = 16 if prog.platform.flags & PlatformFlags.IS_64_BIT else 8

    for row in rows:
        row_text = []
        for i, reg in enumerate(row):
            width = widths.get(reg, default_width)
            if reg in regs:
                value = regs[reg]
                fmt = formats.get(reg, "x")
                row_text.append(f"{reg.upper():>3s}: {value:0{width}{fmt}}")
            else:
                row_text.append(f"{reg.upper():>3s}: {'?' * width}")

        print(f"{indent}{'  '.join(row_text)}")
