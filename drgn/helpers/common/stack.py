# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Stack
-----

The ``drgn.helpers.common.stack`` module provides helpers for working with
stack traces.
"""

from typing import Any, Dict

from drgn import FaultError, PlatformFlags, StackTrace
from drgn.helpers.common.memory import identify_address

__all__ = ("print_annotated_stack",)


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

    if prog.platform.flags & PlatformFlags.IS_64_BIT:
        word_size = 8
        line_format = "{:016x}: {:016x}{}"
        print("STACK POINTER     VALUE")
    else:
        word_size = 4
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
