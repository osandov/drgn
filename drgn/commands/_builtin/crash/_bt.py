# Copyright (c) 2025, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later
import argparse
from typing import Any, Literal, Optional

from drgn import Architecture, FaultError, MainModule, Program, StackFrame
from drgn.commands import argument, drgn_argument, mutually_exclusive_group
from drgn.commands._builtin.crash._rd import _print_memory
from drgn.commands.crash import (
    Cpuspec,
    CrashDrgnCodeBuilder,
    Taskspec,
    crash_command,
    parse_cpuspec,
    print_task_header,
)
from drgn.helpers.common.stack import print_registers
from drgn.helpers.linux.stack import LinuxKernelStack, StackKind, kernel_stack_trace


def _sp_align(trace: LinuxKernelStack) -> int:
    # Some architectures may have shorter address widths than their register
    # width. We want to align the stack frames nicely, and not waste space on
    # extra zeros. Determine the width for the stack pointer field empirically
    # rather than setting it to 8 or 16 based on IS_64_BIT. Subtract 2 to
    # account for the "0x" prefix. Swallow the LookupError in case the sp is not
    # known.
    width = 2
    for segment in trace.segments:
        for frame in segment.frames:
            try:
                width = max(width, len(hex(frame.sp)))
            except LookupError:
                pass
    return width - 2


def _print_frame(
    prog: Program,
    index: int,
    sp: Optional[int],
    frame: StackFrame,
    sp_width: int,
    drgn_style: bool = False,
    show_file_line: bool = False,
) -> None:
    index_str = f"#{index}"

    if drgn_style:
        try:
            source_info = " ({}:{}:{})".format(*frame.source())
        except LookupError:
            source_info = ""
        print(f"{index_str:>3s} {frame.name}{source_info}")
    else:
        mod_text = ""
        try:
            module = prog.module(frame.pc - int(frame.pc > 0 and not frame.interrupted))
            if not isinstance(module, MainModule):
                mod_text = f" [{module.name}]"
        except LookupError:
            pass
        if frame.is_inline:
            print(
                f"{index_str:>3s} {'(inline)':{sp_width + 2}s} {frame.name}{mod_text}"
            )
        elif sp is None:
            print(
                f"{index_str:>3s} [{'?' * sp_width}] {frame.name} at {frame.pc:x}{mod_text}"
            )
        else:
            print(
                f"{index_str:>3s} [{frame.sp:0{sp_width}x}] {frame.name} at {frame.pc:x}{mod_text}"
            )
        if show_file_line:
            try:
                file, line, _ = frame.source()
                print(f"    {file}: {line}")
            except LookupError:
                pass


def _print_variables(prog: Program, frame: StackFrame) -> None:
    for name in frame.locals():
        value = frame[name]
        if not value.absent_:
            try:
                val_str = value.format_(dereference=False).replace("\n", "\n    ")
                print(f"    {name} = {val_str}")
            except FaultError:
                pass


def _maybe_print_mem(
    prog: Program,
    prev_sp: Optional[int],
    sp: Optional[int],
    annotate: Literal[None, "symbols", "slab", "verbose"],
) -> None:
    if prev_sp is None or sp is None:
        return
    # The stack grows down on all supported architectures, and we should never
    # see a gap between frames larger than THREAD_SIZE.
    if sp <= prev_sp or sp - prev_sp >= prog["THREAD_SIZE"]:
        return

    # _print_memory() already asserts this, so let's just yell at the type
    # checker to pervent it complaining.
    unit: Literal[1, 2, 4, 8] = prog.address_size()  # type: ignore

    _print_memory(
        prog,
        prev_sp,
        prog.read(prev_sp, sp - prev_sp),
        unit=unit,
        show_ascii=False,
        annotate=annotate,
        indent="    ",
    )


def _print_crash_bt(
    trace: LinuxKernelStack,
    show_file_line: bool = False,
    drgn_style: bool = False,
    show_variables: bool = False,
    show_mem: bool = False,
    mem_annotate: Literal[None, "symbols", "slab", "verbose"] = None,
) -> None:
    prog = trace.task.prog_
    sp_width = _sp_align(trace)

    i = -1

    # On s390x, the stack pointer points to the top (high address) of a 160-byte
    # stack frame record. However, in practice the kernel is built with
    # -mpacked-stack, so the frames are not actually 160 bytes: only the bottom
    # few words (i.e. the low addresses) of the record are present. The rest of
    # the record is not present. This means that in practice, each frame's stack
    # pointer is pointing several words "too high", pointing into their callers'
    # stack frames. To correct for this, we have to offset the stack pointers by
    # 160 bytes too.
    sp_offset = 0
    assert prog.platform is not None
    if prog.platform.arch == Architecture.S390X:
        sp_offset = 160

    prev_sp = None
    for segment_idx, segment in enumerate(trace.segments):
        if segment_idx != 0:
            print_registers(prog, segment.frames[0].registers())

        # Don't show the last userspace stack segment
        if segment_idx == len(trace.segments) - 1 and segment.kind == StackKind.USER:
            break

        for i, frame in enumerate(segment.frames, i + 1):
            try:
                sp = frame.sp + sp_offset
            except LookupError:
                sp = None
            if show_mem:
                _maybe_print_mem(prog, prev_sp, sp, mem_annotate)
            _print_frame(prog, i, sp, frame, sp_width, drgn_style, show_file_line)
            if show_variables:
                _print_variables(prog, frame)
            prev_sp = sp or prev_sp

        # Print separators for exception/interrupt stacks, like crash does
        if segment.kind not in (StackKind.USER, StackKind.TASK, StackKind.UNKNOWN):
            print(f"--- <{segment.kind.name} stack> ---")


@crash_command(
    description="print stack traces",
    long_description="""
    Print the kernel stack trace for a given PID or task

    If no PID or task is given, print the stack trace for the current context
    task.
    """,
    arguments=(
        # Python 3.9 does not allow this to be in a mutually exclusive argument
        # group (ValueError: mutually exclusive arguments must be optional).
        # This is despite the fact that using nargs="*" means it IS optional.
        argument(
            "tasks",
            metavar="pid|task",
            type="pid_or_task",
            nargs="*",
            help="print stack trace for task(s), given as a decimal process ID or"
            " hexadecimal ``task_struct`` address.",
        ),
        mutually_exclusive_group(
            argument(
                "-c",
                dest="cpus",
                type=str,
                help="print stack trace for one or more CPUs, which can be specified"
                " using the format '3', '1,8,9', '1-23', or '1,8,9-14'.",
            ),
            argument(
                "-a",
                dest="all_cpus",
                action="store_true",
                help="print stack trace for all CPUs",
            ),
            argument(
                "-p",
                dest="panic",
                action="store_true",
                help="print stack trace for the panic task",
            ),
        ),
        mutually_exclusive_group(
            argument(
                "-f",
                dest="frame",
                action="store_true",
                help="display all stack data contained in a frame",
            ),
            argument(
                "-F",
                dest="frame_symbolic",
                action="count",
                default=0,
                help="similar to -f, except that the stack data is displayed "
                "symbolically where appropriate; if the stack data references a "
                "slab cache object, the name of the slab cache will be displayed "
                "in brackets. If -F is entered twice, and the stack data references "
                "a slab cache object, then both the address and the name of the "
                "slab cache will be displayed in brackets",
            ),
        ),
        argument(
            "-l",
            dest="show_file_line",
            action="store_true",
            help="show file and line number of each stack trace text location",
        ),
        argument(
            "-d",
            dest="drgn_style",
            action="store_true",
            help="format the stack frames in drgn's style rather than crash's",
        ),
        argument(
            "-V",
            dest="show_variables",
            action="store_true",
            help="print any local variable values which drgn can determine",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_bt(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> Optional[LinuxKernelStack]:
    if args.tasks and (args.all_cpus or args.cpus or args.panic):
        raise ValueError("Tasks may not be specified with -a, -c, or -p")
    if args.all_cpus:
        taskspec = Taskspec(cpuspec=Cpuspec(all=True))
    elif args.cpus:
        taskspec = Taskspec(cpuspec=parse_cpuspec(args.cpus))
    elif args.panic:
        taskspec = Taskspec(panic=True)
    elif args.tasks:
        taskspec = Taskspec(explicit_tasks=tuple(args.tasks))
    else:
        taskspec = Taskspec(current=True)

    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import("drgn.helpers.linux.stack", "kernel_stack_trace")
        code.add_from_import("drgn.helpers.common.format", "escape_ascii_string")

        # First, build the body of the code for a stack trace, which can be
        # indented if we need to put it into a loop:
        loop_body = """\
trace = kernel_stack_trace(task)
pid = task.pid.value_()
comm = escape_ascii_string(task.comm.string_())
"""
        if args.show_file_line or args.show_variables:
            loop_body += """\
for segment in trace.segments:
    registers = segment.frames[0].registers()
    segment_kind = segment.kind
    for frame in segment.frames:
"""
        if args.show_file_line:
            loop_body += """\
        try:
            file, line, col = frame.source()
        except LookupError:
            pass
"""
        if args.show_variables:
            loop_body += """\
        for var in frame.locals():
            value = frame[var]
"""

        code.append_taskspec(taskspec, loop_body)
        code.print()
        return None

    annotate: Literal[None, "slab", "verbose"] = None
    if args.frame_symbolic >= 1:
        args.frame = True
        annotate = "slab"
    if args.frame_symbolic >= 2:
        annotate = "verbose"

    trace = None
    for i, task in enumerate(taskspec.tasks(prog)):
        if i > 0:
            print()
        print_task_header(task)
        trace = kernel_stack_trace(task)
        _print_crash_bt(
            trace,
            drgn_style=args.drgn_style,
            show_file_line=args.show_file_line,
            show_variables=args.show_variables,
            show_mem=args.frame,
            mem_annotate=annotate,
        )
    return trace
