# Copyright (c) 2025, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later
import argparse
from typing import Any, Optional

from drgn import FaultError, Program, StackFrame
from drgn.commands import argument, drgn_argument, mutually_exclusive_group
from drgn.commands.crash import CrashDrgnCodeBuilder, crash_command, crash_get_context
from drgn.helpers.common.stack import print_registers
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.sched import cpu_curr
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
    index: int,
    frame: StackFrame,
    sp_width: int,
    drgn_style: bool = False,
    show_file_line: bool = False,
) -> None:
    index_str = f"#{index}"

    try:
        sp = frame.sp
    except LookupError:
        sp = None

    if drgn_style:
        try:
            source_info = " (%s:%d:%d)" % frame.source()
        except LookupError:
            source_info = ""
        print(f"{index_str:>3s} {frame.name}{source_info}")
    else:
        if frame.is_inline:
            print(f"{index_str:>3s} {'(inline)':{sp_width + 2}s} {frame.name}")
        elif sp is None:
            print(f"{index_str:>3s} [{'?' * sp_width}] {frame.name} at {frame.pc:x}")
        else:
            print(
                f"{index_str:>3s} [{frame.sp:0{sp_width}x}] {frame.name} at {frame.pc:x}"
            )
        if show_file_line:
            try:
                file, line, _ = frame.source()
                print(f"    {file}: {line}")
            except LookupError:
                pass


def _print_variables(prog: Program, frame: StackFrame) -> None:
    for name in frame.locals():
        try:
            value = frame[name]
        except KeyError:
            continue
        if not value.absent_:
            try:
                val_str = value.format_(dereference=False).replace("\n", "\n    ")
                print(f"    {name} = {val_str}")
            except FaultError:
                pass


def _print_crash_bt(
    trace: LinuxKernelStack,
    show_file_line: bool = False,
    drgn_style: bool = False,
    show_variables: bool = False,
) -> None:
    prog = trace.task.prog_
    pid = int(trace.task.pid)
    comm = trace.task.comm.string_().decode()
    print(
        f'PID: {pid:<7d}  TASK: {int(trace.task):x}  CPU: {trace.cpu:<3d}  COMMAND: "{comm}"'
    )
    sp_width = _sp_align(trace)

    i = -1
    for segment_idx, segment in enumerate(trace.segments):
        if segment_idx != 0:
            print_registers(prog, segment.frames[0].registers())

        # Don't show the last userspace stack segment
        if segment_idx == len(trace.segments) - 1 and segment.kind == StackKind.USER:
            break

        for i, frame in enumerate(segment.frames, i + 1):
            _print_frame(i, frame, sp_width, drgn_style, show_file_line)
            if show_variables:
                _print_variables(prog, frame)

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
        mutually_exclusive_group(
            argument(
                "task",
                metavar="pid|task",
                type="pid_or_task",
                nargs="?",
                help="print stack trace for a task, given as a decimal process ID or"
                "hexadecimal ``task_struct`` address.",
            ),
            argument(
                "-c",
                dest="cpu",
                type=int,
                help="print stack trace for the given CPU",
            ),
            argument(
                "-a",
                dest="all_cpus",
                action="store_true",
                help="print stack trace for the all CPUs",
            ),
            argument(
                "-p",
                dest="panic",
                action="store_true",
                help="print stack trace for the panic task",
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
    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import("drgn.helpers.linux.stack", "kernel_stack_trace")
        if args.all_cpus:
            code.add_from_import("drgn.helpers.linux.sched", "cpu_curr")
            code.add_from_import("drgn.helpers.linux.cpumask", "for_each_online_cpu")
            code.append(
                """\
for cpu in for_each_online_cpu(prog):
    task = cpu_curr(prog, cpu)
    trace = kernel_stack_trace(task)
"""
            )
            if args.show_variables or args.show_file_line:
                code.append(
                    """\
    for segment in trace:
        registers = segment.frames[0].registers()
        segment_kind = segment.kind
        for frame in segment.frames:
"""
                )
            if args.show_file_line:
                code.append(
                    """\
            file, line, col = frame.source()
"""
                )
            if args.show_variables:
                code.append(
                    """\
            for var in frame.locals():
                value = frame[var]
"""
                )
            code.print()
            return None
        if args.cpu is not None:
            code.add_from_import("drgn.helpers.linux.sched", "cpu_curr")
            code.append(f"task = cpu_curr(prog, {args.cpu})\n")
        elif args.panic:
            code.append("task = prog.crashed_thread().object\n")
        else:
            code.append_crash_context(args.task)
        code.append("trace = kernel_stack_trace(task)\n")
        if args.show_variables or args.show_file_line:
            code.append(
                """\
for segment in trace:
    registers = segment.frames[0].registers()
    segment_kind = segment.kind
    for frame in segment.frames:
"""
            )
        if args.show_file_line:
            code.append(
                """\
        file, line, col = frame.source()
"""
            )
        if args.show_variables:
            code.append(
                """\
        for var in frame.locals():
            value = frame[var]
"""
            )
        code.print()
        return None

    params = {
        "drgn_style": args.drgn_style,
        "show_file_line": args.show_file_line,
        "show_variables": args.show_variables,
    }

    if args.all_cpus:
        for i, cpu in enumerate(for_each_online_cpu(prog)):
            if i > 0:
                print()
            task = cpu_curr(prog, cpu)
            trace = kernel_stack_trace(task)
            _print_crash_bt(trace, **params)
        return None

    if args.cpu is not None:
        task = cpu_curr(prog, args.cpu)
    else:
        task = crash_get_context(prog, args.task)
    trace = kernel_stack_trace(task)
    _print_crash_bt(trace, **params)
    return trace
