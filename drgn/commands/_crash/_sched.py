# Copyright (c) Meta Platforms, Inc. and affiliates.
# Copyright (c) 2026, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Scheduler-related crash commands."""

import argparse
import sys
import textwrap
from typing import Any, Iterable, List, Sequence

from drgn import Object, Program, offsetof
from drgn.commands import _repr_black, argument, drgn_argument, mutually_exclusive_group
from drgn.commands._crash.common import (
    Cpuspec,
    CrashDrgnCodeBuilder,
    _crash_foreach_subcommand,
    _guess_type,
    _parse_type_name_and_member,
    _prefer_object_lookup,
    _print_task_header,
    _TaskSelector,
    crash_command,
    parse_cpuspec,
    print_task_header,
)
from drgn.helpers.common.format import CellFormat, escape_ascii_string, print_table
from drgn.helpers.linux.pid import for_each_task_in_group
from drgn.helpers.linux.sched import (
    cfs_rq_for_each_entity,
    cpu_rq,
    rq_for_each_rt_task,
    sched_entity_to_task,
    task_group_name,
)
from drgn.helpers.linux.signal import (
    decode_sigaction_flags_value,
    decode_sigset,
    signal_numbers,
    sigpending_for_each,
    sigset_to_hex,
)
from drgn.helpers.linux.wait import waitqueue_for_each_task


def _runq_timestamps(prog: Program, cpuspec: Cpuspec, drgn_arg: bool) -> None:
    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)

        code.add_from_import("drgn.helpers.linux.sched", "cpu_rq")
        with code.begin_cpuspec_loop(cpuspec):
            code.append(
                """\
rq = cpu_rq(cpu)
rq_clock = rq.clock
curr = rq.curr.read_()
curr_clock = curr.sched_info.last_arrival
"""
            )
            code.append_task_header(variable="curr", cpu=False)

        return code.print()

    for cpu in cpuspec.cpus(prog):
        rq = cpu_rq(prog, cpu)
        print(f" CPU {cpu}: {rq.clock.value_():016d}")
        curr = rq.curr.read_()
        print(f"        {curr.sched_info.last_arrival.value_():016d}  ", end="")
        _print_task_header(curr, cpu=None)


def _runq_lag(prog: Program, cpuspec: Cpuspec, drgn_arg: bool) -> None:
    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import("drgn.helpers.linux.sched", "cpu_rq")
        with code.begin_cpuspec_loop(cpuspec):
            code.append("rq_clock = cpu_rq(cpu).clock\n")
        return code.print()

    timestamps = [(cpu_rq(prog, cpu).clock.value_(), cpu) for cpu in cpuspec.cpus(prog)]
    timestamps.sort(reverse=True)
    if not timestamps:
        return

    cpu_width = max(len(f"CPU {cpu}") for _, cpu in timestamps)
    max_ts = timestamps[0][0]
    for ts, cpu in timestamps:
        cpu_str = f"CPU {cpu}"
        print(f"{cpu_str:>{2 + cpu_width}}: {(max_ts - ts) / 1e9:.2f} secs")


def _elapsed_str(ns: int) -> str:
    ms_total = ns // 1000000
    secs_total, ms = divmod(ms_total, 1000)
    mins_total, secs = divmod(secs_total, 60)
    hours_total, mins = divmod(mins_total, 60)
    days, hours = divmod(hours_total, 24)

    return f"{days} {hours:02}:{mins:02}:{secs:02}.{ms:03}"


def _runq_elapsed(prog: Program, cpuspec: Cpuspec, drgn_arg: bool) -> None:
    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)

        code.add_from_import("drgn.helpers.linux.sched", "cpu_rq")
        with code.begin_cpuspec_loop(cpuspec):
            code.append(
                """\
rq = cpu_rq(cpu)
rq_clock = rq.clock
curr = rq.curr.read_()
curr_clock = curr.sched_info.last_arrival
elapsed = rq_clock - curr_clock
"""
            )
            code.append_task_header(variable="curr", cpu=False)

        return code.print()

    entries = []
    max_cpu_width = 0
    max_elapsed_width = 0
    for cpu in cpuspec.cpus(prog):
        rq = cpu_rq(prog, cpu)
        curr = rq.curr.read_()
        elapsed = max(rq.clock.value_() - curr.sched_info.last_arrival.value_(), 0)

        cpu_str = f"CPU {cpu}"
        elapsed_str = _elapsed_str(elapsed)
        entries.append((cpu_str, elapsed_str, curr))

        max_cpu_width = max(max_cpu_width, len(cpu_str))
        max_elapsed_width = max(max_elapsed_width, len(elapsed_str))

    for cpu_str, elapsed_str, curr in entries:
        print(
            f"{cpu_str:>{2 + max_cpu_width}}: [{elapsed_str:>{max_elapsed_width}}]  ",
            end="",
        )
        _print_task_header(curr, cpu=None)


def _print_task_group(cfs_rq: Object, depth: int) -> None:
    tg = cfs_rq.tg.read_()
    indent = " " * (2 + 3 * depth)

    name = task_group_name(tg)
    if name:
        name_str = f"  <{escape_ascii_string(name, escape_backslash=True)}>"
    else:
        name_str = ""

    # throttled only exists if CONFIG_CFS_BANDWIDTH=y.
    if getattr(cfs_rq, "throttled", False):
        throttled_str = " (THROTTLED)"
    else:
        throttled_str = ""

    print(
        f"{indent}TASK_GROUP: {tg.value_():x}  CFS_RQ: {cfs_rq.value_():x}{name_str}{throttled_str}"
    )


def _print_cfs_rq(cfs_rq: Object) -> None:
    found = False
    for se, depth, is_curr, is_task in cfs_rq_for_each_entity(cfs_rq):
        found = True
        if is_task:
            task = sched_entity_to_task(se)
            sys.stdout.write(" " * (5 + 3 * depth))
            _print_task_header(
                task, cpu=None, prio=True, end=" [CURRENT]\n" if is_curr else "\n"
            )
        else:
            _print_task_group(se.my_q.read_(), depth + 1)

    if not found:
        print("     [no tasks queued]")


def _runq_task_groups(prog: Program, cpuspec: Cpuspec, drgn_arg: bool) -> None:
    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)

        with code.begin_cpuspec_loop(cpuspec):
            code.append("rq = cpu_rq(cpu)\n")

            code.add_from_import(
                "drgn.helpers.linux.sched",
                "cfs_rq_for_each_entity",
                "cpu_rq",
                "sched_entity_to_task",
                "task_group_name",
            )
            with code.begin_block(
                "for se, depth, is_curr, is_task in cfs_rq_for_each_entity(rq.cfs.address_of_()):\n"
            ):
                with code.begin_block("if is_task:\n"):
                    code.append("task = sched_entity_to_task(se)\n")
                    code.append_task_header(cpu=False, prio=True)
                code.append(
                    """\
else:
    cfs_rq = se.my_q.read_()
    task_group = cfs_rq.tg.read_()
    name = task_group_name(task_group)
    try:
        throttled = cfs_rq.throttled
    except AttributeError:
        # throttled only exists if CONFIG_CFS_BANDWIDTH=y.
        pass
"""
                )

        return code.print()

    root_tg_addr = prog["root_task_group"].address_

    first = True
    for cpu in cpuspec.cpus(prog):
        if first:
            first = False
        else:
            print()

        rq = cpu_rq(prog, cpu)
        curr = rq.curr.read_()

        print(f"CPU {cpu}")
        print("  CURRENT: ", end="")
        _print_task_header(curr, cpu=None)

        cfs_rq = rq.cfs.address_of_()
        print(f"  ROOT_TASK_GROUP: {root_tg_addr:x}" f"  CFS_RQ: {cfs_rq.value_():x}")
        _print_cfs_rq(cfs_rq)


def _print_rq_tasks(tasks: Iterable[Object]) -> None:
    found_task = False
    for task in tasks:
        found_task = True
        sys.stdout.write("     ")
        _print_task_header(task, cpu=None, prio=True)

    if not found_task:
        print("     [no tasks queued]")


def _runq_tasks(prog: Program, cpuspec: Cpuspec, drgn_arg: bool) -> None:
    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)

        with code.begin_cpuspec_loop(cpuspec):
            code.append(
                """\
rq = cpu_rq(cpu)

curr = rq.curr.read_()
"""
            )
            code.append_task_header(variable="curr", cpu=False)

            code.add_from_import(
                "drgn.helpers.linux.sched",
                "cfs_rq_for_each_entity",
                "cpu_rq",
                "rq_for_each_rt_task",
                "sched_entity_to_task",
            )
            with code.begin_block(
                """
rt_prio_array = rq.rt.active
for task in rq_for_each_rt_task(rq):
"""
            ):
                code.append_task_header(cpu=False, prio=True)

            with code.begin_block(
                """
cfs_rq = rq.cfs.address_of_()
cfs_rb_root = cfs_rq.tasks_timeline
# Alternatively, you can use rq_for_each_fair_task() if you don't care about
# order or task_group hierarchy.
for se, _, is_curr, is_task in cfs_rq_for_each_entity(cfs_rq):
"""
            ):
                code.append(
                    """\
if is_curr or not is_task:
    continue
task = sched_entity_to_task(se)
"""
                )
                code.append_task_header(cpu=False, prio=True)

        return code.print()

    first = True
    for cpu in cpuspec.cpus(prog):
        if first:
            first = False
        else:
            print()

        rq = cpu_rq(prog, cpu)
        print(f"CPU {cpu} RUNQUEUE {rq.value_():x}")

        print("  CURRENT: ", end="")
        _print_task_header(rq.curr.read_(), cpu=None)

        print(f"  RT PRIO_ARRAY: {rq.rt.active.address_:x}")
        _print_rq_tasks(rq_for_each_rt_task(rq))

        cfs_rq = rq.cfs.address_of_()
        print(f"  CFS RB_ROOT: {cfs_rq.tasks_timeline.address_:x}")
        _print_rq_tasks(
            sched_entity_to_task(se)
            for se, _, is_curr, is_task in cfs_rq_for_each_entity(cfs_rq)
            if not is_curr and is_task
        )


@crash_command(
    description="CPU scheduler run queues",
    long_description="By default, display the tasks on each CPU's runqueue.",
    arguments=(
        mutually_exclusive_group(
            argument(
                "-t",
                dest="timestamps",
                action="store_true",
                help="""
                display the timestamp of each CPU's runqueue and the timestamp
                of the active task on each CPU
                """,
            ),
            argument(
                "-T",
                dest="lag",
                action="store_true",
                help="""
                display the difference between the timestamp of each CPU's
                runqueue relative to the runqueue with the highest timestamp
                """,
            ),
            argument(
                "-m",
                dest="elapsed",
                action="store_true",
                help="""
                display the amount of time that the active task on each CPU has
                been running
                """,
            ),
            argument(
                "-g",
                dest="task_groups",
                action="store_true",
                help="display the task_group hierarchy on each CPU's runqueue",
            ),
        ),
        argument(
            "-c",
            dest="cpu",
            default="all",
            help="restrict the output to one or more CPUs, "
            "which may be a comma-separated string of CPU numbers or ranges "
            "(e.g., '0,3-4')",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_runq(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    cpuspec = parse_cpuspec(args.cpu)

    if args.timestamps:
        _runq_timestamps(prog, cpuspec, args.drgn)
    elif args.lag:
        _runq_lag(prog, cpuspec, args.drgn)
    elif args.elapsed:
        _runq_elapsed(prog, cpuspec, args.drgn)
    elif args.task_groups:
        _runq_task_groups(prog, cpuspec, args.drgn)
    else:
        _runq_tasks(prog, cpuspec, args.drgn)


def _append_sigpending(code: CrashDrgnCodeBuilder, name: str, indent: str = "") -> None:
    code.add_from_import("drgn.helpers.linux.signal", "sigpending_for_each")
    code.append(
        f"""\
{indent}{name}_signals = {name}.signal
{indent}for sigqueue in sigpending_for_each({name}):
{indent}    info = sigqueue.info
{indent}    pending_signo = info.si_signo
"""
    )


def _print_sigpending(pending: Object, indent: str = "") -> None:
    print(indent + "    SIGNAL:", sigset_to_hex(pending.signal))
    rows = []
    first = True
    for sigqueue in sigpending_for_each(pending):
        if first:
            rows.append(
                (
                    indent + "  SIGQUEUE:",
                    CellFormat("SIG", ">"),
                    CellFormat("SIGINFO", "^"),
                )
            )
            first = False
        info = sigqueue.info
        rows.append(("", info.si_signo.value_(), CellFormat(info.address_, "^x")))
    if first:
        print(indent + "  SIGQUEUE: (empty)")
    else:
        print_table(rows)


@_crash_foreach_subcommand(
    arguments=(
        argument(
            "-g",
            dest="thread_group",
            action="store_true",
        ),
        drgn_argument,
    ),
)
def _crash_foreach_sig(task_selector: _TaskSelector, args: argparse.Namespace) -> None:
    prog = task_selector.prog

    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        with task_selector.begin_task_loop(code):
            code.append_task_header()
            code.add_from_import("drgn.helpers.linux.signal", "decode_sigaction_flags")
            code.append(
                """\

signal_struct = task.signal
nr_threads = signal_struct.nr_threads

for signo, action in enumerate(task.sighand.action, 1):
    sigaction = action.sa
    handler = sigaction.sa_handler
    mask = sigaction.sa_mask
    flags = sigaction.sa_flags
    decoded_flags = decode_sigaction_flags(sigaction)
"""
            )

            if not args.thread_group:
                code.append(
                    """
blocked = task.blocked

private_pending = task.pending
"""
                )
                _append_sigpending(code, "private_pending")

            code.append(
                """
shared_pending = signal_struct.shared_pending
"""
            )
            _append_sigpending(code, "shared_pending")

            if args.thread_group:
                code.add_from_import("drgn.helpers.linux.pid", "for_each_task_in_group")
                code.append(
                    """
for task in for_each_task_in_group(task, include_self=True):
"""
                )
                code.append_task_header("    ")
                code.append(
                    """
    blocked = task.blocked

    private_pending = task.pending
"""
                )
                _append_sigpending(code, "private_pending", "    ")

        return code.print()

    first = True
    for task in task_selector.tasks():
        if first:
            first = False
        else:
            print()
        print_task_header(task)

        signal_struct = task.signal.read_()
        print(
            f"SIGNAL_STRUCT: {signal_struct.value_():x}  NR_THREADS: {signal_struct.nr_threads.value_()}"
        )

        rows: List[Sequence[Any]] = [
            (
                CellFormat("SIG", ">"),
                CellFormat("SIGACTION", "^"),
                CellFormat("HANDLER", "^"),
                CellFormat("MASK", "^"),
                "FLAGS",
            ),
        ]
        for signo, action in enumerate(task.sighand.action, 1):
            sa = action.sa

            handler = sa.sa_handler.value_()
            if handler == 0:
                handler_cell = CellFormat("SIG_DFL", "^")
            elif handler == 1:
                handler_cell = CellFormat("SIG_IGN", "^")
            else:
                handler_cell = CellFormat(handler, ">x")

            flags = sa.sa_flags.value_()
            if flags:
                flags_cell = f"{flags:x} ({decode_sigaction_flags_value(prog, flags)})"
            else:
                flags_cell = "0"

            rows.append(
                (
                    CellFormat(f"[{signo}]", ">"),
                    CellFormat(sa.address_, ">x"),
                    handler_cell,
                    sigset_to_hex(sa.sa_mask),
                    flags_cell,
                )
            )
        print_table(rows)

        # Crash also displays SIGPENDING, which checks whether TIF_SIGPENDING
        # is set on the task. But TIF flags are a pain to get, so we omit it
        # for now.
        if not args.thread_group:
            print("   BLOCKED:", sigset_to_hex(task.blocked))
            print("PRIVATE_PENDING")
            _print_sigpending(task.pending)

        print("SHARED_PENDING")
        _print_sigpending(signal_struct.shared_pending)

        if args.thread_group:
            for thread in for_each_task_in_group(task, include_self=True):
                sys.stdout.write("\n  ")
                print_task_header(thread)
                print("     BLOCKED:", sigset_to_hex(thread.blocked))
                print("  PRIVATE_PENDING")
                _print_sigpending(thread.pending, indent="  ")


@crash_command(
    description="signal handling",
    arguments=(
        mutually_exclusive_group(
            argument(
                "-g",
                dest="thread_group",
                action="store_true",
                help="display pending signals for all threads",
            ),
            argument(
                "-l",
                dest="list",
                action="store_true",
                help="display all known signal numbers and names",
            ),
            argument(
                "-s",
                dest="sigset",
                type="hexadecimal",
                help="translate a hexadecimal signal set into a list of signal names",
            ),
        ),
        argument(
            "tasks",
            metavar="pid|task",
            type="pid_or_task",
            nargs="*",
            help="""
            display signal handlers and pending signals for this task, given as
            either a decimal process ID or a hexadecimal ``task_struct``
            address. May be given multiple times. Defaults to the current
            context
            """,
        ),
        drgn_argument,
    ),
)
def _crash_cmd_sig(
    prog: Program,
    name: str,
    args: argparse.Namespace,
    **kwargs: Any,
) -> None:
    if args.list:
        if args.drgn:
            sys.stdout.write(
                """\
from drgn.helpers.linux.signal import signal_numbers


for number, names in signal_numbers().items():
    ...
"""
            )
            return

        print_table(
            [
                (CellFormat(f"[{number}]", ">"), "/".join(names))
                for number, names in sorted(signal_numbers(prog).items())
            ],
            sep=" ",
        )
        return

    if args.sigset is not None:
        if args.drgn:
            sys.stdout.write(
                f"""\
from drgn.helpers.linux.signal import decode_sigset


decoded = decode_sigset({hex(args.sigset)})
"""
            )
            return

        decoded = decode_sigset(prog, args.sigset)
        decoded = decoded.replace("{", "").replace("}", "").replace(",", " ")
        print(textwrap.fill(decoded, width=80))
        return

    if not args.tasks:
        args.tasks.append(None)
    return _crash_foreach_sig(_TaskSelector(prog, args.tasks), args)


@crash_command(
    description="list tasks on a wait queue",
    usage=r"**waitq** (*symbol* | *address* | *struct.member* *struct_addr*) [**\-\-drgn**]",
    arguments=(
        # argparse can't express symbol | address | struct.member struct_addr,
        # so we use this hack to consume all of the positional arguments (which
        # we parse manually) and define dummy arguments that are only used for
        # the help string.
        argument(
            "posargs",
            nargs="*",
            # Work around https://github.com/python/cpython/issues/72795
            # before Python 3.13.
            default=[],
            help=argparse.SUPPRESS,
        ),
        argument(
            "symbol",
            nargs="?",
            help="symbol name of wait queue",
        ),
        argument(
            "address",
            nargs="?",
            help="hexadecimal address of wait queue",
        ),
        argument(
            "struct.member",
            nargs="?",
            help="""
            name of structure type containing a wait queue member with the
            given name
            """,
        ),
        argument(
            "struct_addr",
            nargs="?",
            help="address of structure containing wait queue member",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_waitq(
    prog: Program,
    name: str,
    args: argparse.Namespace,
    *,
    parser: argparse.ArgumentParser,
    **kwargs: Any,
) -> None:
    is_symbol = False
    if not args.posargs:
        parser.error("symbol, address, or struct is required")
    elif len(args.posargs) == 1:
        try:
            address = int(args.posargs[0], 16)
        except ValueError:
            is_symbol = True
    elif len(args.posargs) == 2:
        type_name, member = _parse_type_name_and_member(args.posargs[0])
        address = int(args.posargs[1], 16)
        try:
            offset_type = _guess_type(prog, type_name)
        except LookupError:
            if not args.drgn:
                raise
            type_name = "struct " + type_name
        else:
            type_name = offset_type.type_name()
    else:
        parser.error(f"unrecognized arguments: {' '.join(args.posargs[2:])}")

    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import("drgn.helpers.linux.wait", "waitqueue_for_each_task")

        if len(args.posargs) == 2:
            code.add_from_import("drgn", "Object", "offsetof")
            code.append(
                f"""\
address = {hex(address)}
address += offsetof(prog.type({_repr_black(type_name)}), {_repr_black(member)})
wq = Object(prog, "wait_queue_head_t *", address)
"""
            )
        elif not is_symbol:
            code.add_from_import("drgn", "Object")
            code.append(f'wq = Object(prog, "wait_queue_head_t *", {hex(address)})\n')
        elif _prefer_object_lookup(prog, "wait_queue_head_t", args.posargs[0]):
            code.append(f"wq = prog[{_repr_black(args.posargs[0])}].address_of_()\n")
        else:
            code.add_from_import("drgn", "Object")
            code.append(
                f"""\
address = prog.symbol({_repr_black(args.posargs[0])}).address
wq = Object(prog, "wait_queue_head_t *", address)
"""
            )

        code.append("\nfor task in waitqueue_for_each_task(wq):\n")
        code.append_task_header(indent="    ")
        code.print()
        return

    if len(args.posargs) == 2:
        address += offsetof(offset_type, member)
    elif is_symbol:
        address = prog.symbol(args.posargs[0]).address

    wq = Object(prog, "wait_queue_head_t *", address)
    empty = True
    for task in waitqueue_for_each_task(wq):
        empty = False
        print_task_header(task)
    if empty:
        wq_name = f"{address:x}"
        if is_symbol:
            wq_name = f"{_repr_black(args.posargs[0])} ({wq_name})"
        print(f"wait queue {wq_name} is empty")
