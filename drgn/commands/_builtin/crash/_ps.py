# Copyright (c) 2025 Oracle and/or its affiliates
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Implements the crash "ps" command for drgn.

This command displays process status for selected, or all, processes
in the system.
"""

import argparse
import collections
import functools
import sys
from typing import AbstractSet, Any, List, Optional, Sequence, Tuple

from drgn import FaultError, Object, Program
from drgn.commands import (
    CommandArgumentError,
    argument,
    drgn_argument,
    mutually_exclusive_group,
    parse_shell_command,
    unquote_shell_word,
)
from drgn.commands.crash import (
    _CRASH_FOREACH_SUBCOMMANDS,
    Cpuspec,
    CrashDrgnCodeBuilder,
    _crash_foreach_subcommand,
    _format_seconds_duration,
    _pid_or_task_or_command,
    _print_task_header,
    _TaskSelector,
    crash_custom_command,
    parse_cpuspec,
    print_task_header,
)
from drgn.helpers.common.format import CellFormat, escape_ascii_string, print_table
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.kthread import task_is_kthread
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.mm import (
    mm_cmdline,
    mm_environ,
    task_rss,
    task_vsize,
    totalram_pages,
)
from drgn.helpers.linux.pid import for_each_task_in_group
from drgn.helpers.linux.resource import task_rlimits
from drgn.helpers.linux.sched import (
    _TASK_STATE_CHAR_TO_STATE,
    cpu_rq,
    task_cpu,
    task_on_cpu,
    task_state_to_char,
)
from drgn.helpers.linux.timekeeping import ktime_get_coarse_ns

_SCHED_POLICIES = {
    "NORMAL": 0,
    # Crash doesn't accept this, but it's the standard name.
    "OTHER": 0,
    "FIFO": 1,
    "RR": 2,
    "BATCH": 3,
    # SCHED_ISO never made it upstream, but crash accepts it.
    "ISO": 4,
    "IDLE": 5,
    "DEADLINE": 6,
    "EXT": 7,
}


def _parse_sched_policies(arg: str) -> AbstractSet[int]:
    policies = set()
    for a in arg.split(","):
        try:
            policies.add(int(a, 10))
            continue
        except ValueError:
            pass

        try:
            policies.add(int(a, 16))
            continue
        except ValueError:
            pass

        try:
            policies.add(_SCHED_POLICIES[a.upper()])
        except KeyError:
            raise ValueError(f"invalid scheduling policy: {a}") from None
    return policies


def _format_nanosecond_duration(nanoseconds: int) -> str:
    days, nanoseconds = divmod(nanoseconds, 86400_000_000_000)
    hours, nanoseconds = divmod(nanoseconds, 3600_000_000_000)
    minutes, nanoseconds = divmod(nanoseconds, 60_000_000_000)
    seconds, nanoseconds = divmod(nanoseconds, 1_000_000_000)
    milliseconds = nanoseconds // 1_000_000
    return f"{days} {hours:02d}:{minutes:02d}:{seconds:02d}.{milliseconds:03d}"


def _ps_parents(task_selector: _TaskSelector, drgn_arg: bool) -> None:
    prog = task_selector.prog

    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)
        with task_selector.begin_task_loop(code):
            with code.begin_block("while True:\n"):
                code.append_task_header()
                code.append(
                    """\

parent = task.parent.read_()
if parent == task:
    break
task = parent
"""
                )
        return code.print()

    first = True
    for task in task_selector.tasks():
        if first:
            first = False
        else:
            print()

        parents = [task]
        while True:
            parent = task.parent.read_()
            if parent == task:
                break
            parents.append(parent)
            task = parent

        for level, task in enumerate(reversed(parents)):
            sys.stdout.write(" " * level)
            print_task_header(task)


def _ps_children(task_selector: _TaskSelector, drgn_arg: bool) -> None:
    prog = task_selector.prog

    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)
        with task_selector.begin_task_loop(code):
            code.append_task_header()
            code.add_from_import("drgn.helpers.linux.list", "list_for_each_entry")
            with code.begin_block(
                """\
for child in list_for_each_entry(
    "struct task_struct", task.children.address_of_(), "sibling"
):
"""
            ):
                code.append_task_header(variable="child")
        return code.print()

    first = True
    for task in task_selector.tasks():
        if first:
            first = False
        else:
            print()

        print_task_header(task)
        found = False
        for child in list_for_each_entry(
            "struct task_struct", task.children.address_of_(), "sibling"
        ):
            found = True
            sys.stdout.write("  ")
            print_task_header(child)
        if not found:
            print("  (no children)")


def _ps_times(task_selector: _TaskSelector, drgn_arg: bool) -> None:
    prog = task_selector.prog

    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import("drgn.helpers.linux.timekeeping", "ktime_get_coarse_ns")
        code.append("now = ktime_get_coarse_ns()\n\n")
        with task_selector.begin_task_loop(code):
            code.append_task_header()
            code.append(
                """\
start_time = task.start_time
run_time = now - start_time
utime = task.utime
stime = task.stime
"""
            )
        return code.print()

    now = ktime_get_coarse_ns(prog)

    first = True
    for task in task_selector.tasks():
        if first:
            first = False
        else:
            print()

        print_task_header(task)
        start_time = task.start_time.value_()
        sys.stdout.write(
            f"""\
    RUN TIME: {_format_seconds_duration((now.value_() - start_time) // 1_000_000_000)}
  START TIME: {start_time}
       UTIME: {task.utime.value_()}
       STIME: {task.stime.value_()}
"""
        )


def _ps_last_arrival(
    task_selector: _TaskSelector,
    drgn_arg: bool,
    elapsed: bool,
    cpuspec: Optional[Cpuspec],
) -> None:
    prog = task_selector.prog

    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)
        with task_selector.begin_task_loop(code):
            if elapsed:
                code.add_from_import(
                    "drgn.helpers.linux.sched", "task_since_last_arrival_ns"
                )
                code.append("elapsed = task_since_last_arrival_ns(task)\n")
            else:
                code.append("last_arrival = task.sched_info.last_arrival\n")
            code.add_from_import("drgn.helpers.linux.sched", "task_state_to_char")
            code.append("state = task_state_to_char(task)\n")
            # append_task_header() already gets the CPU, so we don't bother
            # doing anything with the cpuspec.
            code.append_task_header()
        return code.print()

    rows = [
        (
            task.sched_info.last_arrival.value_(),
            task_cpu(task),
            task_state_to_char(task),
            task,
        )
        for task in task_selector.tasks()
    ]
    if elapsed:
        rq_clocks = {
            cpu: cpu_rq(prog, cpu).clock.value_() for cpu in for_each_online_cpu(prog)
        }
    rows.sort(reverse=True)

    def print_rows(rows: Sequence[Tuple[int, int, str, Object]]) -> None:
        timestamp_width = None

        for last_arrival, cpu, state, task in rows:
            if elapsed:
                timestamp = _format_nanosecond_duration(rq_clocks[cpu] - last_arrival)
            else:
                timestamp = str(last_arrival)

            if timestamp_width is None:
                timestamp_width = len(timestamp)
            sys.stdout.write(f"[{timestamp:>{timestamp_width}}] [{state}]  ")
            _print_task_header(task, cpu=cpu)

    if cpuspec is None:
        print_rows(rows)
    else:
        first = True
        for cpu in cpuspec.cpus(prog):
            if first:
                first = False
            else:
                print()
            print(f"CPU: {cpu}")
            print_rows([row for row in rows if row[1] == cpu])


def _ps_arguments(task_selector: _TaskSelector, drgn_arg: bool) -> None:
    prog = task_selector.prog

    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)
        with task_selector.begin_task_loop(code):
            code.append_task_header()
            code.add_from_import("drgn.helpers.linux.mm", "cmdline", "environ")
            code.append(
                """\
arg = cmdline(task)
env = environ(task)
"""
            )
        return code.print()

    first = True
    for task in task_selector.tasks():
        if first:
            first = False
        else:
            print()

        print_task_header(task)

        mm = task.mm.read_()
        if not mm:
            print("  (no mm)")
            continue

        try:
            argv = mm_cmdline(mm)
        except FaultError as e:
            print("ps:", e)
        else:
            print(f"ARG: {' '.join([escape_ascii_string(arg) for arg in argv])}")

        try:
            envp = mm_environ(mm)
        except FaultError as e:
            print("ps:", e)
        else:
            if envp:
                prefix = "ENV:"
                for env in envp:
                    print(prefix, escape_ascii_string(env))
                    prefix = "    "
            else:
                print("ENV:")


def _ps_thread_groups(task_selector: _TaskSelector, drgn_arg: bool) -> None:
    prog = task_selector.prog

    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)
        with task_selector.begin_task_loop(code):
            code.append_task_header()
            code.add_from_import("drgn.helpers.linux.pid", "for_each_task_in_group")
            with code.begin_block("for thread in for_each_task_in_group(task):\n"):
                code.append_task_header(variable="thread")
        return code.print()

    first = True
    for task in task_selector.tasks():
        if first:
            first = False
        else:
            print()

        print_task_header(task)
        found = False
        for task in for_each_task_in_group(task):
            found = True
            sys.stdout.write("  ")
            print_task_header(task)
        if not found:
            print("  (no threads)")


def _ps_rlimit(task_selector: _TaskSelector, drgn_arg: bool) -> None:
    prog = task_selector.prog

    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)
        with task_selector.begin_task_loop(code):
            code.append_task_header()
            code.add_from_import("drgn.helpers.linux.resource", "task_rlimits")
            code.append("rlimits = task_rlimits(task)\n")
        return code.print()

    first = True
    for task in task_selector.tasks():
        if first:
            first = False
        else:
            print()

        print_task_header(task)
        print_table(
            [
                (
                    "",
                    CellFormat("RLIMIT", ">"),
                    CellFormat("CURRENT", "^"),
                    CellFormat("MAXIMUM", "^"),
                ),
                *(
                    (
                        "",
                        CellFormat(name, ">"),
                        CellFormat(
                            "(unlimited)" if limit.cur is None else limit.cur, "^"
                        ),
                        CellFormat(
                            "(unlimited)" if limit.max is None else limit.max, "^"
                        ),
                    )
                    for name, limit in task_rlimits(task).items()
                ),
            ]
        )


def _ps_summary(task_selector: _TaskSelector, drgn_arg: bool) -> None:
    prog = task_selector.prog

    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)
        code.add_import("collections")
        code.append("counter = collections.Counter()\n")
        with task_selector.begin_task_loop(code):
            code.add_from_import("drgn.helpers.linux.sched", "task_state_to_char")
            code.append("counter[task_state_to_char(task)] += 1\n")
        code.append(
            """\

for state, num in counter.items():
    ...
"""
        )
        return code.print()

    for state, num in collections.Counter(
        task_state_to_char(task) for task in task_selector.tasks()
    ).items():
        print(f"  {state}: {num}")


@_crash_foreach_subcommand(
    arguments=(
        argument(
            "-G",
            dest="group_leader",
            action="store_true",
        ),
        argument(
            "-y",
            dest="policy",
        ),
        mutually_exclusive_group(
            argument(
                "-s",
                dest="stack_pointer",
                action="store_true",
            ),
            argument(
                "-p",
                dest="func",
                action="store_const",
                const=_ps_parents,
            ),
            argument(
                "-c",
                dest="func",
                action="store_const",
                const=_ps_children,
            ),
            argument(
                "-t",
                dest="func",
                action="store_const",
                const=_ps_times,
            ),
            argument(
                "-l",
                dest="last_arrival_timestamp",
                action="store_true",
            ),
            argument(
                "-m",
                dest="last_arrival_elapsed",
                action="store_true",
            ),
            argument(
                "-a",
                dest="func",
                action="store_const",
                const=_ps_arguments,
            ),
            argument(
                "-g",
                dest="func",
                action="store_const",
                const=_ps_thread_groups,
            ),
            argument(
                "-r",
                dest="func",
                action="store_const",
                const=_ps_rlimit,
            ),
            argument(
                "-S",
                dest="func",
                action="store_const",
                const=_ps_summary,
            ),
        ),
        argument(
            "-C",
            dest="cpu",
        ),
        argument(
            "-H",
            dest="header",
            action="store_false",
        ),
        # Note: crash doesn't support foreach ps -S, -H, or -C, but supporting
        # them actually makes things easier for us, so we do.
        drgn_argument,
    ),
)
def _crash_foreach_ps(task_selector: _TaskSelector, args: argparse.Namespace) -> None:
    if args.last_arrival_timestamp or args.last_arrival_elapsed:
        cpuspec = None if args.cpu is None else parse_cpuspec(args.cpu)
    elif args.cpu is not None:
        raise CommandArgumentError("-C can only be used with -l or -m")

    if args.group_leader or args.func == _ps_thread_groups:
        task_selector._group_leader = True
    if args.policy is not None:
        task_selector._policies = _parse_sched_policies(args.policy)

    if args.func is not None:
        return args.func(task_selector, args.drgn)

    if args.last_arrival_timestamp or args.last_arrival_elapsed:
        return _ps_last_arrival(
            task_selector, args.drgn, args.last_arrival_elapsed, cpuspec
        )

    prog = task_selector.prog

    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import(
            "drgn.helpers.linux.mm", "task_rss", "task_vsize", "totalram_pages"
        )
        code.append("total_mem = totalram_pages()\n\n")
        with task_selector.begin_task_loop(code):
            code.add_from_import(
                "drgn.helpers.linux.sched", "task_cpu", "task_state_to_char"
            )
            code.append(
                """\
pid = task.pid
ppid = task.parent.pid
cpu = task_cpu(task)
state = task_state_to_char(task)
rss = task_rss(task)
mem_usage = rss.total / total_mem
vsize = task_vsize(task)
comm = task.comm
"""
            )
        return code.print()

    rows: List[Sequence[Any]] = []
    if args.header:
        rows.append(
            (
                "",
                CellFormat("PID", ">"),
                CellFormat("PPID", ">"),
                CellFormat("CPU", ">"),
                CellFormat("KSTACKP" if args.stack_pointer else "TASK", "^"),
                "ST",
                CellFormat("%MEM", ">"),
                CellFormat("VSZ", ">"),
                CellFormat("RSS", ">"),
                "COMM",
            )
        )

    page_size = prog["PAGE_SIZE"].value_()
    total_mem = totalram_pages(prog)
    for task in task_selector.tasks():
        if args.stack_pointer:
            try:
                pointer_cell = CellFormat(prog.stack_trace(task)[0].sp, "^x")
            except ValueError:
                pointer_cell = CellFormat("--", "^")
        else:
            pointer_cell = CellFormat(task.value_(), "^x")

        rss = task_rss(prog, task)

        comm_column = escape_ascii_string(task.comm.string_(), escape_backslash=True)
        if task_is_kthread(task):
            comm_column = f"[{comm_column}]"

        rows.append(
            (
                ">" if task_selector._on_cpu or task_on_cpu(task) else "",
                task.pid.value_(),
                task.parent.pid.value_(),
                task_cpu(task),
                pointer_cell,
                task_state_to_char(task),
                CellFormat(rss.total / total_mem * 100, ".1f"),
                task_vsize(task) // 1024,
                rss.total * page_size // 1024,
                comm_column,
            )
        )
    print_table(rows)


@crash_custom_command(
    description="process information",
    long_description="display process status information",
    arguments=(
        mutually_exclusive_group(
            argument(
                "-k",
                dest="kernel",
                action="store_true",
                help="only display kernel threads",
            ),
            argument(
                "-u",
                dest="user",
                action="store_true",
                help="only display user tasks",
            ),
        ),
        argument(
            "-G",
            dest="group_leader",
            action="store_true",
            help="only display the thread group leader in each thread group",
        ),
        argument(
            "-y",
            dest="policy",
            help="""
            only display tasks with the given scheduling policy, as a
            comma-separated list of the following (case-insensitive) policy
            names or their integer values:

            |NORMAL or OTHER (0)
            |FIFO (1)
            |RR (2)
            |BATCH (3)
            |IDLE (5)
            |DEADLINE (6)
            |EXT (7)
            """,
        ),
        # In crash, -A is mutually exclusive with -p, -c, etc., but we have no
        # reason to make that restriction.
        argument(
            "-A",
            dest="active",
            action="store_true",
            help="display only the active task on each CPU",
        ),
        mutually_exclusive_group(
            argument(
                "-s",
                dest="stack_pointer",
                action="store_true",
                help="display the kernel stack pointer instead of the task_struct",
            ),
            argument(
                "-p",
                dest="func",
                action="store_const",
                const=_ps_parents,
                help="display the parental hierarchy of selected tasks",
            ),
            argument(
                "-c",
                dest="func",
                action="store_const",
                const=_ps_children,
                help="display the children of selected tasks",
            ),
            argument(
                "-t",
                dest="func",
                action="store_const",
                const=_ps_times,
                help="""
                display the task run time, start time, cumulative user time,
                and cumulative system time
                """,
            ),
            argument(
                "-l",
                dest="last_arrival_timestamp",
                action="store_true",
                help="""
                display the last_arrival timestamp of selected tasks, and sort
                from most-recent to least-recent
                """,
            ),
            argument(
                "-m",
                dest="last_arrival_elapsed",
                action="store_true",
                help="""
                like -l, but display the difference between the current
                runqueue clock and the last_arrival timestamp as
                "days hours:minutes:seconds.milliseconds"
                """,
            ),
            argument(
                "-a",
                dest="func",
                action="store_const",
                const=_ps_arguments,
                help="""
                display the command line arguments and environment variables of
                selected userspace tasks
                """,
            ),
            argument(
                "-g",
                dest="func",
                action="store_const",
                const=_ps_thread_groups,
                help="""
                display threads in the thread groups of selected tasks and
                group threads by thread group
                """,
            ),
            argument(
                "-r",
                dest="func",
                action="store_const",
                const=_ps_rlimit,
                help="display resource limits (rlimits) of selected tasks",
            ),
            argument(
                "-S",
                dest="func",
                action="store_const",
                const=_ps_summary,
                help="""
                display a summary of the number of selected tasks in each task
                state
                """,
            ),
        ),
        argument(
            "-C",
            dest="cpu",
            help="""
            for -l or -m, only display tasks on the given CPUs, which may be a
            comma-separated string of CPU numbers or ranges (e.g., '0,3-4'),
            and group selected tasks by CPU
            """,
        ),
        argument(
            "-H",
            dest="header",
            action="store_false",
            help="do not print a header line",
        ),
        argument(
            "tasks",
            metavar="pid|task|command",
            type=_pid_or_task_or_command,
            nargs="*",
            help=r"""
            display only this task, given as a decimal process ID, hexadecimal
            ``task_struct``, single-quoted (``'``) regular expression matching
            command names, or a literal command name (optionally prefixed with
            ``\`` to disambiguate it). May be given multiple times
            """,
        ),
        drgn_argument,
    ),
    parse=functools.partial(parse_shell_command, unquote=False),
)
def _crash_cmd_ps(
    prog: Program,
    name: str,
    quoted_args: Sequence[str],
    *,
    parser: argparse.ArgumentParser,
    **kwargs: Any,
) -> None:
    args = parser.parse_args(
        # Arguments starting with "'" or "\" have special meaning, so we don't
        # unquote those.
        [
            (
                arg
                if arg.startswith("'") or arg.startswith("\\")
                else unquote_shell_word(arg)
            )
            for arg in quoted_args
        ]
    )
    task_selector = _TaskSelector(
        prog,
        args.tasks,
        kernel=args.kernel,
        user=args.user,
        # Note: group_leader and policies are overridden in
        # _crash_foreach_ps().
        on_cpu=args.active,
        sort=True,
    )
    _crash_foreach_ps(task_selector, args)


@crash_custom_command(
    description="run command on multiple tasks",
    long_description="""
    Run the given command on all tasks matching the given constraints (or all
    tasks in the system if no constraints are given).
    """,
    usage=r"**foreach** [**\-\-drgn**] [*pid* | *task* | *name* ...] "
    "[**kernel** | **user** | **gleader**] [**active**] [*state*] "
    "*command* [*-option* ...]",
    arguments=(
        argument(
            "pid",
            help="run the command on the task with this decimal process ID",
        ),
        argument(
            "task",
            help="""
            run the command on the task with this hexadecimal task_struct
            address
            """,
        ),
        argument(
            "name",
            help=r"""
            run the command on tasks with the given name. May be prefixed with
            ``\`` to disambiguate it as a literal command name. If
            single-quoted (``'``), then it is treated as a regular expression
            """,
        ),
        argument(
            "kernel",
            help="run the command on kernel threads",
        ),
        argument(
            "user",
            help="run the command on user tasks",
        ),
        argument(
            "gleader",
            help="run the command on thread group leaders",
        ),
        argument(
            "active",
            help="run the command on the active task on each CPU",
        ),
        argument(
            "state",
            help='run the command on tasks in this state ("R", "D", etc.)',
        ),
        argument(
            "command",
            help="""
            run this command on the selected tasks. Currently, **files**,
            **ps**, **set**, **sig**, **task**, and **vm** are supported
            """,
        ),
        argument(
            "-option",
            action="store_true",
            help="additional option to pass to the command",
        ),
        drgn_argument,
    ),
    parse=functools.partial(parse_shell_command, unquote=False),
)
def _crash_cmd_foreach(
    prog: Program,
    name: str,
    quoted_args: Sequence[str],
    *,
    parser: argparse.ArgumentParser,
    **kwargs: Any,
) -> Any:
    args = [
        (
            arg
            if arg.startswith("'") or arg.startswith("\\")
            else unquote_shell_word(arg)
        )
        for arg in quoted_args
    ]

    tasks = []
    kernel = False
    user = False
    group_leader = False
    on_cpu = False
    state = None
    command_args = []
    for i, arg in enumerate(args):
        if arg in _CRASH_FOREACH_SUBCOMMANDS:
            subcommand = _CRASH_FOREACH_SUBCOMMANDS[arg]
            command_args.extend(args[i + 1 :])
            break
        elif arg.startswith("-"):
            command_args.append(arg)
        elif arg == "kernel":
            if group_leader:
                parser.error("gleader and kernel are mutually exclusive")
            if user:
                parser.error("user and kernel are mutually exclusive")
            kernel = True
        elif arg == "user":
            if kernel:
                parser.error("kernel and user are mutually exclusive")
            user = True
        elif arg == "gleader":
            if kernel:
                parser.error("kernel and gleader are mutually exclusive")
            user = group_leader = True
        elif arg == "active":
            on_cpu = True
        elif arg in _TASK_STATE_CHAR_TO_STATE:
            if state is not None:
                parser.error("only one task state allowed")
            state = arg
        else:
            tasks.append(_pid_or_task_or_command(arg))
    else:
        parser.error("no command given")

    return subcommand.func(
        _TaskSelector(
            prog,
            tasks,
            kernel=kernel,
            user=user,
            group_leader=group_leader,
            on_cpu=on_cpu,
            state=state,
        ),
        subcommand.parser.parse_args(command_args),
    )
