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
import re
import sys
from typing import (
    AbstractSet,
    Any,
    Callable,
    Iterable,
    Iterator,
    List,
    Literal,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
)

from drgn import FaultError, Object, Program
from drgn.commands import (
    DrgnCodeBlockContext,
    DrgnCodeBuilder,
    _repr_black,
    argument,
    drgn_argument,
    mutually_exclusive_group,
    parse_shell_command,
    unquote_shell_word,
)
from drgn.commands.crash import (
    Cpuspec,
    CrashDrgnCodeBuilder,
    _format_seconds_duration,
    _print_task_header,
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
from drgn.helpers.linux.pid import find_task, for_each_task, for_each_task_in_group
from drgn.helpers.linux.resource import task_rlimits
from drgn.helpers.linux.sched import (
    cpu_rq,
    idle_task,
    task_cpu,
    task_on_cpu,
    task_state_to_char,
    thread_group_leader,
)
from drgn.helpers.linux.timekeeping import ktime_get_coarse_ns

_PID_OR_TASK_OR_COMMAND = Union[
    Tuple[Literal["pid"], int],
    Tuple[Literal["task"], int],
    Tuple[Literal["command"], str],
    Tuple[Literal["command_pattern"], "re.Pattern[str]"],
]


def _pid_or_task_or_command(arg: str) -> _PID_OR_TASK_OR_COMMAND:
    try:
        return "pid", int(arg, 10)
    except ValueError:
        pass

    try:
        return "task", int(arg, 16)
    except ValueError:
        pass

    if arg:
        if arg[0] == "'" and arg[-1] == "'":
            return "command_pattern", re.compile(arg[1:-1])
        if arg[0] == "\\":
            return "command", arg[1:]
    return "command", arg


_T = TypeVar("_T")


def _in_set_condition(
    name: str, items: Iterable[_T], convert: Callable[[_T], str] = str
) -> str:
    converted = [convert(item) for item in items]
    if len(converted) == 1:
        return f"{name} == {converted[0]}"
    else:
        return f"{name} in {{{', '.join(converted)}}}"


def _not_in_set_condition(
    name: str, items: Iterable[_T], convert: Callable[[_T], str] = str
) -> str:
    converted = [convert(item) for item in items]
    if len(converted) == 1:
        return f"{name} != {converted[0]}"
    else:
        return f"{name} not in {{{', '.join(converted)}}}"


def _join_if_statement(conditions: Sequence[str], logical_op: str) -> str:
    if len(conditions) == 1:
        return f"if {conditions[0]}:\n"

    logical_op += " "
    parts = ["if (\n"]
    prefix = ""
    for condition in conditions:
        parts.append(f"    {prefix}{condition}\n")
        prefix = logical_op
    parts.append("):\n")
    return "".join(parts)


class _TaskSelector:
    def __init__(
        self,
        prog: Program,
        task_args: Sequence[_PID_OR_TASK_OR_COMMAND] = (),
        *,
        kernel: bool = False,
        user: bool = False,
        group_leader: bool = False,
        policies: Optional[AbstractSet[int]] = None,
        on_cpu: bool = False,
    ) -> None:
        self.prog = prog

        self._pids = set()
        self._task_structs = set()
        self._commands = set()
        self._command_patterns = []
        for task_arg in task_args:
            if task_arg[0] == "pid":
                self._pids.add(task_arg[1])
            elif task_arg[0] == "task":
                self._task_structs.add(task_arg[1])
            elif task_arg[0] == "command_pattern":
                self._command_patterns.append(task_arg[1])
            else:
                self._commands.add(task_arg[1])

        self._kernel = kernel
        self._user = user
        self._group_leader = group_leader
        self._on_cpu = on_cpu
        self._policies = policies

    def _find_by_pid(self) -> bool:
        return bool(
            self._pids
            and not self._task_structs
            and not self._commands
            and not self._command_patterns
        )

    def _filter(self, task: Object) -> Optional[Object]:
        if self._kernel and not task_is_kthread(task):
            return None
        if self._user and task_is_kthread(task):
            return None
        if self._policies is not None and task.policy.value_() not in self._policies:
            return None
        if self._on_cpu and not task_on_cpu(task):
            return None

        if not self._pids and not self._task_structs:
            if self._group_leader and not thread_group_leader(task):
                return None
            if not self._commands and not self._command_patterns:
                return task

        if (
            # If we found the task by PID, then we don't need to check the PID
            # again.
            self._find_by_pid()
            # Otherwise, only read task.pid if we're filtering by PID.
            or (self._pids and task.pid.value_() in self._pids)
            or task.value_() in self._task_structs
        ):
            # If we only want group leaders and match a non-group leader by PID
            # or task_struct, then it should be replaced by its group leader.
            if self._group_leader and not thread_group_leader(task):
                return task.group_leader.read_()
            return task

        # Only read task.comm if we're filtering by comm.
        if self._commands or self._command_patterns:
            comm = task.comm.string_().decode(errors="surrogateescape")
            if comm in self._commands or any(
                pattern.search(comm) for pattern in self._command_patterns
            ):
                return task

        return None

    def tasks(self) -> Iterator[Object]:
        # If we're filtering by PID but not by task_struct or comm, then we can
        # avoid iterating over every task.
        if self._find_by_pid():
            for pid in sorted(self._pids):
                if pid == 0:
                    for cpu in for_each_online_cpu(self.prog):
                        filtered_task = self._filter(idle_task(self.prog, cpu))
                        if filtered_task is not None:
                            yield filtered_task
                    continue

                task = find_task(self.prog, pid)
                if not task:
                    print(f"ps: no such process with PID {pid}")
                    continue

                filtered_task = self._filter(task)
                if filtered_task is not None:
                    yield filtered_task
            return

        unmatched_task_structs = self._task_structs.copy()
        for task in for_each_task(
            self.prog,
            # If we only want user tasks, then we don't need the idle tasks.
            # That is, unless we are filtering by task_struct, in case we need
            # them to check the validity of the given task_structs.
            idle=not self._user or bool(self._task_structs),
        ):
            unmatched_task_structs.discard(task.value_())

            filtered_task = self._filter(task)
            if filtered_task is not None:
                yield filtered_task

        for task_value in unmatched_task_structs:
            print(f"ps: invalid task_struct: {task_value:#x}")

    def begin_task_loop(self, code: DrgnCodeBuilder) -> DrgnCodeBlockContext:
        if self._find_by_pid():
            code.append("tasks = []\n")
            if 0 in self._pids:
                code.add_from_import(
                    "drgn.helpers.linux.cpumask", "for_each_online_cpu"
                )
                code.add_from_import("drgn.helpers.linux.sched", "idle_task")
                code.append(
                    """\
for cpu in for_each_online_cpu():
    tasks.append(idle_task(cpu))
"""
                )
            non_zero_pids = [pid for pid in self._pids if pid != 0]
            non_zero_pids.sort()
            if non_zero_pids:
                code.add_from_import("drgn.helpers.linux.pid", "find_task")
                if len(non_zero_pids) == 1:
                    code.append(f"pid = {non_zero_pids[0]}\n")
                    pid_block = code.begin_block("")
                else:
                    pids_str = ", ".join([str(pid) for pid in non_zero_pids])
                    pid_block = code.begin_block(f"for pid in ({pids_str}):\n")
                code.append(
                    """\
task = find_task(pid)
if task:
    tasks.append(task)
"""
                )
                pid_block.end()
            block = code.begin_block("for task in tasks:\n")
        else:
            code.add_from_import("drgn.helpers.linux.pid", "for_each_task")
            idle = "idle=True" if not self._user or self._task_structs else ""
            block = code.begin_block(f"for task in for_each_task({idle}):\n")

        if self._kernel:
            code.add_from_import("drgn.helpers.linux.kthread", "task_is_kthread")
            code.append("if not task_is_kthread(task):\n    continue\n")
        if self._user:
            code.add_from_import("drgn.helpers.linux.kthread", "task_is_kthread")
            code.append("if task_is_kthread(task):\n    continue\n")
        if self._policies is not None:
            condition = _not_in_set_condition(
                "task.policy.value_()", sorted(self._policies)
            )
            code.append(f"if {condition}:\n    continue\n")
        if self._on_cpu:
            code.add_from_import("drgn.helpers.linux.sched", "task_on_cpu")
            code.append("if not task_on_cpu(task):\n    continue\n")

        block2 = None
        if self._find_by_pid():
            if self._group_leader:
                code.add_from_import("drgn.helpers.linux.sched", "thread_group_leader")
                code.append(
                    """\
if not thread_group_leader(task):
    task = task.group_leader.read_()
"""
                )
        elif self._pids or self._task_structs:
            if self._group_leader or self._commands or self._command_patterns:
                condition_func = _in_set_condition
                logical_op = "or"
            else:
                condition_func = _not_in_set_condition
                logical_op = "and"

            conditions = []
            if self._pids:
                conditions.append(
                    condition_func("task.pid.value_()", sorted(self._pids))
                )
            if self._task_structs:
                conditions.append(
                    condition_func("task.value_()", sorted(self._task_structs), hex)
                )
            code.append(_join_if_statement(conditions, logical_op))

            if self._group_leader:
                code.add_from_import("drgn.helpers.linux.sched", "thread_group_leader")
                code.append(
                    """\
    if not thread_group_leader(task):
        task = task.group_leader.read_()
"""
                )
            elif self._commands or self._command_patterns:
                code.append("    pass\n")

            if self._commands or self._command_patterns:
                block2 = code.begin_block("else:\n")
            else:
                if self._group_leader:
                    code.append("else:\n")
                code.append("    continue\n")
        elif self._group_leader:
            code.add_from_import("drgn.helpers.linux.sched", "thread_group_leader")
            code.append("if not thread_group_leader(task):\n    continue\n")

        if self._commands or self._command_patterns:
            code.append("comm_string = task.comm.string_().decode()\n")
            conditions = []
            if self._commands:
                conditions.append(
                    _not_in_set_condition(
                        "comm_string", sorted(self._commands), _repr_black
                    )
                )
            if self._command_patterns:
                code.add_import("re")
                for pattern in self._command_patterns:
                    conditions.append(
                        f"not re.search({_repr_black(pattern.pattern)}, comm_string)"
                    )
            code.append(_join_if_statement(conditions, "and"))
            code.append("    continue\n")

        if block2:
            block2.end()

        return block


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

    if args.last_arrival_timestamp or args.last_arrival_elapsed:
        cpuspec = None if args.cpu is None else parse_cpuspec(args.cpu)
    elif args.cpu is not None:
        parser.error("-C can only be used with -l or -m")

    task_selector = _TaskSelector(
        prog,
        args.tasks,
        kernel=args.kernel,
        user=args.user,
        group_leader=args.group_leader or args.func == _ps_thread_groups,
        policies=None if args.policy is None else _parse_sched_policies(args.policy),
        on_cpu=args.active,
    )

    if args.func is not None:
        return args.func(task_selector, args.drgn)

    if args.last_arrival_timestamp or args.last_arrival_elapsed:
        return _ps_last_arrival(
            task_selector, args.drgn, args.last_arrival_elapsed, cpuspec
        )

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
                ">" if args.active or task_on_cpu(task) else "",
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
