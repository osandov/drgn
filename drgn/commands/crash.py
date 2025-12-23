# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Functions for porting commands from :doc:`crash <crash_compatibility>`."""

import argparse
import dataclasses
import functools
import operator
import os
import re
import shlex
import shutil
import textwrap
from typing import (
    AbstractSet,
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    Iterator,
    List,
    Literal,
    NamedTuple,
    Optional,
    Sequence,
    Set,
    Tuple,
    TypeVar,
    Union,
)

from drgn import FaultError, Object, Program, ProgramFlags, Type, TypeKind, offsetof
from drgn.commands import (
    _SHELL_TOKEN_REGEX,
    DEFAULT_COMMAND_NAMESPACE,
    Command,
    CommandNamespace,
    CommandNotFoundError,
    DrgnCodeBlockContext,
    DrgnCodeBuilder,
    ParsedCommand,
    _command_name,
    _create_parser,
    _repr_black,
    argument,
    argument_group,
    command,
    custom_command,
    mutually_exclusive_group,
    unquote_shell_word,
)
from drgn.helpers.common.format import double_quote_ascii_string
from drgn.helpers.linux.cpumask import for_each_online_cpu, for_each_possible_cpu
from drgn.helpers.linux.kthread import task_is_kthread
from drgn.helpers.linux.pid import find_task, for_each_task
from drgn.helpers.linux.sched import (
    idle_task,
    task_cpu,
    task_on_cpu,
    task_state_to_char,
    thread_group_leader,
)

_PID_OR_TASK = Union[
    Tuple[Literal["pid"], int],
    Tuple[Literal["task"], int],
]


def _pid_or_task(s: str) -> _PID_OR_TASK:
    try:
        return "pid", int(s)
    except ValueError:
        return "task", int(s, 16)


_PID_OR_TASK_OR_COMMAND = Union[
    _PID_OR_TASK,
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


def _addr_or_sym(
    s: str,
) -> Union[Tuple[Literal["addr"], int], Tuple[Literal["sym"], str]]:
    try:
        return "addr", int(s, 16)
    except ValueError:
        return "sym", s


def _guess_type(prog: Program, name: str, kind: str = "*") -> Type:
    if kind != "union":
        try:
            return prog.type("struct " + name)
        except LookupError:
            pass

    if kind != "struct":
        try:
            return prog.type("union " + name)
        except LookupError:
            pass

    # Try a typedef.
    type = prog.type(name)

    # Make sure it's a typedef of our desired type kind.
    unaliased_kind = type.unaliased_kind()
    if (kind != "union" and unaliased_kind == TypeKind.STRUCT) or (
        kind != "struct" and unaliased_kind == TypeKind.UNION
    ):
        return type

    if kind == "*":
        kind = "struct or union"
    raise LookupError(f"{type.type_name()} is not a {kind}")


def _guess_type_name(prog: Program, name: str, kind: str = "*") -> str:
    try:
        type = _guess_type(prog, name, kind)
    except LookupError:
        return f"{'struct' if kind == '*' else kind} {name}"
    return type.type_name()


def _object_format_options(
    prog: Program, integer_base: Optional[int]
) -> Dict[str, Any]:
    return {
        "columns": shutil.get_terminal_size().columns,
        "dereference": False,
        "integer_base": integer_base or prog.config.get("crash_radix", 10),
    }


def _format_seconds_duration(seconds: int) -> str:
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    if days:
        return f"{days} days, {hours:02}:{minutes:02}:{seconds:02}"
    else:
        return f"{hours:02}:{minutes:02}:{seconds:02}"


def _find_pager(which: Optional[str] = None) -> Optional[str]:
    if which is None or which == "less":
        less = shutil.which("less")
        if less:
            return f"{shlex.quote(less)} -E -X"

    if which is None or which == "more":
        more = shutil.which("more")
        if more:
            return shlex.quote(more)

    return None


def _get_pager(prog: Program) -> Optional[str]:
    if not prog.config.get("crash_scroll", True):
        return None
    try:
        return prog.config["crash_pager"]
    except KeyError:
        pager = _find_pager()
        prog.config["crash_pager"] = pager
        return pager


class _CrashCommandNamespace(CommandNamespace):
    def __init__(self) -> None:
        super().__init__(
            func_name_prefix="_crash_cmd_",
            argparse_types=(
                ("pid_or_task", _pid_or_task),
                ("addr_or_sym", _addr_or_sym),
            ),
        )

    def _resolve(
        self, prog: Program, command: str, kwargs: Dict[str, Any]
    ) -> Tuple[str, str, Command[object], Optional[str]]:
        command = command.lstrip()
        if command.startswith("!"):
            return (
                "!",
                command[1:].lstrip(),
                DEFAULT_COMMAND_NAMESPACE.lookup(prog, "sh"),
                None,
            )

        if command.startswith("*"):
            name = "*"
            command_obj = self.lookup(prog, "*")
            tail = command[1:].lstrip()
        else:
            match = _SHELL_TOKEN_REGEX.match(command)
            if not match or match.lastgroup != "WORD":
                raise SyntaxError("expected command name")

            name = unquote_shell_word(match.group())
            try:
                command_obj = self.lookup(prog, name)
            except CommandNotFoundError as e:
                try:
                    # Smuggle the type into the command function.
                    kwargs["type"] = _guess_type(prog, name.partition(".")[0])
                except LookupError:
                    raise e
                else:
                    name = "*"
                    command_obj = self.lookup(prog, "*")
                    tail = command
            else:
                tail = command[match.end() :].lstrip()

        return name, tail, command_obj, None if name == "drgn" else _get_pager(prog)


CRASH_COMMAND_NAMESPACE: CommandNamespace = _CrashCommandNamespace()
"""Command namespace used for crash commands."""


crash_command = functools.partial(command, namespace=CRASH_COMMAND_NAMESPACE)
"""
Decorator to register a :doc:`crash command <crash_compatibility>`.

This is the same as :func:`~drgn.commands.command()` other than the following:

1. The command is only available as a subcommand of the :drgncommand:`crash`
   command.
2. If *name* is not given, then the name of the decorated function must begin
   with ``_crash_cmd_`` instead of ``_cmd_``.
3. The command may use the ``"pid_or_task"`` argparse type to parse a task
   context argument to a ``(type, value)`` tuple, where ``type`` is either
   ``"pid"`` or ``"task"`` and ``value`` is an :class:`int`.
"""

crash_custom_command = functools.partial(
    custom_command, namespace=CRASH_COMMAND_NAMESPACE
)
"""
Like :func:`crash_command()` but for :func:`~drgn.commands.custom_command()`.
"""

# mypy doesn't handle functools.partial(functools.partial(...), ...) very well,
# so we wrap custom_command() directly instead of raw_command().
crash_raw_command = functools.partial(
    custom_command, parse=ParsedCommand, namespace=CRASH_COMMAND_NAMESPACE
)
"""
Like :func:`crash_command()` but for :func:`~drgn.commands.raw_command()`.
"""


def _crash_get_panic_context(prog: Program) -> Object:
    if (prog.flags & (ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL)) == (
        ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL
    ):
        return find_task(prog, os.getpid())
    elif not (prog.flags & ProgramFlags.IS_LIVE):
        return prog.crashed_thread().object
    else:
        raise ValueError("no default context")


def _is_valid_task_struct(task: Object) -> bool:
    try:
        pid = task.pid.value_()
        if pid:
            return find_task(task.prog_, task.pid) == task
        else:
            return idle_task(task.prog_, task_cpu(task)) == task
    except FaultError:
        return False


def crash_get_context(
    prog: Program, arg: Optional[Tuple[Literal["pid", "task"], int]] = None
) -> Object:
    """
    Get the task context to use for a crash command.

    :param arg: Context parsed by the ``"pid_or_task"`` argparse type to use.
        If ``None`` or not given, use the current context.
    :return: ``struct task_struct *``
    """
    if arg is not None:
        if arg[0] == "pid":
            task = find_task(prog, arg[1])
            if not task:
                raise LookupError("no such process with PID {}".format(arg[1]))
            return task
        else:
            task = Object(prog, "struct task_struct *", arg[1])
            if not _is_valid_task_struct(task):
                raise LookupError(f"invalid task_struct: {arg[1]:#x}")
            return task

    try:
        return prog.config["crash_context"]
    except KeyError:
        pass
    prog.config["crash_context"] = task = _crash_get_panic_context(prog)
    return task


def print_task_header(task: Object) -> None:
    """Print basic information about a task in the same format as crash."""
    _print_task_header(task, cpu=task_cpu(task))


def _print_task_header(task: Object, *, cpu: int) -> None:
    print(
        f"PID: {task.pid.value_():<7}  "
        f"TASK: {task.value_():x}  "
        f"CPU: {cpu}  "
        f"COMMAND: {double_quote_ascii_string(task.comm.string_())}"
    )


@dataclasses.dataclass(frozen=True)
class Cpuspec:
    """Parsed crash CPU specifier."""

    current: bool = False
    """Include the CPU of the current context."""

    all: bool = False
    """Include all possible CPUs."""

    explicit_cpus: FrozenSet[int] = frozenset()
    """Explicitly listed CPUs."""

    def __post_init__(self) -> None:
        if self.current + self.all + bool(self.explicit_cpus) > 1:
            raise ValueError(
                "at most one of current, all, or explicit_cpus may be given"
            )

    def cpus(self, prog: Program) -> List[int]:
        """
        Resolve the CPU specifier to a sorted list of CPU numbers, checking
        that all given CPUs were valid.
        """
        if self.current:
            return [task_cpu(crash_get_context(prog))]
        elif self.all:
            return sorted(for_each_possible_cpu(prog))
        elif self.explicit_cpus:
            possible = set(for_each_possible_cpu(prog))
            if not self.explicit_cpus.issubset(possible):
                raise ValueError(
                    f"invalid CPUs: {','.join([str(cpu) for cpu in self.explicit_cpus - possible])}"
                )
            return sorted(self.explicit_cpus)
        else:
            return []


def parse_cpuspec(spec: str) -> Cpuspec:
    """
    Parse a crash CPU specifier.

    A CPU specifier may be a comma-separated string of CPU numbers or ranges
    (e.g., '0,3-4'), 'a' or 'all' (meaning all possible CPUs), or an empty
    string (meaning the CPU of the current context).
    """
    if not spec:
        return Cpuspec(current=True)

    # Crash's parser is much more permissive: it allows extra commas (e.g.,
    # 0,,1,), extra hyphens (e.g., 0-1-2,-3--4-), and mixing "all" with CPU
    # numbers (e.g., 0-1,all). We chose to be stricter, but we can loosen it if
    # requested.
    if spec == "a" or spec == "all":
        return Cpuspec(all=True)

    cpus: Set[int] = set()
    for part in spec.split(","):
        match = re.fullmatch(r"([0-9]+)(?:-([0-9]+))?", part)
        if not match:
            raise ValueError(f"invalid cpuspec: {spec}") from None
        if match.group(2):
            cpus.update(range(int(match.group(1)), int(match.group(2)) + 1))
        else:
            cpus.add(int(match.group(1)))
    return Cpuspec(explicit_cpus=frozenset(cpus))


_TYPE_NAME_PATTERN = r"[a-zA-Z_][a-zA-Z0-9_]*"
_MEMBER_PATTERN = r"[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*|\[[0-9]+\])*"


# Parse a type name followed by a "." and a member name.
def _parse_type_name_and_member(arg: str) -> Tuple[str, str]:
    name, _, member = arg.partition(".")
    if not re.fullmatch(_TYPE_NAME_PATTERN, name):
        raise ValueError(f"invalid type name: {name}")
    if not re.fullmatch(_MEMBER_PATTERN, member):
        raise ValueError(f"invalid member name: {member}")
    return name, member


# Parse a type name optionally followed by a "." and one or more
# comma-separated members.
def _parse_type_name_and_members(arg: str) -> Tuple[str, List[str]]:
    name, sep, members_str = arg.partition(".")
    if not re.fullmatch(_TYPE_NAME_PATTERN, name):
        raise ValueError(f"invalid type name: {name}")
    if not sep:
        return name, []
    members = members_str.split(",")
    for member in members:
        if not re.fullmatch(_MEMBER_PATTERN, member):
            raise ValueError(f"invalid member name: {member}")
    return name, members


# Parse one or more comma-separated members.
def _parse_members(arg: str) -> List[str]:
    members = arg.split(",")
    for member in members:
        if not re.fullmatch(_MEMBER_PATTERN, member):
            raise ValueError(f"invalid member name: {member}")
    return members


# Sanitize a member name, which can contain "." and "[]" operators, to a name
# suitable for a variable.
def _sanitize_member_name(name: str) -> str:
    return re.sub(r"\.|\[([^]]+)\]", r"_\1", name)


# Parse a type offset, either as a number of bytes or a type name followed by a
# "." and a member.
def _parse_type_offset_arg(arg: str) -> Union[int, Tuple[str, str]]:
    if "." not in arg:
        try:
            return int(arg, 0)
        except ValueError:
            raise ValueError(f"invalid offset: {arg}") from None
    return _parse_type_name_and_member(arg)


# Resolve a type offset parsed with _parse_type_offset_arg() to a number of
# bytes. If match_type is given and it matches the type name, it will be used
# instead of guessing the type.
def _resolve_type_offset_arg(
    prog: Program,
    arg: Union[int, Tuple[str, str], None],
    match_type: Optional[Type] = None,
) -> int:
    if arg is None:
        return 0
    elif isinstance(arg, int):
        return arg
    else:
        name, member = arg

        if match_type is not None:
            try:
                match_name = match_type.tag
            except AttributeError:
                match_name = getattr(match_type, "name", None)
            if name == match_name:
                return offsetof(match_type, member)

        return offsetof(_guess_type(prog, name), member)


# For commands that do a symbol lookup, return whether an object lookup would
# be preferred for the sake of making --drgn output more idiomatic.
def _prefer_object_lookup(
    prog: Program, type_name: str, symbol_name: str, *, strict_type_name: bool = True
) -> bool:
    try:
        symbol_address = prog.symbol(symbol_name).address
    except LookupError:
        # If a symbol isn't found, prefer an object lookup.
        return True

    try:
        object = prog[symbol_name]
    except KeyError:
        # If an object isn't found but a symbol is, prefer a symbol lookup.
        return False

    # If both a symbol and an object are found, prefer an object lookup iff the
    # addresses are the same and the object has the desired type.
    if object.address_ != symbol_address:
        return False

    type = object.type_
    while True:
        if type.type_name() == type_name or (
            not strict_type_name and getattr(type, "tag", None) == type_name
        ):
            return True

        if type.kind != TypeKind.TYPEDEF:
            return False
        type = type.type


class CrashDrgnCodeBuilder(DrgnCodeBuilder):
    """
    Helper class for generating code for :func:`drgn_argument` for crash
    commands.
    """

    def _append_crash_panic_context(self) -> None:
        if (self._prog.flags & (ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL)) == (
            ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL
        ):
            self.add_import("os")
            self.add_from_import("drgn.helpers.linux.pid", "find_task")
            self.append("task = find_task(os.getpid())\n")
        else:
            self.add_from_import("drgn.helpers.linux.panic", "panic_task")
            self.append("task = panic_task()\n")

    def _append_crash_cpu_context(self, cpu: int) -> None:
        self.add_from_import("drgn.helpers.linux.sched", "cpu_curr")
        self.append(
            f"""\
cpu = {cpu}
task = cpu_curr(cpu)
"""
        )

    def _append_crash_pid_context(self, pid: int) -> None:
        self.add_from_import("drgn.helpers.linux.pid", "find_task")
        self.append(
            f"""\
pid = {pid}
task = find_task(pid)
"""
        )

    def _append_crash_task_context(self, address: int) -> None:
        self.add_from_import("drgn", "Object")
        self.append(
            f"""\
address = {hex(address)}
task = Object(prog, "struct task_struct *", address)
"""
        )

    def append_crash_context(
        self, arg: Optional[Tuple[Literal["pid", "task"], int]] = None
    ) -> None:
        """
        Append code for getting the task context in a variable named ``task``.

        :param arg: Context parsed by the ``"pid_or_task"`` argparse type to
            use. If ``None`` or not given, use the current context.
        """

        if arg is None:
            arg = self._prog.config.get("crash_context_origin")
            if arg is None:
                self._append_crash_panic_context()
                return
            elif arg[0] == "cpu":
                self._append_crash_cpu_context(arg[1])
                return

        if arg[0] == "pid":
            self._append_crash_pid_context(arg[1])
        else:
            assert arg[0] == "task"
            self._append_crash_task_context(arg[1])

    def append_task_header(self, indent: str = "", *, variable: str = "task") -> None:
        """Append code for getting basic information about a task."""
        self.add_from_import("drgn.helpers.linux.sched", "task_cpu")
        self.append(
            textwrap.indent(
                f"""\
pid = {variable}.pid
cpu = task_cpu({variable})
command = {variable}.comm
""",
                indent,
            )
        )

    def begin_cpuspec_loop(self, cpuspec: Cpuspec) -> DrgnCodeBlockContext:
        """
        Begin a loop over each CPU in a CPU specifier.

        This must be paired with
        :meth:`~drgn.commands.DrgnCodeBuilder.end_block()` or used as a context
        manager.

        :param cpuspec: CPU specifier parsed by :func:`parse_cpuspec()`.
        """
        if cpuspec.current:
            self.add_from_import("drgn.helpers.linux.sched", "task_cpu")
            self.append_crash_context()
            self.append("cpu = task_cpu(task)\n")
            return self.begin_block("")

        if cpuspec.all:
            self.add_from_import("drgn.helpers.linux.cpumask", "for_each_possible_cpu")
            return self.begin_block("for cpu in for_each_possible_cpu():\n")
        else:
            return self.begin_block(f"for cpu in {cpuspec.cpus(self._prog)!r}:\n")

    def append_cpuspec_list(self, cpuspec: Cpuspec) -> bool:
        """
        Append code that creates a variable or list containing the CPUs in a
        CPU specifier.

        :param cpuspec: CPU specifier parsed by :func:`parse_cpuspec()`.
        :return: Whether there was potentially more than one CPU, so the code
            creates a list.
        """
        if cpuspec.current:
            self.add_from_import("drgn.helpers.linux.sched", "task_cpu")
            self.append_crash_context()
            self.append("cpu = task_cpu(task)\n")
            return False
        elif cpuspec.all:
            self.add_from_import("drgn.helpers.linux.cpumask", "for_each_possible_cpu")
            self.append("cpus = list(for_each_possible_cpu())\n")
            return True
        else:
            cpus = cpuspec.cpus(self._prog)
            if len(cpus) > 1:
                self.append(f"cpus = {cpus!r}\n")
                return True
            else:
                self.append(f"cpu = {cpus[0]}\n")
                return False


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
        task_args: Sequence[Optional[_PID_OR_TASK_OR_COMMAND]] = (),
        *,
        kernel: bool = False,
        user: bool = False,
        group_leader: bool = False,
        policies: Optional[AbstractSet[int]] = None,
        on_cpu: bool = False,
        state: Optional[str] = None,
        sort: bool = False,
    ) -> None:
        self.prog = prog

        self._exact_task_args = []
        current_context = False
        self._pids = set()
        self._task_structs = set()
        self._commands = set()
        self._command_patterns = []
        for task_arg in task_args:
            if task_arg is None:
                current_context = True
            elif task_arg[0] == "pid":
                self._pids.add(task_arg[1])
            elif task_arg[0] == "task":
                self._task_structs.add(task_arg[1])
            elif task_arg[0] == "command_pattern":
                self._command_patterns.append(task_arg[1])
                continue
            else:
                self._commands.add(task_arg[1])
                continue
            self._exact_task_args.append(task_arg)

        # No commands need this, so don't bother with the added complexity.
        if current_context and (self._commands or self._command_patterns):
            raise NotImplementedError("cannot combine current context with comm filter")

        self._kernel = kernel
        self._user = user
        self._group_leader = group_leader
        self._policies = policies
        self._on_cpu = on_cpu
        self._state = state

        self._sort = sort

    def _any_filters(self) -> bool:
        return bool(
            self._commands
            or self._command_patterns
            or self._kernel
            or self._user
            or self._policies is not None
            or self._on_cpu
            or self._state is not None
        )

    def _find_exact(self) -> bool:
        return bool(
            self._exact_task_args and not self._commands and not self._command_patterns
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
        if self._state is not None and task_state_to_char(task) != self._state:
            return None

        if not self._exact_task_args:
            if self._group_leader and not thread_group_leader(task):
                return None
            if not self._commands and not self._command_patterns:
                return task

        if (
            # If we found the task by PID or address, then we don't need to
            # check the PID or address again.
            self._find_exact()
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
        # If we're filtering by exact tasks and not on comm, then we can avoid
        # iterating over every task.
        if self._find_exact():
            to_sort = []
            for task_arg in self._exact_task_args:
                if task_arg == ("pid", 0):
                    for cpu in for_each_online_cpu(self.prog):
                        filtered_task = self._filter(idle_task(self.prog, cpu))
                        if filtered_task is not None:
                            if self._sort:
                                # list.sort() is stable, so these will remain
                                # in CPU order.
                                to_sort.append((0, filtered_task))
                            else:
                                yield filtered_task
                    continue

                try:
                    task = crash_get_context(self.prog, task_arg)
                except LookupError as e:
                    print(e)
                    continue

                filtered_task = self._filter(task)
                if filtered_task is not None:
                    if self._sort:
                        # Note that we sort on the original task's PID.
                        if task_arg is not None and task_arg[0] == "pid":
                            to_sort.append((task_arg[1], filtered_task))
                        else:
                            to_sort.append((task.pid.value_(), filtered_task))
                    else:
                        yield filtered_task

            if self._sort:
                to_sort.sort(key=operator.itemgetter(0))
                for _, task in to_sort:
                    yield task
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
            print(f"invalid task_struct: {task_value:#x}")

    def begin_task_loop(self, code: CrashDrgnCodeBuilder) -> DrgnCodeBlockContext:
        if (
            self._find_exact()
            and len(self._exact_task_args) == 1
            and self._exact_task_args[0] != ("pid", 0)
            and not self._any_filters()
        ):
            task_arg = self._exact_task_args[0]
            code.append_crash_context(task_arg)
            if task_arg is None or task_arg[0] == "pid":
                block = code.begin_block("if task:\n")
            else:
                code.append("\n")
                block = code.begin_block("")
        elif self._find_exact():
            code.append("tasks = []\n\n")
            for task_arg in self._exact_task_args:
                if task_arg == ("pid", 0):
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
                else:
                    code.append_crash_context(task_arg)
                    if task_arg is None or task_arg[0] == "pid":
                        code.append("if task:\n    ")
                    code.append("tasks.append(task)\n\n")
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
        if self._state is not None:
            code.add_from_import("drgn.helpers.linux.sched", "task_state_to_char")
            code.append(
                f"if task_state_to_char(task) != {_repr_black(self._state)}:\n    continue\n"
            )

        block2 = None
        if self._find_exact():
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


_CrashForeachSubcommandFunc = Callable[[_TaskSelector, argparse.Namespace], Any]
_CrashForeachSubcommandFuncDecorator = Callable[
    [_CrashForeachSubcommandFunc], _CrashForeachSubcommandFunc
]


class _CrashForeachSubcommand(NamedTuple):
    parser: argparse.ArgumentParser
    func: _CrashForeachSubcommandFunc


_CRASH_FOREACH_SUBCOMMANDS: Dict[str, _CrashForeachSubcommand] = {}


def _crash_foreach_subcommand(
    *,
    name: Optional[str] = None,
    arguments: Sequence[Union[argument, argument_group, mutually_exclusive_group]] = (),
) -> _CrashForeachSubcommandFuncDecorator:
    def decorator(func: _CrashForeachSubcommandFunc) -> _CrashForeachSubcommandFunc:
        command_name = _command_name(name, func, "_crash_foreach_")

        parser = _create_parser(
            name="foreach " + command_name,
            arguments=arguments,
            types=CRASH_COMMAND_NAMESPACE._argparse_types,
        )

        _CRASH_FOREACH_SUBCOMMANDS[command_name] = _CrashForeachSubcommand(parser, func)

        return func

    return decorator
