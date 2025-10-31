# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Functions for porting commands from :doc:`crash <crash_compatibility>`."""

import contextlib
import dataclasses
import os
import re
import shutil
import subprocess
import sys
import textwrap
from typing import Any, FrozenSet, Iterator, List, Literal, Optional, Set, Tuple, Union

from _drgn_util.typingutils import copy_func_params
from drgn import Object, Program, ProgramFlags, Type, TypeKind, offsetof
from drgn.commands import (
    _SHELL_TOKEN_REGEX,
    CommandFuncDecorator,
    CommandNamespace,
    CommandNotFoundError,
    CustomCommandFuncDecorator,
    DrgnCodeBuilder,
    _unquote,
    command,
    custom_command,
)
from drgn.helpers.common.format import double_quote_ascii_string
from drgn.helpers.linux.cpumask import for_each_possible_cpu
from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.sched import cpu_curr, task_cpu


def _pid_or_task(s: str) -> Tuple[Literal["pid", "task"], int]:
    try:
        return "pid", int(s)
    except ValueError:
        return "task", int(s, 16)


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


def _find_pager(which: Optional[str] = None) -> Optional[List[str]]:
    if which is None or which == "less":
        less = shutil.which("less")
        if less:
            return [less, "-E", "-X"]

    if which is None or which == "more":
        more = shutil.which("more")
        if more:
            return [more]

    return None


def _get_pager(prog: Program) -> Optional[List[str]]:
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
            argparse_types=(("pid_or_task", _pid_or_task),),
        )

    def _run(self, prog: Program, command: str, **kwargs: Any) -> Any:
        command = command.lstrip()
        if command.startswith("!"):
            args = command[1:].lstrip()
            if args:
                return subprocess.call(["sh", "-c", "--", args])
            else:
                return subprocess.call(["sh", "-i"])

        if command.startswith("*"):
            command_name = "*"
            command_obj = self.lookup(prog, "*")
            args = command[1:].lstrip()
        else:
            match = _SHELL_TOKEN_REGEX.match(command)
            if not match or match.lastgroup != "WORD":
                raise SyntaxError("expected command name")

            command_name = _unquote(match.group())
            try:
                command_obj = self.lookup(prog, command_name)
            except CommandNotFoundError as e:
                try:
                    # Smuggle the type into the command function.
                    kwargs["type"] = _guess_type(prog, command_name.partition(".")[0])
                except LookupError:
                    raise e
                else:
                    command_name = "*"
                    command_obj = self.lookup(prog, "*")
                    args = command
            else:
                args = command[match.end() :].lstrip()

        return command_obj.run(prog, command_name, args, **kwargs)

    def run(self, prog: Program, command: str, **kwargs: Any) -> Any:
        if prog.config.get("crash_scroll", True):
            pager = _get_pager(prog)
            if pager:
                # If stdout isn't a file descriptor, we can't actually pipe it
                # to a pager.
                try:
                    stdout_fileno = sys.stdout.fileno()
                except (AttributeError, OSError):
                    pager = None
        else:
            pager = None

        if not pager:
            return super().run(prog, command, **kwargs)

        with subprocess.Popen(
            pager, stdin=subprocess.PIPE, stdout=stdout_fileno, text=True
        ) as pager_process, contextlib.redirect_stdout(pager_process.stdin):
            ret = super().run(prog, command, **kwargs)
            pager_process.stdin.close()  # type: ignore[union-attr]
        return ret


CRASH_COMMAND_NAMESPACE: CommandNamespace = _CrashCommandNamespace()
"""Command namespace used for crash commands."""


@copy_func_params(command)
def crash_command(*args: Any, **kwargs: Any) -> CommandFuncDecorator:
    """
    Decorator to register a :doc:`crash command <crash_compatibility>`.

    This is the same as :func:`~drgn.commands.command()` other than the
    following:

    1. The command is only available as a subcommand of the
       :drgncommand:`crash` command.
    2. If *name* is not given, then the name of the decorated function must
       begin with ``_crash_cmd_`` instead of ``_cmd_``.
    3. The command may use the ``"pid_or_task"`` argparse type to parse a task
       context argument to a ``(type, value)`` tuple, where ``type`` is either
       ``"pid"`` or ``"task"`` and ``value`` is an :class:`int`.
    """
    return command(*args, **kwargs, namespace=CRASH_COMMAND_NAMESPACE)


@copy_func_params(custom_command)
def crash_custom_command(*args: Any, **kwargs: Any) -> CustomCommandFuncDecorator:
    """
    Like :func:`crash_command()` but for
    :func:`~drgn.commands.custom_command()`.
    """
    return custom_command(*args, **kwargs, namespace=CRASH_COMMAND_NAMESPACE)


def _crash_get_panic_context(prog: Program) -> Object:
    if (prog.flags & (ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL)) == (
        ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL
    ):
        return find_task(prog, os.getpid())
    elif not (prog.flags & ProgramFlags.IS_LIVE):
        return prog.crashed_thread().object
    else:
        raise ValueError("no default context")


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
            return Object(prog, "struct task_struct *", arg[1])

    try:
        return prog.config["crash_context"]
    except KeyError:
        pass
    prog.config["crash_context"] = task = _crash_get_panic_context(prog)
    return task


def print_task_header(task: Object) -> None:
    """Print basic information about a task in the same format as crash."""
    print(
        f"PID: {task.pid.value_():<7}  "
        f"TASK: {task.value_():x}  "
        f"CPU: {task_cpu(task)}  "
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


@dataclasses.dataclass(frozen=True)
class Taskspec:
    """A set of selected tasks for a command to operate on"""

    cpuspec: Optional[Cpuspec] = None
    """Include the tasks on-CPU from the given cpu spec"""

    current: bool = False
    """The current context thread"""

    panic: bool = False
    """Only the crashed/panic thread"""

    explicit_tasks: Tuple[Tuple[Literal["pid", "task"], int], ...] = ()
    """Only explicitly listed tasks"""

    def __post_init__(self) -> None:
        if (
            bool(self.cpuspec) + self.current + self.panic + bool(self.explicit_tasks)
            > 1
        ):
            raise ValueError(
                "at most one of cpuspec, current, panic, or explicit_tasks may be given"
            )
        if self.cpuspec and self.cpuspec.current:
            raise ValueError(
                "Use Taskspec.current rather than Cpuspec.current when using Taskspec"
            )

    def tasks(self, prog: Program) -> Iterator[Object]:
        if self.cpuspec:
            for cpu in self.cpuspec.cpus(prog):
                yield cpu_curr(prog, cpu)
        elif self.current:
            # We could just let Cpuspec.current handle this, but for live
            # programs it will return the CPU number. By the time we would
            # convert that back to a task, it may no longer match the original
            # one.
            yield crash_get_context(prog)
        elif self.panic:
            yield prog.crashed_thread().object
        else:
            for kind, value in self.explicit_tasks:
                if kind == "pid":
                    yield find_task(prog, value)
                else:
                    yield Object(prog, "struct task_struct *", value=value)


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
def _prefer_object_lookup(prog: Program, type_name: str, symbol_name: str) -> bool:
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
    return object.type_.type_name() == type_name and object.address_ == symbol_address


class CrashDrgnCodeBuilder(DrgnCodeBuilder):
    """
    Helper class for generating code for :func:`drgn_argument` for crash
    commands.
    """

    def __init__(self, prog: Program) -> None:
        super().__init__()
        self._prog = prog

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

    def append_task_header(self, indent: str = "") -> None:
        """Append code for getting basic information about a task."""
        self.add_from_import("drgn.helpers.linux.sched", "task_cpu")
        self.append(
            textwrap.indent(
                """\
pid = task.pid
cpu = task_cpu(task)
command = task.comm
""",
                indent,
            )
        )

    def append_cpuspec(self, cpuspec: Cpuspec, loop_body: str) -> None:
        """
        Append code to be executed for each CPU in a CPU specifier.

        :param cpuspec: CPU specifier parsed by :func:`parse_cpuspec()`.
        :param loop_body: Code to add for each CPU. Will be indented if
            needed.
        """
        if cpuspec.current:
            self.add_from_import("drgn.helpers.linux.sched", "task_cpu")
            self.append_crash_context()
            self.append("cpu = task_cpu(task)\n")
            self.append(loop_body)
            return

        if cpuspec.all:
            self.add_from_import("drgn.helpers.linux.cpumask", "for_each_possible_cpu")
            self.append("for cpu in for_each_possible_cpu():\n")
        else:
            self.append(f"for cpu in {cpuspec.cpus(self._prog)!r}:\n")
        self.append(textwrap.indent(loop_body, "    "))

    def append_taskspec(self, taskspec: Taskspec, loop_body: str) -> None:
        """
        Append code to be executed for each CPU in a CPU specifier.

        The variables "cpu" and "task" are guaranteed to be available for
        loop_body to use.

        :param taskspec: Task specifier
        :param loop_body: Code to add for each CPU. Will be indented if
            needed.
        """
        if taskspec.cpuspec:
            # We need a "task" variable which is not already present
            self.add_from_import("drgn.helpers.linux.sched", "cpu_curr")
            loop_body = "task = cpu_curr(cpu)\n" + loop_body
            self.append_cpuspec(taskspec.cpuspec, loop_body)
        elif taskspec.current:
            self.add_from_import("drgn.helpers.linux.sched", "task_cpu")
            self.append_crash_context()
            self.append("cpu = task_cpu(task)\n")
            self.append(loop_body)
        elif taskspec.panic:
            self.add_from_import("drgn.helpers.linux.sched", "task_cpu")
            self.append(
                """\
task = prog.crashed_thread().object
cpu = task_cpu(task)
"""
            )
            self.append(loop_body)
        elif len(taskspec.explicit_tasks) == 1:
            self.add_from_import("drgn.helpers.linux.sched", "task_cpu")
            self.append_crash_context(taskspec.explicit_tasks[0])
            self.append("cpu = task_cpu(task)\n")
            self.append(loop_body)
        else:
            self.add_from_import("drgn.helpers.linux.sched", "task_cpu")
            self.append("tasks = [\n")
            for kind, val in taskspec.explicit_tasks:
                if kind == "pid":
                    self.add_from_import("drgn.helpers.linux.pid", "find_task")
                    self.append(f"    find_task({val}),\n")
                else:
                    self.add_from_import("drgn", "Object")
                    self.append(
                        f'    Object(prog, "struct task_struct *", value={val}),\n'
                    )
            self.append("]\n")
            self.append("for task in tasks:\n    cpu = task_cpu(task)\n")
            self.append(textwrap.indent(loop_body, "    "))
