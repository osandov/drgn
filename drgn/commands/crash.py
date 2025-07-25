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
from typing import Any, FrozenSet, List, Literal, Optional, Set, Tuple

from _drgn_util.typingutils import copy_func_params
from drgn import Object, Program, ProgramFlags, Type, TypeKind
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
from drgn.helpers.linux.cpumask import for_each_possible_cpu
from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.sched import task_cpu


def _pid_or_task(s: str) -> Tuple[Literal["pid", "task"], int]:
    try:
        return "pid", int(s)
    except ValueError:
        return "task", int(s, 16)


def _guess_type(prog: Program, kind: str, name: str) -> Type:
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
    underlying_type = type
    while underlying_type.kind == TypeKind.TYPEDEF:
        underlying_type = underlying_type.type
    if (kind != "union" and underlying_type.kind == TypeKind.STRUCT) or (
        kind != "struct" and underlying_type.kind == TypeKind.UNION
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
                    kwargs["type"] = _guess_type(
                        prog, "*", command_name.partition(".")[0]
                    )
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
                raise LookupError("no such process")
            return task
        else:
            return Object(prog, "struct task_struct *", arg[1])

    try:
        return prog.config["crash_context"]
    except KeyError:
        pass
    prog.config["crash_context"] = task = _crash_get_panic_context(prog)
    return task


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
                raise ValueError(f"invalid CPUs: {self.explicit_cpus - possible}")
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
