# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Functions for porting commands from :doc:`crash <crash_compatibility>`."""

import contextlib
import os
import re
import shutil
import subprocess
import sys
from typing import Any, List, Literal, Optional, Tuple

from _drgn_util.typingutils import copy_func_params
from drgn import Object, Program, ProgramFlags
from drgn.commands import (
    CommandFuncDecorator,
    CommandNamespace,
    CustomCommandFuncDecorator,
    DrgnCodeBuilder,
    command,
    custom_command,
)
from drgn.helpers.linux.pid import find_task


def _pid_or_task(s: str) -> Tuple[Literal["pid", "task"], int]:
    try:
        return "pid", int(s)
    except ValueError:
        return "task", int(s, 16)


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

    def split_command(self, command: str) -> Tuple[str, str]:
        # '*' and '!' may be combined with their first argument.
        match = re.fullmatch(r"\s*([!*])\s*(.*)", command)
        if match:
            return match.group(1), match.group(2)
        return super().split_command(command)

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
