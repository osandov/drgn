# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import importlib
import os
import pkgutil
import re
import sys
from typing import Any, Dict, Literal, Optional, Tuple

from _drgn_util.typingutils import copy_func_params
from drgn import Object, Program, ProgramFlags
from drgn.commands import (
    Command,
    CommandFuncDecorator,
    CommandNamespace,
    CommandNotFoundError,
    _cmd_sh,
    _write_command_error,
    argument,
    command,
    custom_command,
    linux_kernel_custom_command,
)
from drgn.helpers.linux.pid import find_task


def _pid_or_task(s: str) -> Tuple[Literal["pid", "task"], int]:
    # TODO: crash has more complicated logic for this that we may or may not
    # want.
    try:
        return "pid", int(s)
    except ValueError:
        return "task", int(s, 16)


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


CRASH_COMMAND_NAMESPACE: CommandNamespace = _CrashCommandNamespace()
"""Command namespace used for crash commands."""


# Note: we implement '!' as a command for convenience, but the crash
# documentation doesn't consider it a command.
custom_command(
    name="!", description="", usage="", help="", namespace=CRASH_COMMAND_NAMESPACE
)(_cmd_sh)


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
        return prog.cache["crash_context"]
    except KeyError:
        pass
    if (prog.flags & (ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL)) == (
        ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL
    ):
        task = find_task(prog, os.getpid())
    elif not (prog.flags & ProgramFlags.IS_LIVE):
        task = prog.crashed_thread().object
    else:
        raise ValueError("no default context")
    prog.cache["crash_context"] = task
    return task


def _crash_interactive_onerror(e: Exception) -> None:
    _write_command_error(sys.stderr, e, prefix="drgn: crash")


@linux_kernel_custom_command(
    description="run a crash command",
    usage="crash [*command*]",
    help="""
    This provides a compatibility mode emulating the `crash utility
    <https://crash-utility.github.io/>`_.

    If *command* is given, run the given crash command (which may include
    arguments, redirections, pipes, etc.). Otherwise, enter an interactive
    prompt where crash commands can be called directly.

    Run ``%crash help`` or see :doc:`crash_compatibility` for the list of
    commands.
    """,
)
def _cmd_crash(
    prog: Program, name: str, args: str, *, globals: Dict[str, Any], **kwargs: Any
) -> Any:
    if args:
        return CRASH_COMMAND_NAMESPACE.run(prog, args, globals=globals)
    while True:
        try:
            line = input("%crash> ")
        except EOFError:
            break
        if not line or line.isspace():
            continue
        CRASH_COMMAND_NAMESPACE.run(
            prog, line, globals=globals, onerror=_crash_interactive_onerror
        )


def _help_overview(prog: Program) -> None:
    command_names = [name for name, _ in CRASH_COMMAND_NAMESPACE.enabled(prog)]
    command_names.sort()
    columns = 5
    rows = (len(command_names) + columns - 1) // columns
    print("Commands:")
    for row in range(rows):
        print(
            "".join(
                [
                    command_names[i].ljust(
                        80 // columns if i + rows < len(command_names) else 0
                    )
                    for i in range(row, len(command_names), rows)
                ]
            )
        )
    # TODO: more background info


def _print_help(name: str, command: Command) -> None:
    print(
        f"""\
NAME
  {name} - {command.description()}

SYNOPSIS
  {command.format_usage()}

DESCRIPTION
{command.format_help(indent="  ")}"""
    )


@crash_command(
    description="get help",
    long_description="""
    Print help about one or more commands.

    If no commands are given, this lists available commands and prints general
    help.
    """,
    arguments=(
        argument(
            "command",
            nargs="*",
            help="command to get help about, or ``all`` for all commands",
        ),
    ),
)
def _crash_cmd_help(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if not args.command:
        return _help_overview(prog)

    first = True
    for name in args.command:
        if name == "all":
            for name, command in CRASH_COMMAND_NAMESPACE.enabled(prog):  # noqa: F402
                if name == "!":  # crash doesn't document '!' as a command.
                    continue
                if first:
                    first = False
                else:
                    print()
                _print_help(name, command)
        else:
            if first:
                first = False
            else:
                print()

            try:
                if name == "!":  # crash doesn't document '!' as a command.
                    raise CommandNotFoundError("!")
                command = CRASH_COMMAND_NAMESPACE.lookup(prog, name)
            except CommandNotFoundError as e:
                print(f"No command named {e.name!r}")
            else:
                _print_help(name, command)


for _module_info in pkgutil.iter_modules(__path__, prefix=__name__ + "."):
    importlib.import_module(_module_info.name)
