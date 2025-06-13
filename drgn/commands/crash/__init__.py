# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import importlib
import pkgutil
import sys
from typing import Any, Dict

from _drgn_util.typingutils import copy_func_params
from drgn import Program
from drgn.commands import (
    Command,
    CommandFuncDecorator,
    CommandNamespace,
    CommandNotFoundError,
    _write_command_error,
    argument,
    command,
    linux_kernel_custom_command,
)

_CRASH_COMMANDS = CommandNamespace(func_name_prefix="_crash_cmd_")


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
        return _CRASH_COMMANDS.run(prog, args, globals=globals)
    while True:
        try:
            line = input("%crash> ")
        except EOFError:
            break
        if not line or line.isspace():
            continue
        _CRASH_COMMANDS.run(
            prog, line, globals=globals, onerror=_crash_interactive_onerror
        )


def _help_overview(prog: Program) -> None:
    command_names = [name for name, _ in _CRASH_COMMANDS.enabled(prog)]
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
    """
    return command(*args, **kwargs, namespace=_CRASH_COMMANDS)


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
            for name, command in _CRASH_COMMANDS.enabled(prog):  # noqa: F402
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
                command = _CRASH_COMMANDS.lookup(prog, name)
            except CommandNotFoundError:
                print(f"No command named {name!r}")
            else:
                _print_help(name, command)


for _module_info in pkgutil.iter_modules(__path__, prefix=__name__ + "."):
    importlib.import_module(_module_info.name)
