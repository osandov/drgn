# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import sys
from typing import Any, Dict

from drgn import Program
from drgn.commands import Command, CommandNotFoundError, _write_command_error, argument
from drgn.commands._builtin.crash.system import _SysPrinter
from drgn.commands.crash import CRASH_COMMAND_NAMESPACE, crash_command
from drgn.commands.linux import linux_kernel_custom_command


def _crash_interactive_onerror(e: Exception) -> None:
    _write_command_error(sys.stderr, e, prefix="drgn: crash")


@linux_kernel_custom_command(
    description="run a crash command",
    usage="**crash** [*command*]",
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
    _SysPrinter(prog, False, context="panic").print()
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
    print(
        """
Try "help <command>" for help with a specific command.
""",
        end="",
    )


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
            for name, command in sorted(CRASH_COMMAND_NAMESPACE.enabled(prog)):
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
                command = CRASH_COMMAND_NAMESPACE.lookup(prog, name)
            except CommandNotFoundError as e:
                print(f"No command named {e.name!r}")
            else:
                _print_help(name, command)
