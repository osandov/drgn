# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import sys
import types
from typing import Any, Dict, Optional, Union

from drgn import Program
import drgn.cli
from drgn.commands import (
    Command,
    CommandNotFoundError,
    _parse_py_command,
    _print_py_command_exception,
    _write_command_error,
    argument,
)
from drgn.commands._builtin.crash._sys import _print_sys
from drgn.commands.crash import (
    CRASH_COMMAND_NAMESPACE,
    crash_command,
    crash_custom_command,
)
from drgn.commands.linux import linux_kernel_raw_command
from drgn.internal.repl import readline


# These inherit from SystemExit to bypass things that attempt to handle most
# exceptions like the Python interactive console.
class _ExitToCrash(SystemExit):
    pass


class _ExitCrash(SystemExit):
    pass


def _crash_interactive_onerror(e: Exception) -> None:
    _write_command_error(sys.stderr, e, prefix="drgn: crash")


class _CrashCompleter:
    def __init__(self, prog: Program) -> None:
        self._prog = prog

    def complete(self, text: str, state: int) -> Optional[str]:
        # Only complete command names at the beginning of a line.
        begidx = readline.get_begidx()
        if begidx > 0:
            if readline.get_line_buffer()[:begidx].strip():
                return None

        if state == 0:
            self._matches = [
                name
                for name, _ in CRASH_COMMAND_NAMESPACE.enabled(self._prog)
                if name.startswith(text)
            ]

        if 0 <= state < len(self._matches):
            return self._matches[state]
        else:
            return None


@linux_kernel_raw_command(
    description="run a crash command",
    usage="**crash** [*command*]",
    long_description="""
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
    try:
        if args:
            return CRASH_COMMAND_NAMESPACE.run(prog, args, globals=globals)

        had_outer_repl = "outer_repl" in prog.config
        try:
            if not had_outer_repl:
                prog.config["outer_repl"] = "crash"
            elif prog.config["outer_repl"] == "crash":
                raise _ExitToCrash()

            with drgn.cli._setup_readline(
                drgn.cli._state_file("crash_history"), _CrashCompleter(prog).complete
            ):
                _print_sys(prog, context="panic")
                while True:
                    try:
                        line = input("%crash> ")
                    except EOFError:
                        break
                    if not line or line.isspace():
                        continue
                    try:
                        CRASH_COMMAND_NAMESPACE.run(
                            prog,
                            line,
                            globals=globals,
                            onerror=_crash_interactive_onerror,
                        )
                    except _ExitToCrash:
                        continue
        finally:
            if not had_outer_repl:
                prog.config.pop("outer_repl", None)
    except _ExitCrash:
        pass


@crash_custom_command(
    description="run drgn code or enter drgn interactive mode",
    usage="**drgn** [*code*]",
    long_description="""
    If *code* is given, execute the given drgn Python code, up to the first
    shell redirection or pipeline.

    Otherwise, enter drgn's interactive mode.
    """,
    parse=_parse_py_command,
)
def _crash_cmd_drgn(
    prog: Program,
    name: str,
    code: Union[types.CodeType, SyntaxError, None],
    *,
    globals: Dict[str, Any],
    **kwargs: Any,
) -> None:
    if code is None:
        if prog.config.get("outer_repl") == "drgn":
            raise _ExitCrash()
        else:
            drgn.cli.run_interactive(prog)
    elif isinstance(code, SyntaxError):
        _print_py_command_exception(code)
    else:
        try:
            exec(code, globals)
        except (Exception, KeyboardInterrupt) as e:
            _print_py_command_exception(e)


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


def _print_help(name: str, command: Command[Any]) -> None:
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
