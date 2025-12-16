# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Built-in commands exported as the "builtin_commands" plugin. All commands built
into drgn should be defined in this package.
"""

import argparse
import importlib
import pkgutil
import subprocess
import types
from typing import Any, Dict, Union

from drgn import Program, execscript
from drgn.commands import (
    CommandArgumentError,
    _parse_py_command,
    _print_py_command_exception,
    argument,
    command,
    custom_command,
    raw_command,
)

# Import all submodules, recursively.
for _module_info in pkgutil.walk_packages(__path__, __name__ + "."):
    importlib.import_module(_module_info.name)


@raw_command(
    description="execute a shell command",
    usage="**sh** [*command*]",
    long_description="""
    If *command* is given, run it with ``sh -c --``. Otherwise, run an
    interactive shell with ``sh -i``.

    In either case, return the command's exit status.
    """,
)
def _cmd_sh(prog: Program, name: str, args: str, **kwargs: Any) -> int:
    if args:
        return subprocess.call(["sh", "-c", "--", args])
    else:
        return subprocess.call(["sh", "-i"])


@custom_command(
    description="execute a python statement and allow shell redirection",
    usage="**py** *code*",
    long_description="""
    Execute the given code, up to the first shell redirection or pipeline
    statement, as Python code.

    For each occurrence of a pipeline operator (``|``) or any redirection
    operator (``<``, ``>``, ``<<``, ``>>``), attempt to parse the preceding text
    as Python code. If the preceding text is syntactically valid code, then
    interpret the remainder of the command as shell redirections or pipelines,
    and execute the Python code with those redirections and pipelines applied.

    The operators above can be used in syntactically valid Python. This means
    you need to be careful when using this function, and ensure that you wrap
    their uses with parentheses.

    For example, consider the command: ``%py field | MY_FLAG | grep foo``. While
    the intent here may be to execute the Python code ``field | MY_FLAG`` and
    pass its result to ``grep``, that is not what will happen. The portion of
    text prior to the first ``|`` is valid Python, so it will be executed, and
    its output piped to the shell pipeline ``MY_FLAG | grep foo``. Instead,
    running ``%py (field | MY_FLAG) | grep foo`` ensures that ``field |
    MY_FLAG`` gets piped to ``grep foo``, because ``(field`` on its own is not
    valid Python syntax.
    """,
    parse=_parse_py_command,
)
def _cmd_py(
    prog: Program,
    name: str,
    code: Union[types.CodeType, SyntaxError, None],
    *,
    globals: Dict[str, Any],
    **kwargs: Any,
) -> None:
    if code is None:
        raise CommandArgumentError("expected code")

    if isinstance(code, SyntaxError):
        _print_py_command_exception(code)
        return

    try:
        exec(code, globals)
    except (Exception, KeyboardInterrupt) as e:
        # Any exception should be formatted just as the interpreter would. This
        # includes keyboard interrupts, but not things like SystemExit or
        # GeneratorExit.
        _print_py_command_exception(e)


@command(
    description="run a drgn script",
    long_description="""
    This loads and runs a drgn script in the current environment. Currently
    defined globals are available to the script, and globals defined by the
    script are added to the environment.
    """,
    arguments=(
        argument("script", help="script file path"),
        argument(
            "args", nargs=argparse.REMAINDER, help="arguments to pass to the script"
        ),
    ),
)
def _cmd_source(
    prog: Program,
    name: str,
    args: argparse.Namespace,
    *,
    globals: Dict[str, Any],
    **kwargs: Any,
) -> None:
    execscript(args.script, *args.args, globals=globals)
