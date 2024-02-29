#!/usr/bin/env python3
# Copyright (c) 2023, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Commands
--------

The ``drgn.helpers.common.commands`` module contains several useful built-in CLI
commands.
"""
from pathlib import Path
import re
import shlex
from typing import Any, Dict

from drgn import Object, Program, execscript
from drgn.cli import command
from drgn.helpers.common.type import eval_typed_expression


@command("x")
def execscript_command(prog: Program, line: str, locals_: Dict[str, Any]) -> None:
    """
    The ``x`` command in the drgn CLI: executes a script

    Usage: ``.x SCRIPT_PATH [ARG1 [ARG2 [...]]]``
    """
    args = shlex.split(line)
    if len(args) < 2:
        print("error: too few arguments")
        return
    if not Path(args[1]).exists():
        print(f"error: script '{args[1]}' not found")
        return
    execscript(args[1], *args[2:], globals=locals_)


@command("let")
def let_command(prog: Program, line: str, locals_: Dict[str, Any]) -> Object:
    """
    The ``let`` command in the drgn CLI: sets a variable to an Object expression

    Usage: ``.let VARNAME = EXPRESSION``

    For example:

        >>> .let secret = (unsigned int) 42
        >>> secret
        (unsigned int)42
        >>> .let ptr = (struct task_struct *)0xffff9ea240dd5640
        >>> ptr.format_(dereference=False)
        '(struct task_struct *)0xffff9ea240dd5640'
    """
    cmd, stmt = line.split(maxsplit=1)
    var, expr = stmt.split("=", maxsplit=1)
    var = var.strip()
    if not re.fullmatch(r"[a-zA-Z_]\w*", var, re.ASCII):
        raise ValueError(f"error: not a valid variable name: {var}")
    obj = eval_typed_expression(prog, expr)
    locals_[var] = obj
    return obj


@command("contrib")
def contrib_command(prog: Program, line: str, locals_: Dict[str, Any]) -> None:
    """
    The ``contrib`` command in the drgn CLI: executes a contrib script

    Usage: ``.contrib SCRIPT_NAME [ARG1 [ARG2 [...]]]``

    The script will be searched for in the ``contrib/`` directory: or at least,
    where we expect to find it. Please note that contrib scripts are not
    included in distributions on PyPI, so this will only work if you are running
    from a Git checkout.

    Scripts can be referenced with or without their ".py" extension.
    """
    args = shlex.split(line)
    if len(args) < 2:
        print("error: too few arguments")
        return
    try:
        contrib_dir = Path(__file__).parents[3] / "contrib"
    except IndexError:
        print("error: could not find contrib directory")
        return
    if not contrib_dir.is_dir():
        print("error: could not find contrib directory")
        return
    if args[1].endswith(".py"):
        script = contrib_dir / args[1]
    else:
        script = contrib_dir / f"{args[1]}.py"
    if not script.exists():
        print(f"error: contrib script '{script.name}' not found")
        return
    execscript(str(script), *args[2:], globals=locals_)
