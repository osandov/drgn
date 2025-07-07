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
from typing import Any, Dict

from drgn import Program, execscript
from drgn.commands import argument, command, custom_command

# Import all submodules, recursively.
for _module_info in pkgutil.walk_packages(__path__, __name__ + "."):
    importlib.import_module(_module_info.name)


@custom_command(
    description="execute a shell command",
    usage="**sh** [*command*]",
    help="""
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
