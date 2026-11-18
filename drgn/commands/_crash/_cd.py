import argparse
import os
from typing import Any, Optional

from drgn.commands import CommandError, argument, drgn_argument
from drgn.commands._crash.common import crash_command

@crash_command(
    name="cd",
    description="change the current working directory",
    long_description="""
    Changes the current working directory to the directory specified by 'path'.
    If no path is given, the command defaults to the user's home directory (~).
    """,
    arguments=(
        argument(
            "path",
            nargs="?",
            help="the path of the directory to change to (optional)",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_cd(prog: Any, cmd: str, args: argparse.Namespace, **kwargs: Any) -> None:
    target = _resolve_path(prog, args.path)
    _change_directory(prog, target)
    print(os.getcwd())

def _resolve_path(prog: Any, path: Optional[str]) -> str:
    # Resolve shell-like path expansions.
    if path is None:
        return os.path.expanduser("~")

    if path == "-":
        prev = prog.config.get("prev_work_path")
        if not prev:
            raise CommandError("cd -: previous directory not set")
        return prev

    # Expand variables ($VAR) and user (~/path)
    return os.path.expandvars(os.path.expanduser(path))


def _change_directory(prog: Any, path: str) -> None:
    try:
        oldpwd = os.getcwd()
    except OSError:
        # Current directory was deleted ?
        oldpwd = None
    try:
        os.chdir(path)
    except Exception as e:
        raise CommandError(f"{e}")

    # Update previous working directory
    if oldpwd is not None:
        prog.config["prev_work_path"] = oldpwd
