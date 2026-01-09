import argparse
import os
from typing import Any, Optional

from drgn.commands import CommandError, argument, drgn_argument
from drgn.commands.crash import crash_command

# Global variable to track the previous directory for 'cd -' support.
PREV_DIR_ENV = "PY_CD_OLDPWD"


@crash_command(
    name="cd",
    description="change the current working directory",
    long_description="""
    Changes the current working directory to the directory specified by 'path'.
    If no path is given, it may optionally navigate to a default home directory
    or display the current path, depending on the environment's implementation.
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
    try:
        target = resolve_path(args.path)
        change_directory(target)
        print(os.getcwd())
    except (FileNotFoundError, NotADirectoryError, PermissionError, RuntimeError) as e:
        raise CommandError(str(e))


def resolve_path(path: Optional[str]) -> str:
    """Resolve shell-like path expansions."""
    if path is None:
        return os.path.expanduser("~")

    if path == "-":
        prev = os.environ.get(PREV_DIR_ENV)
        if not prev:
            raise RuntimeError("cd -: previous directory not set")
        return prev

    # Expand variables ($VAR) and user (~/path)
    expanded = os.path.expandvars(os.path.expanduser(path))
    return expanded


def change_directory(path: str) -> None:
    try:
        oldpwd = os.getcwd()
    except FileNotFoundError:
        # Current directory was deleted ?
        oldpwd = None
    try:
        os.chdir(path)
    except FileNotFoundError:
        raise FileNotFoundError(f"cd: no such file or directory: {path}")
    except NotADirectoryError:
        raise NotADirectoryError(f"cd: not a directory: {path}")
    except PermissionError:
        raise PermissionError(f"cd: permission denied: {path}")

    # Update PREV_DIR_ENV
    if oldpwd is not None:
        os.environ[PREV_DIR_ENV] = oldpwd
