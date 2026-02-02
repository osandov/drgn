# Copyright (c) 2025 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later
import argparse
from pathlib import Path
import shlex
import subprocess
import sys
from typing import List

from vmtest.config import ARCHITECTURES, HOST_ARCHITECTURE

_PASSTHROUGH_ENV_VARS = (
    "TERM",
    "COLORTERM",
)


def chroot_sh_args(new_root: str) -> List[str]:
    # When entering a chroot, we want a clean environment. Preserve only a few
    # specific environment variables and execute a login shell, which will
    # define anything else important.
    return [
        "chroot",
        new_root,
        "env",
        "-i",
        *(f'${{{var}+{var}="${var}"}}' for var in _PASSTHROUGH_ENV_VARS),
        "/bin/sh",
        "-l",
        "-c",
    ]


def chroot_sh_cmd(new_root: str) -> str:
    return " ".join(chroot_sh_args(new_root))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="run commands in the root filesystems for vmtest",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-d",
        "--directory",
        metavar="DIR",
        type=Path,
        default="build/vmtest",
        help="directory for vmtest artifacts",
    )
    parser.add_argument(
        "-a",
        "--architecture",
        type=str,
        choices=sorted(ARCHITECTURES),
        default=None if HOST_ARCHITECTURE is None else HOST_ARCHITECTURE.name,
        required=HOST_ARCHITECTURE is None,
        help="architecture to run in",
    )
    parser.add_argument(
        "command",
        type=str,
        nargs=argparse.REMAINDER,
        help="command to run in rootfs (default: bash -i)",
    )
    args = parser.parse_args()
    arch = ARCHITECTURES[args.architecture]
    dir = args.directory / arch.name / "rootfs"
    command = (
        " ".join([shlex.quote(arg) for arg in args.command])
        if args.command
        else "bash -i"
    )
    sys.exit(
        subprocess.run(
            [
                "unshare",
                "--map-root-user",
                "--map-auto",
                "--fork",
                "--pid",
                f"--mount-proc={dir / 'proc'}",
                *chroot_sh_args(dir),
                command,
            ],
        ).returncode
    )
