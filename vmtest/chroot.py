# Copyright (c) 2025 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later
import argparse
import os
from pathlib import Path
import subprocess
import sys

from vmtest.config import ARCHITECTURES, HOST_ARCHITECTURE

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
    command = args.command or ["bash", "-i"]
    env_passthrough = {
        "TERM",
        "COLORTERM",
    }
    filtered_env = {k: v for k, v in os.environ.items() if k in env_passthrough}
    sys.exit(
        subprocess.run(
            [
                "unshare",
                "--map-root-user",
                "--map-users=auto",
                "--map-groups=auto",
                "--fork",
                "--pid",
                f"--mount-proc={dir / 'proc'}",
                "chroot",
                dir,
                *command,
            ],
            env=filtered_env,
        ).returncode
    )
