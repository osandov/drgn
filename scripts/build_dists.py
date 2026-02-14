#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import os
import subprocess
import sys

MANYLINUX_VERSIONS = ("manylinux_2_28", "manylinux2014")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build drgn source and manylinux distributions"
    )
    parser.add_argument(
        "--python-version",
        default="",
        help="Python version to build for (e.g., 3.12). "
        "If not given, build for all supported versions",
    )
    parser.add_argument(
        "--manylinux-version",
        dest="manylinux_versions",
        action="append",
        choices=MANYLINUX_VERSIONS,
        help="manylinux version to build for (may be given multiple times). "
        "If not given, build for all supported versions",
    )
    args = parser.parse_args()

    manylinux_versions = args.manylinux_versions or MANYLINUX_VERSIONS

    subprocess.check_call([sys.executable, "setup.py", "sdist"])

    version = subprocess.check_output(
        [sys.executable, "setup.py", "--version"], text=True
    ).strip()
    sdist = f"dist/drgn-{version}.tar.gz"

    docker = os.environ.get("DOCKER")
    if docker is None:
        podman = "podman"
        podman_opts = ["--security-opt", "label=disable"]
    else:
        podman = docker
        uid_gid = f"{os.getuid()}:{os.getgid()}"
        podman_opts = ["--env", f"OWNER={uid_gid}"]

    cwd = os.getcwd()
    for manylinux_version in manylinux_versions:
        plat = manylinux_version + "_x86_64"
        subprocess.check_call(
            [
                podman,
                "run",
                "-it",
                "--env",
                f"PLAT={plat}",
                "--env",
                f"SDIST={sdist}",
                *podman_opts,
                "--volume",
                f"{cwd}:/io:ro",
                "--volume",
                f"{cwd}/dist:/io/dist",
                "--workdir",
                "/io",
                "--hostname",
                "drgn",
                "--rm",
                "--pull",
                "always",
                f"quay.io/pypa/{plat}",
                "./scripts/build_manylinux_in_docker.sh",
                args.python_version,
            ]
        )


if __name__ == "__main__":
    main()
