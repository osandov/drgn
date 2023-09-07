# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import logging
from pathlib import Path
import subprocess
import sys
import tempfile
import typing

if typing.TYPE_CHECKING:
    if sys.version_info < (3, 8):
        from typing_extensions import Literal
    else:
        from typing import Literal  # novermin

from vmtest.config import ARCHITECTURES, HOST_ARCHITECTURE, Architecture

logger = logging.getLogger(__name__)


_ROOTFS_PACKAGES = [
    # drgn build dependencies.
    "autoconf",
    "automake",
    "gcc",
    "git",
    "libdw-dev",
    "libelf-dev",
    "libkdumpfile-dev",
    "libtool",
    "make",
    "pkgconf",
    "python3",
    "python3-dev",
    "python3-pip",
    "python3-setuptools",
    # Test dependencies.
    "iproute2",
    "kexec-tools",
    "kmod",
    "python3-pyroute2",
    "python3-pytest",
    "zstd",
]


def build_rootfs(
    arch: Architecture,
    path: Path,
    *,
    btrfs: "Literal['never', 'always', 'auto']" = "auto",
) -> None:
    if path.exists():
        logger.info("%s already exists", path)
        return

    logger.info("creating debootstrap rootfs %s", path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=path.parent) as tmp_name:
        tmp_dir = Path(tmp_name)
        snapshot = False

        if btrfs != "never":
            try:
                import btrfsutil

                btrfsutil.create_subvolume(tmp_dir / path.name)
                snapshot = True
            except (ImportError, OSError):
                if btrfs == "always":
                    raise

        subprocess.check_call(
            [
                "unshare",
                "--map-root-user",
                "--map-users=auto",
                "--map-groups=auto",
                "sh",
                "-c",
                r"""
set -e

arch="$1"
target="$2"
packages="$3"

# We're not really an LXC container, but this convinces debootstrap to skip
# some operations that it can't do in a user namespace.
export container=lxc
debootstrap --variant=minbase --foreign --include="$packages" --arch="$arch" stable "$target"
chroot "$target" /debootstrap/debootstrap --second-stage
chroot "$target" apt clean
""",
                "sh",
                arch.debian_arch,
                tmp_dir / path.name,
                ",".join(_ROOTFS_PACKAGES),
            ]
        )
        (tmp_dir / path.name).rename(path)
    logger.info("created debootstrap rootfs %s", path)

    if snapshot:
        snapshot_dir = path.parent / (path.name + ".pristine")
        btrfsutil.create_snapshot(path, snapshot_dir, read_only=True)
        logger.info("created snapshot %s", snapshot_dir)


def build_drgn_in_rootfs(rootfs: Path) -> None:
    logger.info("building drgn using %s", rootfs)
    subprocess.check_call(
        [
            "unshare",
            "--mount",
            "--map-root-user",
            "--map-users=auto",
            "--map-groups=auto",
            "sh",
            "-c",
            r"""
set -e

mount --bind . "$1/mnt"
chroot "$1" sh -c 'cd /mnt && CONFIGURE_FLAGS=--enable-compiler-warnings=error python3 setup.py build_ext -i'
""",
            "sh",
            rootfs,
        ]
    )


if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        format="%(asctime)s:%(levelname)s:%(name)s:%(message)s", level=logging.INFO
    )

    parser = argparse.ArgumentParser(
        description="build root filesystems for vmtest. "
        "This requires debootstrap(8), qemu-user-static, and unprivileged user namespaces.",
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
        "--build-drgn",
        action="store_true",
        help="also build drgn in the current directory using the built rootfs",
    )
    parser.add_argument(
        "--btrfs",
        choices=["never", "always", "auto"],
        default="auto",
        help="make the rootfs a Btrfs subvolume and create a read-only snapshot",
    )
    parser.add_argument(
        "-a",
        "--architecture",
        dest="architectures",
        action="append",
        choices=["all", "foreign", *sorted(ARCHITECTURES)],
        default=argparse.SUPPRESS,
        help='architecture to build for, or "foreign" for all architectures other than the host architecture; may be given multiple times (default: foreign)',
    )
    args = parser.parse_args()

    if not hasattr(args, "architectures"):
        args.architectures = ["foreign"]
    architectures = []
    for name in args.architectures:
        if name == "foreign":
            architectures.extend(
                [
                    arch
                    for arch in ARCHITECTURES.values()
                    if arch is not HOST_ARCHITECTURE
                ]
            )
        elif name == "all":
            architectures.extend(ARCHITECTURES.values())
        else:
            architectures.append(ARCHITECTURES[name])

    for arch in architectures:
        dir = args.directory / arch.name / "rootfs"
        build_rootfs(arch, dir, btrfs=args.btrfs)
        if args.build_drgn:
            build_drgn_in_rootfs(dir)
