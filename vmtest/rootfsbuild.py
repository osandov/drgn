# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import logging
from pathlib import Path
import subprocess
import tempfile
from typing import Literal, Optional, TextIO

from vmtest.chroot import chroot_sh_cmd
from vmtest.config import (
    ARCHITECTURES,
    HOST_ARCHITECTURE,
    Architecture,
    _run_autoreconf,
)

logger = logging.getLogger(__name__)


_ROOTFS_PACKAGES = (
    # drgn build dependencies.
    "autoconf",
    "automake",
    "gcc",
    "git",
    "libdw-dev",
    "libelf-dev",
    "libkdumpfile-dev",
    "liblzma-dev",
    "libpcre2-dev",
    "libtool",
    "make",
    "pkgconf",
    "python3",
    "python3-dev",
    "python3-pip",
    "python3-setuptools",
    # Test dependencies.
    "btrfs-progs",
    "check",
    "e2fsprogs",
    "iproute2",
    "kexec-tools",
    "kmod",
    "python3-pyroute2",
    "python3-pytest",
    "python3-pytest-subtests",
    "zstd",
)


def build_rootfs(
    arch: Architecture,
    path: Path,
    *,
    btrfs: Literal["never", "always", "auto"] = "auto",
) -> None:
    if path.exists():
        logger.info("%s already exists", path)
        return

    packages = list(_ROOTFS_PACKAGES)
    if arch is HOST_ARCHITECTURE:
        for other_arch in ARCHITECTURES.values():
            if other_arch is not arch:
                packages.append(f"gcc-{other_arch.debian_gcc_target}")

    logger.info("creating debootstrap rootfs %s", path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=path.parent) as tmp_name:
        tmp_dir = Path(tmp_name)
        snapshot = False

        if btrfs != "never":
            try:
                import btrfsutil  # type: ignore  # No type hints available.

                btrfsutil.create_subvolume(tmp_dir / path.name)
                snapshot = True
            except (ImportError, OSError):
                if btrfs == "always":
                    raise

        subprocess.check_call(
            [
                "unshare",
                "--map-root-user",
                "--map-auto",
                "sh",
                "-c",
                rf"""
set -e

arch="$1"
target="$2"
packages="$3"

# We're not really an LXC container, but this convinces debootstrap to skip
# some operations that it can't do in a user namespace.
container=lxc debootstrap --variant=minbase --foreign --include="$packages" --arch="$arch" stable "$target"
{chroot_sh_cmd('"$target"')} 'container=lxc /debootstrap/debootstrap --second-stage && apt clean'
""",
                "sh",
                arch.debian_arch,
                tmp_dir / path.name,
                ",".join(packages),
            ]
        )
        (tmp_dir / path.name).rename(path)
    logger.info("created debootstrap rootfs %s", path)

    if snapshot:
        snapshot_dir = path.parent / (path.name + ".pristine")
        btrfsutil.create_snapshot(path, snapshot_dir, read_only=True)
        logger.info("created snapshot %s", snapshot_dir)


def _cross_compile_drgn(
    target: Architecture, directory: Path, *, outfile: Optional[TextIO] = None
) -> None:
    assert HOST_ARCHITECTURE is not None
    host_rootfs = directory / HOST_ARCHITECTURE.name / "rootfs"
    target_rootfs = directory / target.name / "rootfs"
    logger.info("cross-compiling drgn in %s for %s", host_rootfs, target_rootfs)
    subprocess.check_call(
        [
            "unshare",
            "--map-root-user",
            "--map-auto",
            "--mount",
            "sh",
            "-c",
            rf"""
set -e

mount --bind . "$1/mnt"
mount --bind "$3" "$1/srv"
{chroot_sh_cmd('"$1"')} '
set -e

extension_suffix="$(/srv/usr/bin/python3-config --extension-suffix)"
build_temp="/mnt/build/temp${{extension_suffix%.so}}"
mkdir -p "$build_temp"
cd "$build_temp"
export CFLAGS="--sysroot=/srv"
export LDFLAGS="--sysroot=/srv"
export PYTHON_CPPFLAGS="$(/srv/usr/bin/python3-config --includes)"
export PKG_CONFIG_LIBDIR="$(pkg-config --variable pc_path pkg-config | sed -r -e "s!(^|:)/!\1/srv/!g" -e "s/$1/$2/g")"
export PKG_CONFIG_SYSROOT_DIR=/srv
if [ ! -e Makefile ]; then
    /mnt/libdrgn/configure --host="$2" --with-sysroot=/srv --disable-static --disable-libdrgn --enable-python-extension
fi
make -j"$(nproc)"
cp -v ".libs/_drgn.so" "/mnt/_drgn$extension_suffix"
' sh "$2" "$4"
""",
            "sh",
            host_rootfs,
            HOST_ARCHITECTURE.debian_gcc_target,
            target_rootfs,
            target.debian_gcc_target,
        ],
        stdout=outfile,
        stderr=outfile,
    )


def _build_drgn_in_rootfs(rootfs: Path, *, outfile: Optional[TextIO] = None) -> None:
    logger.info("building drgn using %s", rootfs)
    subprocess.check_call(
        [
            "unshare",
            "--map-root-user",
            "--map-auto",
            "--mount",
            "sh",
            "-c",
            rf"""
set -e

mount --bind . "$1/mnt"
{chroot_sh_cmd('"$1"')} 'cd /mnt && CONFIGURE_FLAGS=--enable-compiler-warnings=error python3 setup.py build_ext -i'
""",
            "sh",
            rootfs,
        ],
        stdout=outfile,
        stderr=outfile,
    )


def build_drgn_for_arch(
    target: Architecture, directory: Path, *, outfile: Optional[TextIO] = None
) -> None:
    _run_autoreconf()
    if target is not HOST_ARCHITECTURE and HOST_ARCHITECTURE is not None:
        return _cross_compile_drgn(target, directory, outfile=outfile)
    else:
        return _build_drgn_in_rootfs(
            directory / target.name / "rootfs", outfile=outfile
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

    # Create the host architecture rootfs first in case it's needed for
    # building drgn for other architectures.
    try:
        index = architectures.index(HOST_ARCHITECTURE)  # type: ignore[arg-type]
    except ValueError:
        pass
    else:
        architectures.insert(0, architectures.pop(index))

    for arch in architectures:
        dir = args.directory / arch.name / "rootfs"
        build_rootfs(arch, dir, btrfs=args.btrfs)
        if args.build_drgn:
            build_drgn_for_arch(arch, args.directory)
