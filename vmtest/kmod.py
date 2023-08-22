# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import logging
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from util import nproc, out_of_date
from vmtest.config import Kernel, local_kernel
from vmtest.download import downloaded_compiler

logger = logging.getLogger(__name__)


def build_kmod(download_dir: Path, kernel: Kernel) -> Path:
    kmod = kernel.path.parent / f"drgn_test-{kernel.release}.ko"
    # External modules can't do out-of-tree builds for some reason, so copy the
    # source files to a temporary directory and build the module there, then
    # move it to the final location.
    kmod_source_dir = Path("tests/linux_kernel/kmod")
    source_files = ("drgn_test.c", "Makefile")
    if out_of_date(kmod, *[kmod_source_dir / filename for filename in source_files]):
        logger.info("building %s", kmod)

        compiler = downloaded_compiler(download_dir, kernel.arch)
        kernel_build_dir = kernel.path / "build"

        with tempfile.TemporaryDirectory(dir=kmod.parent) as tmp_name:
            tmp_dir = Path(tmp_name)
            # Make sure that header files have the same paths as in the
            # original kernel build.
            debug_prefix_map = [
                f"{kernel_build_dir.resolve()}=.",
                f"{tmp_dir.resolve()}=./drgn_test",
            ]
            cflags = " ".join(["-fdebug-prefix-map=" + map for map in debug_prefix_map])
            for filename in source_files:
                shutil.copy(kmod_source_dir / filename, tmp_dir / filename)
            subprocess.check_call(
                [
                    "make",
                    "ARCH=" + kernel.arch.kernel_arch,
                    "-C",
                    kernel_build_dir,
                    f"M={tmp_dir.resolve()}",
                    "KAFLAGS=" + cflags,
                    "KCFLAGS=" + cflags,
                    "-j",
                    str(nproc()),
                ],
                env={**os.environ, **compiler.env()},
            )
            (tmp_dir / "drgn_test.ko").rename(kmod)
    else:
        logger.info("%s is up to date", kmod)
    return kmod


def _main() -> None:
    import argparse

    from vmtest.download import (
        DOWNLOAD_KERNEL_ARGPARSE_METAVAR,
        DownloadCompiler,
        download_in_thread,
        download_kernel_argparse_type,
    )

    logging.basicConfig(
        format="%(asctime)s:%(levelname)s:%(name)s:%(message)s", level=logging.INFO
    )

    parser = argparse.ArgumentParser(
        description="build drgn test kernel module",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-k",
        "--kernel",
        metavar=DOWNLOAD_KERNEL_ARGPARSE_METAVAR,
        dest="kernels",
        action="append",
        type=download_kernel_argparse_type,
        default=argparse.SUPPRESS,
        help="kernel to build for; may be given multiple times",
    )
    parser.add_argument(
        "-d",
        "--directory",
        metavar="DIR",
        type=Path,
        default="build/vmtest",
        help="directory to download assets to",
    )
    args = parser.parse_args()
    if not hasattr(args, "kernels"):
        args.kernels = []

    compilers_needed = {
        kernel.arch.name: DownloadCompiler(kernel.arch) for kernel in args.kernels
    }

    to_download = list(compilers_needed.values())
    for kernel in args.kernels:
        if not kernel.pattern.startswith(".") and not kernel.pattern.startswith("/"):
            to_download.append(kernel)
    with download_in_thread(args.directory, to_download) as downloads:
        download_it = iter(downloads)

        for i in range(len(compilers_needed)):
            next(download_it)

        for kernel in args.kernels:
            if kernel.pattern.startswith(".") or kernel.pattern.startswith("/"):
                downloaded = local_kernel(kernel.arch, Path(kernel.pattern))
            else:
                downloaded = next(download_it)  # type: ignore[assignment]
            print(build_kmod(args.directory, downloaded))


if __name__ == "__main__":
    _main()
