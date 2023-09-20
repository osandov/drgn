#!/usr/bin/env python3

from collections import OrderedDict
import logging
import os
from pathlib import Path
import shlex
import subprocess
import sys

from util import KernelVersion
from vmtest.config import (
    ARCHITECTURES,
    HOST_ARCHITECTURE,
    KERNEL_FLAVORS,
    SUPPORTED_KERNEL_VERSIONS,
    Kernel,
)
from vmtest.download import DownloadCompiler, DownloadKernel, download_in_thread
from vmtest.kmod import build_kmod
from vmtest.rootfsbuild import build_drgn_in_rootfs
from vmtest.vm import LostVMError, run_in_vm

logger = logging.getLogger(__name__)


class _ProgressPrinter:
    def __init__(self, file):
        self._file = file
        if hasattr(file, "fileno"):
            try:
                columns = os.get_terminal_size(file.fileno())[0]
                self._color = True
            except OSError:
                columns = 80
                self._color = False
        self._header = "#" * columns
        self._passed = {}
        self._failed = {}

    def _green(self, s: str) -> str:
        if self._color:
            return "\033[32m" + s + "\033[0m"
        else:
            return s

    def _red(self, s: str) -> str:
        if self._color:
            return "\033[31m" + s + "\033[0m"
        else:
            return s

    def update(self, category: str, name: str, passed: bool):
        d = self._passed if passed else self._failed
        d.setdefault(category, []).append(name)

        if self._failed:
            header = self._red(self._header)
        else:
            header = self._green(self._header)

        print(header, file=self._file)
        print(file=self._file)

        if self._passed:
            first = True
            for category, names in self._passed.items():
                if first:
                    first = False
                    print(self._green("Passed:"), end=" ")
                else:
                    print("       ", end=" ")
                print(f"{category}: {', '.join(names)}")
        if self._failed:
            first = True
            for category, names in self._failed.items():
                if first:
                    first = False
                    print(self._red("Failed:"), end=" ")
                else:
                    print("       ", end=" ")
                print(f"{category}: {', '.join(names)}")

        print(file=self._file)
        print(header, file=self._file, flush=True)


def _kdump_works(kernel: Kernel) -> bool:
    if kernel.arch.name == "aarch64":
        # kexec fails with "kexec: setup_2nd_dtb failed." on older versions.
        # See
        # http://lists.infradead.org/pipermail/kexec/2020-November/021740.html.
        return KernelVersion(kernel.release) >= KernelVersion("5.10")
    elif kernel.arch.name == "arm":
        # Without virtual address translation, we can't debug vmcores. Besides,
        # kexec fails with "Could not find a free area of memory of 0xXXX
        # bytes...".
        return False
    elif kernel.arch.name == "ppc64":
        # Before 6.1, sysrq-c hangs.
        return KernelVersion(kernel.release) >= KernelVersion("6.1")
    elif kernel.arch.name == "s390x":
        # Before 5.15, sysrq-c hangs.
        return KernelVersion(kernel.release) >= KernelVersion("5.15")
    elif kernel.arch.name == "x86_64":
        return True
    else:
        assert False, kernel.arch.name


if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        format="%(asctime)s:%(levelname)s:%(name)s:%(message)s", level=logging.INFO
    )
    parser = argparse.ArgumentParser(
        description="test drgn in a virtual machine",
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
        dest="architectures",
        action="append",
        choices=["all", "foreign", *sorted(ARCHITECTURES)],
        default=argparse.SUPPRESS,
        required=HOST_ARCHITECTURE is None,
        help="architecture to test, "
        '"all" to test all supported architectures, '
        'or "foreign" to test all supported architectures other than the host architecture; '
        "may be given multiple times"
        + (
            "" if HOST_ARCHITECTURE is None else f" (default: {HOST_ARCHITECTURE.name})"
        ),
    )
    parser.add_argument(
        "-k",
        "--kernel",
        metavar="PATTERN|{all," + ",".join(KERNEL_FLAVORS) + "}",
        dest="kernels",
        action="append",
        default=argparse.SUPPRESS,
        help="kernel to test, "
        '"all" to test all supported kernels, '
        "or flavor name to test all supported kernels of a specific flavor; "
        "may be given multiple times (default: none)",
    )
    parser.add_argument(
        "-l",
        "--local",
        action="store_true",
        help="run local tests",
    )
    args = parser.parse_args()

    architecture_names = []
    if hasattr(args, "architectures"):
        for name in args.architectures:
            if name == "all":
                architecture_names.extend(ARCHITECTURES)
            elif name == "foreign":
                architecture_names.extend(
                    [
                        arch.name
                        for arch in ARCHITECTURES.values()
                        if arch is not HOST_ARCHITECTURE
                    ]
                )
            else:
                architecture_names.append(name)
        architectures = [
            ARCHITECTURES[name] for name in OrderedDict.fromkeys(architecture_names)
        ]
    else:
        architectures = [HOST_ARCHITECTURE]

    if hasattr(args, "kernels"):
        kernels = []
        for pattern in args.kernels:
            if pattern == "all":
                kernels.extend(
                    [
                        version + ".*" + flavor
                        for version in SUPPORTED_KERNEL_VERSIONS
                        for flavor in KERNEL_FLAVORS
                    ]
                )
            elif pattern in KERNEL_FLAVORS:
                kernels.extend(
                    [version + ".*" + pattern for version in SUPPORTED_KERNEL_VERSIONS]
                )
            else:
                kernels.append(pattern)
        args.kernels = OrderedDict.fromkeys(kernels)
    else:
        args.kernels = []

    if not args.kernels and not args.local:
        parser.error("at least one of -k/--kernel or -l/--local is required")

    if args.kernels:
        to_download = [DownloadCompiler(arch) for arch in architectures]
        for pattern in args.kernels:
            for arch in architectures:
                to_download.append(DownloadKernel(arch, pattern))
    else:
        to_download = []

    progress = _ProgressPrinter(sys.stderr)

    with download_in_thread(args.directory, to_download) as downloads:
        for arch in architectures:
            if arch is HOST_ARCHITECTURE:
                subprocess.check_call(
                    [sys.executable, "setup.py", "build_ext", "-i"],
                    env={
                        **os.environ,
                        "CONFIGURE_FLAGS": "--enable-compiler-warnings=error",
                    },
                )
                if args.local:
                    logger.info("running local tests on %s", arch.name)
                    status = subprocess.call(
                        [
                            sys.executable,
                            "-m",
                            "pytest",
                            "-v",
                            "--ignore=tests/linux_kernel",
                        ]
                    )
                    progress.update(arch.name, "local", status == 0)
            else:
                rootfs = args.directory / arch.name / "rootfs"
                build_drgn_in_rootfs(rootfs)
                if args.local:
                    logger.info("running local tests on %s", arch.name)
                    status = subprocess.call(
                        [
                            "unshare",
                            "--map-root-user",
                            "--map-users=auto",
                            "--map-groups=auto",
                            "--fork",
                            "--pid",
                            "--mount-proc=" + str(rootfs / "proc"),
                            "sh",
                            "-c",
                            r"""
set -e

mount --bind . "$1/mnt"
chroot "$1" sh -c 'cd /mnt && pytest -v --ignore=tests/linux_kernel'
""",
                            "sh",
                            rootfs,
                        ]
                    )
                    progress.update(arch.name, "local", status == 0)
        for kernel in downloads:
            if not isinstance(kernel, Kernel):
                continue
            kmod = build_kmod(args.directory, kernel)
            if _kdump_works(kernel):
                kdump_command = """\
    "$PYTHON" -Bm vmtest.enter_kdump
    # We should crash and not reach this.
    exit 1
"""
            else:
                kdump_command = ""
            test_command = rf"""
set -e

export PYTHON={shlex.quote(sys.executable)}
export DRGN_TEST_KMOD={shlex.quote(str(kmod))}
export DRGN_RUN_LINUX_KERNEL_TESTS=1
if [ -e /proc/vmcore ]; then
    "$PYTHON" -Bm pytest -v tests/linux_kernel/vmcore
else
    insmod "$DRGN_TEST_KMOD"
    "$PYTHON" -Bm pytest -v tests/linux_kernel --ignore=tests/linux_kernel/vmcore
{kdump_command}
fi
"""
            try:
                status = run_in_vm(
                    test_command,
                    kernel,
                    args.directory / kernel.arch.name / "rootfs",
                    args.directory,
                )
            except LostVMError as e:
                print("error:", e, file=sys.stderr)
                status = -1
            progress.update(kernel.arch.name, kernel.release, status == 0)
