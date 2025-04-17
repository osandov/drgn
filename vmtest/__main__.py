#!/usr/bin/env python3

from collections import OrderedDict
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import logging
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
from typing import Dict, List, TextIO

from util import KernelVersion
from vmtest.config import (
    ARCHITECTURES,
    HOST_ARCHITECTURE,
    KERNEL_FLAVORS,
    SUPPORTED_KERNEL_VERSIONS,
    Architecture,
    Kernel,
)
from vmtest.download import (
    Download,
    DownloadCompiler,
    DownloadKernel,
    download_in_thread,
)
from vmtest.rootfsbuild import build_drgn_in_rootfs
from vmtest.vm import LostVMError, TestKmodMode, run_in_vm

logger = logging.getLogger(__name__)


class _ProgressPrinter:
    def __init__(self, file: TextIO) -> None:
        self._file = file
        if hasattr(file, "fileno"):
            try:
                columns = os.get_terminal_size(file.fileno())[0]
                self._color = True
            except OSError:
                columns = 80
                self._color = False
        self._header = "#" * columns
        self._passed: Dict[str, List[str]] = {}
        self._failed: Dict[str, List[str]] = {}

    def succeeded(self) -> bool:
        return not self._failed

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

    def _yellow(self, s: str) -> str:
        if self._color:
            return "\033[33m" + s + "\033[0m"
        else:
            return s

    def update(
        self, category: str, name: str, passed: bool, in_progress: List[str] = ()
    ) -> None:
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
                    print(self._green("Passed:"), end=" ", file=self._file)
                else:
                    print("       ", end=" ", file=self._file)
                print(f"{category}: {', '.join(names)}", file=self._file)
        if self._failed:
            first = True
            for category, names in self._failed.items():
                if first:
                    first = False
                    print(self._red("Failed:"), end=" ", file=self._file)
                else:
                    print("       ", end=" ", file=self._file)
                print(f"{category}: {', '.join(names)}", file=self._file)
        if in_progress:
            print(
                f"{self._yellow('In Progress')}: {', '.join(in_progress)}",
                file=self._file,
            )

        print(file=self._file)
        print(header, file=self._file, flush=True)


def _kernel_version_is_supported(version: str, arch: Architecture) -> bool:
    # /proc/kcore is broken on AArch64 and Arm on older versions.
    if arch.name in ("aarch64", "arm") and KernelVersion(version) < KernelVersion(
        "4.19"
    ):
        return False
    # Before 4.11, we need an implementation of the
    # linux_kernel_live_direct_mapping_fallback architecture callback in
    # libdrgn, which we only have for x86_64.
    if KernelVersion(version) < KernelVersion("4.11") and arch.name != "x86_64":
        return False
    return True


def _kdump_works(kernel: Kernel) -> bool:
    if kernel.arch.name == "aarch64":
        # kexec fails with "kexec: setup_2nd_dtb failed." on older versions.
        # See
        # http://lists.infradead.org/pipermail/kexec/2020-November/021740.html.
        return KernelVersion(kernel.release) >= KernelVersion("5.10")
    elif kernel.arch.name == "arm":
        # /proc/vmcore fails to initialize. See
        # https://lore.kernel.org/linux-debuggers/ZvxT9EmYkyFuFBH9@telecaster/T/.
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


def _default_parallelism(mem_gb: float = 2, cpu: float = 1.75) -> int:
    for line in open("/proc/meminfo"):
        fields = line.split()
        if fields[0] == "MemAvailable:":
            mem_available_gb = int(fields[1]) / (1024 * 1024)
            break
    else:
        return 1

    limit_mem = mem_available_gb // mem_gb
    limit_cpu = os.cpu_count() // cpu
    parallel = int(max(1, min(limit_mem, limit_cpu)))
    logger.info("Using parallelism: %d", parallel)
    return parallel


class _TestExecutor:
    # This is somewhat similar to the thread pool executor, but when max_workers
    # == 1, it just runs tasks synchronously. The other difference is once we
    # hit the maximum inflight tests, submit() will block until there is room to
    # launch another. This ensures that we don't immediately exhaust the
    # download generator as we enqueue each task.

    def __init__(
        self, max_workers: int, progress: _ProgressPrinter, in_github_actions: bool
    ):
        if max_workers == 0:
            max_workers = _default_parallelism()
        self.max_workers = max_workers
        self.progress = progress
        self.future_to_kernel = {}
        self.in_github_actions = in_github_actions
        if max_workers > 1:
            self.pool = ThreadPoolExecutor(max_workers=max_workers)
        else:
            self.pool = None

    def __enter__(self):
        if self.pool:
            self.pool.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.pool:
            if exc_val:
                print(
                    f"error: {exc_type} {exc_val}\nshutting down tests...",
                    file=sys.stderr,
                )
            self.pool.shutdown(wait=True, cancel_futures=True)
            self.pool.__exit__(exc_type, exc_val, exc_tb)

    def _report_result(self, kernel: Kernel, fn, *args, **kwargs):
        try:
            status = fn(*args, **kwargs)
        except LostVMError as e:
            print("error:", e, file=sys.stderr)
            status = -1

        if self.in_github_actions:
            shutil.rmtree(kernel.path)
        in_progress = [
            f"{k.release} ({k.arch.name})" for k in self.future_to_kernel.values()
        ]
        self.progress.update(kernel.arch.name, kernel.release, status == 0, in_progress)

    def submit(self, kernel, fn, *args, **kwargs):
        if self.pool:
            future = self.pool.submit(fn, *args, **kwargs, main_thread=False)
            self.future_to_kernel[future] = kernel
            # Only allow max_workers tasks to remain in flight
            self.wait(self.max_workers)
        else:
            self._report_result(kernel, fn, *args, **kwargs, main_thread=True)

    def wait(self, inflight: int = 0):
        while self.future_to_kernel and len(self.future_to_kernel) >= inflight:
            done, _ = wait(self.future_to_kernel, return_when=FIRST_COMPLETED)
            for fut in done:
                kernel = self.future_to_kernel[fut]
                del self.future_to_kernel[fut]
                self._report_result(kernel, fut.result)


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
    parser.add_argument(
        "-j",
        "--parallel",
        type=int,
        default=1,
        help="run tests in parallel with the given number of threads; "
        "if 0, automatically select an appropriate parallelism",
    )
    parser.add_argument(
        "--use-host-rootfs",
        choices=["never", "auto"],
        default="auto",
        help='if "never", use $directory/$arch/rootfs even for host architecture; '
        'if "auto", use / for host architecture',
    )
    args = parser.parse_args()

    if not hasattr(args, "kernels") and not args.local:
        parser.error("at least one of -k/--kernel or -l/--local is required")

    if args.use_host_rootfs == "auto":

        def use_host_rootfs(arch: Architecture) -> bool:
            return arch is HOST_ARCHITECTURE

    else:

        def use_host_rootfs(arch: Architecture) -> bool:
            return False

    architecture_names: List[str] = []
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
        assert HOST_ARCHITECTURE is not None
        architectures = [HOST_ARCHITECTURE]

    seen_arches = set()
    seen_kernels = set()
    to_download: List[Download] = []
    kernels = []

    def add_kernel(arch: Architecture, pattern: str) -> None:
        key = (arch.name, pattern)
        if key not in seen_kernels:
            seen_kernels.add(key)
            if arch.name not in seen_arches:
                seen_arches.add(arch.name)
                to_download.append(DownloadCompiler(arch))
            kernels.append(DownloadKernel(arch, pattern))

    if hasattr(args, "kernels"):
        for pattern in args.kernels:
            if pattern == "all":
                for version in SUPPORTED_KERNEL_VERSIONS:
                    for arch in architectures:
                        if _kernel_version_is_supported(version, arch):
                            for flavor in KERNEL_FLAVORS.values():
                                add_kernel(arch, version + ".*" + flavor.name)
            elif pattern in KERNEL_FLAVORS:
                flavor = KERNEL_FLAVORS[pattern]
                for version in SUPPORTED_KERNEL_VERSIONS:
                    for arch in architectures:
                        if _kernel_version_is_supported(version, arch):
                            add_kernel(arch, version + ".*" + flavor.name)
            else:
                for arch in architectures:
                    add_kernel(arch, pattern)

    to_download.extend(kernels)

    progress = _ProgressPrinter(sys.stderr)

    in_github_actions = os.getenv("GITHUB_ACTIONS") == "true"

    # Downloading too many files before they can be used for testing runs the
    # risk of filling up the limited disk space is Github Actions. Set a limit
    # of no more than 5 files which can be downloaded ahead of time. This is a
    # magic number which is inexact, but works well enough.
    # Note that Github Actions does not run vmtest via this script currently,
    # but may in the future.
    max_pending_kernels = 5 if in_github_actions else 0

    with download_in_thread(
        args.directory, to_download, max_pending_kernels
    ) as downloads, _TestExecutor(
        args.parallel, progress, in_github_actions
    ) as executor:
        for arch in architectures:
            if use_host_rootfs(arch):
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

            if use_host_rootfs(kernel.arch):
                python_executable = sys.executable
                tests_expression = ""
            else:
                python_executable = "/usr/bin/python3"
                # Skip excessively slow tests when emulating.
                tests_expression = "-k 'not test_slab_cache_for_each_allocated_object and not test_mtree_load_three_levels'"

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

export PYTHON={shlex.quote(python_executable)}
export DRGN_RUN_LINUX_KERNEL_TESTS=1
if [ -e /proc/vmcore ]; then
    "$PYTHON" -Bm pytest -v tests/linux_kernel/vmcore
else
    insmod "$DRGN_TEST_KMOD"
    "$PYTHON" -Bm pytest -v tests/linux_kernel --ignore=tests/linux_kernel/vmcore {tests_expression}
{kdump_command}
fi
"""
            outfile = sys.stdout
            if executor.max_workers > 1:
                outpath = args.directory / kernel.arch.name / f"log-{kernel.release}"
                outfile = outpath.open("w")
            future = executor.submit(
                kernel,
                run_in_vm,
                test_command,
                kernel,
                (
                    Path("/")
                    if use_host_rootfs(kernel.arch)
                    else args.directory / kernel.arch.name / "rootfs"
                ),
                args.directory,
                test_kmod=TestKmodMode.BUILD,
                outfile=outfile,
            )
        executor.wait()

    sys.exit(0 if progress.succeeded() else 1)
