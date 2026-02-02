#!/usr/bin/env python3

from collections import deque
import concurrent.futures
import contextlib
import functools
import logging
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time
import traceback
from typing import (
    TYPE_CHECKING,
    Callable,
    Deque,
    Dict,
    List,
    Optional,
    Protocol,
    Set,
    TextIO,
    Tuple,
    Union,
)

from util import KernelVersion, nproc
from vmtest.chroot import chroot_sh_cmd
from vmtest.config import (
    ARCHITECTURES,
    HOST_ARCHITECTURE,
    KERNEL_FLAVORS,
    SUPPORTED_KERNEL_VERSIONS,
    Architecture,
    Compiler,
    Kernel,
)
from vmtest.download import Downloader
from vmtest.rootfsbuild import build_drgn_for_arch
from vmtest.vm import LostVMError, TestKmodMode, run_in_vm

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    if sys.version_info < (3, 10):
        from typing_extensions import ParamSpec
    else:
        from typing import ParamSpec  # novermin
    _P = ParamSpec("_P")


class _TestFunction(Protocol):
    def __call__(self, *, outfile: Optional[TextIO] = None) -> bool: ...


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
    limit_cpu = nproc() // cpu
    return int(max(1, min(limit_mem, limit_cpu)))


class _TestRunner:
    def __init__(
        self,
        *,
        directory: Path,
        jobs: Optional[int] = None,
        use_host_rootfs: bool = True,
        skip_build: bool = False,
        pytest_kernel_args: Optional[str] = None,
        skip_kdump: bool = False,
    ) -> None:
        self._directory = directory
        if jobs is None:
            self._jobs = 1
        elif jobs == 0:
            self._jobs = _default_parallelism()
            logger.info("using default parallelism %d", self._jobs)
        else:
            self._jobs = jobs
            logger.info("using parallelism %d", self._jobs)
        self._foreground = jobs is None
        self._use_host_rootfs = use_host_rootfs
        self._skip_build = skip_build

        self._compilers_to_resolve: Dict[Architecture, None] = {}
        self._kernels_to_resolve: Dict[Tuple[Architecture, str], None] = {}
        self._drgn_builds: Dict[Architecture, None] = {}

        # + 1 for download tasks.
        self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=self._jobs + 1)
        self._futures: Set["concurrent.futures.Future[Callable[[], bool]]"] = set()

        self._downloader = Downloader(directory)
        self._download_queue: Deque[Union[Compiler, Kernel]] = deque()

        self._test_queue: Deque[Tuple[str, str, _TestFunction]] = deque()
        self._tests_running: Dict[Tuple[str, str], float] = {}
        self._tests_passed: Dict[str, List[str]] = {}
        self._tests_failed: Dict[str, List[str]] = {}

        try:
            self._color = os.isatty(sys.stderr.fileno())
        except (AttributeError, OSError):
            self._color = False

        self._pytest_kernel_args = pytest_kernel_args
        self._skip_kdump = skip_kdump

    def add_kernel(self, arch: Architecture, pattern: str) -> None:
        self._compilers_to_resolve[arch] = None
        self._kernels_to_resolve[(arch, pattern)] = None
        if not self._skip_build:
            self._drgn_builds[arch] = None

    def add_local(self, arch: Architecture) -> None:
        if not self._skip_build:
            self._drgn_builds[arch] = None
        self._queue_local_test(arch)

    def _submit(
        self,
        fn: Callable["_P", Callable[[], bool]],
        *args: "_P.args",
        **kwargs: "_P.kwargs",
    ) -> None:
        self._futures.add(self._pool.submit(fn, *args, **kwargs))

    def run(self) -> bool:
        try:
            self._submit(self._resolve_downloads)

            self._submit_next_drgn_build()

            self._print_progress()
            while self._futures:
                done, self._futures = concurrent.futures.wait(
                    self._futures,
                    timeout=None if self._foreground else 1,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                update_progress = not self._foreground
                for future in done:
                    callback = future.result()
                    update_progress |= callback()
                if update_progress:
                    self._print_progress()
        except Exception:
            traceback.print_exc()
            return False
        finally:
            for future in self._futures:
                future.cancel()
            self._pool.shutdown()
        return not self._tests_failed

    def _green(self, s: str) -> str:
        if self._color:
            return "\033[32m" + s + "\033[m"
        else:
            return s

    def _red(self, s: str) -> str:
        if self._color:
            return "\033[31m" + s + "\033[m"
        else:
            return s

    def _yellow(self, s: str) -> str:
        if self._color:
            return "\033[33m" + s + "\033[m"
        else:
            return s

    def _cyan(self, s: str) -> str:
        if self._color:
            return "\033[36m" + s + "\033[m"
        else:
            return s

    def _print_progress(self) -> None:
        parts = []
        if self._foreground:
            endl = "\n"
        else:
            # To minimize flicker, we overwrite the output instead of clearing.
            parts.append("\033[H")  # Move cursor to top left corner.
            endl = "\033[K\n"  # Clear to the end of line on each newline.
            if self._compilers_to_resolve or self._kernels_to_resolve:
                parts.append(self._cyan("Queueing downloads..."))
                parts.append(endl)
            elif self._download_queue:
                num_compilers = sum(
                    isinstance(download, Compiler) for download in self._download_queue
                )
                num_kernels = len(self._download_queue) - num_compilers

                downloading_parts = []
                if num_compilers == 1:
                    downloading_parts.append("1 compiler")
                elif num_compilers > 1:
                    downloading_parts.append(f"{num_compilers} compilers")
                if num_kernels == 1:
                    downloading_parts.append("1 kernel")
                elif num_kernels > 1:
                    downloading_parts.append(f"{num_kernels} kernels")

                parts.append(
                    self._cyan(f"Downloading {' and '.join(downloading_parts)}...")
                )
                parts.append(endl)

            if self._test_queue:
                parts.append(self._cyan(f"{len(self._test_queue)} tests waiting..."))
                parts.append(endl)

            if self._drgn_builds:
                parts.append(self._yellow("Building: "))
                parts.append(", ".join([arch.name for arch in self._drgn_builds]))
                parts.append(endl)

            now = time.monotonic()
            first = True
            for (category_name, test_name), start_time in reversed(
                self._tests_running.items()
            ):
                if first:
                    parts.append(self._yellow("Running: "))
                    first = False
                else:
                    parts.append("         ")
                parts.append(f"{category_name}: {test_name} ({int(now - start_time)}s)")
                parts.append(endl)

        for title, results, color in (
            ("Passed", self._tests_passed, self._green),
            ("Failed", self._tests_failed, self._red),
        ):
            first = True
            for category_name, test_names in sorted(results.items()):
                if first:
                    parts.append(color(title + ":"))
                    parts.append(" ")
                    first = False
                else:
                    parts.append(" " * (len(title) + 2))
                parts.append(f"{category_name}: {', '.join(test_names)}")
                parts.append(endl)

        if not self._foreground:
            parts.append("\033[J")  # Clear the rest of the screen.
        sys.stderr.write("".join(parts))

    def _submit_next_drgn_build(self) -> None:
        if self._drgn_builds:
            self._submit(self._build_drgn, next(iter(self._drgn_builds)))
        else:
            self._submit_tests()

    def _rootfs(self, arch: Architecture) -> Path:
        if self._use_host_rootfs and arch is HOST_ARCHITECTURE:
            return Path("/")
        else:
            return self._directory / arch.name / "rootfs"

    def _build_drgn(self, arch: Architecture) -> Callable[[], bool]:
        with contextlib.ExitStack() as exit_stack:
            if self._foreground:
                outfile = None
            else:
                outfile = exit_stack.enter_context(
                    (self._directory / "log" / f"{arch.name}-build.log").open("w")
                )
            if self._use_host_rootfs and arch is HOST_ARCHITECTURE:
                subprocess.check_call(
                    [sys.executable, "setup.py", "build_ext", "-i"],
                    stdout=outfile,
                    stderr=outfile,
                )
            else:
                build_drgn_for_arch(arch, self._directory, outfile=outfile)
        return functools.partial(self._drgn_build_done, arch)

    def _drgn_build_done(self, arch: Architecture) -> bool:
        del self._drgn_builds[arch]
        self._submit_next_drgn_build()
        return not self._foreground

    def _resolve_downloads(self) -> Callable[[], bool]:
        for target in self._compilers_to_resolve:
            compiler = self._downloader.resolve_compiler(target)
            self._download_queue.append(compiler)

        for arch, pattern in self._kernels_to_resolve:
            kernel = self._downloader.resolve_kernel(arch, pattern)
            self._download_queue.append(kernel)

        return self._resolved_downloads

    def _resolved_downloads(self) -> bool:
        self._compilers_to_resolve.clear()
        self._kernels_to_resolve.clear()
        return self._submit_next_download()

    def _submit_next_download(self) -> bool:
        if self._download_queue:
            self._submit(self._download, self._download_queue[0])
        return not self._foreground

    def _download(self, download: Union[Compiler, Kernel]) -> Callable[[], bool]:
        if isinstance(download, Compiler):
            self._downloader.download_compiler(download)
        else:
            self._downloader.download_kernel(download)
        return functools.partial(self._download_done, download)

    def _download_done(self, download: Union[Compiler, Kernel]) -> bool:
        popped = self._download_queue.popleft()
        assert popped is download
        self._submit_next_download()
        if isinstance(download, Kernel):
            self._queue_kernel_test(download)
        return not self._foreground

    def _queue_local_test(self, arch: Architecture) -> None:
        self._queue_test(arch.name, "local", functools.partial(self._test_local, arch))

    def _queue_kernel_test(self, kernel: Kernel) -> None:
        self._queue_test(
            kernel.arch.name,
            kernel.release,
            functools.partial(self._test_kernel, kernel),
        )

    def _queue_test(
        self, category_name: str, test_name: str, fn: _TestFunction
    ) -> None:
        self._test_queue.append((category_name, test_name, fn))
        logger.info("%s %s test queued", category_name, test_name)
        if not self._drgn_builds:
            self._submit_tests()

    def _submit_tests(self) -> None:
        assert not self._drgn_builds
        while self._test_queue and len(self._tests_running) < self._jobs:
            category_name, test_name, fn = self._test_queue.popleft()
            self._tests_running[(category_name, test_name)] = time.monotonic()
            logger.info("%s %s test started", category_name, test_name)
            self._submit(self._test_wrapper, category_name, test_name, fn)

    def _test_wrapper(
        self, category_name: str, test_name: str, fn: _TestFunction
    ) -> Callable[[], bool]:
        with contextlib.ExitStack() as exit_stack:
            if self._foreground:
                outfile = None
            else:
                outfile = exit_stack.enter_context(
                    (self._directory / "log" / f"{category_name}-{test_name}.log").open(
                        "w"
                    )
                )
            success = fn(outfile=outfile)
        return functools.partial(self._test_done, category_name, test_name, success)

    def _test_done(self, category_name: str, test_name: str, success: bool) -> bool:
        start_time = self._tests_running.pop((category_name, test_name))
        logger.info(
            "%s %s test %s (%ds)",
            category_name,
            test_name,
            "passed" if success else "failed",
            time.monotonic() - start_time,
        )
        (self._tests_passed if success else self._tests_failed).setdefault(
            category_name, []
        ).append(test_name)
        self._submit_tests()
        return True

    def _test_local(
        self, arch: Architecture, *, outfile: Optional[TextIO] = None
    ) -> bool:
        rootfs = self._rootfs(arch)
        if rootfs == Path("/"):
            args = [
                sys.executable,
                "-m",
                "pytest",
                "-v",
                "--ignore=tests/linux_kernel",
            ]
        else:
            args = [
                "unshare",
                "--map-root-user",
                "--map-auto",
                "--fork",
                "--pid",
                "--mount-proc=" + str(rootfs / "proc"),
                "sh",
                "-c",
                f"""\
set -e

mount --bind . "$1/mnt"
{chroot_sh_cmd('"$1"')} 'cd /mnt && pytest -v --ignore=tests/linux_kernel'
""",
                "sh",
                str(rootfs),
            ]
        return subprocess.call(args, stdout=outfile, stderr=outfile) == 0

    def _test_kernel(self, kernel: Kernel, *, outfile: Optional[TextIO] = None) -> bool:
        rootfs = self._rootfs(kernel.arch)
        if rootfs == Path("/"):
            python_executable = sys.executable
        else:
            python_executable = "/usr/bin/python3"

        if _kdump_works(kernel) and not self._skip_kdump:
            kdump_command = """\
    "$PYTHON" -Bm vmtest.enter_kdump
    # We should crash and not reach this.
    exit 1
"""
        else:
            kdump_command = ""

        if self._pytest_kernel_args is not None:
            pytest_args = self._pytest_kernel_args
        elif kernel.arch is HOST_ARCHITECTURE:
            pytest_args = "tests/linux_kernel --ignore tests/linux_kernel/vmcore"
        else:
            pytest_args = (
                "tests/linux_kernel --ignore tests/linux_kernel/vmcore -m 'not slow'"
            )

        test_command = rf"""
set -e

export PYTHON={shlex.quote(python_executable)}
export DRGN_RUN_LINUX_KERNEL_TESTS=1
if [ -e /proc/vmcore ]; then
    "$PYTHON" -Bm pytest -v tests/linux_kernel/vmcore
else
    insmod "$DRGN_TEST_KMOD"
    "$PYTHON" -Bm pytest -v {pytest_args}
{kdump_command}
fi
"""

        # Silence as much boot text as possible if we're specifying tests to run
        # in the foreground
        extra_kernel_cmdline = []
        if self._pytest_kernel_args and self._foreground:
            extra_kernel_cmdline.append("quiet")

        try:
            status = run_in_vm(
                test_command,
                kernel,
                rootfs,
                self._directory,
                test_kmod=TestKmodMode.BUILD,
                outfile=outfile,
                extra_kernel_cmdline=extra_kernel_cmdline,
            )
            return status == 0
        except (
            LostVMError,
            subprocess.CalledProcessError,  # For kmod build errors.
        ) as e:
            print(e, file=sys.stderr if outfile is None else outfile)
            return False


if __name__ == "__main__":
    import argparse

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
        "--jobs",
        type=int,
        nargs="?",
        default=argparse.SUPPRESS,
        help="number of tests to run in parallel (default: 1). "
        "If the argument is omitted or 0, "
        "an appropriate number is chosen automatically",
    )
    parser.add_argument(
        "--use-host-rootfs",
        choices=["never", "auto"],
        default="auto",
        help='if "never", use $directory/$arch/rootfs even for host architecture; '
        'if "auto", use / for host architecture',
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="don't rebuild drgn even if it's out of date",
    )
    parser.add_argument(
        "--pytest-args",
        help="a string of args passed to pytest for kernel tests",
    )
    parser.add_argument(
        "--skip-kdump",
        action="store_true",
        help="skip kdump and vmcore tests (useful with --pytest-args)",
    )
    args = parser.parse_args()

    if not hasattr(args, "kernels") and not args.local:
        parser.error("at least one of -k/--kernel or -l/--local is required")

    if hasattr(args, "jobs"):
        if args.jobs is None:
            args.jobs = 0

        log_directory = args.directory / "log"
        log_old_directory = args.directory / "log.old"

        try:
            shutil.rmtree(log_old_directory)
        except FileNotFoundError:
            pass
        try:
            log_directory.rename(log_old_directory)
        except FileNotFoundError:
            pass
        log_directory.mkdir(parents=True)

        main_log_path = log_directory / "main.log"
    else:
        args.jobs = None
        main_log_path = None
    logging.basicConfig(
        format="%(asctime)s:%(levelname)s:%(name)s:%(message)s",
        level=logging.INFO,
        filename=main_log_path,
    )

    architectures: Dict[Architecture, None] = {}
    if hasattr(args, "architectures"):
        for name in args.architectures:
            if name == "all":
                for arch in ARCHITECTURES.values():
                    architectures[arch] = None
            elif name == "foreign":
                for arch in ARCHITECTURES.values():
                    if arch is not HOST_ARCHITECTURE:
                        architectures[arch] = None
            else:
                architectures[ARCHITECTURES[name]] = None
    else:
        assert HOST_ARCHITECTURE is not None
        architectures = {HOST_ARCHITECTURE: None}

    runner = _TestRunner(
        directory=args.directory,
        jobs=args.jobs,
        use_host_rootfs=args.use_host_rootfs == "auto",
        skip_build=args.skip_build,
        pytest_kernel_args=args.pytest_args,
        skip_kdump=args.skip_kdump,
    )

    if hasattr(args, "kernels"):
        for pattern in args.kernels:
            if pattern == "all":
                for version in SUPPORTED_KERNEL_VERSIONS:
                    for arch in architectures:
                        if _kernel_version_is_supported(version, arch):
                            for flavor in KERNEL_FLAVORS.values():
                                runner.add_kernel(arch, version + ".*" + flavor.name)
            elif pattern in KERNEL_FLAVORS:
                flavor = KERNEL_FLAVORS[pattern]
                for version in SUPPORTED_KERNEL_VERSIONS:
                    for arch in architectures:
                        if _kernel_version_is_supported(version, arch):
                            runner.add_kernel(arch, version + ".*" + flavor.name)
            else:
                for arch in architectures:
                    runner.add_kernel(arch, pattern)

    if args.local:
        for arch in architectures:
            runner.add_local(arch)

    success = runner.run()
    sys.exit(0 if success else 1)
