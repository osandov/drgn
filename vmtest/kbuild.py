# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import asyncio
import filecmp
import logging
from pathlib import Path
import shlex
import shutil
import sys
import tempfile
from typing import IO, Any, Optional, Tuple, Union

from util import nproc
from vmtest.asynciosubprocess import (
    CalledProcessError,
    check_call,
    check_output,
    check_output_shell,
    pipe_context,
)

logger = logging.getLogger(__name__)

KERNEL_LOCALVERSION = "-vmtest6"


def kconfig() -> str:
    return rf"""# Minimal Linux kernel configuration for booting into vmtest and running drgn
# tests.

CONFIG_LOCALVERSION="{KERNEL_LOCALVERSION}"

CONFIG_SMP=y
CONFIG_MODULES=y

# We run the tests in KVM.
CONFIG_HYPERVISOR_GUEST=y
CONFIG_KVM_GUEST=y
CONFIG_PARAVIRT=y
CONFIG_PARAVIRT_SPINLOCKS=y

# Minimum requirements for vmtest.
CONFIG_9P_FS=y
CONFIG_DEVTMPFS=y
CONFIG_INET=y
CONFIG_NET=y
CONFIG_NETWORK_FILESYSTEMS=y
CONFIG_NET_9P=y
CONFIG_NET_9P_VIRTIO=y
CONFIG_OVERLAY_FS=y
CONFIG_PCI=y
CONFIG_PROC_FS=y
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_SYSFS=y
CONFIG_TMPFS=y
CONFIG_TMPFS_XATTR=y
CONFIG_VIRTIO_CONSOLE=y
CONFIG_VIRTIO_PCI=y
CONFIG_HW_RANDOM=m
CONFIG_HW_RANDOM_VIRTIO=m

# drgn needs /proc/kcore for live debugging.
CONFIG_PROC_KCORE=y
# In some cases, it also needs /proc/kallsyms.
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y

# drgn needs debug info.
CONFIG_DEBUG_KERNEL=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_DWARF4=y

# Before Linux kernel commit 8757dc970f55 ("x86/crash: Define
# arch_crash_save_vmcoreinfo() if CONFIG_CRASH_CORE=y") (in v5.6), some
# important information in VMCOREINFO is initialized by the kexec code.
CONFIG_KEXEC=y

# For block tests.
CONFIG_BLK_DEV_LOOP=m

# For cgroup tests.
CONFIG_CGROUPS=y

# For kconfig tests.
CONFIG_IKCONFIG=m
CONFIG_IKCONFIG_PROC=y

# For nodemask tests.
CONFIG_NUMA=y

# For Traffic Control tests.
CONFIG_NET_SCHED=y
CONFIG_NET_SCH_PRIO=m
CONFIG_NET_SCH_SFQ=m
CONFIG_NET_SCH_TBF=m
CONFIG_NET_SCH_INGRESS=m
CONFIG_NET_CLS_ACT=y
CONFIG_NETDEVICES=y
CONFIG_DUMMY=m
"""


class KBuild:
    def __init__(
        self,
        kernel_dir: Path,
        build_dir: Path,
        arch: str,
        build_log_file: Union[int, IO[Any], None] = None,
    ) -> None:
        self._build_dir = build_dir
        self._kernel_dir = kernel_dir
        self._arch = arch
        self._build_stdout = build_log_file
        self._build_stderr = (
            None if build_log_file is None else asyncio.subprocess.STDOUT
        )
        self._cached_make_args: Optional[Tuple[str, ...]] = None
        self._cached_kernel_release: Optional[str] = None

    async def _prepare_make(self) -> Tuple[str, ...]:
        if self._cached_make_args is None:
            self._build_dir.mkdir(parents=True, exist_ok=True)

            debug_prefix_map = []
            # GCC uses the "logical" working directory, i.e., the PWD
            # environment variable, when it can. See
            # https://gcc.gnu.org/git/?p=gcc.git;a=blob;f=libiberty/getpwd.c;hb=HEAD.
            # Map both the canonical and logical paths.
            build_dir_real = self._build_dir.resolve()
            debug_prefix_map.append(str(build_dir_real) + "=.")
            build_dir_logical = (
                await check_output_shell(
                    f"cd {shlex.quote(str(self._build_dir))}; pwd -L",
                )
            ).decode()[:-1]
            if build_dir_logical != str(build_dir_real):
                debug_prefix_map.append(build_dir_logical + "=.")

            # Before Linux kernel commit 25b146c5b8ce ("kbuild: allow Kbuild to
            # start from any directory") (in v5.2), O= forces the source
            # directory to be absolute. Since Linux kernel commit 95fd3f87bfbe
            # ("kbuild: add a flag to force absolute path for srctree") (in
            # v5.3), KBUILD_ABS_SRCTREE=1 does the same. This means that except
            # for v5.2, which we don't support, the source directory will
            # always be absolute, and we don't need to worry about mapping it
            # from a relative path.
            kernel_dir_real = self._kernel_dir.resolve()
            if kernel_dir_real != build_dir_real:
                debug_prefix_map.append(str(kernel_dir_real) + "/=./")

            cflags = " ".join(["-fdebug-prefix-map=" + map for map in debug_prefix_map])

            self._cached_make_args = (
                "-C",
                str(self._kernel_dir),
                "ARCH=" + str(self._arch),
                "O=" + str(build_dir_real),
                "KBUILD_ABS_SRCTREE=1",
                "KBUILD_BUILD_USER=drgn",
                "KBUILD_BUILD_HOST=drgn",
                "KAFLAGS=" + cflags,
                "KCFLAGS=" + cflags,
                "-j",
                str(nproc()),
            )
        return self._cached_make_args

    async def _kernel_release(self) -> str:
        if self._cached_kernel_release is None:
            # Must call _prepare_make() first.
            assert self._cached_make_args is not None
            self._cached_kernel_release = (
                (
                    await check_output(
                        "make", *self._cached_make_args, "-s", "kernelrelease"
                    )
                )
                .decode()
                .strip()
            )
        return self._cached_kernel_release

    async def build(self) -> None:
        logger.info("building kernel in %s", self._build_dir)
        build_log_file_name = getattr(self._build_stdout, "name", None)
        if build_log_file_name is not None:
            logger.info("build logs in %s", build_log_file_name)

        make_args = await self._prepare_make()

        config = self._build_dir / ".config"
        tmp_config = self._build_dir / ".config.vmtest.tmp"

        tmp_config.write_text(kconfig())
        await check_call(
            "make",
            *make_args,
            "KCONFIG_CONFIG=" + tmp_config.name,
            "olddefconfig",
            stdout=self._build_stdout,
            stderr=self._build_stderr,
        )
        try:
            equal = filecmp.cmp(config, tmp_config)
            if not equal:
                logger.info("kernel configuration changed")
        except FileNotFoundError:
            equal = False
            logger.info("no previous kernel configuration")
        if equal:
            logger.info("kernel configuration did not change")
            tmp_config.unlink()
        else:
            tmp_config.rename(config)

        kernel_release = await self._kernel_release()
        logger.info("kernel release is %s", kernel_release)
        await check_call(
            "make",
            *make_args,
            "all",
            stdout=self._build_stdout,
            stderr=self._build_stderr,
        )
        logger.info("built kernel %s in %s", kernel_release, self._build_dir)

    async def package(self, output_dir: Path) -> Path:
        make_args = await self._prepare_make()
        kernel_release = await self._kernel_release()

        tarball = output_dir / f"kernel-{kernel_release}.{self._arch}.tar.zst"

        logger.info(
            "packaging kernel %s from %s to %s",
            kernel_release,
            self._build_dir,
            tarball,
        )

        image_name = (
            (await check_output("make", *make_args, "-s", "image_name"))
            .decode()
            .strip()
        )

        with tempfile.TemporaryDirectory(
            prefix="install.", dir=self._build_dir
        ) as tmp_name:
            install_dir = Path(tmp_name)
            modules_dir = install_dir / "lib" / "modules" / kernel_release

            logger.info("installing modules")
            await check_call(
                "make",
                *make_args,
                "INSTALL_MOD_PATH=" + str(install_dir.resolve()),
                "modules_install",
                stdout=self._build_stdout,
                stderr=self._build_stderr,
            )
            # Don't want these symlinks.
            (modules_dir / "build").unlink()
            (modules_dir / "source").unlink()

            logger.info("copying vmlinux")
            vmlinux = modules_dir / "vmlinux"
            await check_call(
                "objcopy",
                "--remove-relocations=*",
                self._build_dir / "vmlinux",
                str(vmlinux),
            )
            vmlinux.chmod(0o644)

            logger.info("copying vmlinuz")
            vmlinuz = modules_dir / "vmlinuz"
            shutil.copy(self._build_dir / image_name, vmlinuz)
            vmlinuz.chmod(0o644)

            logger.info("creating tarball")
            tarball.parent.mkdir(parents=True, exist_ok=True)
            tar_cmd = ("tar", "-C", str(modules_dir), "-c", ".")
            zstd_cmd = ("zstd", "-T0", "-19", "-q", "-", "-o", str(tarball), "-f")
            with pipe_context() as (pipe_r, pipe_w):
                tar_proc, zstd_proc = await asyncio.gather(
                    asyncio.create_subprocess_exec(*tar_cmd, stdout=pipe_w),
                    asyncio.create_subprocess_exec(*zstd_cmd, stdin=pipe_r),
                )
            tar_returncode, zstd_returncode = await asyncio.gather(
                tar_proc.wait(), zstd_proc.wait()
            )
            if tar_returncode != 0:
                raise CalledProcessError(tar_returncode, tar_cmd)
            if zstd_returncode != 0:
                raise CalledProcessError(zstd_returncode, zstd_cmd)

        logger.info(
            "packaged kernel %s from %s to %s", kernel_release, self._build_dir, tarball
        )
        return tarball


async def main() -> None:
    logging.basicConfig(
        format="%(asctime)s:%(levelname)s:%(name)s:%(message)s", level=logging.INFO
    )

    parser = argparse.ArgumentParser(
        description="Build a drgn vmtest kernel",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-k",
        "--kernel-directory",
        metavar="DIR",
        type=Path,
        help="kernel source tree directory",
        default=".",
    )
    parser.add_argument(
        "-b",
        "--build-directory",
        metavar="DIR",
        type=Path,
        help="build output directory",
        default=".",
    )
    parser.add_argument(
        "-p",
        "--package",
        metavar="DIR",
        type=Path,
        help="also package the built kernel and place it in DIR",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--dump-kconfig",
        action="store_true",
        help="dump kernel configuration file to standard output instead of building",
    )
    args = parser.parse_args()

    if args.dump_kconfig:
        sys.stdout.write(kconfig())
        return

    kbuild = KBuild(args.kernel_directory, args.build_directory, "x86_64")
    await kbuild.build()
    if hasattr(args, "package"):
        await kbuild.package(args.package)


if __name__ == "__main__":
    asyncio.run(main())
