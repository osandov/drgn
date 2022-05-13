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
from typing import IO, Any, NamedTuple, Optional, Tuple, Union

from util import nproc
from vmtest.asynciosubprocess import (
    CalledProcessError,
    check_call,
    check_output,
    check_output_shell,
    pipe_context,
)

logger = logging.getLogger(__name__)


class KernelFlavor(NamedTuple):
    name: str
    description: str
    config: str

    def localversion(self) -> str:
        localversion = "-vmtest11"
        # The default flavor should be the "latest" version.
        localversion += ".1" if self.name == "default" else ".0"
        localversion += self.name
        return localversion


KERNEL_FLAVORS = [
    KernelFlavor(
        name="default",
        description="Default configuration",
        config="""
CONFIG_SMP=y
CONFIG_SLUB=y
# For slab tests.
CONFIG_SLUB_DEBUG=y
""",
    ),
    KernelFlavor(
        name="alternative",
        description="SLAB allocator",
        config="""
CONFIG_SMP=y
CONFIG_SLAB=y
""",
    ),
    KernelFlavor(
        name="tiny",
        description="!SMP, !PREEMPT, and SLOB allocator",
        config="""
CONFIG_SMP=n
CONFIG_SLOB=y
# CONFIG_PREEMPT_DYNAMIC is not set
CONFIG_PREEMPT_NONE=y
# !PREEMPTION && !SMP will also select TINY_RCU.
""",
    ),
]


def kconfig(flavor: KernelFlavor) -> str:
    return rf"""# Minimal Linux kernel configuration for booting into vmtest and running drgn
# tests ({flavor.name} flavor).

CONFIG_LOCALVERSION="{flavor.localversion()}"
CONFIG_EXPERT=y
{flavor.config}
CONFIG_MODULES=y
CONFIG_CC_OPTIMIZE_FOR_SIZE=y

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

# drgn needs debug info.
CONFIG_DEBUG_KERNEL=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_DWARF4=y

# For testing live kernel debugging with /proc/kcore.
CONFIG_PROC_KCORE=y
# drgn needs /proc/kallsyms in some cases. Some test cases also need it.
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y

# For testing kernel core dumps with /proc/vmcore.
CONFIG_CRASH_DUMP=y
CONFIG_PROC_VMCORE=y
CONFIG_KEXEC=y
CONFIG_KEXEC_FILE=y
# Needed for CONFIG_KEXEC_FILE.
CONFIG_CRYPTO=y
CONFIG_CRYPTO_SHA256=y

# So that we can trigger a crash with /proc/sysrq-trigger.
CONFIG_MAGIC_SYSRQ=y

# For block tests.
CONFIG_BLK_DEV_LOOP=m

# For cgroup tests.
CONFIG_CGROUPS=y

# For kconfig tests.
CONFIG_IKCONFIG=m
CONFIG_IKCONFIG_PROC=y

# For net tests.
CONFIG_NAMESPACES=y

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
        flavor: KernelFlavor,
        arch: str,
        build_log_file: Union[int, IO[Any], None] = None,
    ) -> None:
        self._build_dir = build_dir
        self._kernel_dir = kernel_dir
        self._flavor = flavor
        self._arch = arch
        self._srcarch = {"x86_64": "x86"}.get(arch, arch)
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
                "HOSTCFLAGS=" + cflags,
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
        logger.info("building %s kernel in %s", self._flavor.name, self._build_dir)
        build_log_file_name = getattr(self._build_stdout, "name", None)
        if build_log_file_name is not None:
            logger.info("build logs in %s", build_log_file_name)

        make_args = await self._prepare_make()

        config = self._build_dir / ".config"
        tmp_config = self._build_dir / ".config.vmtest.tmp"

        tmp_config.write_text(kconfig(self._flavor))
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

    def _copy_module_build(self, modules_dir: Path) -> None:
        logger.info("copying module build files")

        # `make modules_install` creates these as symlinks to the absolute path
        # of the source directory. Delete them, populate build, and make source
        # a symlink to build.
        modules_build_dir = modules_dir / "build"
        modules_source_dir = modules_dir / "source"
        modules_build_dir.unlink()
        modules_build_dir.mkdir()
        modules_source_dir.unlink()
        modules_source_dir.symlink_to("build")

        # Files and directories (as glob patterns) required for external module
        # builds. This list was determined through trial and error.
        files = (
            ".config",
            "Module.symvers",
            f"arch/{self._srcarch}/Makefile",
            "scripts/Kbuild.include",
            "scripts/Makefile*",
            "scripts/basic/fixdep",
            "scripts/gcc-goto.sh",
            "scripts/gcc-version.sh",
            "scripts/mod/modpost",
            "scripts/module-common.lds",
            "scripts/module.lds",
            "scripts/modules-check.sh",
            "scripts/pahole-flags.sh",
            "scripts/pahole-version.sh",
            "scripts/subarch.include",
            "tools/objtool/objtool",
        )
        directories = (
            f"arch/{self._srcarch}/include",
            "include",
        )

        # Copy from the source and build directories.
        src_dirs = [self._kernel_dir]
        if not self._build_dir.samefile(self._kernel_dir):
            src_dirs.append(self._build_dir)
        # The top-level Makefile is a special case because we only want the one
        # from the source directory; the one in the build directory is a stub.
        shutil.copy2(
            self._kernel_dir / "Makefile",
            modules_build_dir / "Makefile",
            follow_symlinks=False,
        )
        for glob in files:
            for src_dir in src_dirs:
                for src_path in src_dir.glob(glob):
                    dst_path = modules_build_dir / src_path.relative_to(src_dir)
                    dst_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src_path, dst_path, follow_symlinks=False)
        for glob in directories:
            for src_dir in src_dirs:
                for src_path in src_dir.glob(glob):
                    dst_path = modules_build_dir / src_path.relative_to(src_dir)
                    dst_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copytree(
                        src_path, dst_path, symlinks=True, dirs_exist_ok=True
                    )

    async def _test_external_module_build(self, modules_dir: Path) -> None:
        logger.info("testing external module build")

        with tempfile.TemporaryDirectory(
            prefix="test_module.", dir=self._build_dir
        ) as tmp_name:
            test_module_dir = Path(tmp_name)
            (test_module_dir / "test.c").write_text(
                r"""
#include <linux/module.h>

static int __init test_init(void)
{
	return 0;
}

module_init(test_init);

MODULE_LICENSE("GPL");
"""
            )
            (test_module_dir / "Makefile").write_text("obj-m := test.o\n")
            # Execute make and look for errors in its output. It's not
            # enough to check its exit status because some of the build
            # scripts limp along (possibly incorrectly) even if they're
            # missing some files.
            cmd = (
                "make",
                "-C",
                modules_dir / "build",
                f"M={test_module_dir.resolve()}",
            )
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            try:
                stdout_task = asyncio.create_task(proc.stdout.readline())
                stderr_task = asyncio.create_task(proc.stderr.readline())
                error = False
                while stdout_task is not None or stderr_task is not None:
                    aws = []
                    if stdout_task is not None:
                        aws.append(stdout_task)
                    if stderr_task is not None:
                        aws.append(stderr_task)
                    done, pending = await asyncio.wait(
                        aws, return_when=asyncio.FIRST_COMPLETED
                    )
                    for task in done:
                        line = task.result()
                        if b"No such file or directory" in line:
                            error = True
                        if task is stdout_task:
                            sys.stdout.buffer.write(line)
                            sys.stdout.buffer.flush()
                            stdout_task = (
                                asyncio.create_task(proc.stdout.readline())
                                if line
                                else None
                            )
                        else:
                            sys.stderr.buffer.write(line)
                            sys.stderr.buffer.flush()
                            stderr_task = (
                                asyncio.create_task(proc.stderr.readline())
                                if line
                                else None
                            )
            finally:
                returncode = await proc.wait()
                if returncode != 0:
                    raise CalledProcessError(returncode, cmd)
            if error:
                raise Exception(f"Command {cmd} output contained error")

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

            self._copy_module_build(modules_dir)
            await self._test_external_module_build(modules_dir)

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
        "-f",
        "--flavor",
        choices=[flavor.name for flavor in KERNEL_FLAVORS],
        help="kernel configuration flavor. "
        + ". ".join(
            [f"{flavor.name}: {flavor.description}" for flavor in KERNEL_FLAVORS]
        ),
        default=KERNEL_FLAVORS[0].name,
    )
    parser.add_argument(
        "--dump-kconfig",
        action="store_true",
        help="dump kernel configuration file to standard output instead of building",
    )
    args = parser.parse_args()

    flavor = [flavor for flavor in KERNEL_FLAVORS if flavor.name == args.flavor][0]

    if args.dump_kconfig:
        sys.stdout.write(kconfig(flavor))
        return

    kbuild = KBuild(args.kernel_directory, args.build_directory, flavor, "x86_64")
    await kbuild.build()
    if hasattr(args, "package"):
        await kbuild.package(args.package)


if __name__ == "__main__":
    asyncio.run(main())
