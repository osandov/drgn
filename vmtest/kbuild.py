# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import asyncio
import filecmp
import logging
import os
from pathlib import Path
import shlex
import shutil
import sys
import tempfile
from typing import IO, Any, Mapping, NamedTuple, Optional, Sequence, Tuple, Union

from util import KernelVersion, nproc
from vmtest.asynciosubprocess import (
    CalledProcessError,
    check_call,
    check_output,
    check_output_shell,
    pipe_context,
)
from vmtest.config import (
    ARCHITECTURES,
    HOST_ARCHITECTURE,
    KERNEL_FLAVORS,
    Architecture,
    Compiler,
    KernelFlavor,
    kconfig,
    kconfig_localversion,
)
from vmtest.download import COMPILER_URL, DownloadCompiler, download

logger = logging.getLogger(__name__)


_PACKAGE_FORMATS = ("tar.zst", "directory")


class _Patch(NamedTuple):
    name: str
    # [inclusive, exclusive) ranges of kernel versions to apply this patch to.
    # None means any version.
    versions: Sequence[Tuple[Optional[KernelVersion], Optional[KernelVersion]]]


_PATCHES = (
    _Patch(
        name="proc-kcore-allow-enabling-CONFIG_PROC_KCORE-on-ARM.patch",
        versions=((None, None),),
    ),
    _Patch(
        name="5.15-kbuild-Unify-options-for-BTF-generation-for-vmlinux.patch",
        versions=((KernelVersion("5.13"), KernelVersion("5.15.66")),),
    ),
    _Patch(
        name="5.12-kbuild-Quote-OBJCOPY-var-to-avoid-a-pahole-call-brea.patch",
        versions=((KernelVersion("5.11"), KernelVersion("5.12.10")),),
    ),
    _Patch(
        name="5.11-bpf-Generate-BTF_KIND_FLOAT-when-linking-vmlinux.patch",
        versions=((KernelVersion("5.11"), KernelVersion("5.13")),),
    ),
    _Patch(
        name="5.10-kbuild-skip-per-CPU-BTF-generation-for-pahole-v1.18-.patch",
        versions=((KernelVersion("5.11"), KernelVersion("5.13")),),
    ),
    _Patch(
        name="5.11-kbuild-Unify-options-for-BTF-generation-for-vmlinux.patch",
        versions=((KernelVersion("5.11"), KernelVersion("5.13")),),
    ),
    _Patch(
        name="kbuild-Add-skip_encoding_btf_enum64-option-to-pahole.patch",
        versions=((KernelVersion("5.18"), KernelVersion("5.19.17")),),
    ),
    _Patch(
        name="5.15-kbuild-Add-skip_encoding_btf_enum64-option-to-pahole.patch",
        versions=(
            (KernelVersion("5.16"), KernelVersion("5.18")),
            (KernelVersion("5.13"), KernelVersion("5.15.66")),
        ),
    ),
    _Patch(
        name="5.10-kbuild-Add-skip_encoding_btf_enum64-option-to-pahole.patch",
        versions=((KernelVersion("5.11"), KernelVersion("5.13")),),
    ),
    _Patch(
        name="s390-mm-make-memory_block_size_bytes-available-for-M.patch",
        versions=((KernelVersion("4.3"), KernelVersion("4.11")),),
    ),
    _Patch(
        name="libsubcmd-Fix-use-after-free-for-realloc-.-0.patch",
        versions=(
            (KernelVersion("5.16"), KernelVersion("5.16.11")),
            (KernelVersion("5.11"), KernelVersion("5.15.25")),
            (KernelVersion("5.5"), KernelVersion("5.10.102")),
            (KernelVersion("4.20"), KernelVersion("5.4.181")),
            (KernelVersion("4.15"), KernelVersion("4.19.231")),
            (KernelVersion("4.10"), KernelVersion("4.14.268")),
            (KernelVersion("4.5"), KernelVersion("4.9.303")),
        ),
    ),
)


async def apply_patches(kernel_dir: Path) -> None:
    patch_dir = Path(__file__).parent / "patches"
    version = KernelVersion(
        (await check_output("make", "-s", "kernelversion", cwd=kernel_dir))
        .decode()
        .strip()
    )
    logger.info("applying patches for kernel version %s", version)
    any_applied = False
    for patch in _PATCHES:
        for min_version, max_version in patch.versions:
            if (min_version is None or min_version <= version) and (
                max_version is None or version < max_version
            ):
                break
        else:
            continue
        logger.info("applying %s", patch.name)
        any_applied = True
        proc = await asyncio.create_subprocess_exec(
            "git",
            "apply",
            str(patch_dir / patch.name),
            cwd=kernel_dir,
            stderr=asyncio.subprocess.PIPE,
        )
        stderr = await proc.stderr.read()
        if await proc.wait() != 0:
            try:
                await check_call(
                    "git",
                    "apply",
                    "--reverse",
                    "--check",
                    str(patch_dir / patch.name),
                    cwd=kernel_dir,
                    stderr=asyncio.subprocess.DEVNULL,
                )
            except CalledProcessError:
                sys.stderr.buffer.write(stderr)
                sys.stderr.buffer.flush()
                raise
            logger.info("already applied")
    if not any_applied:
        logger.info("no patches")


class KBuild:
    def __init__(
        self,
        kernel_dir: Path,
        build_dir: Path,
        arch: Architecture,
        flavor: KernelFlavor,
        env: Optional[Mapping[str, str]] = None,
        build_log_file: Union[int, IO[Any], None] = None,
    ) -> None:
        self._build_dir = build_dir
        self._kernel_dir = kernel_dir
        self._flavor = flavor
        self._arch = arch
        self._env = env
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
                "ARCH=" + str(self._arch.kernel_arch),
                "LOCALVERSION=" + kconfig_localversion(self._flavor),
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
                        "make",
                        *self._cached_make_args,
                        "-s",
                        "kernelrelease",
                        env=self._env,
                    )
                )
                .decode()
                .strip()
            )
        return self._cached_kernel_release

    async def build(self) -> None:
        logger.info(
            "building %s %s kernel in %s",
            self._arch.name,
            self._flavor.name,
            self._build_dir,
        )
        build_log_file_name = getattr(self._build_stdout, "name", None)
        if build_log_file_name is not None:
            logger.info("build logs in %s", build_log_file_name)

        make_args = await self._prepare_make()

        config = self._build_dir / ".config"
        tmp_config = self._build_dir / ".config.vmtest.tmp"

        tmp_config.write_text(kconfig(self._arch, self._flavor))
        await check_call(
            "make",
            *make_args,
            "KCONFIG_CONFIG=" + tmp_config.name,
            "olddefconfig",
            stdout=self._build_stdout,
            stderr=self._build_stderr,
            env=self._env,
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
            env=self._env,
        )
        logger.info(
            "built kernel %s for %s in %s",
            kernel_release,
            self._arch.name,
            self._build_dir,
        )

    def _copy_module_build(self, modules_build_dir: Path) -> None:
        logger.info("copying module build files")

        # Files and directories (as glob patterns) required for external module
        # builds. This list was determined through trial and error.
        files = [
            ".config",
            "Module.symvers",
            f"arch/{self._arch.kernel_srcarch}/Makefile",
            f"arch/{self._arch.kernel_srcarch}/kernel/module.lds",
            "scripts/Kbuild.include",
            "scripts/Makefile*",
            "scripts/basic/fixdep",
            "scripts/check-local-export",
            "scripts/gcc-goto.sh",
            "scripts/gcc-version.sh",
            "scripts/ld-version.sh",
            "scripts/mod/modpost",
            "scripts/module-common.lds",
            "scripts/module.lds",
            "scripts/modules-check.sh",
            "scripts/pahole-flags.sh",
            "scripts/pahole-version.sh",
            "scripts/subarch.include",
            "tools/bpf/resolve_btfids/resolve_btfids",
            "tools/objtool/objtool",
        ]
        # Before Linux kernel commit bca8f17f57bd ("arm64: Get rid of
        # asm/opcodes.h") (in v4.10), AArch64 includes this file from 32-bit
        # Arm.
        if self._arch.name == "aarch64":
            files.append("arch/arm/include/asm/opcodes.h")
        # Before Linux kernel commit efe0160cfd40 ("powerpc/64: Linker
        # on-demand sfpr functions for modules") (in v4.13), this must be
        # available to link into modules.
        if self._arch.name == "ppc64":
            files.append("arch/powerpc/lib/crtsavres.o")
        directories = (
            f"arch/{self._arch.kernel_srcarch}/include",
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
                        src_path,
                        dst_path,
                        ignore=shutil.ignore_patterns("*.cmd"),
                        symlinks=True,
                        dirs_exist_ok=True,
                    )

    async def _test_external_module_build(self, modules_build_dir: Path) -> None:
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
                "ARCH=" + str(self._arch.kernel_arch),
                "-C",
                modules_build_dir,
                f"M={test_module_dir.resolve()}",
            )
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._env,
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

    async def package(self, format: str, output_dir: Path) -> Path:
        if format not in _PACKAGE_FORMATS:
            raise ValueError("unknown package format")

        make_args = await self._prepare_make()
        kernel_release = await self._kernel_release()

        extension = "" if format == "directory" else ("." + format)
        package = output_dir / f"kernel-{kernel_release}.{self._arch.name}{extension}"

        logger.info(
            "packaging kernel %s for %s from %s to %s",
            kernel_release,
            self._arch.name,
            self._build_dir,
            package,
        )

        image_name = (
            (await check_output("make", *make_args, "-s", "image_name", env=self._env))
            .decode()
            .strip()
        )

        with tempfile.TemporaryDirectory(
            prefix=package.name + ".tmp.", dir=package.parent
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
                env=self._env,
            )

            # `make modules_install` creates build as a symlink to the absolute
            # path of the build directory. Delete it and make it an empty
            # directory for us to populate.
            modules_build_dir = modules_dir / "build"
            modules_build_dir.unlink()
            modules_build_dir.mkdir()
            # Before Linux kernel commit d8131c2965d5 ("kbuild: remove
            # $(MODLIB)/source symlink") (in v6.6), source is a symlink to the
            # absolute path of the source directory. It's not needed.
            try:
                (modules_dir / "source").unlink()
            except FileNotFoundError:
                pass

            logger.info("copying vmlinux")
            vmlinux = modules_build_dir / "vmlinux"
            await check_call(
                (os.environ if self._env is None else self._env).get(
                    "CROSS_COMPILE", ""
                )
                + "objcopy",
                "--remove-relocations=*",
                self._build_dir / "vmlinux",
                str(vmlinux),
                env=self._env,
            )
            vmlinux.chmod(0o644)

            logger.info("copying vmlinuz")
            vmlinuz = modules_dir / "vmlinuz"
            try:
                shutil.copy(self._build_dir / image_name, vmlinuz)
            except FileNotFoundError:
                # Before Linux kernel commits 06995804b576 ("arm64: Use full
                # path in KBUILD_IMAGE definition") and 152e6744ebfc ("arm: Use
                # full path in KBUILD_IMAGE definition") (in v4.12), image_name
                # may be relative to the architecture boot directory.
                shutil.copy(
                    self._build_dir
                    / "arch"
                    / self._arch.kernel_srcarch
                    / "boot"
                    / image_name,
                    vmlinuz,
                )
            vmlinuz.chmod(0o644)

            self._copy_module_build(modules_build_dir)
            await self._test_external_module_build(modules_build_dir)

            package.parent.mkdir(parents=True, exist_ok=True)
            if format == "directory":
                logger.info("renaming directory")
                try:
                    shutil.rmtree(package)
                except FileNotFoundError:
                    pass
                modules_dir.rename(package)
            else:
                logger.info("creating tarball")
                tar_cmd = ("tar", "-C", str(modules_dir), "-c", ".")
                zstd_cmd = ("zstd", "-T0", "-19", "-q", "-", "-o", str(package), "-f")
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
            "packaged kernel %s for %s from %s to %s",
            kernel_release,
            self._arch.name,
            self._build_dir,
            package,
        )
        return package


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
        "--package-format",
        choices=_PACKAGE_FORMATS,
        help='package archive format, or "directory" for an unarchived directory',
        default=_PACKAGE_FORMATS[0],
    )
    parser.add_argument(
        "--patch",
        action="store_true",
        help="apply patches to kernel source tree",
    )
    parser.add_argument(
        "-a",
        "--architecture",
        choices=sorted(ARCHITECTURES),
        help="architecture to build for",
        default=None if HOST_ARCHITECTURE is None else HOST_ARCHITECTURE.name,
        required=HOST_ARCHITECTURE is None,
    )
    parser.add_argument(
        "-f",
        "--flavor",
        choices=KERNEL_FLAVORS,
        help="kernel configuration flavor. "
        + ". ".join(
            [
                f"{flavor.name}: {flavor.description}"
                for flavor in KERNEL_FLAVORS.values()
            ]
        ),
        default=next(iter(KERNEL_FLAVORS)),
    )
    default_download_compiler_directory = Path("build/vmtest")
    parser.add_argument(
        "--download-compiler",
        metavar="DIR",
        nargs="?",
        default=argparse.SUPPRESS,
        type=Path,
        help=f"download a compiler from {COMPILER_URL} to the given directory ({default_download_compiler_directory} by default) and use it to build",
    )
    parser.add_argument(
        "--dump-kconfig",
        action="store_true",
        help="dump kernel configuration file to standard output instead of building",
    )
    args = parser.parse_args()

    arch = ARCHITECTURES[args.architecture]
    flavor = KERNEL_FLAVORS[args.flavor]

    if args.dump_kconfig:
        sys.stdout.write(kconfig(arch, flavor))
        return

    if hasattr(args, "download_compiler"):
        if args.download_compiler is None:
            args.download_compiler = default_download_compiler_directory
        downloaded = next(download(args.download_compiler, [DownloadCompiler(arch)]))
        assert isinstance(downloaded, Compiler)
        env = {**os.environ, **downloaded.env()}
    else:
        env = None

    if args.patch:
        await apply_patches(args.kernel_directory)

    kbuild = KBuild(args.kernel_directory, args.build_directory, arch, flavor, env)
    await kbuild.build()
    if hasattr(args, "package"):
        await kbuild.package(args.package_format, args.package)


if __name__ == "__main__":
    asyncio.run(main())
