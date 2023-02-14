# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
from contextlib import contextmanager
import fnmatch
import functools
import glob
import logging
import os
from pathlib import Path
import queue
import re
import shutil
import subprocess
import tempfile
import threading
from typing import (
    Any,
    Callable,
    Dict,
    Generator,
    Iterable,
    Iterator,
    List,
    NamedTuple,
    Optional,
    Union,
)
import urllib.request

from util import NORMALIZED_MACHINE_NAME, KernelVersion
from vmtest.config import (
    ARCHITECTURES,
    HOST_ARCHITECTURE,
    KERNEL_ORG_COMPILER_VERSION,
    Architecture,
    Compiler,
    Kernel,
)
from vmtest.githubapi import GitHubApi

logger = logging.getLogger(__name__)

COMPILER_URL = "https://mirrors.kernel.org/pub/tools/crosstool/"
VMTEST_GITHUB_RELEASE = ("osandov", "drgn", "vmtest-assets")


GitHubAsset = Dict[str, Any]


def available_kernel_releases(
    github_release: Dict[str, Any]
) -> Dict[str, Dict[str, GitHubAsset]]:
    releases: Dict[str, Dict[str, GitHubAsset]] = {}
    pattern = re.compile(r"kernel-(?P<release>.*)\.(?P<arch>\w+)\.tar\.zst")
    for asset in github_release["assets"]:
        match = pattern.fullmatch(asset["name"])
        if match:
            try:
                arch_releases = releases[match.group("arch")]
            except KeyError:
                arch_releases = releases[match.group("arch")] = {}
            arch_releases[match.group("release")] = asset
    return releases


class DownloadKernel(NamedTuple):
    arch: Architecture
    pattern: str


class DownloadCompiler(NamedTuple):
    target: Architecture


Download = Union[DownloadKernel, DownloadCompiler]
Downloaded = Union[Kernel, Compiler]


def _download_kernel(
    gh: GitHubApi, arch: Architecture, release: str, url: Optional[str], dir: Path
) -> Kernel:
    if url is None:
        logger.info(
            "kernel release %s for %s already downloaded to %s", release, arch.name, dir
        )
    else:
        logger.info(
            "downloading kernel release %s for %s to %s from %s",
            release,
            arch.name,
            dir,
            url,
        )
        dir.parent.mkdir(parents=True, exist_ok=True)
        tmp_dir = Path(tempfile.mkdtemp(dir=dir.parent))
        try:
            # Don't assume that the available version of tar has zstd support or
            # the non-standard -I/--use-compress-program option.
            with subprocess.Popen(
                ["zstd", "-d", "-", "--stdout"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
            ) as zstd_proc, subprocess.Popen(
                ["tar", "-C", str(tmp_dir), "-x"],
                stdin=zstd_proc.stdout,
            ) as tar_proc:
                assert zstd_proc.stdin is not None
                try:
                    with gh.download(url) as resp:
                        shutil.copyfileobj(resp, zstd_proc.stdin)
                finally:
                    zstd_proc.stdin.close()
            if zstd_proc.returncode != 0:
                raise subprocess.CalledProcessError(
                    zstd_proc.returncode, zstd_proc.args
                )
            if tar_proc.returncode != 0:
                raise subprocess.CalledProcessError(tar_proc.returncode, tar_proc.args)
        except BaseException:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise
        else:
            tmp_dir.rename(dir)
    return Kernel(arch, release, dir)


_KERNEL_ORG_COMPILER_HOST_NAME = {
    "aarch64": "arm64",
    "ppc64": "ppc64le",
    "x86_64": "x86_64",
}.get(NORMALIZED_MACHINE_NAME)


def downloaded_compiler(download_dir: Path, target: Architecture) -> Compiler:
    if _KERNEL_ORG_COMPILER_HOST_NAME is None:
        raise FileNotFoundError(
            f"kernel.org compilers are not available for {NORMALIZED_MACHINE_NAME} hosts"
        )
    return Compiler(
        target=target,
        bin=download_dir
        / f"{_KERNEL_ORG_COMPILER_HOST_NAME}-gcc-{KERNEL_ORG_COMPILER_VERSION}-nolibc-{target.kernel_org_compiler_name}"
        / "bin",
        prefix=target.kernel_org_compiler_name + "-",
    )


def _download_compiler(compiler: Compiler) -> Compiler:
    dir = compiler.bin.parent
    if dir.exists():
        logger.info(
            "compiler for %s already downloaded to %s", compiler.target.name, dir
        )
    else:
        url = f"{COMPILER_URL}files/bin/{_KERNEL_ORG_COMPILER_HOST_NAME}/{KERNEL_ORG_COMPILER_VERSION}/{dir.name}.tar.xz"
        logger.info(
            "downloading compiler for %s from %s to %s", compiler.target.name, url, dir
        )
        dir.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=dir.parent) as tmp_name:
            tmp_dir = Path(tmp_name)
            with subprocess.Popen(
                ["xz", "--decompress"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
            ) as xz_proc, subprocess.Popen(
                ["tar", "-C", str(tmp_dir), "-x"],
                stdin=xz_proc.stdout,
            ) as tar_proc:
                assert xz_proc.stdin is not None
                try:
                    with urllib.request.urlopen(url) as resp:
                        shutil.copyfileobj(resp, xz_proc.stdin)
                finally:
                    xz_proc.stdin.close()
            if xz_proc.returncode != 0:
                raise subprocess.CalledProcessError(xz_proc.returncode, xz_proc.args)
            if tar_proc.returncode != 0:
                raise subprocess.CalledProcessError(tar_proc.returncode, tar_proc.args)
            archive_subdir = Path(
                f"gcc-{KERNEL_ORG_COMPILER_VERSION}-nolibc/{compiler.target.kernel_org_compiler_name}"
            )
            archive_bin_subdir = archive_subdir / "bin"
            if not (tmp_dir / archive_bin_subdir).exists():
                raise FileNotFoundError(
                    f"downloaded archive does not contain {archive_bin_subdir}"
                )
            (tmp_dir / archive_subdir).rename(dir)
    return compiler


def download(download_dir: Path, downloads: Iterable[Download]) -> Iterator[Downloaded]:
    gh = GitHubApi(os.getenv("GITHUB_TOKEN"))

    # We don't want to make any API requests if we don't have to, so we don't
    # fetch this until we need it.
    cached_kernel_releases = None

    def get_available_kernel_releases() -> Dict[str, Dict[str, GitHubAsset]]:
        nonlocal cached_kernel_releases
        if cached_kernel_releases is None:
            logger.info("getting available kernel releases")
            download_dir.mkdir(parents=True, exist_ok=True)
            cached_kernel_releases = available_kernel_releases(
                gh.get_release_by_tag(
                    *VMTEST_GITHUB_RELEASE, cache=download_dir / "github_release.json"
                ),
            )
        return cached_kernel_releases

    download_calls: List[Callable[[], Downloaded]] = []
    for download in downloads:
        if isinstance(download, DownloadKernel):
            if download.pattern == glob.escape(download.pattern):
                release = download.pattern
            else:
                try:
                    release = max(
                        (
                            available
                            for available in get_available_kernel_releases()[
                                download.arch.name
                            ]
                            if fnmatch.fnmatch(available, download.pattern)
                        ),
                        key=KernelVersion,
                    )
                except ValueError:
                    raise Exception(
                        f"no available kernel release matches {download.pattern!r} on {download.arch.name}"
                    )
                else:
                    logger.info(
                        "kernel release pattern %s matches %s on %s",
                        download.pattern,
                        release,
                        download.arch.name,
                    )
            kernel_dir = download_dir / download.arch.name / ("kernel-" + release)
            if kernel_dir.exists():
                # As a policy, vmtest assets will never be updated with the
                # same name. Therefore, if the kernel was previously
                # downloaded, we don't need to download it again.
                url = None
            else:
                try:
                    asset = get_available_kernel_releases()[download.arch.name][release]
                except KeyError:
                    raise Exception(f"kernel release {release} not found")
                url = asset["url"]
            download_calls.append(
                functools.partial(
                    _download_kernel, gh, download.arch, release, url, kernel_dir
                )
            )
        elif isinstance(download, DownloadCompiler):
            download_calls.append(
                functools.partial(
                    _download_compiler,
                    downloaded_compiler(download_dir, download.target),
                )
            )
        else:
            assert False

    for call in download_calls:
        yield call()


def _download_thread(
    download_dir: Path,
    downloads: Iterable[Download],
    q: "queue.Queue[Union[Downloaded, Exception]]",
) -> None:
    try:
        it = download(download_dir, downloads)
        while True:
            q.put(next(it))
    except Exception as e:
        q.put(e)


@contextmanager
def download_in_thread(
    download_dir: Path, downloads: Iterable[Download]
) -> Generator[Iterator[Downloaded], None, None]:
    q: "queue.Queue[Union[Downloaded, Exception]]" = queue.Queue()

    def aux() -> Iterator[Downloaded]:
        while True:
            obj = q.get()
            if isinstance(obj, StopIteration):
                break
            elif isinstance(obj, Exception):
                raise obj
            yield obj

    thread = None
    try:
        thread = threading.Thread(
            target=_download_thread,
            args=(download_dir, downloads, q),
            daemon=True,
        )
        thread.start()
        yield aux()
    finally:
        if thread:
            thread.join()


ARCH_ARGPARSE_METAVAR = f"{{{','.join(ARCHITECTURES)}}}"
if HOST_ARCHITECTURE is None:
    DOWNLOAD_KERNEL_ARGPARSE_METAVAR = f"{ARCH_ARGPARSE_METAVAR}:PATTERN"
    DEFAULT_ARCH_ARGPARSE_HELP = ""
else:
    DOWNLOAD_KERNEL_ARGPARSE_METAVAR = f"[{ARCH_ARGPARSE_METAVAR}:]PATTERN"
    DEFAULT_ARCH_ARGPARSE_HELP = f" (default: {HOST_ARCHITECTURE.name})"


def architecture_argparse_type(arg: str) -> Architecture:
    try:
        return ARCHITECTURES[arg]
    except KeyError:
        raise argparse.ArgumentTypeError(
            f"architecture must be one of ({', '.join(ARCHITECTURES)})"
        ) from None


def download_kernel_argparse_type(arg: str) -> DownloadKernel:
    arch_name, sep, pattern = arg.rpartition(":")
    if sep:
        arch = architecture_argparse_type(arch_name)
    else:
        if HOST_ARCHITECTURE is None:
            raise argparse.ArgumentTypeError("architecture is required")
        arch = HOST_ARCHITECTURE
    return DownloadKernel(arch, pattern)


def main() -> None:
    logging.basicConfig(
        format="%(asctime)s:%(levelname)s:%(name)s:%(message)s", level=logging.INFO
    )

    parser = argparse.ArgumentParser(
        description="Download drgn vmtest assets",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-k",
        "--kernel",
        metavar=DOWNLOAD_KERNEL_ARGPARSE_METAVAR,
        dest="downloads",
        action="append",
        type=download_kernel_argparse_type,
        default=argparse.SUPPRESS,
        help=f"download latest kernel for given architecture{DEFAULT_ARCH_ARGPARSE_HELP} matching glob pattern; may be given multiple times",
    )
    parser.add_argument(
        "-c",
        "--compiler",
        metavar=ARCH_ARGPARSE_METAVAR,
        dest="downloads",
        action="append",
        nargs=1 if HOST_ARCHITECTURE is None else "?",
        type=lambda arg: DownloadCompiler(architecture_argparse_type(arg)),
        default=argparse.SUPPRESS,
        help=f"download compiler for given architecture{DEFAULT_ARCH_ARGPARSE_HELP} from {COMPILER_URL}; may be given multiple times",
    )
    parser.add_argument(
        "-d",
        "--download-directory",
        metavar="DIR",
        type=Path,
        default="build/vmtest",
        help="directory to download assets to",
    )
    args = parser.parse_args()
    if not hasattr(args, "downloads"):
        args.downloads = []
    # --compiler with no argument is appended as None. Fix it.
    for i, download_arg in enumerate(args.downloads):
        if download_arg is None:
            assert HOST_ARCHITECTURE is not None
            args.downloads[i] = DownloadCompiler(HOST_ARCHITECTURE)

    for downloaded in download(args.download_directory, args.downloads):
        if isinstance(downloaded, Kernel):
            print(
                f"kernel: arch={downloaded.arch.name} release={downloaded.release} path={downloaded.path}"
            )
        elif isinstance(downloaded, Compiler):
            print(
                f"compiler: target={downloaded.target.name} bin={downloaded.bin} prefix={downloaded.prefix}"
            )
        else:
            assert False


if __name__ == "__main__":
    main()
