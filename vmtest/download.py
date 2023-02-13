# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
from contextlib import contextmanager
import fnmatch
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
from typing import Any, Dict, Iterator, NamedTuple, Optional, Sequence, Union

from util import KernelVersion
from vmtest.config import ARCHITECTURES, HOST_ARCHITECTURE, Architecture, Kernel
from vmtest.githubapi import GitHubApi

logger = logging.getLogger(__name__)

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


def download_kernels(
    download_dir: Path, kernels: Sequence[DownloadKernel]
) -> Iterator[Kernel]:
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

    # Make sure all of the given kernels exist first.
    to_download = []
    for download in kernels:
        if download.pattern == glob.escape(download.pattern):
            release = download.pattern
        else:
            try:
                release = max(
                    (
                        available
                        for available in get_available_kernel_releases().get(
                            download.arch.name, {}
                        )
                        if fnmatch.fnmatch(available, download.pattern)
                    ),
                    key=KernelVersion,
                )
            except ValueError:
                raise Exception(
                    f"no available kernel release matches {download.pattern!r} on {download.arch.name}"
                ) from None
            else:
                logger.info(
                    "kernel release pattern %s matches %s on %s",
                    download.pattern,
                    release,
                    download.arch.name,
                )
        kernel_dir = download_dir / download.arch.name / ("kernel-" + release)
        if kernel_dir.exists():
            # As a policy, vmtest assets will never be updated with the same
            # name. Therefore, if the kernel was previously downloaded, we
            # don't need to download it again.
            url = None
        else:
            try:
                asset = get_available_kernel_releases()[download.arch.name][release]
            except KeyError:
                raise Exception(f"kernel release {release} not found")
            url = asset["url"]
        to_download.append((download.arch, release, kernel_dir, url))

    for arch, release, kernel_dir, url in to_download:
        yield _download_kernel(gh, arch, release, url, kernel_dir)


def _download_kernels_thread(
    download_dir: Path,
    kernels: Sequence[DownloadKernel],
    q: "queue.Queue[Union[Kernel, Exception]]",
) -> None:
    try:
        it = download_kernels(download_dir, kernels)
        while True:
            q.put(next(it))
    except Exception as e:
        q.put(e)


@contextmanager
def download_kernels_in_thread(
    download_dir: Path, kernels: Sequence[DownloadKernel]
) -> Iterator[Iterator[Kernel]]:
    q: "queue.Queue[Union[Kernel, Exception]]" = queue.Queue()

    def aux() -> Iterator[Kernel]:
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
            target=_download_kernels_thread,
            args=(download_dir, kernels, q),
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

    for downloaded in download_kernels(args.download_directory, args.downloads):
        print(
            f"kernel: arch={downloaded.arch.name} release={downloaded.release} path={downloaded.path}"
        )


if __name__ == "__main__":
    main()
