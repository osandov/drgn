# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

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
from typing import Any, Dict, Iterator, Sequence, Union

from util import KernelVersion
from vmtest.githubapi import GitHubApi

logger = logging.getLogger(__name__)

VMTEST_GITHUB_RELEASE = ("osandov", "drgn", "vmtest-assets")


def available_kernel_releases(
    github_release: Dict[str, Any], arch: str
) -> Dict[str, Dict[str, Any]]:
    pattern = re.compile(r"kernel-(.*)\." + re.escape(arch) + r"\.tar\.zst")
    releases = {}
    for asset in github_release["assets"]:
        match = pattern.fullmatch(asset["name"])
        if match:
            releases[match.group(1)] = asset
    return releases


def _download_kernel(gh: GitHubApi, url: str, dir: Path) -> None:
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
        ) as tar_proc, gh.download(
            url
        ) as resp:
            assert zstd_proc.stdin is not None
            shutil.copyfileobj(resp, zstd_proc.stdin)
            zstd_proc.stdin.close()
        if zstd_proc.returncode != 0:
            raise subprocess.CalledProcessError(zstd_proc.returncode, zstd_proc.args)
        if tar_proc.returncode != 0:
            raise subprocess.CalledProcessError(tar_proc.returncode, tar_proc.args)
    except:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise
    else:
        tmp_dir.rename(dir)


def download_kernels(
    download_dir: Path, arch: str, kernels: Sequence[str]
) -> Iterator[Path]:
    gh = GitHubApi(os.getenv("GITHUB_TOKEN"))

    # We don't want to make any API requests if we don't have to, so we don't
    # fetch this until we need it.
    cached_kernel_releases = None

    def get_available_kernel_releases() -> Dict[str, Dict[str, Any]]:
        nonlocal cached_kernel_releases
        if cached_kernel_releases is None:
            logger.info("getting available kernel releases")
            download_dir.mkdir(parents=True, exist_ok=True)
            cached_kernel_releases = available_kernel_releases(
                gh.get_release_by_tag(
                    *VMTEST_GITHUB_RELEASE, cache=download_dir / "github_release.json"
                ),
                arch,
            )
        return cached_kernel_releases

    arch_download_dir = download_dir / arch

    # Make sure all of the given kernels exist first.
    to_download = []
    for kernel in kernels:
        if kernel != glob.escape(kernel):
            try:
                match = max(
                    (
                        available
                        for available in get_available_kernel_releases()
                        if fnmatch.fnmatch(available, kernel)
                    ),
                    key=KernelVersion,
                )
            except ValueError:
                raise Exception(f"no available kernel release matches {kernel!r}")
            else:
                logger.info("kernel release pattern %s matches %s", kernel, match)
                kernel = match
        kernel_dir = arch_download_dir / ("kernel-" + kernel)
        if kernel_dir.exists():
            # As a policy, vmtest assets will never be updated with the same
            # name. Therefore, if the kernel was previously downloaded, we
            # don't need to download it again.
            url = None
        else:
            try:
                asset = get_available_kernel_releases()[kernel]
            except KeyError:
                raise Exception(f"kernel release {kernel} not found")
            url = asset["url"]
        to_download.append((kernel, kernel_dir, url))

    for release, kernel_dir, url in to_download:
        if url is None:
            logger.info(
                "kernel release %s already downloaded to %s", release, kernel_dir
            )
        else:
            logger.info(
                "downloading kernel release %s to %s from %s", release, kernel_dir, url
            )
            _download_kernel(gh, url, kernel_dir)
        yield kernel_dir


def _download_kernels_thread(
    download_dir: Path,
    arch: str,
    kernels: Sequence[str],
    q: "queue.Queue[Union[Path, Exception]]",
) -> None:
    try:
        it = download_kernels(download_dir, arch, kernels)
        while True:
            q.put(next(it))
    except Exception as e:
        q.put(e)


@contextmanager
def download_kernels_in_thread(
    download_dir: Path, arch: str, kernels: Sequence[str]
) -> Iterator[Iterator[Path]]:
    q: "queue.Queue[Union[Path, Exception]]" = queue.Queue()

    def aux() -> Iterator[Path]:
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
            args=(download_dir, arch, kernels, q),
            daemon=True,
        )
        thread.start()
        yield aux()
    finally:
        if thread:
            thread.join()


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
        action="append",
        dest="kernels",
        help="download latest kernel matching glob pattern; may be given multiple times",
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

    for path in download_kernels(args.download_directory, "x86_64", args.kernels or ()):
        print(path)


if __name__ == "__main__":
    main()
