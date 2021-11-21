# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import asyncio
import itertools
import logging
import os
from pathlib import Path
import re
import sys
from typing import AsyncIterator, Dict, List, NamedTuple, Optional, Sequence, Union

import aiohttp
import uritemplate

from util import KernelVersion
from vmtest.asynciosubprocess import check_call, check_output
from vmtest.download import VMTEST_GITHUB_RELEASE, available_kernel_releases
from vmtest.githubapi import AioGitHubApi
from vmtest.kbuild import KERNEL_LOCALVERSION, KBuild

logger = logging.getLogger(__name__)

# [inclusive, exclusive) ranges of kernel versions to ignore when building
# latest releases of each version.
IGNORE_KERNEL_RANGES = (
    (KernelVersion("~"), KernelVersion("4.4")),
    (KernelVersion("4.5~"), KernelVersion("4.9")),
    (KernelVersion("4.10~"), KernelVersion("4.14")),
    (KernelVersion("4.15~"), KernelVersion("4.19")),
    (KernelVersion("4.20~"), KernelVersion("5.4")),
    (KernelVersion("5.5~"), KernelVersion("5.10")),
)

# Use the GitHub mirrors rather than the official kernel.org repositories since
# this script usually runs in GitHub Actions.
LINUX_GIT_URL = "https://github.com/torvalds/linux.git"
STABLE_LINUX_GIT_URL = "https://github.com/gregkh/linux.git"


async def get_latest_kernel_tags() -> List[str]:
    mainline_refs, stable_refs = await asyncio.gather(
        check_output("git", "ls-remote", "--tags", "--refs", LINUX_GIT_URL),
        check_output("git", "ls-remote", "--tags", "--refs", STABLE_LINUX_GIT_URL),
    )
    latest: Dict[str, KernelVersion] = {}
    for match in itertools.chain(
        re.finditer(
            r"^[a-f0-9]+\s+refs/tags/v([0-9]+\.[0-9]+)(-rc[0-9]+)?$",
            mainline_refs.decode(),
            re.M,
        ),
        re.finditer(
            r"^[a-f0-9]+\s+refs/tags/v([0-9]+\.[0-9]+)(\.[0-9]+)$",
            stable_refs.decode(),
            re.M,
        ),
    ):
        version = KernelVersion(match.group(1) + (match.group(2) or ""))
        for start_version, end_version in IGNORE_KERNEL_RANGES:
            if start_version <= version < end_version:
                break
        else:
            latest[match.group(1)] = max(version, latest.get(match.group(1), version))
    return ["v" + str(version) for version in sorted(latest.values(), reverse=True)]


def kernel_tag_to_release(tag: str) -> str:
    match = re.fullmatch(r"v([0-9]+\.[0-9]+)(\.[0-9]+)?(-rc\d+)?", tag)
    assert match
    return "".join(
        [
            match.group(1),
            match.group(2) or ".0",
            match.group(3) or "",
            KERNEL_LOCALVERSION,
        ]
    )


async def fetch_kernel_tags(kernel_dir: Path, kernel_tags: Sequence[str]) -> None:
    if not kernel_dir.exists():
        logger.info("creating kernel repository in %s", kernel_dir)
        await check_call("git", "init", "-q", str(kernel_dir))

    mainline_tags = []
    stable_tags = []
    for tag in kernel_tags:
        if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
            stable_tags.append(tag)
        else:
            mainline_tags.append(tag)

    for (name, url, tags) in (
        ("mainline", LINUX_GIT_URL, mainline_tags),
        ("stable", STABLE_LINUX_GIT_URL, stable_tags),
    ):
        if tags:
            logger.info("fetching %s kernel tags: %s", name, ", ".join(tags))
            await check_call(
                "git",
                "-C",
                str(kernel_dir),
                "fetch",
                "--depth",
                "1",
                url,
                *(f"refs/tags/{tag}:refs/tags/{tag}" for tag in tags),
            )


async def build_kernels(
    kernel_dir: Path, build_dir: Path, arch: str, kernel_revs: Sequence[str]
) -> AsyncIterator[Path]:
    build_dir.mkdir(parents=True, exist_ok=True)
    for rev in kernel_revs:
        rev_build_dir = build_dir / ("build-" + rev)
        logger.info("checking out %s in %s", rev, rev_build_dir)
        await check_call("git", "-C", str(kernel_dir), "checkout", "-q", rev)
        with open(build_dir / f"build-{rev}.log", "w") as build_log_file:
            kbuild = KBuild(kernel_dir, rev_build_dir, arch, build_log_file)
            await kbuild.build()
            yield await kbuild.package(build_dir)


class AssetUploadWork(NamedTuple):
    upload_url: str
    path: Union[str, bytes, Path]
    name: str
    content_type: str


async def asset_uploader(
    gh: AioGitHubApi,
    queue: "asyncio.Queue[Optional[AssetUploadWork]]",
) -> bool:
    success = True
    while True:
        work = await queue.get()
        if not work:
            queue.task_done()
            return success
        logger.info("uploading %s", work.name)
        try:
            with open(work.path, "rb") as f:
                await gh.upload(
                    uritemplate.expand(work.upload_url, name=work.name),
                    f,
                    work.content_type,
                )
        except Exception:
            logger.exception("uploading %s failed", work.name)
            success = False
        else:
            logger.info("uploaded %s", work.name)
        finally:
            queue.task_done()


async def main() -> None:
    logging.basicConfig(
        format="%(asctime)s:%(levelname)s:%(name)s:%(message)s", level=logging.INFO
    )

    parser = argparse.ArgumentParser(
        description="Build and upload drgn vmtest assets",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-K",
        "--latest-kernels",
        action="store_true",
        help="build and upload latest supported kernel releases",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="build but don't upload anything to GitHub",
    )
    parser.add_argument(
        "--kernel-directory",
        metavar="DIR",
        type=Path,
        help="kernel Git repository directory (created if needed)",
        default=".",
    )
    parser.add_argument(
        "--build-directory",
        metavar="DIR",
        type=Path,
        help="directory for build artifacts",
        default=".",
    )
    parser.add_argument(
        "--cache-directory",
        metavar="DIR",
        type=Path,
        default="build/vmtest",
        help="directory to cache API calls in",
    )
    args = parser.parse_args()

    arch = "x86_64"

    async with aiohttp.ClientSession(trust_env=True) as session:
        GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
        if GITHUB_TOKEN is None and not args.dry_run:
            sys.exit("GITHUB_TOKEN environment variable is not set")
        gh = AioGitHubApi(session, GITHUB_TOKEN)

        args.cache_directory.mkdir(parents=True, exist_ok=True)
        github_release_coro = gh.get_release_by_tag(
            *VMTEST_GITHUB_RELEASE, cache=args.cache_directory / "github_release.json"
        )
        if args.latest_kernels:
            github_release, latest_kernel_tags = await asyncio.gather(
                github_release_coro, get_latest_kernel_tags()
            )
        else:
            github_release = await github_release_coro

        kernel_releases = available_kernel_releases(github_release, arch)
        logger.info(
            "available %s kernel releases: %s",
            arch,
            ", ".join(sorted(kernel_releases, key=KernelVersion, reverse=True)),
        )

        if args.latest_kernels:
            logger.info("latest kernel versions: %s", ", ".join(latest_kernel_tags))
            kernel_tags = [
                tag
                for tag in latest_kernel_tags
                if kernel_tag_to_release(tag) not in kernel_releases
            ]
        else:
            kernel_tags = []

        if kernel_tags:
            logger.info("kernel versions to build: %s", ", ".join(kernel_tags))

            if not args.dry_run:
                upload_queue: "asyncio.Queue[Optional[AssetUploadWork]]" = (
                    asyncio.Queue()
                )
                uploader = asyncio.create_task(asset_uploader(gh, upload_queue))

            await fetch_kernel_tags(args.kernel_directory, kernel_tags)

            async for kernel_package in build_kernels(
                args.kernel_directory, args.build_directory, arch, kernel_tags
            ):
                if args.dry_run:
                    logger.info("would upload %s", kernel_package)
                else:
                    await upload_queue.put(
                        AssetUploadWork(
                            upload_url=github_release["upload_url"],
                            path=kernel_package,
                            name=kernel_package.name,
                            content_type="application/zstd",
                        )
                    )

            if not args.dry_run:
                await upload_queue.put(None)
                await upload_queue.join()
                if not await uploader:
                    sys.exit("some uploads failed")


if __name__ == "__main__":
    asyncio.run(main())
