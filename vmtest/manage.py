# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import asyncio
import itertools
import logging
import os
from pathlib import Path
import re
import sys
from typing import (
    AsyncIterator,
    Dict,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
    Union,
    cast,
)

import aiohttp
import uritemplate

from util import KernelVersion
from vmtest.asynciosubprocess import check_call, check_output
from vmtest.config import (
    ARCHITECTURES,
    KERNEL_FLAVORS,
    Architecture,
    Compiler,
    KernelFlavor,
    kconfig_localversion,
)
from vmtest.download import (
    VMTEST_GITHUB_RELEASE,
    DownloadCompiler,
    available_kernel_releases,
    download,
)
from vmtest.githubapi import AioGitHubApi
from vmtest.kbuild import KBuild, apply_patches

logger = logging.getLogger(__name__)

# [inclusive, exclusive) ranges of kernel versions to ignore when building
# latest releases of each version.
IGNORE_KERNEL_RANGES = (
    (KernelVersion("~"), KernelVersion("4.9")),
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


def kernel_tag_to_release(tag: str, flavor: KernelFlavor) -> str:
    match = re.fullmatch(r"v([0-9]+\.[0-9]+)(\.[0-9]+)?(-rc\d+)?", tag)
    assert match
    return "".join(
        [
            match.group(1),
            match.group(2) or ".0",
            match.group(3) or "",
            kconfig_localversion(flavor),
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

    for name, url, tags in (
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
    kernel_dir: Path,
    build_dir: Path,
    kernel_revs: Sequence[
        Tuple[str, Sequence[Tuple[Architecture, Sequence[KernelFlavor]]]]
    ],
    compilers: Mapping[str, Compiler],
    keep_builds: bool,
) -> AsyncIterator[Path]:
    build_dir.mkdir(parents=True, exist_ok=True)
    for rev, arches in kernel_revs:
        logger.info("checking out %s in %s", rev, kernel_dir)
        await check_call(
            "git", "-C", str(kernel_dir), "checkout", "--force", "--quiet", rev
        )
        await check_call("git", "-C", str(kernel_dir), "clean", "-dqf")
        await apply_patches(kernel_dir)
        for arch, flavors in arches:
            env = {**os.environ, **compilers[arch.name].env()}
            for flavor in flavors:
                flavor_rev_build_dir = (
                    build_dir / f"build-{arch.name}-{flavor.name}-{rev}"
                )
                with open(
                    build_dir / f"build-{arch.name}-{flavor.name}-{rev}.log", "w"
                ) as build_log_file:
                    kbuild = KBuild(
                        kernel_dir,
                        flavor_rev_build_dir,
                        arch,
                        flavor,
                        env=env,
                        build_log_file=build_log_file,
                    )
                    await kbuild.build()
                    yield await kbuild.package("tar.zst", build_dir)
                    if not keep_builds:
                        logger.info("deleting %s", flavor_rev_build_dir)
                        # Shell out instead of using, e.g., shutil.rmtree(), to
                        # avoid blocking the main thread and the GIL.
                        await check_call("rm", "-rf", str(flavor_rev_build_dir))


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
        "-a",
        "--architecture",
        dest="architectures",
        choices=["all", *sorted(ARCHITECTURES)],
        action="append",
        help="build architecture; may be given multiple times (default: all)",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-f",
        "--flavor",
        dest="flavors",
        choices=["all", *KERNEL_FLAVORS],
        action="append",
        help="build flavor; may be given multiple times (default: all)",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--no-build",
        dest="build",
        action="store_false",
        help="don't build or upload anything; just log what would be built",
    )
    parser.add_argument(
        "--no-upload",
        dest="upload",
        action="store_false",
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
        "--no-keep-builds",
        dest="keep_builds",
        action="store_false",
        help="delete kernel builds after packaging (default if uploading)",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--keep-builds",
        action="store_true",
        help="keep kernel builds after packaging (default if not uploading)",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--download-directory",
        metavar="DIR",
        type=Path,
        default="build/vmtest",
        help="directory to download assets to",
    )
    args = parser.parse_args()

    if not hasattr(args, "architectures") or "all" in args.architectures:
        args.architectures = list(ARCHITECTURES.values())
    else:
        args.architectures = [
            arch for arch in ARCHITECTURES.values() if arch.name in args.architectures
        ]
    if not hasattr(args, "flavors") or "all" in args.flavors:
        args.flavors = list(KERNEL_FLAVORS.values())
    else:
        args.flavors = [
            flavor for flavor in KERNEL_FLAVORS.values() if flavor.name in args.flavors
        ]

    if not args.build:
        args.upload = False
    if not hasattr(args, "keep_builds"):
        args.keep_builds = not args.upload

    async with aiohttp.ClientSession(trust_env=True) as session:
        GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
        if GITHUB_TOKEN is None and args.upload:
            sys.exit("GITHUB_TOKEN environment variable is not set")
        gh = AioGitHubApi(session, GITHUB_TOKEN)

        args.download_directory.mkdir(parents=True, exist_ok=True)
        github_release_coro = gh.get_release_by_tag(
            *VMTEST_GITHUB_RELEASE,
            cache=args.download_directory / "github_release.json",
        )
        if args.latest_kernels:
            github_release, latest_kernel_tags = await asyncio.gather(
                github_release_coro, get_latest_kernel_tags()
            )
        else:
            github_release = await github_release_coro

        kernel_releases = available_kernel_releases(github_release)
        logger.info("available kernel releases:")
        for arch in args.architectures:
            arch_kernel_releases = kernel_releases.get(arch.name, {})
            logger.info(
                "  %s: %s",
                arch.name,
                ", ".join(
                    sorted(arch_kernel_releases, key=KernelVersion, reverse=True)
                ),
            )

        to_build = []
        if args.latest_kernels:
            logger.info("latest kernel versions: %s", ", ".join(latest_kernel_tags))
            for tag in latest_kernel_tags:
                tag_arches_to_build = []
                for arch in args.architectures:
                    arch_kernel_releases = kernel_releases.get(arch.name, {})
                    tag_arch_flavors_to_build = [
                        flavor
                        for flavor in args.flavors
                        if kernel_tag_to_release(tag, flavor)
                        not in arch_kernel_releases
                    ]
                    if tag_arch_flavors_to_build:
                        tag_arches_to_build.append((arch, tag_arch_flavors_to_build))
                if tag_arches_to_build:
                    to_build.append((tag, tag_arches_to_build))

        if to_build:
            logger.info("kernel versions to build:")
            for tag, tag_arches_to_build in to_build:
                logger.info(
                    "  %s (%s)",
                    tag,
                    ", ".join(
                        [
                            f"{arch.name} [{', '.join([flavor.name for flavor in tag_arch_flavors_to_build])}]"
                            for arch, tag_arch_flavors_to_build in tag_arches_to_build
                        ]
                    ),
                )

            if args.build:
                compilers = {
                    cast(Compiler, downloaded).target.name: cast(Compiler, downloaded)
                    for downloaded in download(
                        args.download_directory,
                        {
                            arch.name: DownloadCompiler(arch)
                            for _, tag_arches_to_build in to_build
                            for arch, _ in tag_arches_to_build
                        }.values(),
                    )
                }

                if args.upload:
                    upload_queue: "asyncio.Queue[Optional[AssetUploadWork]]" = (
                        asyncio.Queue()
                    )
                    uploader = asyncio.create_task(asset_uploader(gh, upload_queue))

                await fetch_kernel_tags(
                    args.kernel_directory, [tag for tag, _ in to_build]
                )

                async for kernel_package in build_kernels(
                    args.kernel_directory,
                    args.build_directory,
                    to_build,
                    compilers,
                    args.keep_builds,
                ):
                    if args.upload:
                        await upload_queue.put(
                            AssetUploadWork(
                                upload_url=github_release["upload_url"],
                                path=kernel_package,
                                name=kernel_package.name,
                                content_type="application/zstd",
                            )
                        )
                    else:
                        logger.info("would upload %s", kernel_package)

                if args.upload:
                    await upload_queue.put(None)
                    await upload_queue.join()
                    if not await uploader:
                        sys.exit("some uploads failed")
        else:
            logger.info("nothing to build")


if __name__ == "__main__":
    asyncio.run(main())
