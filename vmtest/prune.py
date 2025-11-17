# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import asyncio
from collections import defaultdict
import logging
import operator
import os
from pathlib import Path
import re
import shutil
import sys
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Tuple, TypeVar

import aiohttp

from util import KernelVersion
from vmtest.download import VMTEST_GITHUB_RELEASE
from vmtest.githubapi import AioGitHubApi

logger = logging.getLogger(__name__)


def _prompt_yes_no(prompt: str, default: bool = True) -> bool:
    prompt += " [Y/n] " if default else " [y/N] "
    sys.stdout.flush()
    sys.stderr.write(prompt)
    sys.stderr.flush()
    answer = input().strip().lower()
    if answer.startswith("y"):
        return True
    elif answer.startswith("n"):
        return False
    else:
        return default


def _kernel_asset_sort_key(x: Tuple[str, str, Any]) -> Tuple[KernelVersion, str]:
    release, arch, _ = x
    return KernelVersion(release), arch


_AssetT = TypeVar("_AssetT")


async def _prune(
    *,
    kernels: Iterable[Tuple[str, str, _AssetT]],
    kmods: Iterable[Tuple[str, str, _AssetT]] = (),
    keep: int,
    asset_name: Callable[[_AssetT], str],
    delete_asset: Callable[[_AssetT], Awaitable[None]],
) -> int:
    def print_asset_list(assets: List[Tuple[str, str, _AssetT]]) -> None:
        for _, _, asset in assets:
            print(f"    {asset_name(asset)}")

    grouped_kernels: Dict[Tuple[str, str, str], List[Tuple[str, _AssetT]]] = (
        defaultdict(list)
    )
    unrecognized_kernels: List[Tuple[str, str, _AssetT]] = []

    for release, arch, asset in kernels:
        match = re.fullmatch(
            r"(?P<major_minor>[0-9]+\.[0-9]+)\.(?P<patch_rc>[0-9]+(?:-rc[0-9]+)?)-vmtest(?P<vmtest>[0-9]+(?:\.[0-9]+)*)(?P<flavor>[^.]+)",
            release,
        )
        if match:
            grouped_kernels[
                (match.group("major_minor"), match.group("flavor"), arch)
            ].append((release, asset))
        else:
            unrecognized_kernels.append((release, arch, asset))

    kernels_to_keep = {(release, arch) for release, arch, _ in unrecognized_kernels}
    kernels_to_delete: List[Tuple[str, str, _AssetT]] = []
    for (_, _, arch), kernel_group in grouped_kernels.items():
        kernel_group.sort(key=lambda x: KernelVersion(x[0]), reverse=True)
        for release, _ in kernel_group[:keep]:
            kernels_to_keep.add((release, arch))
        kernels_to_delete.extend(
            (release, arch, asset) for release, asset in kernel_group[keep:]
        )
    kernels_to_delete.sort(key=_kernel_asset_sort_key)

    kmods_to_delete = [
        (release, arch, asset)
        for release, arch, asset in kmods
        if (release, arch) not in kernels_to_keep
    ]
    kmods_to_delete.sort(key=_kernel_asset_sort_key)

    if kernels_to_delete:
        print("Deleting kernels:")
        print_asset_list(kernels_to_delete)

    if kmods_to_delete:
        print("Deleting kernel modules:")
        print_asset_list(kmods_to_delete)

    if unrecognized_kernels:
        unrecognized_kernels.sort(key=_kernel_asset_sort_key)
        print("Ignoring unrecognized kernels:")
        print_asset_list(unrecognized_kernels)

    if not kernels_to_delete and not kmods_to_delete:
        return 0

    if not _prompt_yes_no("Continue?", default=False):
        return 1

    to_delete = kernels_to_delete + kmods_to_delete
    for _, _, asset in to_delete:
        await delete_asset(asset)
    return 0


async def _delete_local_asset(asset: Path) -> None:
    try:
        asset.unlink()
    except IsADirectoryError:
        shutil.rmtree(asset)


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="delete old vmtest kernels",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--directory",
        metavar="DIR",
        type=Path,
        default="build/vmtest",
        help="directory for vmtest artifacts",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-l",
        "--local",
        action="store_true",
        default=argparse.SUPPRESS,
        help="delete locally downloaded vmtest kernels and their kernel modules",
    )
    group.add_argument(
        "-r",
        "--remote",
        dest="local",
        action="store_false",
        default=argparse.SUPPRESS,
        help="delete uploaded vmtest kernel assets",
    )
    parser.add_argument(
        "-k", "--keep", type=int, default=1, help="number of latest kernels to keep"
    )
    args = parser.parse_args()

    if args.keep <= 0:
        sys.exit("keep must be >= 1")

    if args.local:
        status = await _prune(
            kernels=(
                (kernel.name[len("kernel-") :], kernel.parent.name, kernel)
                for kernel in args.directory.glob("*/kernel-*")
            ),
            kmods=(
                (kmod.name[len("drgn_test-") : -len(".ko")], kmod.parent.name, kmod)
                for kmod in args.directory.glob("*/drgn_test-*.ko")
            ),
            keep=args.keep,
            asset_name=str,
            delete_asset=_delete_local_asset,
        )
    else:
        GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
        if GITHUB_TOKEN is None:
            sys.exit("GITHUB_TOKEN environment variable is not set")
        async with aiohttp.ClientSession(trust_env=True) as session:
            gh = AioGitHubApi(session, GITHUB_TOKEN)

            github_release = await gh.get_release_by_tag(
                *VMTEST_GITHUB_RELEASE, cache=args.directory / "github_release.json"
            )

            kernels = []
            for asset in github_release["assets"]:
                match = re.fullmatch(
                    r"kernel-(?P<release>.*)\.(?P<arch>[^.]+)\.tar\.zst", asset["name"]
                )
                if match:
                    kernels.append((match.group("release"), match.group("arch"), asset))
                elif asset["name"].startswith("kernel-"):
                    logger.warning("ignoring unrecognized kernel: %s", asset["name"])

            async def _delete_remote_asset(asset: Dict[str, Any]) -> None:
                await gh.delete(asset["url"])

            status = await _prune(
                kernels=kernels,
                keep=args.keep,
                asset_name=operator.itemgetter("name"),
                delete_asset=_delete_remote_asset,
            )

    sys.exit(status)


if __name__ == "__main__":
    asyncio.run(main())
