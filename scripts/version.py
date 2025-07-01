#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import os
from pathlib import Path
import re
import subprocess


def _get_public_version(source_root: Path) -> str:
    parts = {}
    with (source_root / "libdrgn/drgn.h").open("r") as f:
        for line in f:
            match = re.match(r"#define DRGN_VERSION_(MAJOR|MINOR|PATCH) ([0-9]+)", line)
            if match:
                parts[match.group(1)] = match.group(2)
    return f"{parts['MAJOR']}.{parts['MINOR']}.{parts['PATCH']}"


def _get_local_version(source_root: Path, public_version: str) -> str:
    # Default if we fail.
    local_version = "+unknown"

    # If this is a git repository, use a git-describe(1)-esque local version.
    # Otherwise, get the local version saved in the sdist.
    if (source_root / ".git").exists() and (
        subprocess.call(
            ["git", "--git-dir=.git", "rev-parse"],
            cwd=source_root,
            stderr=subprocess.DEVNULL,
        )
        == 0
    ):
        # Read the Docs modifies the working tree (namely, docs/conf.py). We
        # don't want the documentation to display a dirty version, so ignore
        # modifications for RTD builds.
        dirty = os.getenv("READTHEDOCS") != "True" and bool(
            subprocess.check_output(
                ["git", "status", "-uno", "--porcelain"],
                cwd=source_root,
                # Use the environment variable instead of --no-optional-locks
                # to support Git < 2.14.
                env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
            )
        )

        try:
            count = int(
                subprocess.check_output(
                    ["git", "rev-list", "--count", f"v{public_version}.."],
                    cwd=source_root,
                    stderr=subprocess.DEVNULL,
                    universal_newlines=True,
                )
            )
        except subprocess.CalledProcessError:
            logger.warning("warning: v%s tag not found", public_version)
        else:
            if count == 0:
                local_version = "+dirty" if dirty else ""
            else:
                commit = subprocess.check_output(
                    ["git", "rev-parse", "--short", "HEAD"],
                    cwd=source_root,
                    universal_newlines=True,
                ).strip()
                local_version = f"+{count}.g{commit}"
                if dirty:
                    local_version += ".dirty"
    else:
        assert False, f"TODO {source_root=}"
    return local_version


def _get_version(source_root: Path) -> str:
    public_version = _get_public_version(source_root)
    local_version = _get_local_version(source_root, public_version)
    return public_version + local_version


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", metavar="PATH", type=Path)
    parser.add_argument("--gen-version-c", metavar="PATH", type=Path)
    args = parser.parse_args()

    if args.source_root is None:
        try:
            args.source_root = Path(os.environ["MESON_SOURCE_ROOT"])
        except KeyError:
            args.source_root = Path(".")

    version = _get_version(args.source_root)

    if args.gen_version_c is not None:
        new_version_c = f'__attribute__((__visibility__("default"))) const char drgn_version[] = "{version}";\n'
        try:
            version_c = args.gen_version_c.read_text()
        except FileNotFoundError:
            version_c = None
        if new_version_c != version_c:
            args.gen_version_c.write_text(new_version_c)
    else:
        print(version)


if __name__ == "__main__":
    main()
