# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import logging
import os
from pathlib import Path
import shutil
import sys
import tempfile
import urllib.request

import uritemplate

from vmtest.config import ARCHITECTURES, compiler_url
from vmtest.githubapi import GitHubApi

logger = logging.getLogger(__name__)


def main() -> None:
    logging.basicConfig(
        format="%(asctime)s:%(levelname)s:%(name)s:%(message)s", level=logging.INFO
    )

    parser = argparse.ArgumentParser(
        description="mirror compilers from kernel.org to GitHub"
    )
    parser.parse_args()

    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
    if GITHUB_TOKEN is None:
        sys.exit("GITHUB_TOKEN environment variable is not set")
    gh = GitHubApi(GITHUB_TOKEN)

    host_names = []
    target_names = []
    for arch in ARCHITECTURES.values():
        if arch.kernel_org_compiler_host_name is not None:
            host_names.append(arch.kernel_org_compiler_host_name)
        target_names.append(arch.kernel_org_compiler_target_name)

    release = gh.get_release_by_tag("osandov", "drgn", "vmtest-compilers")
    upload_url = release["upload_url"]
    available_compilers = {asset["name"] for asset in release["assets"]}

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)

        for host_name in host_names:
            for target_name in target_names:
                url = compiler_url(host_name, target_name)
                file_name = url.rpartition("/")[2]

                if file_name in available_compilers:
                    logger.info("%s is already available", file_name)
                    continue

                file_path = tmp_dir / file_name

                with file_path.open("w+b") as f:
                    logger.info("downloading %s", url)
                    with urllib.request.urlopen(url) as resp:
                        shutil.copyfileobj(resp, f)
                    logger.info("downloaded %s", url)

                    content_length = f.tell()
                    f.flush()
                    f.seek(0)

                    logger.info("uploading %s", file_name)
                    print(uritemplate.expand(upload_url, name=file_name))
                    gh.upload(
                        uritemplate.expand(upload_url, name=file_name),
                        f,
                        "application/x-xz",
                        content_length,
                    )
                    logger.info("uploaded %s", file_name)

                file_path.unlink()


if __name__ == "__main__":
    main()
