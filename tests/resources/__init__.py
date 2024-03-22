# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from util import out_of_date


def get_resource(name: str) -> Path:
    dir = Path(__file__).parent
    decompressed_path = dir / name
    compressed_path = dir / (name + ".zst")
    if out_of_date(decompressed_path, compressed_path):
        tmp_file = tempfile.NamedTemporaryFile(dir=dir, prefix=name, delete=False)
        try:
            try:
                subprocess.check_call(
                    [
                        "zstd",
                        "--quiet",
                        "--force",
                        "--decompress",
                        "--stdout",
                        str(compressed_path),
                    ],
                    stdout=tmp_file,
                )
            except FileNotFoundError:
                raise unittest.SkipTest("zstd not found")
        except BaseException:
            os.unlink(tmp_file.name)
            raise
        else:
            os.rename(tmp_file.name, decompressed_path)
    return decompressed_path
