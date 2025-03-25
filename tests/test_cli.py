# Copyright (c) 2025, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later


import subprocess
import sys

from tests import TestCase


class TestCli(TestCase):

    def run_cli(self, *args: str):
        try:
            return subprocess.run(
                [sys.executable, "-m", "drgn"] + list(args),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            # With captured output, there's nothing left to debug in CI logs.
            # Print output on a failure so we can debug.
            print(f"STDOUT:\n{e.stdout.decode()}")
            print(f"STDERR:\n{e.stderr.decode()}")
            raise

    def test_smoke(self):
        proc = self.run_cli(
            "--quiet", "--pid", "0", "--no-default-symbols", "-e", "print('pass')"
        )
        self.assertEqual(proc.stdout, b"pass\n")
