# Copyright (c) 2025, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later


import subprocess
import sys
import tempfile

from tests import TestCase


class TestCli(TestCase):

    def run_cli(self, *args: str, **kwargs):
        try:
            return subprocess.run(
                [sys.executable, "-m", "drgn"] + list(args),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                **kwargs,
            )
        except subprocess.CalledProcessError as e:
            # With captured output, there's nothing left to debug in CI logs.
            # Print output on a failure so we can debug.
            print(f"STDOUT:\n{e.stdout.decode()}")
            print(f"STDERR:\n{e.stderr.decode()}")
            raise

    def test_e(self):
        script = r"""
import sys

assert drgn.get_default_prog() is prog
assert __name__ == "__main__"
assert "__file__" not in globals()
assert sys.path[0] == ""
print(sys.argv)
"""
        proc = self.run_cli(
            "--quiet", "--pid", "0", "--no-default-symbols", "-e", script, "pass"
        )
        self.assertEqual(proc.stdout, b"['-e', 'pass']\n")

    def test_script(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(
                rb"""
assert "drgn" not in globals()

import drgn
import os.path
import sys

assert drgn.get_default_prog() is prog
assert __name__ == "__main__"
assert __file__ == sys.argv[0]
assert sys.path[0] == os.path.dirname(__file__)
print(sys.argv)
"""
            )
            f.flush()
            proc = self.run_cli(
                "--quiet", "--pid", "0", "--no-default-symbols", f.name, "pass"
            )
            self.assertEqual(proc.stdout, f"[{f.name!r}, 'pass']\n".encode())

    def test_pipe(self):
        script = rb"""
import sys

assert drgn.get_default_prog() is prog
assert __name__ == "__main__"
assert __file__ == "<stdin>"
assert sys.path[0] == ""
# Dummy if statement to test handling of multi-line blocks.
if True:
    print(sys.argv)
"""
        proc = self.run_cli(
            "--quiet", "--pid", "0", "--no-default-symbols", input=script
        )
        self.assertEqual(proc.stdout, b"['']\n")
