# Copyright (c) SUSE Linux.
# SPDX-License-Identifier: LGPL-2.1-or-later

from pathlib import Path
import subprocess

from tests.linux_kernel import LinuxKernelTestCase


class TestContrib(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.contrib = Path(__file__).absolute().parents[2] / "contrib"

    def _run_script(self, script_name, args=[]):
        return subprocess.check_output(
            ["python3", "-Bm", "drgn", str(self.contrib / script_name)] + args,
            encoding="utf8",
        )

    def test_cgroup(self):
        output = self._run_script("cgroup.py")
        self.assertEqual(output.strip(), "/")

    def test_fs_inodes(self):
        lines = self._run_script("fs_inodes.py").splitlines()
        self.assertIn("dev", lines)

    def test_lsmod(self):
        output = self._run_script("lsmod.py")
        self.assertIn("drgn_test", output)

    def test_mount(self):
        output = self._run_script("mount.py")
        self.assertIn("rootfs", output)

    def test_ps(self):
        lines = self._run_script("ps.py").splitlines()
        self.assertTrue(lines[0].startswith("PID"))
        self.assertEqual(lines[1].split()[0], "1")

    def test_tcp_sock(self):
        self._run_script("tcp_sock.py")

    def test_vmstat(self):
        output = self._run_script("vmstat.py")
        self.assertIn("NR_SHM", output)
