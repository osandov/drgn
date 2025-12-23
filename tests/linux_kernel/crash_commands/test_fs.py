# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import ctypes
import mmap
import os
import os.path
import re
import tempfile

from drgn import Object
from drgn.helpers.linux.fs import fget
from drgn.helpers.linux.pid import find_task
from tests.linux_kernel import CLONE_NEWNS, fork_and_stop, mlock, unshare
from tests.linux_kernel.crash_commands import CrashCommandTestCase


class TestFiles(CrashCommandTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.run_crash_command("set -p")

    def _test_drgn_common(self, cmd, cache=False):
        self.assertIn("for_each_file(", cmd.drgn_option.stdout)

        for variable in (
            "task",
            "pid",
            "command",
            "inode",
        ):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)

        if cache:
            for variable in ("i_mapping", "nrpages"):
                with self.subTest(variable=variable):
                    self.assertIsInstance(cmd.drgn_option.globals[variable], Object)

            self.assertNotIn("dentry", cmd.drgn_option.globals)
        else:
            for variable in ("file", "dentry"):
                with self.subTest(variable=variable):
                    self.assertIsInstance(cmd.drgn_option.globals[variable], Object)

            self.assertNotIn("i_mapping", cmd.drgn_option.globals)
            self.assertNotIn("nrpages", cmd.drgn_option.globals)

        self.assertIsInstance(cmd.drgn_option.globals["cpu"], int)
        self.assertIsInstance(cmd.drgn_option.globals["fd"], int)
        self.assertIsInstance(cmd.drgn_option.globals["type"], str)
        for variable in (
            "root",
            "cwd",
            "path",
        ):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], bytes)

    def test_no_options(self):
        with tempfile.NamedTemporaryFile() as f:
            cmd = self.check_crash_command("files")
            self.assertRegex(cmd.stdout, r"(?m)^ROOT: .* CWD:")
            self.assertRegex(
                cmd.stdout,
                rf"(?m)^\s*{f.fileno()}\s+[0-9a-f]+\s+[0-9a-f]+\s+[0-9a-f]+\s+REG\s+{re.escape(f.name)}",
            )

        self._test_drgn_common(cmd)

    def test_tasks(self):
        with tempfile.NamedTemporaryFile() as f:
            with fork_and_stop() as pid:
                cmd = self.check_crash_command(f"files {os.getpid()} {pid}")
                foreach_cmd = self.check_crash_command(
                    f"foreach {os.getpid()} {pid} files", mode="capture"
                )

            for c in (cmd, foreach_cmd):
                self.assertIn(f"PID: {os.getpid()}", c.stdout)
                self.assertIn(f"PID: {pid}", c.stdout)
                self.assertRegex(c.stdout, r"(?m)^ROOT: .* CWD:")
                self.assertEqual(
                    len(re.findall(rf"^\s*{f.fileno()}\b", c.stdout, flags=re.M)), 2
                )

        self._test_drgn_common(cmd)

        self.assertEqual(cmd.drgn_option.stdout, foreach_cmd.drgn_option.stdout)

    def test_c(self):
        with tempfile.NamedTemporaryFile() as f:
            cmd = self.check_crash_command(f"files -c {os.getpid()}")
            foreach_cmd = self.check_crash_command(
                f"foreach {os.getpid()} files -c", mode="capture"
            )

            for c in (cmd, foreach_cmd):
                self.assertRegex(c.stdout, r"(?m)^ROOT: .* CWD:")
                self.assertRegex(
                    c.stdout,
                    rf"(?m)^\s*{f.fileno()}\s+[0-9a-f]+\s+[0-9a-f]+\s+[0-9]+\s+REG\s+{re.escape(f.name)}",
                )

        self._test_drgn_common(cmd, cache=True)

        self.assertEqual(cmd.drgn_option.stdout, foreach_cmd.drgn_option.stdout)

    def test_d(self):
        with tempfile.NamedTemporaryFile() as f:
            dentry = fget(
                find_task(self.prog, os.getpid()), f.fileno()
            ).f_path.dentry.read_()
            cmd = self.check_crash_command(f"files -d {dentry.value_():x}")

        self.assertRegex(
            cmd.stdout,
            rf"(?m)^\s*{dentry.value_():x}\s+[0-9a-f]+\s+[0-9a-f]+\s+REG\s+.*{re.escape(os.path.basename(f.name))}",
        )

        self.assertEqual(cmd.drgn_option.globals["dentry"], dentry)

        for variable in ("inode", "sb"):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)
        self.assertEqual(cmd.drgn_option.globals["type"], "REG")
        self.assertIsInstance(cmd.drgn_option.globals["path"], bytes)

    def test_p(self):
        with tempfile.TemporaryFile(dir="/dev/shm") as f:
            f.write(os.urandom(2 * mmap.PAGESIZE))
            f.flush()
            inode = fget(find_task(self.prog, os.getpid()), f.fileno()).f_inode.read_()
            with mmap.mmap(f.fileno(), 2 * mmap.PAGESIZE) as map:
                f.close()
                address = ctypes.addressof(ctypes.c_char.from_buffer(map))
                # Make sure the pages are faulted in and stay that way.
                mlock(address, 2 * mmap.PAGESIZE)

                cmd = self.check_crash_command(f"files -p {inode.value_():x}")

        self.assertRegex(cmd.stdout, r"(?m)^\s*INODE\s+NRPAGES.*\n\s*[0-9a-f]+\s+2")
        self.assertRegex(
            cmd.stdout, r"(?m)^\s*PAGE\s+PHYSICAL\s+MAPPING\s+INDEX\s+CNT\s+FLAGS.*\n"
        )
        self.assertRegex(cmd.stdout, r"(?m)^\s*[0-9a-f]+\s+[0-9a-f]+\s+[0-9a-f]+\s+\b")

        self.assertIn("inode_for_each_page(", cmd.drgn_option.stdout)
        for variable in (
            "inode",
            "i_mapping",
            "nrpages",
            "page",
            "physical",
            "cnt",
            "flags",
        ):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)

        self.assertIsInstance(cmd.drgn_option.globals["index"], int)
        self.assertIsInstance(cmd.drgn_option.globals["decoded_flags"], str)

    def _test_R(self, arg_fn, expect_no_cache, expect_cache, test_foreach=False):
        with tempfile.NamedTemporaryFile() as f:
            arg = arg_fn(f)

            cmd = self.check_crash_command(f"files -R {arg} {os.getpid()}")
            cmds = [cmd]
            if test_foreach:
                foreach_cmd = self.check_crash_command(
                    f"foreach {os.getpid()} files -R {arg}", mode="capture"
                )
                cmds.append(foreach_cmd)

            for c in cmds:
                if expect_no_cache:
                    self.assertRegex(
                        c.stdout,
                        rf"(?m)^\s*{f.fileno()}\s+[0-9a-f]+\s+[0-9a-f]+\s+[0-9a-f]+\s+REG\s+{re.escape(f.name)}",
                    )
                else:
                    self.assertFalse(c.stdout)
            self._test_drgn_common(cmd)
            self.assertIsInstance(cmd.drgn_option.globals["is_match"], bool)
            if test_foreach:
                self.assertEqual(cmd.drgn_option.stdout, foreach_cmd.drgn_option.stdout)

            cmd = self.check_crash_command(f"files -c -R {arg} {os.getpid()}")
            cmds = [cmd]
            if test_foreach:
                foreach_cmd = self.check_crash_command(
                    f"foreach {os.getpid()} files -c -R {arg}", mode="capture"
                )
                cmds.append(foreach_cmd)

            for c in cmds:
                if expect_cache:
                    self.assertRegex(
                        c.stdout,
                        rf"(?m)^\s*{f.fileno()}\s+[0-9a-f]+\s+[0-9a-f]+\s+[0-9]+\s+REG\s+{re.escape(f.name)}",
                    )
                else:
                    self.assertFalse(c.stdout)
            self._test_drgn_common(cmd, cache=True)
            self.assertIsInstance(cmd.drgn_option.globals["is_match"], bool)
            if test_foreach:
                self.assertEqual(cmd.drgn_option.stdout, foreach_cmd.drgn_option.stdout)

    def test_R_fd(self):
        self._test_R(lambda f: str(f.fileno()), True, True, True)

    def test_R_filename(self):
        self._test_R(lambda f: f.name, True, True)

    def test_R_dentry(self):
        self._test_R(
            lambda f: hex(
                fget(find_task(self.prog, os.getpid()), f.fileno()).f_path.dentry
            ),
            True,
            False,
        )

    def test_R_inode(self):
        self._test_R(
            lambda f: hex(fget(find_task(self.prog, os.getpid()), f.fileno()).f_inode),
            True,
            True,
        )

    def test_R_address_space(self):
        self._test_R(
            lambda f: hex(
                fget(find_task(self.prog, os.getpid()), f.fileno()).f_inode.i_mapping
            ),
            False,
            True,
        )

    def test_R_file(self):
        self._test_R(
            lambda f: hex(fget(find_task(self.prog, os.getpid()), f.fileno())),
            True,
            False,
        )

    def test_R_cwd(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            with fork_and_stop(os.chdir, tmp_dir) as (pid, _):
                cmd = self.check_crash_command(f"files -R {tmp_dir} {pid}")

        self.assertRegex(cmd.stdout, rf"CWD: {re.escape(tmp_dir)}\n$")

        self.assertEqual(cmd.drgn_option.globals["cwd"], os.fsencode(tmp_dir))
        self.assertIsInstance(cmd.drgn_option.globals["is_match"], bool)

    def test_no_files(self):
        cmd = self.check_crash_command(f"files {hex(self.prog['init_task'].address_)}")
        self.assertRegex(cmd.stdout, r"\nNo open files\n$")


class TestMount(CrashCommandTestCase):
    def test_no_options(self):
        self.run_crash_command("set 1")
        cmd = self.check_crash_command("mount")
        self.assertRegex(cmd.stdout, r"(?m)^\s*[0-9a-f]+\s+[0-9a-f]+.*proc")
        self.assertIn("for_each_mount()", cmd.drgn_option.stdout)
        self.assertNotIn("mnt_ns", cmd.drgn_option.globals)

    def test_no_options_in_namespace(self):
        with fork_and_stop(unshare, CLONE_NEWNS) as (pid, _):
            self.run_crash_command(f"set {pid}")
            cmd = self.check_crash_command("mount")
            self.assertIn("for_each_mount(mnt_ns)", cmd.drgn_option.stdout)
            self.assertEqual(
                cmd.drgn_option.globals["mnt_ns"],
                find_task(self.prog, pid).nsproxy.mnt_ns,
            )

    def test_n_pid(self):
        cmd = self.check_crash_command("mount -n 1")
        self.assertRegex(cmd.stdout, r"(?m)^\s*[0-9a-f]+\s+[0-9a-f]+.*proc")
        self.assertIn("for_each_mount(mnt_ns)", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["mnt_ns"], find_task(self.prog, 1).nsproxy.mnt_ns
        )

    def test_n_task(self):
        task = self.prog["init_task"].address_of_()
        cmd = self.check_crash_command(f"mount -n {hex(task)}")
        self.assertRegex(cmd.stdout, r"(?m)^\s*[0-9a-f]+\s+[0-9a-f]+.*proc")
        self.assertIn("for_each_mount(mnt_ns)", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["mnt_ns"], self.prog["init_task"].nsproxy.mnt_ns
        )
