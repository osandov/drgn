# Copyright (c) 2025 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import shutil
import tempfile
from unittest import mock

from drgn.commands import CommandError
from tests.linux_kernel.crash_commands import CrashCommandTestCase


class TestCrashCd(CrashCommandTestCase):
    def setUp(self):
        super().setUp()

        # Create a temporary directory to act as our filesystem
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()

        # Save OLDPWD if present
        self.original_env_prev = os.environ.get("PY_CD_OLDPWD")

        # Start inside test directory
        os.chdir(self.test_dir)

    def tearDown(self):
        # Restore CWD
        os.chdir(self.original_cwd)

        # Restore environment
        if self.original_env_prev is not None:
            os.environ["PY_CD_OLDPWD"] = self.original_env_prev
        else:
            os.environ.pop("PY_CD_OLDPWD", None)

        shutil.rmtree(self.test_dir)
        super().tearDown()

    def test_cd_basic_navigation(self):
        subdir = os.path.join(self.test_dir, "subdir")
        os.mkdir(subdir)

        self.run_crash_command(f"cd {subdir}")

        self.assertEqual(os.path.realpath(os.getcwd()), os.path.realpath(subdir))

    def test_cd_no_args_goes_home(self):
        fake_home = os.path.join(self.test_dir, "fake_home")
        os.mkdir(fake_home)

        with mock.patch("os.path.expanduser", return_value=fake_home):
            self.run_crash_command("cd")

            self.assertEqual(os.path.realpath(os.getcwd()), os.path.realpath(fake_home))

    def test_cd_hyphen_previous_dir(self):
        dir_a = os.path.join(self.test_dir, "dir_a")
        dir_b = os.path.join(self.test_dir, "dir_b")
        os.mkdir(dir_a)
        os.mkdir(dir_b)

        # Start in A
        os.chdir(dir_a)

        # Move to B (sets OLDPWD -> A)
        self.run_crash_command(f"cd {dir_b}")
        self.assertEqual(os.path.realpath(os.getcwd()), os.path.realpath(dir_b))

        # 'cd -' should go back to A
        self.run_crash_command("cd -")
        self.assertEqual(os.path.realpath(os.getcwd()), os.path.realpath(dir_a))

        # 'cd -' should go back to B
        self.run_crash_command("cd -")
        self.assertEqual(os.path.realpath(os.getcwd()), os.path.realpath(dir_b))

    def test_cd_error_non_existent(self):
        bad_path = os.path.join(self.test_dir, "does_not_exist")

        self.assertRaisesRegex(
            CommandError,
            "no such file",
            self.run_crash_command,
            f"cd {bad_path}",
        )

    def test_cd_error_not_a_directory(self):
        some_file = os.path.join(self.test_dir, "file.txt")
        with open(some_file, "w"):
            pass

        self.assertRaisesRegex(
            CommandError,
            "not a directory",
            self.run_crash_command,
            f"cd {some_file}",
        )

    def test_cd_empty_string(self):
        self.assertRaises(
            CommandError,
            self.run_crash_command,
            'cd ""',
        )

    def test_cd_stale_oldpwd_handling(self):
        dir_a = os.path.join(self.test_dir, "dir_a")
        dir_b = os.path.join(self.test_dir, "dir_b")
        os.mkdir(dir_a)
        os.mkdir(dir_b)

        os.chdir(dir_a)

        try:
            os.rmdir(dir_a)
        except OSError:
            self.skipTest("Filesystem does not allow removing current directory")

        self.run_crash_command(f"cd {dir_b}")
        self.assertEqual(os.path.realpath(os.getcwd()), os.path.realpath(dir_b))

        self.assertRaises(
            CommandError,
            self.run_crash_command,
            "cd -",
        )
