# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import re
import shutil
import unittest.mock

from drgn import Object
from drgn.commands import CommandArgumentError, CommandError
from drgn.commands.crash import crash_get_context
from drgn.helpers.linux.pid import find_task
from tests.linux_kernel.crash_commands import CrashCommandTestCase


class TestSet(CrashCommandTestCase):
    def test_no_options(self):
        cmd = self.check_crash_command("set")
        self.assertIn("CPU:", cmd.stdout)
        for name in "task", "pid", "comm", "thread_info", "cpu", "state":
            self.assertIn(name, cmd.drgn_option.globals)

    def test_pid(self):
        cmd = self.check_crash_command("set 1")
        self.assertIn("PID: 1", cmd.stdout)
        self.assertEqual(crash_get_context(self.prog).pid.value_(), 1)
        self.assertEqual(cmd.drgn_option.globals["task"].pid, 1)

    def test_task(self):
        cmd = self.check_crash_command(f"set {hex(self.prog['init_task'].address_)}")
        self.assertIn("PID: 0", cmd.stdout)
        self.assertEqual(
            crash_get_context(self.prog), self.prog["init_task"].address_of_()
        )
        self.assertEqual(
            cmd.drgn_option.globals["task"], self.prog["init_task"].address_of_()
        )

    def test_cpu(self):
        cpu = os.cpu_count() - 1
        old_affinity = os.sched_getaffinity(0)
        os.sched_setaffinity(0, (cpu,))
        try:
            cmd = self.check_crash_command(f"set -c {cpu}")
        finally:
            os.sched_setaffinity(0, old_affinity)
        self.assertIn(f"PID: {os.getpid()}", cmd.stdout)
        task = find_task(self.prog, os.getpid())
        self.assertEqual(crash_get_context(self.prog), task)
        self.assertEqual(cmd.drgn_option.globals["task"], task)

    def test_panic(self):
        cmd = self.check_crash_command("set -p")
        task = find_task(self.prog, os.getpid())
        self.assertIn(f"PID: {os.getpid()}", cmd.stdout)
        self.assertEqual(
            crash_get_context(self.prog), find_task(self.prog, os.getpid())
        )
        self.assertEqual(cmd.drgn_option.globals["task"], task)

    def test_foreach(self):
        self.run_crash_command(f"set {hex(self.prog['init_task'].address_)}")
        cmd = self.check_crash_command(f"foreach 1 {os.getpid()} set")
        # Task information gets printed twice (once in the header and once in
        # the sys format).
        self.assertEqual(len(re.findall(r"\bPID: 1\b", cmd.stdout)), 2)
        self.assertEqual(len(re.findall(rf"\bPID: {os.getpid()}\b", cmd.stdout)), 2)
        # foreach set shouldn't change the context.
        self.assertEqual(
            crash_get_context(self.prog), self.prog["init_task"].address_of_()
        )

        for variable in ("task", "pid", "comm", "thread_info"):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)
        self.assertIsInstance(cmd.drgn_option.globals["cpu"], int)
        self.assertIsInstance(cmd.drgn_option.globals["state"], str)

    def test_scroll_on_off(self):
        try:
            old_crash_scroll = self.prog.config["crash_scroll"]
        except KeyError:
            self.addCleanup(self.prog.config.pop, "crash_scroll", None)
        else:
            self.addCleanup(
                self.prog.config.__setitem__, "crash_scroll", old_crash_scroll
            )

        cmd = self.run_crash_command("set scroll on")
        self.assertIn("scroll: on", cmd.stdout)
        cmd = self.run_crash_command("set scroll")
        self.assertIn("scroll: on", cmd.stdout)

        cmd = self.run_crash_command("set scroll off")
        self.assertIn("scroll: off", cmd.stdout)
        cmd = self.run_crash_command("set scroll")
        self.assertIn("scroll: off", cmd.stdout)

    def test_scroll_less_more(self):
        try:
            old_crash_pager = self.prog.config["crash_pager"]
        except KeyError:
            self.addCleanup(self.prog.config.pop, "crash_pager", None)
        else:
            self.addCleanup(
                self.prog.config.__setitem__, "crash_pager", old_crash_pager
            )

        def only_less(cmd):
            if cmd == "less":
                return "/usr/bin/less"
            elif cmd == "more":
                return None
            else:
                return unittest.mock.DEFAULT

        with unittest.mock.patch(
            "shutil.which", side_effect=only_less, wraps=shutil.which
        ):
            self.prog.config.pop("crash_pager", None)
            cmd = self.run_crash_command("set scroll")
            self.assertIn("/usr/bin/less", cmd.stdout)

            cmd = self.run_crash_command("set scroll less")
            self.assertIn("/usr/bin/less", cmd.stdout)
            cmd = self.run_crash_command("set scroll")
            self.assertIn("/usr/bin/less", cmd.stdout)

            with self.assertRaisesRegex(CommandError, "pager not found"):
                self.run_crash_command("set scroll more")

        def only_more(cmd):
            if cmd == "less":
                return None
            elif cmd == "more":
                return "/bin/more"
            else:
                return unittest.mock.DEFAULT

        with unittest.mock.patch(
            "shutil.which", side_effect=only_more, wraps=shutil.which
        ):
            self.prog.config.pop("crash_pager", None)
            cmd = self.run_crash_command("set scroll")
            self.assertIn("/bin/more", cmd.stdout)

            cmd = self.run_crash_command("set scroll more")
            self.assertIn("/bin/more", cmd.stdout)
            cmd = self.run_crash_command("set scroll")
            self.assertIn("/bin/more", cmd.stdout)

            with self.assertRaisesRegex(CommandError, "pager not found"):
                self.run_crash_command("set scroll less")

        def neither(cmd):
            if cmd == "less" or cmd == "more":
                return None
            else:
                return unittest.mock.DEFAULT

        with unittest.mock.patch(
            "shutil.which", side_effect=neither, wraps=shutil.which
        ):
            self.prog.config.pop("crash_pager", None)
            cmd = self.run_crash_command("set scroll")
            self.assertIn("scroll: off (pager not found)", cmd.stdout)

            with self.assertRaisesRegex(CommandError, "pager not found"):
                self.run_crash_command("set scroll less")
            with self.assertRaisesRegex(CommandError, "pager not found"):
                self.run_crash_command("set scroll more")

    def test_radix(self):
        self.addCleanup(self.prog.config.pop, "crash_radix", None)

        cmd = self.run_crash_command("set radix 10")
        self.assertIn("output radix: 10 (decimal)", cmd.stdout)
        cmd = self.run_crash_command("set radix")
        self.assertIn("output radix: 10 (decimal)", cmd.stdout)

        cmd = self.run_crash_command("set radix 16")
        self.assertIn("output radix: 16 (hex)", cmd.stdout)
        cmd = self.run_crash_command("set radix")
        self.assertIn("output radix: 16 (hex)", cmd.stdout)

    def test_radix_invalid(self):
        self.assertRaisesRegex(
            CommandArgumentError,
            "invalid value for radix",
            self.run_crash_command,
            "set radix 0",
        )
        self.assertRaisesRegex(
            CommandArgumentError,
            "invalid value for radix",
            self.run_crash_command,
            "set radix sixty",
        )
