# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later


import os
from pathlib import Path
import re
import signal

from drgn import Object
from drgn.commands import CommandArgumentError
from tests.linux_kernel import fork_and_stop, skip_unless_have_test_kmod
from tests.linux_kernel.crash_commands import CrashCommandTestCase


class TestSig(CrashCommandTestCase):
    def _test_sig_drgn_option_common(self, cmd):
        for variable in (
            "pid",
            "command",
            "signal_struct",
            "nr_threads",
            "sigaction",
            "handler",
            "mask",
            "flags",
            "blocked",
            "private_pending",
            "private_pending_signals",
            "shared_pending",
            "shared_pending_signals",
        ):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)

        for variable in ("cpu", "signo"):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], int)

        self.assertIsInstance(cmd.drgn_option.globals["decoded_flags"], str)

    def test_sig(self):
        with fork_and_stop(
            signal.pthread_sigmask, signal.SIG_BLOCK, {signal.SIGUSR1, signal.SIGUSR2}
        ) as (pid, _):
            os.kill(pid, signal.SIGUSR1)
            os.kill(pid, signal.SIGUSR2)

            sig_status = dict(
                re.findall(
                    r"^(SigBlk|SigPnd|ShdPnd):\s*([0-9a-f]+)",
                    Path(f"/proc/{pid}/status").read_text(),
                    flags=re.M,
                )
            )

            cmd = self.check_crash_command(f"sig {pid}")
            foreach_cmd = self.check_crash_command(f"foreach {pid} sig", mode="capture")

        for c in (cmd, foreach_cmd):
            self.assertIn("PID:", c.stdout)
            self.assertIn("SIGNAL_STRUCT:", c.stdout)
            self.assertIn("NR_THREADS:", c.stdout)

            self.assertEqual(
                re.search(r"^\s*BLOCKED: ([0-9a-f]+)$", c.stdout, flags=re.M).group(1),
                sig_status["SigBlk"],
            )

            for crash_name, proc_name in (
                ("PRIVATE_PENDING", "SigPnd"),
                ("SHARED_PENDING", "ShdPnd"),
            ):
                with self.subTest(set=crash_name):
                    self.assertEqual(
                        re.search(
                            rf"^{crash_name}\n\s*SIGNAL: ([0-9a-f]+)$",
                            c.stdout,
                            flags=re.M,
                        ).group(1),
                        sig_status[proc_name],
                    )
                    sigqueue = re.search(
                        rf"^{crash_name}\n.*\n\s*SIGQUEUE: (.*)", c.stdout, flags=re.M
                    ).group(1)
                    if sig_status[proc_name].replace("0", ""):
                        self.assertRegex(sigqueue, r"^\s*SIG\s+SIGINFO\s*$")
                    else:
                        self.assertEqual(sigqueue, "(empty)")

        self._test_sig_drgn_option_common(cmd)
        for variable in ("sigqueue", "info", "pending_signo"):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)

        self.assertEqual(cmd.drgn_option.stdout, foreach_cmd.drgn_option.stdout)

    def test_thread_group(self):
        cmd = self.check_crash_command(f"sig -g {os.getpid()}")
        foreach_cmd = self.check_crash_command(
            f"foreach {os.getpid()} sig -g", mode="capture"
        )

        for c in (cmd, foreach_cmd):
            self.assertEqual(
                len(re.findall(r"^\s*PID:", c.stdout, flags=re.M)),
                len(os.listdir("/proc/self/task")) + 1,
            )

        self.assertIn("for_each_task_in_group(", cmd.drgn_option.stdout)
        self._test_sig_drgn_option_common(cmd)
        # We may not have any pending signals, so don't check for those variables.

        self.assertEqual(cmd.drgn_option.stdout, foreach_cmd.drgn_option.stdout)

    def test_list(self):
        cmd = self.check_crash_command("sig -l")
        self.assertRegex(cmd.stdout, r"(?m)^\s*\[9\] SIGKILL$")

        self.assertIn("signal_numbers(", cmd.drgn_option.stdout)
        self.assertIsInstance(cmd.drgn_option.globals["number"], int)
        self.assertIsInstance(cmd.drgn_option.globals["names"], list)
        self.assertIsInstance(cmd.drgn_option.globals["names"][0], str)

    def test_sigset(self):
        value = (1 << (signal.SIGHUP - 1)) | (1 << (signal.SIGTERM - 1))
        cmd = self.check_crash_command(f"sig -s {value:x}")
        self.assertEqual(cmd.stdout, "SIGHUP SIGTERM\n")
        self.assertIn("decode_sigset(0x", cmd.drgn_option.stdout)
        self.assertEqual(cmd.drgn_option.globals["decoded"], "{SIGHUP,SIGTERM}")


class TestWaitq(CrashCommandTestCase):
    @skip_unless_have_test_kmod
    def test_empty(self):
        cmd = self.check_crash_command("waitq drgn_test_empty_waitq")
        self.assertIn("is empty", cmd.stdout)
        self.assertIn("waitqueue_for_each_task(", cmd.drgn_option.stdout)

    @skip_unless_have_test_kmod
    def test_non_empty(self):
        cmd = self.check_crash_command("waitq drgn_test_waitq")
        self.assertIn('COMMAND: "drgn_test_', cmd.stdout)
        self.assertIn("waitqueue_for_each_task(", cmd.drgn_option.stdout)
        for variable in (
            "task",
            "pid",
            "command",
        ):
            self.assertIsInstance(cmd.drgn_option.globals[variable], Object)
        self.assertIsInstance(cmd.drgn_option.globals["cpu"], int)

    @skip_unless_have_test_kmod
    def test_empty_symbol(self):
        address = self.prog.symbol("drgn_test_empty_waitq").address
        cmd = self.check_crash_command(f"waitq {address:x}")
        self.assertIn("is empty", cmd.stdout)
        self.assertIn("waitqueue_for_each_task(", cmd.drgn_option.stdout)

    @skip_unless_have_test_kmod
    def test_struct(self):
        address = self.prog.symbol("drgn_test_waitq_container").address
        cmd = self.check_crash_command(
            f"waitq drgn_test_waitq_container_struct.waitq {address:x}"
        )
        self.assertIn("is empty", cmd.stdout)
        self.assertIn("waitqueue_for_each_task(", cmd.drgn_option.stdout)

    def test_no_arguments(self):
        self.assertRaisesRegex(
            CommandArgumentError,
            "is required",
            self.run_crash_command,
            "waitq",
        )

    def test_too_many_arguments(self):
        self.assertRaisesRegex(
            CommandArgumentError,
            "unrecognized",
            self.run_crash_command,
            "waitq foo.bar abcd1234 baz",
        )
