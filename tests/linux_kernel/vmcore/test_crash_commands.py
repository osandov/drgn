# Copyright (c) 2026 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

from _drgn_util.platform import NORMALIZED_MACHINE_NAME
import drgn.commands._builtin  # noqa  # needed to register crash commands
from drgn.helpers.linux.cpumask import for_each_online_cpu
from tests.linux_kernel import skip_unless_have_stack_tracing
from tests.linux_kernel.vmcore import LinuxVMCoreCrashCommandTestCase


@skip_unless_have_stack_tracing
class TestBtVMCore(LinuxVMCoreCrashCommandTestCase):
    # When CPU 0 panics on s390x, the kernel switches to a different stack that
    # we don't know how to unwind through. This is a bug. For now,
    # vmtest.enter_kdump tries to avoid this so we can get some test coverage,
    # and we skip the tests otherwise.
    def _skip_if_cpu0_on_s390x(self):
        if NORMALIZED_MACHINE_NAME == "s390x" and self.prog["panic_cpu"].counter == 0:
            self.skipTest("drgn can't unwind s390x panic stack on CPU 0")

    def test_cpu(self):
        self._skip_if_cpu0_on_s390x()
        cmd = self.check_crash_command("bt -c 0")
        self.assertIn("CPU: 0", cmd.stdout)
        self.assertNotIn("(active)", cmd.stdout)

    def test_panic(self):
        self._skip_if_cpu0_on_s390x()
        tid = self.prog.crashed_thread().tid
        for cmd in ("bt", "bt -p"):
            with self.subTest(cmd=cmd):
                res = self.check_crash_command(cmd)
                self.assertIn("drgn_test_crash_func", res.stdout)
                self.assertIn(f"PID: {tid}", res.stdout)
                self.assertNotIn("(active)", res.stdout)

    def test_all(self):
        self._skip_if_cpu0_on_s390x()
        cmd = self.check_crash_command("bt -a")
        self.assertNotIn("(active)", cmd.stdout)
        for cpu in for_each_online_cpu(self.prog):
            self.assertIn(f"CPU: {cpu}", cmd.stdout)
