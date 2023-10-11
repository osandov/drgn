# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
from pathlib import Path
import unittest

from drgn import Object, Program
from tests import modifyenv
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod

KALLSYMS_PATH = Path("/proc/kallsyms")


@unittest.skipUnless(
    KALLSYMS_PATH.exists(), "kernel does not have kallsyms (CONFIG_KALLSYMS)"
)
@skip_unless_have_test_kmod
class TestModuleDebugInfo(LinuxKernelTestCase):
    # Arbitrary symbol that we can use to check that the module debug info was
    # loaded.
    SYMBOL = "drgn_test_function"

    def setUp(self):
        super().setUp()
        with KALLSYMS_PATH.open() as f:
            for line in f:
                tokens = line.split()
                if tokens[2] == self.SYMBOL:
                    self.symbol_address = int(tokens[0], 16)
                    break
            else:
                self.fail(f"{self.SYMBOL!r} symbol not found")

    def _test_module_debug_info(self, use_sys_module):
        old_use_sys_module = int(os.environ.get("DRGN_USE_SYS_MODULE", "1")) != 0
        with modifyenv({"DRGN_USE_SYS_MODULE": "1" if use_sys_module else "0"}):
            if old_use_sys_module == use_sys_module:
                prog = self.prog
            else:
                prog = Program()
                prog.set_kernel()
                self._load_debug_info(prog)
            self.assertEqual(prog.symbol(self.SYMBOL).address, self.symbol_address)

    def test_module_debug_info_use_proc_and_sys(self):
        self._test_module_debug_info(True)

    def test_module_debug_info_use_core_dump(self):
        self._test_module_debug_info(False)


class TestLinuxKernelObjectFinder(LinuxKernelTestCase):
    def test_jiffies(self):
        self.assertIdentical(
            self.prog["jiffies"],
            Object(
                self.prog,
                "volatile unsigned long",
                address=self.prog.symbol("jiffies").address,
            ),
        )
