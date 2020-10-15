# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

import os

import drgn
from tests.helpers.linux import LinuxHelperTestCase


class TestDebugInfo(LinuxHelperTestCase):
    def test_module_debug_info(self):
        with open("/proc/modules", "r") as f:
            for line in f:
                if line.startswith("loop "):
                    break
            else:
                self.skipTest("loop module is built in or not loaded")

        # An arbitrary symbol that we can use to check that the module debug
        # info was loaded.
        with open("/proc/kallsyms", "r") as f:
            for line in f:
                tokens = line.split()
                if tokens[2] == "loop_register_transfer":
                    address = int(tokens[0], 16)
                    break
            else:
                self.skipTest("loop_register_transfer symbol not found")

        # Test with and without using /proc and /sys.
        key = "DRGN_USE_PROC_AND_SYS_MODULES"
        old_value = os.environ.get(key)
        if old_value is None or int(old_value):
            new_value = "0"
        else:
            new_value = "1"
        try:
            os.environ[key] = new_value
            other_prog = drgn.Program()
            other_prog.set_kernel()
            other_prog.load_default_debug_info()

            for prog in (self.prog, other_prog):
                self.assertEqual(prog.symbol("loop_register_transfer").address, address)
        finally:
            if old_value is None:
                del os.environ[key]
            else:
                os.environ[key] = old_value
