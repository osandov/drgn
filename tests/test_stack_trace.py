# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn import Program
from tests import TestCase
from tests.resources import get_resource


class TestLinuxUserspaceCoreDump(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prog = Program()
        cls.prog.set_enabled_debug_info_finders([])
        cls.prog.set_core_dump(get_resource("crashme.core"))
        cls.prog.load_debug_info([get_resource("crashme"), get_resource("crashme.so")])
        cls.trace = cls.prog.crashed_thread().stack_trace()

    @classmethod
    def tearDownClass(cls):
        del cls.trace
        del cls.prog

    def test_stack_frame_name(self):
        self.assertEqual(self.trace[0].name, "c")
        self.assertEqual(self.trace[5].name, "0x7f6112ad8088")
        self.assertEqual(self.trace[7].name, "_start")
        self.assertEqual(self.trace[8].name, "???")

    def test_stack_frame_function_name(self):
        self.assertEqual(self.trace[0].function_name, "c")
        self.assertIsNone(self.trace[5].function_name)
        self.assertIsNone(self.trace[7].function_name)
        self.assertIsNone(self.trace[8].function_name)

    def test_register_state(self):
        regs = self.trace[0].register_state()

        # Shouldn't be able to modify it.
        self.assertRaises(ValueError, setattr, regs, "interrupted", False)
        self.assertRaises(ValueError, setattr, regs, "pc", 0)
        self.assertRaises(ValueError, setattr, regs, "pc", None)
        self.assertRaises(ValueError, setattr, regs, "cfa", 0)
        self.assertRaises(ValueError, setattr, regs, "cfa", None)
        self.assertRaises(ValueError, regs.set, "rax", 0)
        self.assertRaises(ValueError, regs.set_raw, "rax", bytes(8))
        self.assertRaises(ValueError, regs.unset, "rax")

        # Should be able to modify a copy.
        copied = regs.copy()
        copied.set("rax", 0)
        self.assertEqual(copied.get("rax"), 0)
