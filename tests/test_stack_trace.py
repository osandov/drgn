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
