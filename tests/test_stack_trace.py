# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import struct

from drgn import Architecture, Object, Platform, PlatformFlags, Program
from tests import MockMemorySegment, TestCase, mock_program
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

    def test_stack_frame_contains(self):
        self.assertIn("cm", self.trace[0])
        self.assertNotIn("foo", self.trace[0])
        self.assertNotIn(1, self.trace[0])
        # Make sure that calling the method directly also works.
        self.assertIs(self.trace[0].__contains__("cm"), True)
        self.assertIs(self.trace[0].__contains__("foo"), False)
        self.assertIs(self.trace[0].__contains__(1), False)

    def test_stack_trace_type_error(self):
        self.assertRaises(
            TypeError,
            self.prog.stack_trace,
            Object(self.prog, self.prog.void_type(), address=0),
        )
        self.assertRaises(
            TypeError,
            self.prog.stack_trace,
            Object(self.prog, self.prog.pointer_type(self.prog.void_type()), 0),
        )
        self.assertRaises(
            TypeError,
            self.prog.stack_trace,
            Object(self.prog, self.prog.struct_type(None), address=0),
        )
        self.assertRaises(
            TypeError,
            self.prog.stack_trace,
            Object(self.prog, self.prog.pointer_type(self.prog.struct_type(None)), 0),
        )


class TestAarch64StackTrace(TestCase):
    def test_userspace_pac(self):
        pac_mask = 0x007F000000000000
        pac = 0x0055000000000000
        pcs = [0x400100, 0x400200, 0x400300]
        stack_address = 0xFFFF0000
        stack = struct.pack(
            "<6Q",
            stack_address + 16,
            pcs[1] | pac,
            stack_address + 32,
            pcs[2] | pac,
            0,
            pcs[2] | pac,
        )
        prog = mock_program(
            Platform(
                Architecture.AARCH64,
                PlatformFlags.IS_64_BIT | PlatformFlags.IS_LITTLE_ENDIAN,
            ),
            segments=[MockMemorySegment(stack, stack_address)],
        )
        prog.set_userspace_custom(aarch64_insn_pac_mask=pac_mask)

        # Aarch64 pt_regs starts with x0-x30, sp, pc, and pstate.
        regs = Object.from_bytes_(
            prog,
            prog.struct_type("pt_regs", 34 * 8, ()),
            struct.pack(
                "<34Q",
                *([0] * 29),
                stack_address,
                pcs[1] | pac,
                stack_address,
                pcs[0],
                0,
            ),
        )
        self.assertEqual([frame.pc for frame in prog.stack_trace(regs)], pcs)


class TestStackTraceFromPcs(TestCase):
    def test_no_platform(self):
        self.assertRaises(ValueError, Program().stack_trace_from_pcs, [0xDEADBEEF])

    def test_unknown_platform(self):
        self.assertRaises(
            NotImplementedError,
            Program(
                Platform(
                    Architecture.UNKNOWN,
                    PlatformFlags.IS_64_BIT | PlatformFlags.IS_LITTLE_ENDIAN,
                )
            ).stack_trace_from_pcs,
            [0xDEADBEEF],
        )
