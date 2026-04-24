# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import copy

from drgn import Architecture, Platform, Program, RegisterState
from tests import IntWrapper, TestCase


class TestRegisterState(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.prog = Program(platform=Platform(Architecture.X86_64))

    def test_new(self):
        regs = RegisterState(self.prog, False)
        self.assertIs(regs.prog, self.prog)
        self.assertFalse(regs.interrupted)

    def test_no_platform(self):
        self.assertRaises(ValueError, RegisterState, Program(), False)

    def test_interrupted(self):
        regs = RegisterState(self.prog, True)
        self.assertTrue(regs.interrupted)
        regs.interrupted = False
        self.assertFalse(regs.interrupted)

    def test_pc(self):
        regs = RegisterState(self.prog, False)
        self.assertIsNone(regs.pc)

        regs.pc = 0x1234
        self.assertEqual(regs.pc, 0x1234)

        regs.pc = None
        self.assertIsNone(regs.pc)

    def test_cfa(self):
        regs = RegisterState(self.prog, False)
        self.assertIsNone(regs.cfa)

        regs.cfa = 0x1234
        self.assertEqual(regs.cfa, 0x1234)

        regs.cfa = None
        self.assertIsNone(regs.cfa)

    def test_get_set(self):
        regs = RegisterState(self.prog, False)
        self.assertIsNone(regs.get("rax"))
        self.assertIsNone(regs.get(self.prog.platform.register("rax")))
        self.assertFalse(regs.is_set("rax"))

        regs.set("rax", 1234)
        self.assertEqual(regs.get("rax"), 1234)
        self.assertEqual(regs.get(self.prog.platform.register("rax")), 1234)
        self.assertTrue(regs.is_set("rax"))

        regs.set(self.prog.platform.register("rax"), 5678)
        self.assertEqual(regs.get("rax"), 5678)

    def test_get_set_raw(self):
        regs = RegisterState(self.prog, False)
        self.assertIsNone(regs.get_raw("rax"))
        self.assertIsNone(regs.get_raw(self.prog.platform.register("rax")))

        regs.set_raw("rax", b"\x04\x03\x02\x01\x00\x00\x00\x00")
        self.assertEqual(regs.get_raw("rax"), b"\x04\x03\x02\x01\x00\x00\x00\x00")
        self.assertEqual(
            regs.get_raw(self.prog.platform.register("rax")),
            b"\x04\x03\x02\x01\x00\x00\x00\x00",
        )
        self.assertEqual(regs.get("rax"), 0x01020304)
        self.assertTrue(regs.is_set("rax"))

        regs.set_raw(
            self.prog.platform.register("rax"), b"\x08\x07\x06\x05\x00\x00\x00\x00"
        )
        self.assertEqual(regs.get_raw("rax"), b"\x08\x07\x06\x05\x00\x00\x00\x00")

    def test_unknown_register(self):
        regs = RegisterState(self.prog, False)
        self.assertRaises(ValueError, regs.is_set, "foo")
        self.assertRaises(ValueError, regs.get, "foo")
        self.assertRaises(ValueError, regs.get_raw, "foo")
        self.assertRaises(ValueError, regs.set, "foo", 1)
        self.assertRaises(ValueError, regs.set_raw, "foo", b"")

    def test_wrong_register_type(self):
        regs = RegisterState(self.prog, False)
        self.assertRaises(TypeError, regs.is_set, 1)
        self.assertRaises(TypeError, regs.get, 1)
        self.assertRaises(TypeError, regs.get_raw, 1)
        self.assertRaises(TypeError, regs.set, 1, 1)
        self.assertRaises(TypeError, regs.set_raw, 1, b"")

    def test_wrong_register_architecture(self):
        regs = RegisterState(self.prog, False)
        reg = Platform(Architecture.S390X).register("r0")
        self.assertFalse(regs.is_set(reg))
        self.assertIsNone(regs.get(reg))
        self.assertIsNone(regs.get_raw(reg))
        self.assertRaises(ValueError, regs.set, reg, 1)
        self.assertRaises(ValueError, regs.set_raw, reg, b"")

    def test_set_negative(self):
        regs = RegisterState(self.prog, False)
        regs.set("rax", -2)
        self.assertEqual(regs.get("rax"), 0xFFFFFFFFFFFFFFFE)

    def test_set_truncate(self):
        regs = RegisterState(self.prog, False)
        regs.set("rax", 20000000000000000000)
        self.assertEqual(regs.get("rax"), 1553255926290448384)

    def test_set_index(self):
        regs = RegisterState(self.prog, False)
        regs.set("rax", IntWrapper(1234))
        self.assertEqual(regs.get("rax"), 1234)

    def test_set_raw_wrong_size(self):
        regs = RegisterState(self.prog, False)
        self.assertRaises(ValueError, regs.set_raw, "rax", bytes(4))
        self.assertRaises(ValueError, regs.set_raw, "rax", bytes(16))

    def test_unset(self):
        regs = RegisterState(self.prog, False)

        regs.unset("rax")
        self.assertIsNone(regs.get("rax"))

        regs.set("rax", 1234)
        self.assertEqual(regs.get("rax"), 1234)

        regs.unset("rax")
        self.assertIsNone(regs.get("rax"))

        regs.set("rax", 1234)
        regs.unset(self.prog.platform.register("rax"))
        self.assertIsNone(regs.get("rax"))

    def test_str(self):
        regs = RegisterState(self.prog, False)
        regs.set("rax", 12345678)
        self.assertRegex(str(regs), r"rax\s+0x0000000000bc614e")

    def test_str_big_endian(self):
        regs = RegisterState(Program(platform=Platform(Architecture.S390X)), False)
        regs.set("r0", 12345678)
        self.assertRegex(str(regs), r"r0\s+0x0000000000bc614e")

    def test_str_interrupted(self):
        regs = RegisterState(self.prog, True)
        self.assertIn("(interrupted)", str(regs))
        regs.pc = 0x1234
        self.assertIn("(interrupted)", str(regs))

    def test_copy(self):
        regs = RegisterState(self.prog, False)
        regs.set("rax", 12345678)

        copied = regs.copy()
        self.assertEqual(copied.get("rax"), 12345678)

        regs.set("rax", 0)
        self.assertEqual(copied.get("rax"), 12345678)

        copied.set("rax", 1)
        self.assertEqual(regs.get("rax"), 0)

    def test_copy_lib(self):
        regs = RegisterState(self.prog, False)
        regs.set("rax", 12345678)

        copied = copy.copy(regs)
        self.assertEqual(copied.get("rax"), 12345678)

        regs.set("rax", 0)
        self.assertEqual(copied.get("rax"), 12345678)

        copied.set("rax", 1)
        self.assertEqual(regs.get("rax"), 0)

    def test_deepcopy(self):
        regs = RegisterState(self.prog, False)
        regs.set("rax", 12345678)

        copied = copy.deepcopy([regs])[0]
        self.assertEqual(copied.get("rax"), 12345678)

        regs.set("rax", 0)
        self.assertEqual(copied.get("rax"), 12345678)

        copied.set("rax", 1)
        self.assertEqual(regs.get("rax"), 0)
