# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import random
import unittest

from _drgn_util.platform import NORMALIZED_MACHINE_NAME
from drgn import FaultError, Object
from drgn.helpers.experimental.kmodify import (
    call_function,
    pass_pointer,
    write_memory,
    write_object,
)
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod

skip_unless_have_kmodify = unittest.skipUnless(
    NORMALIZED_MACHINE_NAME == "x86_64",
    f"kmodify is not implemented for {NORMALIZED_MACHINE_NAME}",
)


@skip_unless_have_test_kmod
@skip_unless_have_kmodify
class TestCallFunction(LinuxKernelTestCase):
    def assert_called(self, name, args, expected_return_value=None):
        if expected_return_value is None:
            expected_return_value = Object(self.prog, "void")
        before = self.prog[f"drgn_kmodify_test_{name}_called"].read_()
        return_value = call_function(self.prog["drgn_kmodify_test_" + name], *args)
        self.assertEqual(
            self.prog[f"drgn_kmodify_test_{name}_called"].read_(),
            before + 1,
        )
        self.assertIdentical(return_value, expected_return_value)

    def assert_returns(self, name, expected_return_value):
        self.assert_called(name, (), expected_return_value)

    def test_void_return(self):
        self.assert_returns("void_return", Object(self.prog, "void"))

    def test_integer_returns(self):
        for name, return_value in (
            ("signed_char", Object(self.prog, "signed char", -66)),
            ("unsigned_char", Object(self.prog, "unsigned char", 200)),
            ("short", Object(self.prog, "short", -666)),
            ("unsigned_short", Object(self.prog, "unsigned short", 7777)),
            ("int", Object(self.prog, "int", -12345)),
            ("unsigned_int", Object(self.prog, "unsigned int", 54321)),
            ("long", Object(self.prog, "long", -2468013579)),
            ("unsigned_long", Object(self.prog, "unsigned long", 4000000000)),
            ("long_long", Object(self.prog, "long long", -9080706050403020100)),
            (
                "unsigned_long_long",
                Object(self.prog, "unsigned long long", 12345678909876543210),
            ),
        ):
            with self.subTest(name=name):
                self.assert_returns(name + "_return", return_value)

    def test_integer_args(self):
        self.assert_called(
            "signed_args",
            (
                Object(self.prog, "signed char", -66),
                Object(self.prog, "short", -666),
                Object(self.prog, "int", -12345),
                Object(self.prog, "long", -2468013579),
                Object(self.prog, "long long", -9080706050403020100),
            ),
        )
        self.assert_called(
            "unsigned_args",
            (
                Object(self.prog, "unsigned char", 200),
                Object(self.prog, "unsigned short", 7777),
                Object(self.prog, "unsigned int", 54321),
                Object(self.prog, "unsigned long", 4000000000),
                Object(self.prog, "unsigned long long", 12345678909876543210),
            ),
        )

    def test_integer_literal_args(self):
        self.assert_called(
            "signed_args",
            (
                -66,
                -666,
                -12345,
                -2468013579,
                -9080706050403020100,
            ),
        )
        self.assert_called(
            "unsigned_args",
            (
                200,
                7777,
                54321,
                4000000000,
                12345678909876543210,
            ),
        )

    def test_many_args(self):
        self.assert_called(
            "many_args",
            (
                48,
                -66,
                -666,
                -12345,
                -2468013579,
                -9080706050403020100,
                200,
                7777,
                54321,
                4000000000,
                12345678909876543210,
            ),
        )

    def test_enum_returns(self):
        self.assert_returns(
            "enum_return", Object(self.prog, "enum drgn_kmodify_enum", 2)
        )

    def test_enum_args(self):
        args = (
            self.prog["DRGN_KMODIFY_ONE"],
            pass_pointer(Object(self.prog, "enum drgn_kmodify_enum", 2)),
        )
        self.assert_called("enum_args", args)
        self.assertIdentical(
            args[1].object, Object(self.prog, "enum drgn_kmodify_enum", 3)
        )

    def test_pointer_returns(self):
        self.assert_returns(
            "pointer_return", self.prog["drgn_kmodify_test_ptr"].read_()
        )

    def test_pointer_args(self):
        self.assert_called(
            "pointer_args", (self.prog["drgn_kmodify_test_ptr"].read_(),)
        )

    def test_string_args(self):
        for msg, f in (
            ("str", lambda t, s: s),
            ("bytes", lambda t, s: s.encode()),
            (
                "array",
                lambda t, s: Object(
                    self.prog,
                    self.prog.array_type(self.prog.type(t), len(s) + 1),
                    s.encode(),
                ),
            ),
            ("str pointer", lambda t, s: pass_pointer(s)),
            ("bytes pointer", lambda t, s: pass_pointer(s.encode())),
            (
                "array pointer",
                lambda t, s: pass_pointer(
                    Object(
                        self.prog,
                        self.prog.array_type(self.prog.type(t), len(s) + 1),
                        s.encode(),
                    )
                ),
            ),
            (
                "pointer",
                lambda t, s: self.prog[f"drgn_kmodify_test_{t.replace(' ', '_')}_str"],
            ),
        ):
            with self.subTest(msg):
                self.assert_called(
                    "string_args",
                    (
                        f("char", "Hello"),
                        f("signed char", ", "),
                        f("unsigned char", "world"),
                        f("const char", "!"),
                    ),
                )

    def test_integer_out_params(self):
        args = [
            pass_pointer(Object(self.prog, "signed char", -66)),
            pass_pointer(Object(self.prog, "short", -666)),
            pass_pointer(-12345),
            pass_pointer(Object(self.prog, "long", -2468013579)),
            pass_pointer(Object(self.prog, "long long", -9080706050403020100)),
        ]
        self.assert_called("integer_out_params", args)
        self.assertIdentical(
            [ptr.object for ptr in args],
            [
                Object(self.prog, "signed char", 33),
                Object(self.prog, "short", 333),
                Object(self.prog, "int", 23456),
                Object(self.prog, "long", 2222222222),
                Object(self.prog, "long long", 9090909090909090909),
            ],
        )

    def test_array_out_params(self):
        arg = pass_pointer(Object(self.prog, "long [3]", [1, 2, 3]))
        self.assert_called("array_out_params", (arg,))
        self.assertIdentical(arg.object, Object(self.prog, "long [3]", [2, 3, 5]))

    def test_array_out_params_extra(self):
        arg = pass_pointer(Object(self.prog, "long [4]", [1, 2, 3, 100]))
        self.assert_called("array_out_params", (arg,))
        self.assertIdentical(arg.object, Object(self.prog, "long [4]", [2, 3, 5, 100]))

    def test_array_out_params_inferred(self):
        self.assert_called(
            "array_out_params", (Object(self.prog, "long [3]", [1, 2, 3]),)
        )

    def test_many_out_params(self):
        args = [
            pass_pointer(Object(self.prog, "char", 48)),
            pass_pointer(Object(self.prog, "signed char", -66)),
            pass_pointer(Object(self.prog, "short", -666)),
            pass_pointer(Object(self.prog, "int", -12345)),
            pass_pointer(Object(self.prog, "long", -2468013579)),
            pass_pointer(Object(self.prog, "long long", -9080706050403020100)),
            pass_pointer(Object(self.prog, "unsigned char", 200)),
            pass_pointer(Object(self.prog, "unsigned short", 7777)),
            pass_pointer(Object(self.prog, "unsigned int", 54321)),
            pass_pointer(Object(self.prog, "unsigned long", 4000000000)),
            pass_pointer(Object(self.prog, "unsigned long long", 12345678909876543210)),
        ]
        self.assert_called("many_out_params", args)
        self.assertIdentical(
            [arg.object for arg in args],
            [
                Object(self.prog, "char", 16),
                Object(self.prog, "signed char", -22),
                Object(self.prog, "short", -222),
                Object(self.prog, "int", -4115),
                Object(self.prog, "long", -822671193),
                Object(self.prog, "long long", -3026902016801006700),
                Object(self.prog, "unsigned char", 66),
                Object(self.prog, "unsigned short", 2592),
                Object(self.prog, "unsigned int", 18107),
                Object(self.prog, "unsigned long", 1333333333),
                Object(self.prog, "unsigned long long", 4115226303292181070),
            ],
        )


@skip_unless_have_test_kmod
@skip_unless_have_kmodify
class TestWriteMemory(LinuxKernelTestCase):
    def test_write_memory(self):
        buf = os.urandom(16)
        write_memory(self.prog, self.prog["drgn_kmodify_test_memory"].address_, buf)
        self.assertEqual(
            self.prog.read(self.prog["drgn_kmodify_test_memory"].address_, len(buf)),
            buf,
        )

    def test_fault(self):
        self.assertRaises(FaultError, write_memory, self.prog, 0, b"asdf")


@skip_unless_have_test_kmod
@skip_unless_have_kmodify
class TestWriteObject(LinuxKernelTestCase):
    def test_python_value(self):
        value = random.randrange(2**31)
        write_object(self.prog["drgn_kmodify_test_int"], value)
        self.assertEqual(self.prog["drgn_kmodify_test_int"].value_(), value)

    def test_object_value(self):
        value = random.randrange(2**31)
        write_object(
            self.prog["drgn_kmodify_test_int"], Object(self.prog, "long", value)
        )
        self.assertEqual(self.prog["drgn_kmodify_test_int"].value_(), value)

    def test_pointer_dereference(self):
        value = random.randrange(2**31)
        write_object(
            self.prog["drgn_kmodify_test_int"].address_of_(), value, dereference=True
        )
        self.assertEqual(self.prog["drgn_kmodify_test_int"].value_(), value)

    def test_pointer_no_dereference(self):
        write_object(
            self.prog["drgn_kmodify_test_int_ptr"],
            self.prog["drgn_kmodify_test_int"].address_of_(),
            dereference=False,
        )
        self.assertEqual(
            self.prog["drgn_kmodify_test_int_ptr"],
            self.prog["drgn_kmodify_test_int"].address_of_(),
        )
        write_object(self.prog["drgn_kmodify_test_int_ptr"], 0, dereference=False)
        self.assertEqual(self.prog["drgn_kmodify_test_int_ptr"].value_(), 0)

    def test_pointer_ambiguous(self):
        self.assertRaisesRegex(
            TypeError,
            "use dereference",
            write_object,
            self.prog["drgn_kmodify_test_int_ptr"],
            0,
        )

    def test_not_pointer(self):
        self.assertRaisesRegex(
            TypeError,
            "not a pointer",
            write_object,
            self.prog["drgn_kmodify_test_int"],
            0,
            dereference=True,
        )
