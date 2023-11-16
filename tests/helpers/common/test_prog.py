# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import inspect
import unittest.mock

from drgn import NoDefaultProgramError, Object, get_default_prog, set_default_prog
from drgn.helpers.common.prog import (
    takes_object_or_program_or_default,
    takes_program_or_default,
)
from tests import IdenticalMatcher, TestCase, mock_program


def my_create_autospec(f):
    mock = unittest.mock.create_autospec(f)
    # unittest.mock.create_autospec() does this automatically since CPython
    # commit f7fa62ef4422 ("bpo-17185: Add __signature__ to mock that can be
    # used by inspect for signature (GH11048)") (in v3.8).
    mock.__signature__ = inspect.signature(f)
    return mock


@contextlib.contextmanager
def mock_default_prog():
    try:
        old_default_prog = get_default_prog()
    except NoDefaultProgramError:
        old_default_prog = None
    prog = mock_program()
    try:
        set_default_prog(prog)
        yield prog
    finally:
        set_default_prog(old_default_prog)


class TestTakesProgramOrDefault(TestCase):
    def setUp(self):
        def f1(prog):
            pass

        self.mock1 = my_create_autospec(f1)

        def f2(prog, x):
            pass

        self.mock2 = my_create_autospec(f2)

        def f3(prog, x, s):
            pass

        self.mock3 = my_create_autospec(f3)

    def test_explicit_prog_no_args(self):
        prog = mock_program()
        takes_program_or_default(self.mock1)(prog)
        self.mock1.assert_called_once_with(prog)

    def test_explicit_prog_kwarg_no_args(self):
        prog = mock_program()
        takes_program_or_default(self.mock1)(prog=prog)
        self.mock1.assert_called_once_with(prog=prog)

    def test_default_prog_no_args(self):
        with mock_default_prog() as prog:
            takes_program_or_default(self.mock1)()
            self.mock1.assert_called_once_with(prog)

    def test_explicit_prog_one_arg(self):
        prog = mock_program()
        takes_program_or_default(self.mock2)(prog, 1)
        self.mock2.assert_called_once_with(prog, 1)

    def test_explicit_prog_one_kwarg(self):
        prog = mock_program()
        takes_program_or_default(self.mock2)(prog, x=1)
        self.mock2.assert_called_once_with(prog, x=1)

    def test_explicit_prog_kwarg_one_kwarg(self):
        prog = mock_program()
        takes_program_or_default(self.mock2)(prog=prog, x=1)
        self.mock2.assert_called_once_with(prog=prog, x=1)

    def test_object_prog_one_arg(self):
        prog = mock_program()
        takes_program_or_default(self.mock2)(Object(prog, "int", 1))
        self.mock2.assert_called_once_with(
            prog, IdenticalMatcher(Object(prog, "int", 1))
        )

    def test_object_prog_one_kwarg(self):
        prog = mock_program()
        takes_program_or_default(self.mock2)(x=Object(prog, "int", 1))
        self.mock2.assert_called_once_with(
            prog, x=IdenticalMatcher(Object(prog, "int", 1))
        )

    def test_default_prog_one_arg(self):
        with mock_default_prog() as prog:
            takes_program_or_default(self.mock2)(1)
            self.mock2.assert_called_once_with(prog, 1)

    def test_default_prog_one_kwarg(self):
        with mock_default_prog() as prog:
            takes_program_or_default(self.mock2)(x=1)
            self.mock2.assert_called_once_with(prog, x=1)

    def test_explicit_prog_two_args(self):
        prog = mock_program()
        takes_program_or_default(self.mock3)(prog, 1, "foo")
        self.mock3.assert_called_once_with(prog, 1, "foo")

    def test_explicit_prog_one_arg_one_kwarg(self):
        prog = mock_program()
        takes_program_or_default(self.mock3)(prog, 1, s="foo")
        self.mock3.assert_called_once_with(prog, 1, s="foo")

    def test_explicit_prog_two_kwargs(self):
        prog = mock_program()
        takes_program_or_default(self.mock3)(prog, x=1, s="foo")
        self.mock3.assert_called_once_with(prog, x=1, s="foo")

    def test_explicit_prog_kwarg_two_kwargs(self):
        prog = mock_program()
        takes_program_or_default(self.mock3)(prog=prog, x=1, s="foo")
        self.mock3.assert_called_once_with(prog=prog, x=1, s="foo")

    def test_object_prog_two_args(self):
        prog = mock_program()
        takes_program_or_default(self.mock3)(Object(prog, "int", 2), "foo")
        self.mock3.assert_called_once_with(
            prog, IdenticalMatcher(Object(prog, "int", 2)), "foo"
        )

    def test_object_prog_one_arg_one_kwarg(self):
        prog = mock_program()
        takes_program_or_default(self.mock3)(Object(prog, "int", 2), s="foo")
        self.mock3.assert_called_once_with(
            prog, IdenticalMatcher(Object(prog, "int", 2)), s="foo"
        )

    def test_object_prog_two_kwargs(self):
        prog = mock_program()
        takes_program_or_default(self.mock3)(x=Object(prog, "int", 2), s="foo")
        self.mock3.assert_called_once_with(
            prog, x=IdenticalMatcher(Object(prog, "int", 2)), s="foo"
        )

    def test_default_prog_two_args(self):
        with mock_default_prog() as prog:
            takes_program_or_default(self.mock3)(2, "foo")
            self.mock3.assert_called_once_with(prog, 2, "foo")

    def test_default_prog_one_arg_one_kwarg(self):
        with mock_default_prog() as prog:
            takes_program_or_default(self.mock3)(2, s="foo")
            self.mock3.assert_called_once_with(prog, 2, s="foo")

    def test_default_prog_two_kwargs(self):
        with mock_default_prog() as prog:
            takes_program_or_default(self.mock3)(x=2, s="foo")
            self.mock3.assert_called_once_with(prog, x=2, s="foo")


class TestTakesObjectOrProgramOrDefault(TestCase):
    def setUp(self):
        def f1(prog, obj):
            pass

        self.mock1 = my_create_autospec(f1)

        def f2(prog, obj, x):
            pass

        self.mock2 = my_create_autospec(f2)

        def f3(prog, obj, x, s):
            pass

        self.mock3 = my_create_autospec(f3)

    def test_explicit_prog_no_args(self):
        prog = mock_program()
        takes_object_or_program_or_default(self.mock1)(prog)
        self.mock1.assert_called_once_with(prog, None)

    def test_explicit_prog_kwarg_no_args(self):
        prog = mock_program()
        takes_object_or_program_or_default(self.mock1)(prog=prog)
        self.mock1.assert_called_once_with(prog=prog, obj=None)

    def test_obj_no_args(self):
        prog = mock_program()
        takes_object_or_program_or_default(self.mock1)(Object(prog, "int", 1))
        self.mock1.assert_called_once_with(
            prog, IdenticalMatcher(Object(prog, "int", 1))
        )

    def test_obj_kwarg_no_args(self):
        prog = mock_program()
        takes_object_or_program_or_default(self.mock1)(obj=Object(prog, "int", 1))
        self.mock1.assert_called_once_with(
            prog, obj=IdenticalMatcher(Object(prog, "int", 1))
        )

    def test_default_prog_no_args(self):
        with mock_default_prog() as prog:
            takes_object_or_program_or_default(self.mock1)()
            self.mock1.assert_called_once_with(prog, None)

    def test_explicit_prog_one_arg(self):
        prog = mock_program()
        takes_object_or_program_or_default(self.mock2)(prog, 1)
        self.mock2.assert_called_once_with(prog, None, 1)

    def test_explicit_prog_one_kwarg(self):
        prog = mock_program()
        takes_object_or_program_or_default(self.mock2)(prog, x=1)
        self.mock2.assert_called_once_with(prog, None, x=1)

    def test_explicit_prog_kwarg_one_kwarg(self):
        prog = mock_program()
        takes_object_or_program_or_default(self.mock2)(prog=prog, x=1)
        self.mock2.assert_called_once_with(prog=prog, obj=None, x=1)

    def test_obj_one_arg(self):
        prog = mock_program()
        takes_object_or_program_or_default(self.mock2)(Object(prog, "int", 1), 2)
        self.mock2.assert_called_once_with(
            prog, IdenticalMatcher(Object(prog, "int", 1)), 2
        )

    def test_obj_one_kwarg(self):
        prog = mock_program()
        takes_object_or_program_or_default(self.mock2)(Object(prog, "int", 1), x=2)
        self.mock2.assert_called_once_with(
            prog, IdenticalMatcher(Object(prog, "int", 1)), x=2
        )

    def test_obj_kwarg_one_kwarg(self):
        prog = mock_program()
        takes_object_or_program_or_default(self.mock2)(obj=Object(prog, "int", 1), x=2)
        self.mock2.assert_called_once_with(
            prog, obj=IdenticalMatcher(Object(prog, "int", 1)), x=2
        )

    def test_object_prog_one_arg(self):
        prog = mock_program()
        takes_object_or_program_or_default(self.mock2)(Object(prog, "int", 2))
        self.mock2.assert_called_once_with(
            prog, None, IdenticalMatcher(Object(prog, "int", 2))
        )

    def test_object_prog_one_kwarg(self):
        prog = mock_program()
        takes_object_or_program_or_default(self.mock2)(x=Object(prog, "int", 2))
        self.mock2.assert_called_once_with(
            prog, None, x=IdenticalMatcher(Object(prog, "int", 2))
        )

    def test_default_prog_one_arg(self):
        with mock_default_prog() as prog:
            takes_object_or_program_or_default(self.mock2)(2)
            self.mock2.assert_called_once_with(prog, None, 2)

    def test_default_prog_one_kwarg(self):
        with mock_default_prog() as prog:
            takes_object_or_program_or_default(self.mock2)(x=2)
            self.mock2.assert_called_once_with(prog, None, x=2)

    def test_explicit_prog_two_args(self):
        prog = mock_program()
        takes_object_or_program_or_default(self.mock3)(prog, 1, "foo")
        self.mock3.assert_called_once_with(prog, None, 1, "foo")

    def test_explicit_prog_one_arg_one_kwarg(self):
        prog = mock_program()
        takes_object_or_program_or_default(self.mock3)(prog, 1, s="foo")
        self.mock3.assert_called_once_with(prog, None, 1, s="foo")

    def test_explicit_prog_two_kwargs(self):
        prog = mock_program()
        takes_object_or_program_or_default(self.mock3)(prog, x=1, s="foo")
        self.mock3.assert_called_once_with(prog, None, x=1, s="foo")

    def test_explicit_prog_kwarg_two_kwargs(self):
        prog = mock_program()
        takes_object_or_program_or_default(self.mock3)(prog=prog, x=1, s="foo")
        self.mock3.assert_called_once_with(prog=prog, obj=None, x=1, s="foo")

    def test_obj_two_args(self):
        prog = mock_program()
        takes_object_or_program_or_default(self.mock3)(Object(prog, "int", 1), 2, "foo")
        self.mock3.assert_called_once_with(
            prog, IdenticalMatcher(Object(prog, "int", 1)), 2, "foo"
        )

    def test_obj_one_arg_one_kwarg(self):
        prog = mock_program()
        takes_object_or_program_or_default(self.mock3)(
            Object(prog, "int", 1), 2, s="foo"
        )
        self.mock3.assert_called_once_with(
            prog, IdenticalMatcher(Object(prog, "int", 1)), 2, s="foo"
        )

    def test_obj_two_kwargs(self):
        prog = mock_program()
        takes_object_or_program_or_default(self.mock3)(
            Object(prog, "int", 1), x=2, s="foo"
        )
        self.mock3.assert_called_once_with(
            prog, IdenticalMatcher(Object(prog, "int", 1)), x=2, s="foo"
        )

    def test_obj_kwarg_two_kwargs(self):
        prog = mock_program()
        takes_object_or_program_or_default(self.mock3)(
            obj=Object(prog, "int", 1), x=2, s="foo"
        )
        self.mock3.assert_called_once_with(
            prog, obj=IdenticalMatcher(Object(prog, "int", 1)), x=2, s="foo"
        )

    def test_object_prog_two_args(self):
        prog = mock_program()
        takes_object_or_program_or_default(self.mock3)(Object(prog, "int", 2), "foo")
        self.mock3.assert_called_once_with(
            prog, None, IdenticalMatcher(Object(prog, "int", 2)), "foo"
        )

    def test_object_prog_one_arg_one_kwarg(self):
        prog = mock_program()
        takes_object_or_program_or_default(self.mock3)(Object(prog, "int", 2), s="foo")
        self.mock3.assert_called_once_with(
            prog, None, IdenticalMatcher(Object(prog, "int", 2)), s="foo"
        )

    def test_object_prog_two_kwargs(self):
        prog = mock_program()
        takes_object_or_program_or_default(self.mock3)(
            x=Object(prog, "int", 2), s="foo"
        )
        self.mock3.assert_called_once_with(
            prog, None, x=IdenticalMatcher(Object(prog, "int", 2)), s="foo"
        )

    def test_default_prog_two_args(self):
        with mock_default_prog() as prog:
            takes_object_or_program_or_default(self.mock3)(2, "foo")
            self.mock3.assert_called_once_with(prog, None, 2, "foo")

    def test_default_prog_one_arg_one_kwarg(self):
        with mock_default_prog() as prog:
            takes_object_or_program_or_default(self.mock3)(2, s="foo")
            self.mock3.assert_called_once_with(prog, None, 2, s="foo")

    def test_default_prog_two_kwargs(self):
        with mock_default_prog() as prog:
            takes_object_or_program_or_default(self.mock3)(x=2, s="foo")
            self.mock3.assert_called_once_with(prog, None, x=2, s="foo")
