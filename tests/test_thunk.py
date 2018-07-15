import unittest
from unittest.mock import MagicMock

from drgn.internal.thunk import thunk


class TestThunk(unittest.TestCase):
    def test_no_args(self):
        self.assertRaises(TypeError, thunk)

    def test_not_func(self):
        self.assertRaises(TypeError, thunk, 1)

    def test_extra_args(self):
        t = thunk(lambda: 99)
        self.assertRaises(TypeError, t, 1)
        self.assertRaises(TypeError, t, foo=1)

    def test_raises(self):
        func = MagicMock(side_effect=ValueError())
        t = thunk(func)
        self.assertRaises(ValueError, t)
        self.assertRaises(ValueError, t)
        func.assert_has_calls([(), ()])

    def test_cache(self):
        func = MagicMock(return_value=99)
        t = thunk(func)
        self.assertEqual(t(), 99)
        self.assertEqual(t(), 99)
        func.assert_called_once()

    def test_args(self):
        func = MagicMock(return_value=99)
        t = thunk(func, 1, 2)
        self.assertEqual(t(), 99)
        func.assert_called_once_with(1, 2)

    def test_kwargs(self):
        func = MagicMock(return_value=99)
        t = thunk(func, foo=1, bar=2)
        self.assertEqual(t(), 99)
        func.assert_called_once_with(foo=1, bar=2)

    def test_args_and_kwargs(self):
        func = MagicMock(return_value=99)
        t = thunk(func, 0, foo=1, bar=2)
        self.assertEqual(t(), 99)
        func.assert_called_once_with(0, foo=1, bar=2)
