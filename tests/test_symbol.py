import unittest

from drgn import enum_type, float_type, int_type
from _drgn import Symbol
from tests import color_type, line_segment_type, point_type


class TestSymbol(unittest.TestCase):
    def test_init(self):
        self.assertRaisesRegex(ValueError, 'one of.*is required', Symbol,
                               int_type('int', 4, True))
        self.assertRaisesRegex(ValueError, 'only one of', Symbol,
                               int_type('int', 4, True), value=1, address=0)
        self.assertRaisesRegex(ValueError, 'only one of', Symbol,
                               int_type('int', 4, True), value=1,
                               is_enumerator=True)
        self.assertRaisesRegex(ValueError, 'only one of', Symbol,
                               int_type('int', 4, True), address=0,
                               is_enumerator=True)
        self.assertRaisesRegex(ValueError,
                               'byteorder must be given with address', Symbol,
                               int_type('int', 4, True), address=0)
        self.assertRaisesRegex(ValueError,
                               'byteorder may only be given with address',
                               Symbol, int_type('int', 4, True), value=1,
                               byteorder='little')

    def test_constant(self):
        sym = Symbol(int_type('int', 4, True), value=1)
        self.assertEqual(sym.type, int_type('int', 4, True))
        self.assertEqual(sym.value, 1)
        self.assertIsNone(sym.address)
        self.assertFalse(sym.is_enumerator)
        self.assertIsNone(sym.byteorder)
        self.assertRaises(TypeError, Symbol, int_type('int', 4, True),
                          value='foo')
        self.assertEqual(sym, Symbol(int_type('int', 4, True), value=1))
        self.assertNotEqual(sym, Symbol(int_type('int', 4, True), value=2))
        self.assertNotEqual(sym, Symbol(int_type('unsigned int', 4, False),
                                        value=1))

        sym = Symbol(float_type('double', 8), value=3.14)
        self.assertEqual(sym.type, float_type('double', 8))
        self.assertEqual(sym.value, 3.14)
        self.assertIsNone(sym.address)
        self.assertFalse(sym.is_enumerator)
        self.assertIsNone(sym.byteorder)
        self.assertRaises(TypeError, Symbol, float_type('double', 8),
                          value='foo')
        self.assertNotEqual(sym, Symbol(float_type('double', 8),
                                        address=0xffff0000,
                                        byteorder='little'))

    def test_address(self):
        sym = Symbol(point_type, address=0xffff0000, byteorder='little')
        self.assertEqual(sym.type, point_type)
        self.assertIsNone(sym.value)
        self.assertEqual(sym.address, 0xffff0000)
        self.assertFalse(sym.is_enumerator)
        self.assertEqual(sym.byteorder, 'little')
        self.assertRaises(TypeError, Symbol, point_type, address='foo',
                          byteorder='little')
        self.assertEqual(sym, Symbol(point_type, address=0xffff0000,
                                     byteorder='little'))
        self.assertNotEqual(sym, Symbol(line_segment_type, address=0xffff0000,
                                        byteorder='little'))
        self.assertNotEqual(sym, Symbol(point_type, address=0xfffeffe0,
                                        byteorder='little'))
        self.assertNotEqual(sym, Symbol(point_type, address=0xffff0000,
                                        byteorder='big'))
        self.assertEqual(
            Symbol(point_type, address=0xffff0000, byteorder='big').byteorder,
            'big')

    def test_enumerator(self):
        sym = Symbol(color_type, is_enumerator=True)
        self.assertEqual(sym.type, color_type)
        self.assertIsNone(sym.value)
        self.assertIsNone(sym.value)
        self.assertTrue(sym.is_enumerator)
        self.assertIsNone(sym.byteorder)
        self.assertEqual(sym, Symbol(color_type, is_enumerator=True))
        self.assertNotEqual(sym, Symbol(enum_type('color2'), is_enumerator=True))
        self.assertNotEqual(sym, Symbol(color_type, value=1))

    def test_cmp(self):
        self.assertNotEqual(Symbol(color_type, is_enumerator=True), 1)
        self.assertNotEqual(1, Symbol(color_type, is_enumerator=True))
