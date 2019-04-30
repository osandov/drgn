import unittest

from drgn import FindObjectFlags, TypeKind, function_type, int_type, void_type
from _drgn import Symbol, SymbolIndex
from tests.test_type_index import color_type


def mock_symbol_index(syms):
    def mock_symbol_find(name, flags, filename):
        if filename:
            return None
        for sym_name, sym in syms:
            if sym_name == name:
                if sym.value is not None or sym.is_enumerator:
                    if flags & FindObjectFlags.CONSTANT:
                        break
                elif sym.type.kind == TypeKind.FUNCTION:
                    if flags & FindObjectFlags.FUNCTION:
                        break
                elif flags & FindObjectFlags.VARIABLE:
                    break
        else:
            return None
        return sym
    sindex = SymbolIndex()
    sindex.add_finder(mock_symbol_find)
    return sindex


class TestSymbolIndex(unittest.TestCase):
    def test_invalid_finder(self):
        self.assertRaises(TypeError, SymbolIndex().add_finder, 'foo')

        sindex = SymbolIndex()
        sindex.add_finder(lambda name, flags, filename: 'foo')
        self.assertRaises(TypeError, sindex.find, 'foo', FindObjectFlags.ANY)

    def test_not_found(self):
        sindex = SymbolIndex()
        self.assertRaises(LookupError, sindex.find, 'foo', FindObjectFlags.ANY)
        sindex.add_finder(lambda name, flags, filename: None)
        self.assertRaises(LookupError, sindex.find, 'foo', FindObjectFlags.ANY)

    def test_constant(self):
        sym = Symbol(int_type('int', 4, True), value=4096)
        sindex = mock_symbol_index([('PAGE_SIZE', sym)])
        self.assertEqual(sindex.find('PAGE_SIZE', FindObjectFlags.CONSTANT), sym)
        self.assertEqual(sindex.find('PAGE_SIZE', FindObjectFlags.ANY), sym)

    def test_function(self):
        sym = Symbol(function_type(void_type(), (), False), address=0xffff0000,
                     byteorder='little')
        sindex = mock_symbol_index([('func', sym)])
        self.assertEqual(sindex.find('func', FindObjectFlags.FUNCTION), sym)
        self.assertEqual(sindex.find('func', FindObjectFlags.ANY), sym)

    def test_variable(self):
        sym = Symbol(int_type('int', 4, True), address=0xffff0000,
                     byteorder='little')
        sindex = mock_symbol_index([('counter', sym)])
        self.assertEqual(sindex.find('counter', FindObjectFlags.VARIABLE), sym)
        self.assertEqual(sindex.find('counter', FindObjectFlags.ANY), sym)

    def test_wrong_kind(self):
        sindex = SymbolIndex()
        sindex.add_finder(lambda name, flags, filename:
                          Symbol(color_type, is_enumerator=True))
        self.assertRaisesRegex(TypeError, 'wrong kind', sindex.find, 'foo',
                               FindObjectFlags.VARIABLE | FindObjectFlags.FUNCTION)
