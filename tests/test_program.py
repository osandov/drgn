import unittest

from drgn import FaultError, ProgramFlags, Qualifiers
from drgn.internal.mock import MockMemorySegment, mock_program


class TestProgram(unittest.TestCase):
    def test_lookup_error(self):
        prog = mock_program(8, 'little')
        self.assertRaisesRegex(LookupError, "^could not find constant 'foo'$",
                               prog.constant, 'foo')
        self.assertRaisesRegex(LookupError,
                               "^could not find constant 'foo' in 'foo.c'$",
                               prog.constant, 'foo', 'foo.c')
        self.assertRaisesRegex(LookupError, "^could not find function 'foo'$",
                               prog.function, 'foo')
        self.assertRaisesRegex(LookupError,
                               "^could not find function 'foo' in 'foo.c'$",
                               prog.function, 'foo', 'foo.c')
        self.assertRaisesRegex(LookupError, "^could not find 'typedef foo'$",
                               prog.type, 'foo')
        self.assertRaisesRegex(LookupError,
                               "^could not find 'typedef foo' in 'foo.c'$",
                               prog.type, 'foo', 'foo.c')
        self.assertRaisesRegex(LookupError, "^could not find variable 'foo'$",
                               prog.variable, 'foo')
        self.assertRaisesRegex(LookupError,
                               "^could not find variable 'foo' in 'foo.c'$",
                               prog.variable, 'foo', 'foo.c')
        # prog[key] should raise KeyError instead of LookupError.
        self.assertRaises(KeyError, prog.__getitem__, 'foo')
        # Even for non-strings.
        self.assertRaises(KeyError, prog.__getitem__, 9)

    def test_read(self):
        prog = mock_program(8, 'little', segments=[
            MockMemorySegment(b'hello\0', virt_addr=0xffff0000),
        ])
        self.assertEqual(prog.read(0xffff0000, 5), b'hello')
        self.assertEqual(prog.read(0xffff0000, 6), b'hello\0')
        self.assertRaises(FaultError, prog.read, 0xffff0006, 2)
        self.assertRaises(FaultError, prog.read, 0xffff0007, 1)

    def test_byteorder(self):
        self.assertEqual(mock_program(8, 'little').byteorder, 'little')
        self.assertEqual(mock_program(8, 'big').byteorder, 'big')

    def test_word_size(self):
        self.assertEqual(mock_program(8, 'little').word_size, 8)
        self.assertEqual(mock_program(4, 'little').word_size, 4)

    def test_flags(self):
        self.assertIsInstance(mock_program(8, 'little').flags, ProgramFlags)

    def test_pointer_type(self):
        prog = mock_program(8, 'little')
        self.assertEqual(prog.pointer_type(prog.type('int')),
                         prog.type('int *'))
        self.assertEqual(prog.pointer_type('int'),
                         prog.type('int *'))
        self.assertEqual(prog.pointer_type(prog.type('int'), Qualifiers.CONST),
                         prog.type('int * const'))
