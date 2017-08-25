import drgn.lldwarf as lldwarf
import unittest


def header(offset=0, unit_length=8192, version=2, header_length=57,
           minimum_instruction_length=1, maximum_operations_per_instruction=1,
           default_is_stmt=True, line_base=-5, line_range=14, opcode_base=13,
           standard_opcode_lengths=None, include_directories=None,
           file_names=None, is_64_bit=False):
    if standard_opcode_lengths is None:
        standard_opcode_lengths = [0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]
    if include_directories is None:
        include_directories = [b'include']
    if file_names is None:
        file_names = [(b'main.c', 0, 1, 2), (b'defs.h', 1, 2, 3)]
    return lldwarf.LineNumberProgramHeader(
        offset, unit_length, version, header_length,
        minimum_instruction_length, maximum_operations_per_instruction,
        default_is_stmt, line_base, line_range, opcode_base,
        standard_opcode_lengths, include_directories, file_names, is_64_bit)


def row(address=0, op_index=0, file=1, line=1, column=0, is_stmt=True,
	basic_block=False, end_sequence=False, prologue_end=False,
        epilogue_begin=False, isa=0, discriminator=0):
    return lldwarf.LineNumberRow(address, op_index, file, line, column,
                                 is_stmt, basic_block, end_sequence,
                                 prologue_end, epilogue_begin, isa,
                                 discriminator)


class TestLineNumberProgramHeaderObject(unittest.TestCase):
    def test_offset(self):
        self.assertEqual(header().program_offset(), 67)
        self.assertEqual(header(is_64_bit=True).program_offset(), 79)

        self.assertEqual(header().end_offset(), 8196)
        self.assertEqual(header(is_64_bit=True).end_offset(), 8204)

    def test_offset_overflow(self):
        lnp = header(header_length=2**64 - 10)
        with self.assertRaises(OverflowError):
            lnp.program_offset()

        lnp = header(offset=2**63 - 100, header_length=90)
        with self.assertRaises(OverflowError):
            lnp.program_offset()

        lnp = header(unit_length=2**64 - 4)
        with self.assertRaises(OverflowError):
            lnp.end_offset()

        lnp = header(offset=2**63 - 8192)
        with self.assertRaises(OverflowError):
            lnp.end_offset()


class TestParseLineNumberProgramHeader(unittest.TestCase):
    def test_v2(self):
        buf = (b'\x00\x20\x00\x00'  # unit_length
               b'\x02\x00'          # version
               b'\x39\x00\x00\x00'  # header_length
               b'\x01'              # minimum_instruction_length
               b'\x01'              # default_is_stmt
               b'\xfb'              # line_base
               b'\x0e'              # line_range
               b'\x0d'              # opcode_base
               b'\x00\x01\x01\x01\x01\x00\x00\x00\x01\x00\x00\x01'
               b'include\x00\x00'   # include_directories
               b'main.c\x00\x00\x01\x02'
               b'defs.h\x00\x01\x02\x03'  # file_names
               b'\x00')
        self.assertEqual(lldwarf.parse_line_number_program_header(buf), header())

    def test_v4(self):
        buf = (b'\x00\x20\x00\x00'  # unit_length
               b'\x04\x00'          # version
               b'\x39\x00\x00\x00'  # header_length
               b'\x01'              # minimum_instruction_length
               b'\x01'              # maximum_operations_per_instruction
               b'\x01'              # default_is_stmt
               b'\xfb'              # line_base
               b'\x0e'              # line_range
               b'\x0d'              # opcode_base
               b'\x00\x01\x01\x01\x01\x00\x00\x00\x01\x00\x00\x01'
               b'include\x00\x00'   # include_directories
               b'main.c\x00\x00\x01\x02'
               b'defs.h\x00\x01\x02\x03'  # file_names
               b'\x00')
        self.assertEqual(lldwarf.parse_line_number_program_header(buf), header(version=4))

    def test_64bit(self):
        buf = (b'\xff\xff\xff\xff\x00\x20\x00\x00\x00\x00\x00\x00'  # unit_length
               b'\x02\x00'          # version
               b'\x39\x00\x00\x00\x00\x00\x00\x00'  # header_length
               b'\x01'              # minimum_instruction_length
               b'\x01'              # default_is_stmt
               b'\xfb'              # line_base
               b'\x0e'              # line_range
               b'\x0d'              # opcode_base
               b'\x00\x01\x01\x01\x01\x00\x00\x00\x01\x00\x00\x01'
               b'include\x00\x00'   # include_directories
               b'main.c\x00\x00\x01\x02'
               b'defs.h\x00\x01\x02\x03'  # file_names
               b'\x00')
        self.assertEqual(lldwarf.parse_line_number_program_header(buf), header(is_64_bit=True))

    def test_bad_opcode_base(self):
        buf = (b'\x00\x20\x00\x00'  # unit_length
               b'\x02\x00'          # version
               b'\x00\x00\x00\x00'  # header_length
               b'\x01'              # minimum_instruction_length
               b'\x01'              # default_is_stmt
               b'\xfb'              # line_base
               b'\x0e'              # line_range
               b'\x00')             # opcode_base
        with self.assertRaises(ValueError):
            lldwarf.parse_line_number_program_header(buf)
