import base64
import contextlib
import struct
import tempfile
import unittest

from drgn.corereader import CoreReader
from drgn.elf import ElfFormatError


@contextlib.contextmanager
def tmpfile(data):
    file = tempfile.NamedTemporaryFile()
    try:
        file.write(data)
        file.flush()
        yield file
    finally:
        file.close()


def make_elf_file(segments=None):
    if segments is None:
        segments = [(0xffff0000, b'foobar\0\0')]
    buf = bytearray(64 + 56 * len(segments))
    struct.pack_into(
        '<16sHHLQQQLHHHHHH', buf, 0,
        b'\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0', # e_ident
        4,  # e_type (ET_CORE)
        62, # e_machine (EM_X86_64)
        1,  # e_version (EV_CURRENT)
        0,  # e_entry
        64, # e_phoff (right after the header)
        0,  # e_shoff
        0,  # e_flags
        64, # e_ehsize
        56, # e_phentsize
        len(segments), # e_phnum
        0,  # e_shentsize
        0,  # e_shnum
        0,  # e_shstrndx
    )
    for i, segment in enumerate(segments):
        if len(buf) % 4096:
            buf.extend(bytes(4096 - len(buf) % 4096))
        struct.pack_into(
            '<LLQQQQQQ', buf, 64 + i * 56,
            1, # p_type (PT_LOAD)
            0x7, # p_flags (PF_R | PF_W | PF_X)
            len(buf), # p_offset
            segment[0], # p_vaddr
            0xffffffffffffffff, # p_paddr
            len(segment[1]), # p_filesz
            len(segment[1]), # p_memsz
            4096, # p_align
        )
        buf.extend(segment[1])
    return buf


class TestCoreReader(unittest.TestCase):
    def test_short_file(self):
        elf_file = make_elf_file()
        with tmpfile(elf_file[:3]) as file:
            self.assertRaisesRegex(ElfFormatError, 'not an ELF file',
                                   CoreReader, file.name)

    def test_invalid_elf_magic(self):
        elf_file = make_elf_file()
        elf_file[0] = 88
        with tmpfile(elf_file) as file:
            self.assertRaisesRegex(ElfFormatError, 'not an ELF file',
                                   CoreReader, file.name)

    def test_invalid_elf_version(self):
        elf_file = make_elf_file()
        elf_file[6] = 2
        with tmpfile(elf_file) as file:
            self.assertRaisesRegex(ElfFormatError, 'ELF version',
                                   CoreReader, file.name)

    def test_truncated_elf_header(self):
        elf_file = make_elf_file()
        with tmpfile(elf_file[:16]) as file:
            self.assertRaisesRegex(ElfFormatError, 'ELF header is truncated',
                                   CoreReader, file.name)

    def test_program_header_table_overflow(self):
        elf_file = make_elf_file()
        elf_file[32:40] = b'\xff\xff\xff\xff\xff\xff\xff\xff'
        with tmpfile(elf_file) as file:
            self.assertRaisesRegex(ElfFormatError, 'ELF program header table is beyond EOF',
                                   CoreReader, file.name)

    def test_truncated_program_header_table(self):
        elf_file = make_elf_file()
        with tmpfile(elf_file[:64]) as file:
            self.assertRaisesRegex(ElfFormatError, 'ELF program header table is beyond EOF',
                                   CoreReader, file.name)

    def test_simple_read(self):
        data = b'hello, world!'
        elf_file = make_elf_file([(0xffff0000, data)])
        with tmpfile(elf_file) as file:
            core_reader = CoreReader(file.name)
            self.assertEqual(core_reader.read(0xffff0000, len(data)), data)

    def test_bad_address(self):
        elf_file = make_elf_file()
        with tmpfile(elf_file) as file:
            core_reader = CoreReader(file.name)
            self.assertRaisesRegex(ValueError, 'could not find memory segment',
                                   core_reader.read, 0x0, 4)

    def test_segment_overflow(self):
        data = b'hello, world!'
        elf_file = make_elf_file([(0xffff0000, data)])
        with tmpfile(elf_file) as file:
            core_reader = CoreReader(file.name)
            self.assertRaisesRegex(ValueError, 'could not find memory segment',
                                   core_reader.read, 0xffff0000, len(data) + 1)

    def test_contiguous_segments(self):
        data = b'hello, world!'
        elf_file = make_elf_file([
            (0xffff0000, data[:4]),
            (0xfffff000, b'foobar'),
            (0xffff0004, data[4:]),
        ])
        with tmpfile(elf_file) as file:
            core_reader = CoreReader(file.name)
            self.assertEqual(core_reader.read(0xffff0000, len(data)), data)
