# Copyright (c) 2025, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later
import contextlib
import io
import struct

from drgn import (
    Architecture,
    FaultError,
    Platform,
    Program,
    Symbol,
    SymbolBinding,
    SymbolKind,
)
from drgn.commands._builtin.crash._rd import _print_memory
from tests import TestCase


def add_fake_memory_segment(prog, start, bytes, is_phys=False):

    def reader(address, count, offset, physical):
        if physical == is_phys:
            return bytes[offset : offset + count]
        raise FaultError("unable to read memory", address)

    prog.add_memory_segment(start, len(bytes), reader, physical=is_phys)


class TestPrintMemory(TestCase):

    @classmethod
    def setUpClass(cls):
        # The only reason to set a specific architecture is to have a known word
        # size, which does impact alignment. The rest is not
        # architecture-specific.
        cls.prog = Program(platform=Platform(Architecture.X86_64))
        mem_data = bytes(range(8)) + struct.pack("<Q", 0x12345678) + bytes(range(8, 64))
        add_fake_memory_segment(cls.prog, 0xFFFF0000, mem_data)
        add_fake_memory_segment(cls.prog, 0x10000, b"ABCD", is_phys=True)
        cls.prog.register_symbol_finder(
            "test",
            lambda prog, name, address, one: (
                [
                    Symbol(
                        "test_sym",
                        0x12345678,
                        0,
                        SymbolBinding.GLOBAL,
                        SymbolKind.OBJECT,
                    )
                ]
                if (name == "test_sym" or (name is None and address == 0x12345678))
                else []
            ),
        )
        cls.prog.set_enabled_symbol_finders(["test"])

    def run_print_memory(self, address: int, count: int, *, unit: int, **kwargs):
        output = io.StringIO()
        physical = kwargs.pop("physical", False)
        memory = self.prog.read(address, count * unit, physical=physical)
        with contextlib.redirect_stdout(output):
            _print_memory(self.prog, address, memory, unit=unit, **kwargs)
        return output.getvalue()

    def test_print_memory_basic(self):
        result = self.run_print_memory(0xFFFF0000, 4, unit=1)
        self.assertEqual(
            result,
            """\
        ffff0000:  00 01 02 03                                       ....
""",
        )

    def test_unit_2(self):
        result = self.run_print_memory(0xFFFF0000, 2, unit=2)
        self.assertEqual(
            result,
            """\
        ffff0000:  0100 0302                                 ....
""",
        )

    def test_physical(self):
        result = self.run_print_memory(0x10000, 1, physical=True, unit=4)
        self.assertEqual(
            result,
            """\
           10000:  44434241                              ABCD
""",
        )

    def test_no_ascii(self):
        result = self.run_print_memory(0xFFFF0000, 4, unit=1, show_ascii=False)
        self.assertEqual(
            result,
            """\
        ffff0000:  00 01 02 03
""",
        )

    def test_annotate_symbols(self):
        result = self.run_print_memory(
            0xFFFF0008, 2, unit=8, annotate="symbols", show_ascii=False
        )
        self.assertEqual(
            result,
            """\
        ffff0008:  test_sym+0       0f0e0d0c0b0a0908
""",
        )

    def test_format_decimal(self):
        result = self.run_print_memory(0xFFFF0000, 1, unit=4, format="d")
        self.assertEqual(
            result,
            """\
        ffff0000:     50462976                                       ....
""",
        )

    def test_endian_big(self):
        result = self.run_print_memory(0x10000, 1, physical=True, unit=4, endian="big")
        self.assertEqual(
            result,
            """\
           10000:  41424344                              ABCD
""",
        )

    def test_annotate_wrong_unit(self):
        with self.assertRaises(ValueError):
            self.run_print_memory(0xFFFF0000, 1, unit=4, annotate="symbols")

    def test_annotate_wrong_format(self):
        with self.assertRaises(ValueError):
            self.run_print_memory(0xFFFF0000, 1, unit=4, format="d", annotate="symbols")
