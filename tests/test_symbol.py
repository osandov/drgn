# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later
import tempfile
from typing import NamedTuple

from drgn import Program, SymbolBinding, SymbolKind
from tests import TestCase
from tests.dwarfwriter import dwarf_sections
from tests.elf import ET, PT, SHT, STB, STT
from tests.elfwriter import ElfSection, ElfSymbol, create_elf_file


def create_elf_symbol_file(symbols):
    # We need some DWARF data so that libdwfl will load the file.
    sections = dwarf_sections(())
    # Create a section for the symbols to reference and the corresponding
    # segment for address lookups.
    min_address = min(symbol.value for symbol in symbols)
    max_address = max(symbol.value + symbol.size for symbol in symbols)
    sections.append(
        ElfSection(
            name=".foo",
            sh_type=SHT.NOBITS,
            p_type=PT.LOAD,
            vaddr=min_address,
            memsz=max_address - min_address,
        )
    )
    symbols = [
        symbol._replace(
            shindex=len(sections) if symbol.shindex is None else symbol.shindex
        )
        for symbol in symbols
    ]
    return create_elf_file(ET.EXEC, sections, symbols)


def elf_symbol_program(*modules):
    prog = Program()
    for symbols in modules:
        with tempfile.NamedTemporaryFile() as f:
            f.write(create_elf_symbol_file(symbols))
            f.flush()
            prog.load_debug_info([f.name])
    return prog


# We don't want to support creating drgn.Symbol instances yet, so use this dumb
# class for testing.
class Symbol(NamedTuple):
    name: str
    address: int
    size: int
    binding: SymbolBinding
    kind: SymbolKind


class TestElfSymbol(TestCase):
    def assert_symbol_equal(self, drgn_symbol, symbol):
        self.assertEqual(
            Symbol(
                drgn_symbol.name,
                drgn_symbol.address,
                drgn_symbol.size,
                drgn_symbol.binding,
                drgn_symbol.kind,
            ),
            symbol,
        )

    def assert_symbols_equal_unordered(self, drgn_symbols, symbols):
        self.assertEqual(len(drgn_symbols), len(symbols))
        drgn_symbols = sorted(drgn_symbols, key=lambda x: (x.address, x.name))
        symbols = sorted(symbols, key=lambda x: (x.address, x.name))
        for drgn_symbol, symbol in zip(drgn_symbols, symbols):
            self.assert_symbol_equal(drgn_symbol, symbol)

    def test_by_address(self):
        elf_first = ElfSymbol("first", 0xFFFF0000, 0x8, STT.OBJECT, STB.LOCAL)
        elf_second = ElfSymbol("second", 0xFFFF0008, 0x8, STT.OBJECT, STB.LOCAL)
        first = Symbol("first", 0xFFFF0000, 0x8, SymbolBinding.LOCAL, SymbolKind.OBJECT)
        second = Symbol(
            "second", 0xFFFF0008, 0x8, SymbolBinding.LOCAL, SymbolKind.OBJECT
        )

        same_module = ((elf_first, elf_second),)
        different_modules = ((elf_first,), (elf_second,))

        for modules in same_module, different_modules:
            with self.subTest(modules=len(modules)):
                prog = elf_symbol_program(*modules)
                self.assertRaises(LookupError, prog.symbol, 0xFFFEFFFF)
                self.assertEqual(prog.symbols(0xFFFEFFFF), [])
                self.assert_symbol_equal(prog.symbol(0xFFFF0000), first)
                self.assert_symbols_equal_unordered(prog.symbols(0xFFFF0000), [first])
                self.assert_symbol_equal(prog.symbol(0xFFFF0004), first)
                self.assert_symbols_equal_unordered(prog.symbols(0xFFFF0004), [first])
                self.assert_symbol_equal(prog.symbol(0xFFFF0008), second)
                self.assert_symbols_equal_unordered(prog.symbols(0xFFFF0008), [second])
                self.assert_symbol_equal(prog.symbol(0xFFFF000C), second)
                self.assert_symbols_equal_unordered(prog.symbols(0xFFFF000C), [second])
                self.assertRaises(LookupError, prog.symbol, 0xFFFF0010)

    def test_by_address_precedence(self):
        precedence = (STB.GLOBAL, STB.WEAK, STB.LOCAL)
        drgn_precedence = (
            SymbolBinding.GLOBAL,
            SymbolBinding.WEAK,
            SymbolBinding.LOCAL,
        )

        def assert_find_higher(*modules):
            self.assertEqual(
                elf_symbol_program(*modules).symbol(0xFFFF0000).name, "foo"
            )

        def assert_finds_both(symbols, *modules):
            self.assert_symbols_equal_unordered(
                elf_symbol_program(*modules).symbols(0xFFFF0000),
                symbols,
            )

        for i in range(len(precedence) - 1):
            higher_binding = precedence[i]
            higher_binding_drgn = drgn_precedence[i]
            for j in range(i + 1, len(precedence)):
                lower_binding = precedence[j]
                lower_binding_drgn = drgn_precedence[j]
                with self.subTest(higher=higher_binding, lower=lower_binding):
                    higher = ElfSymbol(
                        "foo", 0xFFFF0000, 0x8, STT.OBJECT, higher_binding
                    )
                    lower = ElfSymbol("bar", 0xFFFF0000, 0x8, STT.OBJECT, lower_binding)
                    symbols = [
                        Symbol(
                            "foo",
                            0xFFFF0000,
                            0x8,
                            higher_binding_drgn,
                            SymbolKind.OBJECT,
                        ),
                        Symbol(
                            "bar",
                            0xFFFF0000,
                            0x8,
                            lower_binding_drgn,
                            SymbolKind.OBJECT,
                        ),
                    ]
                    # Local symbols must be before global symbols.
                    if lower_binding != STB.LOCAL:
                        with self.subTest("higher before lower"):
                            assert_find_higher((higher, lower))
                    with self.subTest("lower before higher"):
                        assert_find_higher((lower, higher))
                    assert_finds_both(symbols, (lower, higher))

    def test_by_name(self):
        elf_first = ElfSymbol("first", 0xFFFF0000, 0x8, STT.OBJECT, STB.GLOBAL)
        elf_second = ElfSymbol("second", 0xFFFF0008, 0x8, STT.OBJECT, STB.GLOBAL)
        first = Symbol(
            "first", 0xFFFF0000, 0x8, SymbolBinding.GLOBAL, SymbolKind.OBJECT
        )
        second = Symbol(
            "second", 0xFFFF0008, 0x8, SymbolBinding.GLOBAL, SymbolKind.OBJECT
        )

        same_module = ((elf_first, elf_second),)
        different_modules = ((elf_first,), (elf_second,))

        for modules in same_module, different_modules:
            with self.subTest(modules=len(modules)):
                prog = elf_symbol_program(*modules)
                self.assert_symbol_equal(prog.symbol("first"), first)
                self.assert_symbol_equal(prog.symbol("second"), second)
                self.assertRaises(LookupError, prog.symbol, "third")

                self.assert_symbols_equal_unordered(prog.symbols("first"), [first])
                self.assert_symbols_equal_unordered(prog.symbols("second"), [second])
                self.assertEqual(prog.symbols("third"), [])

    def test_by_name_precedence(self):
        precedence = (
            (STB.GLOBAL, STB.GNU_UNIQUE),
            (STB.WEAK,),
            (STB.LOCAL, STB.HIPROC),
        )

        expected = 0xFFFF0008
        other = expected - 0x8

        def assert_find_higher(*modules):
            prog = elf_symbol_program(*modules)
            self.assertEqual(prog.symbol("foo").address, expected)
            # assert symbols() always finds both
            symbols = sorted(prog.symbols("foo"), key=lambda s: s.address)
            self.assertEqual(len(symbols), 2)
            self.assertEqual(symbols[0].address, other)
            self.assertEqual(symbols[1].address, expected)

        for i in range(len(precedence) - 1):
            for higher_binding in precedence[i]:
                for j in range(i + 1, len(precedence)):
                    for lower_binding in precedence[j]:
                        with self.subTest(higher=higher_binding, lower=lower_binding):
                            higher = ElfSymbol(
                                "foo", expected, 0x8, STT.OBJECT, higher_binding
                            )
                            lower = ElfSymbol(
                                "foo", other, 0x8, STT.OBJECT, lower_binding
                            )
                            # Local symbols must be before global symbols.
                            if lower_binding not in precedence[-1]:
                                with self.subTest("same module, higher before lower"):
                                    assert_find_higher((higher, lower))
                            with self.subTest("same module, lower before higher"):
                                assert_find_higher((lower, higher))
                            with self.subTest("different modules, higher before lower"):
                                assert_find_higher((higher,), (lower,))
                            with self.subTest("different modules, lower before higher"):
                                assert_find_higher((lower,), (higher,))

    def test_binding(self):
        for by in "name", "address":
            for elf_binding, drgn_binding in (
                (STB.LOCAL, SymbolBinding.LOCAL),
                (STB.GLOBAL, SymbolBinding.GLOBAL),
                (STB.WEAK, SymbolBinding.WEAK),
                (STB.GNU_UNIQUE, SymbolBinding.UNIQUE),
                (STB.HIPROC, SymbolBinding.UNKNOWN),
            ):
                with self.subTest(by=by, binding=elf_binding):
                    prog = elf_symbol_program(
                        (ElfSymbol("foo", 0xFFFF0000, 1, STT.OBJECT, elf_binding),)
                    )
                    self.assertEqual(
                        prog.symbol("foo" if by == "name" else 0xFFFF0000).binding,
                        drgn_binding,
                    )
                    if by == "name":
                        symbols = prog.symbols("foo")
                        self.assertEqual(len(symbols), 1)
                        self.assertEqual(symbols[0].binding, drgn_binding)

    def test_kind(self):
        for elf_type, drgn_kind in (
            (STT.NOTYPE, SymbolKind.UNKNOWN),
            (STT.OBJECT, SymbolKind.OBJECT),
            (STT.FUNC, SymbolKind.FUNC),
            (STT.SECTION, SymbolKind.SECTION),
            (STT.FILE, SymbolKind.FILE),
            (STT.COMMON, SymbolKind.COMMON),
            (STT.TLS, SymbolKind.TLS),
            (STT.GNU_IFUNC, SymbolKind.IFUNC),
        ):
            with self.subTest(type=elf_type):
                prog = elf_symbol_program(
                    (ElfSymbol("foo", 0xFFFF0000, 1, elf_type, STB.GLOBAL),)
                )
                symbol = Symbol("foo", 0xFFFF0000, 1, SymbolBinding.GLOBAL, drgn_kind)
                self.assert_symbol_equal(prog.symbol("foo"), symbol)
                symbols = prog.symbols("foo")
                self.assert_symbols_equal_unordered(symbols, [symbol])

    def test_all_symbols(self):
        elf_syms = (
            (
                ElfSymbol("two", 0xFFFF0012, 1, STT.OBJECT, STB.LOCAL),
                ElfSymbol("three", 0xFFFF0013, 1, STT.OBJECT, STB.LOCAL),
                ElfSymbol("one", 0xFFFF0011, 1, STT.OBJECT, STB.GLOBAL),
            ),
            (
                ElfSymbol("three", 0xFFFF0023, 1, STT.OBJECT, STB.LOCAL),
                ElfSymbol("two", 0xFFFF0022, 1, STT.OBJECT, STB.GLOBAL),
            ),
            (ElfSymbol("three", 0xFFFF0033, 1, STT.OBJECT, STB.GLOBAL),),
        )
        kind = SymbolKind.OBJECT
        syms = [
            Symbol("two", 0xFFFF0012, 1, SymbolBinding.LOCAL, kind),
            Symbol("three", 0xFFFF0013, 1, SymbolBinding.LOCAL, kind),
            Symbol("one", 0xFFFF0011, 1, SymbolBinding.GLOBAL, kind),
            Symbol("three", 0xFFFF0023, 1, SymbolBinding.LOCAL, kind),
            Symbol("two", 0xFFFF0022, 1, SymbolBinding.GLOBAL, kind),
            Symbol("three", 0xFFFF0033, 1, SymbolBinding.GLOBAL, kind),
        ]
        prog = elf_symbol_program(*elf_syms)
        self.assert_symbols_equal_unordered(prog.symbols(), syms)
