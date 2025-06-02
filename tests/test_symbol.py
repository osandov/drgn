# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import itertools
import lzma
import tempfile
import unittest

from _drgn_util.elf import ET, PT, SHF, SHT, STB, STT
import drgn
from drgn import Program, Symbol, SymbolBinding, SymbolIndex, SymbolKind
from tests import TestCase
from tests.dwarfwriter import create_dwarf_file
from tests.elfwriter import ElfSection, ElfSymbol, create_elf_file


def add_shndx(symbols, shndx):
    return [
        symbol._replace(shindex=shndx if symbol.shindex is None else symbol.shindex)
        for symbol in symbols
    ]


def create_elf_symbol_file(
    symbols=(),
    dynamic_symbols=(),
    gnu_debugdata_symbols=(),
    dwarf=False,
    loadable=True,
):
    def symbols_start(symbols):
        return min(symbol.value for symbol in symbols)

    def symbols_end(symbols):
        return max(symbol.value + max(symbol.size, 1) for symbol in symbols)

    assert symbols or dynamic_symbols or gnu_debugdata_symbols
    start = float("inf")
    end = float("-inf")
    if symbols:
        start = min(start, symbols_start(symbols))
        end = max(end, symbols_end(symbols))
    if dynamic_symbols:
        start = min(start, symbols_start(dynamic_symbols))
        end = max(end, symbols_end(dynamic_symbols))
    if gnu_debugdata_symbols:
        start = min(start, symbols_start(gnu_debugdata_symbols))
        end = max(end, symbols_end(gnu_debugdata_symbols))

    start &= ~7
    end = (end + 7) & ~7

    # Create a section for the symbols to reference and the corresponding
    # segment for address lookups. It must be SHF_ALLOC and must not be
    # SHT_NOBITS or SHT_NOTE for the file to be loadable.
    size = end - start
    assert size <= 4096, "symbols are too far apart; file would be too large"
    sections = [
        ElfSection(
            name=".data",
            sh_type=SHT.PROGBITS,
            sh_flags=SHF.ALLOC if loadable else 0,
            p_type=PT.LOAD,
            vaddr=start,
            memsz=size,
            data=bytes(size),
        ),
    ]
    symbols = add_shndx(symbols, len(sections))
    dynamic_symbols = add_shndx(dynamic_symbols, len(sections))

    if gnu_debugdata_symbols:
        gds_sections = [
            ElfSection(
                name=".data",
                sh_type=SHT.NOBITS,
                sh_flags=SHF.ALLOC,
                p_type=PT.LOAD,
                vaddr=start,
                memsz=size,
            ),
        ]
        gds_contents = create_elf_file(
            ET.EXEC,
            sections=gds_sections,
            symbols=add_shndx(gnu_debugdata_symbols, len(gds_sections)),
        )
        compressor = lzma.LZMACompressor()
        gds_compressed = compressor.compress(gds_contents) + compressor.flush()
        sections.append(
            ElfSection(
                name=".gnu_debugdata",
                sh_type=SHT.PROGBITS,
                memsz=len(gds_compressed),
                data=gds_compressed,
            )
        )

    if dwarf:
        contents = create_dwarf_file(
            (),
            sections=sections,
            symbols=symbols,
            dynamic_symbols=dynamic_symbols,
        )
    else:
        contents = create_elf_file(
            ET.EXEC,
            sections=sections,
            symbols=symbols,
            dynamic_symbols=dynamic_symbols,
        )

    return contents, start, end


def module_set_elf_symbol_file(module, **kwargs):
    contents, start, end = create_elf_symbol_file(**kwargs)

    with tempfile.NamedTemporaryFile() as f:
        f.write(contents)
        f.flush()

        if module.address_range is None:
            for other_module in module.prog.modules():
                other_address_range = other_module.address_range
                if other_address_range is not None:
                    other_start, other_end = other_address_range
                    assert (
                        end <= other_start or start >= other_end
                    ), f"{module.name} overlaps {other_module.name}"
            module.address_range = (start, end)
        else:
            assert (start, end) == module.address_range

        module.try_file(f.name, force=True)


def program_add_elf_symbol_file(prog, name, **kwargs):
    module = prog.extra_module(name, create=True)
    module_set_elf_symbol_file(module, **kwargs)


def elf_symbol_program(*modules):
    prog = Program()
    for i, symbols in enumerate(modules):
        program_add_elf_symbol_file(prog, f"module{i}", symbols=symbols)
    return prog


class TestElfSymbol(TestCase):
    def assert_symbols_equal_unordered(self, drgn_symbols, symbols):
        self.assertEqual(len(drgn_symbols), len(symbols))
        drgn_symbols = sorted(drgn_symbols, key=lambda x: (x.address, x.name))
        symbols = sorted(symbols, key=lambda x: (x.address, x.name))
        for drgn_symbol, symbol in zip(drgn_symbols, symbols):
            self.assertEqual(drgn_symbol, symbol)

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
                self.assertEqual(prog.symbol(0xFFFF0000), first)
                self.assert_symbols_equal_unordered(prog.symbols(0xFFFF0000), [first])
                self.assertEqual(prog.symbol(0xFFFF0004), first)
                self.assert_symbols_equal_unordered(prog.symbols(0xFFFF0004), [first])
                self.assertEqual(prog.symbol(0xFFFF0008), second)
                self.assert_symbols_equal_unordered(prog.symbols(0xFFFF0008), [second])
                self.assertEqual(prog.symbol(0xFFFF000C), second)
                self.assert_symbols_equal_unordered(prog.symbols(0xFFFF000C), [second])
                self.assertRaises(LookupError, prog.symbol, 0xFFFF0010)

    def test_by_address_closest(self):
        # If two symbols contain the given address, then the one whose start
        # address is closest to the given address should be preferred
        # (regardless of the binding of either symbol).
        elf_closest = ElfSymbol("closest", 0xFFFF0008, 0x8, STT.OBJECT, STB.WEAK)
        elf_furthest = ElfSymbol("furthest", 0xFFFF0000, 0xC, STT.OBJECT, STB.GLOBAL)
        closest = Symbol(
            "closest", 0xFFFF0008, 0x8, SymbolBinding.WEAK, SymbolKind.OBJECT
        )
        furthest = Symbol(
            "furthest", 0xFFFF0000, 0xC, SymbolBinding.GLOBAL, SymbolKind.OBJECT
        )

        def test(elf_symbols):
            prog = elf_symbol_program(elf_symbols)
            self.assertEqual(prog.symbol(0xFFFF000B), closest)
            self.assert_symbols_equal_unordered(
                prog.symbols(0xFFFF000B), [closest, furthest]
            )

        with self.subTest("closest first"):
            test([elf_closest, elf_furthest])

        with self.subTest("furthest first"):
            test([elf_furthest, elf_closest])

    def test_by_address_closest_end(self):
        # If two symbols contain the given address and have the same start
        # address, then the one whose end address is closest to the given
        # address should be preferred (regardless of the binding of either
        # symbol).
        elf_closest = ElfSymbol("closest", 0xFFFF0000, 0xC, STT.OBJECT, STB.WEAK)
        elf_furthest = ElfSymbol("furthest", 0xFFFF0000, 0x10, STT.OBJECT, STB.GLOBAL)
        closest = Symbol(
            "closest", 0xFFFF0000, 0xC, SymbolBinding.WEAK, SymbolKind.OBJECT
        )
        furthest = Symbol(
            "furthest", 0xFFFF0000, 0x10, SymbolBinding.GLOBAL, SymbolKind.OBJECT
        )

        def test(elf_symbols):
            prog = elf_symbol_program(elf_symbols)
            self.assertEqual(prog.symbol(0xFFFF000B), closest)
            self.assert_symbols_equal_unordered(
                prog.symbols(0xFFFF000B), [closest, furthest]
            )

        with self.subTest("closest first"):
            test([elf_closest, elf_furthest])

        with self.subTest("furthest first"):
            test([elf_furthest, elf_closest])

    def test_by_address_sizeless(self):
        label = ElfSymbol("label", 0xFFFF0008, 0x0, STT.FUNC, STB.LOCAL)
        less = ElfSymbol("less", 0xFFFF0000, 0x4, STT.FUNC, STB.LOCAL)
        greater = ElfSymbol("greater", 0xFFFF0010, 0x4, STT.FUNC, STB.LOCAL)

        expected = Symbol(
            "label", 0xFFFF0008, 0x0, SymbolBinding.LOCAL, SymbolKind.FUNC
        )

        # Test every permutation of every combination of symbols that includes
        # "label".
        for elf_symbols in itertools.chain.from_iterable(
            itertools.permutations((label,) + extra_elf_symbols)
            for r in range(3)
            for extra_elf_symbols in itertools.combinations((less, greater), r)
        ):
            with self.subTest(elf_symbols=[sym.name for sym in elf_symbols]):
                prog = elf_symbol_program(elf_symbols)
                self.assertEqual(prog.symbol(0xFFFF0009), expected)
                self.assertEqual(prog.symbols(0xFFFF0009), [expected])

    def test_by_address_sizeless_subsumed(self):
        label = ElfSymbol("label", 0xFFFF0008, 0x0, STT.FUNC, STB.LOCAL)
        subsume = ElfSymbol("subsume", 0xFFFF0004, 0x8, STT.FUNC, STB.LOCAL)
        less = ElfSymbol("less", 0xFFFF0000, 0x4, STT.FUNC, STB.LOCAL)
        greater = ElfSymbol("greater", 0xFFFF0010, 0x4, STT.FUNC, STB.LOCAL)

        expected = Symbol(
            "subsume", 0xFFFF0004, 0x8, SymbolBinding.LOCAL, SymbolKind.FUNC
        )

        # Test every permutation of every combination of symbols that includes
        # "label" and "subsume".
        for elf_symbols in itertools.chain.from_iterable(
            itertools.permutations((label, subsume) + extra_elf_symbols)
            for r in range(3)
            for extra_elf_symbols in itertools.combinations((less, greater), r)
        ):
            with self.subTest(elf_symbols=[sym.name for sym in elf_symbols]):
                prog = elf_symbol_program(elf_symbols)
                self.assertEqual(prog.symbol(0xFFFF0009), expected)
                self.assertEqual(prog.symbols(0xFFFF0009), [expected])

    def test_by_address_sizeless_wrong_section(self):
        prog = elf_symbol_program(
            (ElfSymbol("label", 0xFFFF0008, 0x0, STT.FUNC, STB.LOCAL),)
        )
        for module in prog.modules():
            start, end = module.address_range
            module.address_range = (start, 0xFFFFFF00)
        self.assertRaises(LookupError, prog.symbol, 0xFFFFFE00)

    def test_by_address_binding_precedence(self):
        precedence = (
            (STB.GLOBAL, STB.GNU_UNIQUE),
            (STB.WEAK,),
            (STB.LOCAL, STB.HIPROC),
        )

        def assert_find_higher(*modules, both):
            prog = elf_symbol_program(*modules)
            self.assertEqual(prog.symbol(0xFFFF0000).name, "foo")
            # Test that symbols() finds both if expected or either one if not.
            if both:
                self.assertCountEqual(
                    [sym.name for sym in prog.symbols(0xFFFF0000)], ["foo", "bar"]
                )
            else:
                self.assertIn(
                    [sym.name for sym in prog.symbols(0xFFFF0000)], (["foo"], ["bar"])
                )

        for size in (8, 0):
            with self.subTest(size=size):
                for i in range(len(precedence) - 1):
                    for higher_binding in precedence[i]:
                        for j in range(i + 1, len(precedence)):
                            for lower_binding in precedence[j]:
                                with self.subTest(
                                    higher=higher_binding, lower=lower_binding
                                ):
                                    higher = ElfSymbol(
                                        "foo",
                                        0xFFFF0000,
                                        size,
                                        STT.OBJECT,
                                        higher_binding,
                                    )
                                    lower = ElfSymbol(
                                        "bar",
                                        0xFFFF0000,
                                        size,
                                        STT.OBJECT,
                                        lower_binding,
                                    )
                                    # Local symbols must be before global symbols.
                                    if lower_binding not in precedence[-1]:
                                        with self.subTest("higher before lower"):
                                            assert_find_higher(
                                                (higher, lower), both=size > 0
                                            )
                                    with self.subTest("lower before higher"):
                                        assert_find_higher(
                                            (lower, higher), both=size > 0
                                        )

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
                self.assertEqual(prog.symbol("first"), first)
                self.assertEqual(prog.symbol("second"), second)
                self.assertRaises(LookupError, prog.symbol, "third")

                self.assert_symbols_equal_unordered(prog.symbols("first"), [first])
                self.assert_symbols_equal_unordered(prog.symbols("second"), [second])
                self.assertEqual(prog.symbols("third"), [])

    def test_by_name_binding_precedence(self):
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
            self.assertCountEqual(
                [sym.address for sym in prog.symbols("foo")], [expected, other]
            )

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
                self.assertEqual(prog.symbol("foo"), symbol)
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

    def test_dynsym(self):
        prog = Program()
        program_add_elf_symbol_file(
            prog,
            "module0",
            dynamic_symbols=[
                ElfSymbol("sym", 0xFFFF0000, 0x8, STT.OBJECT, STB.LOCAL),
            ],
        )

        sym = Symbol("sym", 0xFFFF0000, 0x8, SymbolBinding.LOCAL, SymbolKind.OBJECT)
        self.assertEqual(prog.symbol("sym"), sym)
        self.assertEqual(prog.symbol(0xFFFF0004), sym)

    def test_ignore_dynsym_same_file(self):
        # Test that .dynsym is ignored in a file with both .symtab and .dynsym.
        prog = Program()
        program_add_elf_symbol_file(
            prog,
            "module0",
            # Normally .symtab is a superset of .dynsym, but to test that we
            # ignore .dynsym, make them distinct.
            symbols=[
                ElfSymbol("full", 0xFFFF0000, 0x8, STT.OBJECT, STB.LOCAL),
            ],
            dynamic_symbols=[
                ElfSymbol("partial", 0xFFFF0000, 0x8, STT.OBJECT, STB.LOCAL),
            ],
        )

        self.assertRaises(LookupError, prog.symbol, "partial")

        full = Symbol("full", 0xFFFF0000, 0x8, SymbolBinding.LOCAL, SymbolKind.OBJECT)
        self.assertEqual(prog.symbol("full"), full)
        self.assertEqual(prog.symbol(0xFFFF0004), full)

    def test_ignore_dynsym_separate_files(self):
        # Same as test_ignore_dynsym_same_file(), except .symtab and .dynsym
        # are in different files.
        prog = Program()
        program_add_elf_symbol_file(
            prog,
            "module0",
            dynamic_symbols=[
                ElfSymbol("partial", 0xFFFF0000, 0x8, STT.OBJECT, STB.LOCAL),
            ],
        )
        program_add_elf_symbol_file(
            prog,
            "module0",
            symbols=[
                ElfSymbol("full", 0xFFFF0000, 0x8, STT.OBJECT, STB.LOCAL),
            ],
            dwarf=True,
        )

        self.assertRaises(LookupError, prog.symbol, "partial")

        full = Symbol("full", 0xFFFF0000, 0x8, SymbolBinding.LOCAL, SymbolKind.OBJECT)
        self.assertEqual(prog.symbol("full"), full)
        self.assertEqual(prog.symbol(0xFFFF0004), full)

    def test_override_dynsym(self):
        # Same as test_ignore_dynsym_separate_files(), except we do a lookup in
        # .dynsym before we have .symtab.
        prog = Program()
        program_add_elf_symbol_file(
            prog,
            "module0",
            dynamic_symbols=[
                ElfSymbol("partial", 0xFFFF0000, 0x8, STT.OBJECT, STB.LOCAL),
            ],
        )

        partial = Symbol(
            "partial", 0xFFFF0000, 0x8, SymbolBinding.LOCAL, SymbolKind.OBJECT
        )
        self.assertEqual(prog.symbol("partial"), partial)
        self.assertEqual(prog.symbol(0xFFFF0004), partial)

        program_add_elf_symbol_file(
            prog,
            "module0",
            symbols=[
                ElfSymbol("full", 0xFFFF0000, 0x8, STT.OBJECT, STB.LOCAL),
            ],
            dwarf=True,
        )

        self.assertRaises(LookupError, prog.symbol, "partial")

        full = Symbol("full", 0xFFFF0000, 0x8, SymbolBinding.LOCAL, SymbolKind.OBJECT)
        self.assertEqual(prog.symbol("full"), full)
        self.assertEqual(prog.symbol(0xFFFF0004), full)


@unittest.skipUnless(drgn._with_lzma, "built without lzma support")
class TestGnuDebugdata(TestCase):

    def assert_all_symbols_found_by_name(self, prog, symbols):
        for symbol in symbols:
            self.assertEqual(prog.symbol(symbol.name), symbol)

    def assert_all_symbols_found_by_address(self, prog, symbols):
        for symbol in symbols:
            self.assertEqual(prog.symbol(symbol.address), symbol)
            self.assertEqual(prog.symbol(symbol.address + symbol.size - 1), symbol)

    def assert_all_symbols_returned_by_lookup(self, prog, symbols):
        def sort_key(sym):
            return (sym.address, sym.name)

        expected = sorted(symbols, key=sort_key)
        actual = prog.symbols()
        actual.sort(key=sort_key)
        self.assertEqual(expected, actual)

    def test_gnu_debugdata_and_dynamic_lookup(self):
        gnu_symbols = [
            ElfSymbol("first", 0xFFFF0000, 0x8, STT.FUNC, STB.LOCAL),
            ElfSymbol("second", 0xFFFF0018, 0x8, STT.FUNC, STB.LOCAL),
        ]
        dynamic_symbols = [
            ElfSymbol("third", 0xFFFF0010, 0x8, STT.FUNC, STB.LOCAL),
            ElfSymbol("fourth", 0xFFFF0008, 0x8, STT.FUNC, STB.LOCAL),
        ]
        prog = Program()
        program_add_elf_symbol_file(
            prog,
            "module0",
            dynamic_symbols=dynamic_symbols,
            gnu_debugdata_symbols=gnu_symbols,
        )
        drgn_symbols = [
            Symbol("first", 0xFFFF0000, 0x8, SymbolBinding.LOCAL, SymbolKind.FUNC),
            Symbol("second", 0xFFFF0018, 0x8, SymbolBinding.LOCAL, SymbolKind.FUNC),
            Symbol("third", 0xFFFF0010, 0x8, SymbolBinding.LOCAL, SymbolKind.FUNC),
            Symbol("fourth", 0xFFFF0008, 0x8, SymbolBinding.LOCAL, SymbolKind.FUNC),
        ]
        self.assert_all_symbols_found_by_name(prog, drgn_symbols)
        self.assert_all_symbols_found_by_address(prog, drgn_symbols)
        self.assert_all_symbols_returned_by_lookup(prog, drgn_symbols)

    def test_sizeless_symbols_gnu_debugdata(self):
        gnu_symbols = [
            ElfSymbol("zero", 0xFFFF0000, 0x0, STT.FUNC, STB.LOCAL),
            ElfSymbol("two", 0xFFFF0002, 0x4, STT.FUNC, STB.LOCAL),
            ElfSymbol("ten", 0xFFFF000A, 0x0, STT.FUNC, STB.LOCAL),
        ]
        dynamic_symbols = [
            ElfSymbol("four", 0xFFFF0004, 0x0, STT.FUNC, STB.LOCAL),
            ElfSymbol("eight", 0xFFFF0008, 0x0, STT.FUNC, STB.LOCAL),
        ]
        drgn_symbols = {
            s.name: s
            for s in (
                Symbol("zero", 0xFFFF0000, 0x0, SymbolBinding.LOCAL, SymbolKind.FUNC),
                Symbol("two", 0xFFFF0002, 0x4, SymbolBinding.LOCAL, SymbolKind.FUNC),
                Symbol("four", 0xFFFF0004, 0x0, SymbolBinding.LOCAL, SymbolKind.FUNC),
                Symbol("eight", 0xFFFF0008, 0x0, SymbolBinding.LOCAL, SymbolKind.FUNC),
                Symbol("ten", 0xFFFF000A, 0x0, SymbolBinding.LOCAL, SymbolKind.FUNC),
            )
        }

        for swap in (False, True):
            prog = Program()
            program_add_elf_symbol_file(
                prog,
                "module0",
                dynamic_symbols=gnu_symbols if swap else dynamic_symbols,
                gnu_debugdata_symbols=dynamic_symbols if swap else gnu_symbols,
            )

            self.assert_all_symbols_found_by_name(prog, drgn_symbols.values())
            self.assert_all_symbols_returned_by_lookup(prog, drgn_symbols.values())

            # Address 9 has a best match in .dynsym, despite other sizeless matches
            # in .gnu_debugdata.
            self.assertEqual(drgn_symbols["eight"], prog.symbol(0xFFFF0009))

            # Address 5 is conained by symbol "two" in .gnu_debugdata, despite
            # "four" being a sizeless match in .dynsym.
            self.assertEqual(drgn_symbols["two"], prog.symbol(0xFFFF0005))

            # Address 11 has a best sizeless match of "ten" in .gnu_debugdata,
            # despite having a sizeless match of "eight" in .dynsym.
            self.assertEqual(drgn_symbols["ten"], prog.symbol(0xFFFF000B))

    def test_file_preferences(self):
        # We need to be careful to make the address range the same for both
        # files: so the minimum and maximum address for gnu + dynamic must be
        # the same as for symtab.
        # Normally a debug file would contain the same symbols as the loaded
        # file, plus more. For testing, give them different names to
        # distinguish.
        loaded = [
            ElfSymbol("loaded_lo", 0xFFFF0000, 0x4, STT.FUNC, STB.LOCAL),
            ElfSymbol("loaded_hi", 0xFFFF0004, 0x4, STT.FUNC, STB.LOCAL),
        ]
        debug = [
            ElfSymbol("symtab_lo", 0xFFFF0000, 0x4, STT.OBJECT, STB.LOCAL),
            ElfSymbol("symtab_hi", 0xFFFF0004, 0x4, STT.OBJECT, STB.LOCAL),
        ]
        empty = [ElfSymbol("", 0xFFFF0000, 0, 0, 0, 0, 0)]
        loaded_file_symbols = [
            Symbol("loaded_lo", 0xFFFF0000, 0x4, SymbolBinding.LOCAL, SymbolKind.FUNC),
            Symbol("loaded_hi", 0xFFFF0004, 0x4, SymbolBinding.LOCAL, SymbolKind.FUNC),
        ]
        debug_file_symbols = [
            Symbol(
                "symtab_lo", 0xFFFF0000, 0x4, SymbolBinding.LOCAL, SymbolKind.OBJECT
            ),
            Symbol(
                "symtab_hi", 0xFFFF0004, 0x4, SymbolBinding.LOCAL, SymbolKind.OBJECT
            ),
        ]
        file_choices = {
            "loaded": (
                {"gnu_debugdata_symbols": loaded[:1], "dynamic_symbols": loaded[1:]},
                loaded_file_symbols,
            ),
            "loaded_dyn": (
                {"dynamic_symbols": loaded},
                loaded_file_symbols,
            ),
            "loaded_gnu": (
                {"gnu_debugdata_symbols": loaded},
                loaded_file_symbols,
            ),
            "loaded_gnu_dynempty": (
                {"gnu_debugdata_symbols": loaded, "dynamic_symbols": empty},
                loaded_file_symbols,
            ),
            "debug": (
                {"symbols": debug, "dwarf": True, "loadable": False},
                debug_file_symbols,
            ),
            "debug_dyn": (
                {"dynamic_symbols": debug, "dwarf": True, "loadable": False},
                debug_file_symbols,
            ),
        }

        # First file, second file, whether or not the symtab should be replaced.
        # Combining the symbol table is possible in a corner case (.dynsym from
        # the debug file, plus .gnu_debugdata from the loaded, if the loaded
        # file has no .dynsym of its own). This really ought not to happen in
        # practice, but it's worth ensuring that it's handled safely.
        cases = [
            ("loaded", "debug", "replace"),
            ("loaded_dyn", "debug", "replace"),
            ("loaded_gnu", "debug", "replace"),
            ("loaded_gnu_dynempty", "debug", "replace"),
            ("debug", "loaded", None),
            ("debug", "loaded_dyn", None),
            ("debug", "loaded_gnu", None),
            ("debug", "loaded_gnu_dynempty", None),
            ("loaded", "debug_dyn", None),
            ("loaded_dyn", "debug_dyn", None),
            ("loaded_gnu", "debug_dyn", "combine"),
            ("loaded_gnu_dynempty", "debug_dyn", None),
            # We will replace a .dynsym with another .dynsym only if the file
            # also has a .gnu_debugdata
            ("debug_dyn", "loaded", "replace"),
            ("debug_dyn", "loaded_dyn", None),
            ("debug_dyn", "loaded_gnu", "combine"),
            ("debug_dyn", "loaded_gnu_dynempty", "replace"),
        ]

        for first, second, action in cases:
            with self.subTest(f"{first}, {second}"):
                prog = Program()
                module = prog.extra_module("module0", create=True)
                module_set_elf_symbol_file(module, **file_choices[first][0])
                expected = file_choices[first][1]
                self.assert_all_symbols_found_by_name(prog, expected)
                self.assert_all_symbols_found_by_address(prog, expected)
                self.assert_all_symbols_returned_by_lookup(prog, expected)

                module_set_elf_symbol_file(module, **file_choices[second][0])
                if action == "replace":
                    expected = file_choices[second][1]
                elif action == "combine":
                    expected = expected + file_choices[second][1]
                self.assert_all_symbols_found_by_name(prog, expected)
                # We end up with overlapping symbols when tables get combined.
                # Don't bother checking address lookup there.
                if action != "combine":
                    self.assert_all_symbols_found_by_address(prog, expected)
                self.assert_all_symbols_returned_by_lookup(prog, expected)


class TestSymbolFinder(TestCase):
    TEST_SYMS = [
        Symbol("one", 0xFFFF1000, 16, SymbolBinding.LOCAL, SymbolKind.FUNC),
        Symbol("two", 0xFFFF2000, 16, SymbolBinding.GLOBAL, SymbolKind.FUNC),
        Symbol("three", 0xFFFF2008, 8, SymbolBinding.GLOBAL, SymbolKind.FUNC),
    ]

    def finder(self, prog, arg_name, arg_address, arg_one):
        self.called = True
        res = []
        self.assertEqual(self.expected_name, arg_name)
        self.assertEqual(self.expected_address, arg_address)
        self.assertEqual(self.expected_one, arg_one)
        for sym in self.TEST_SYMS:
            if arg_name and sym.name == arg_name:
                res.append(sym)
            elif arg_address and sym.address <= arg_address < sym.address + sym.size:
                res.append(sym)
            elif not arg_name and not arg_address:
                res.append(sym)

        # This symbol finder intentionally has a bug: it does not respect the
        # "arg_one" flag: it may return multiple symbols even when "arg_one" is
        # true.
        return res

    def setUp(self):
        self.prog = Program()
        self.prog.register_symbol_finder("test", self.finder, enable_index=0)
        self.called = False

    def expect_args(self, name, address, one):
        self.expected_name = name
        self.expected_address = address
        self.expected_one = one

    def test_args_single_string(self):
        self.expect_args("search_symbol", None, True)
        with self.assertRaises(LookupError):
            self.prog.symbol("search_symbol")
        self.assertTrue(self.called)

    def test_args_single_int(self):
        self.expect_args(None, 0xFF00, True)
        with self.assertRaises(LookupError):
            self.prog.symbol(0xFF00)
        self.assertTrue(self.called)

    def test_args_single_with_many_results(self):
        self.expect_args(None, 0xFFFF2008, True)
        with self.assertRaises(ValueError):
            self.prog.symbol(0xFFFF2008)
        self.assertTrue(self.called)

    def test_single_with_result(self):
        self.expect_args("one", None, True)
        self.assertEqual(self.prog.symbol("one"), self.TEST_SYMS[0])
        self.assertTrue(self.called)

    def test_args_many_string(self):
        self.expect_args("search_symbol", None, False)
        self.assertEqual(self.prog.symbols("search_symbol"), [])
        self.assertTrue(self.called)

    def test_args_many_int(self):
        self.expect_args(None, 0xFF00, False)
        self.assertEqual(self.prog.symbols(0xFF00), [])
        self.assertTrue(self.called)

    def test_many_with_result(self):
        self.expect_args(None, 0xFFFF2004, False)
        self.assertEqual(self.prog.symbols(0xFFFF2004), [self.TEST_SYMS[1]])
        self.assertTrue(self.called)

    def test_many_without_filter(self):
        self.expect_args(None, None, False)
        self.assertEqual(self.prog.symbols(), self.TEST_SYMS)
        self.assertTrue(self.called)


class TestSymbolIndex(TestCase):
    # Symbols are listed here in order of address, but are shuffled below
    AA = Symbol("AA", 10, 5, SymbolBinding.GLOBAL, SymbolKind.OBJECT)
    BB = Symbol("BB", 12, 1, SymbolBinding.GLOBAL, SymbolKind.OBJECT)
    CC = Symbol("CC", 13, 8, SymbolBinding.GLOBAL, SymbolKind.OBJECT)
    DD = Symbol("DD", 28, 5, SymbolBinding.GLOBAL, SymbolKind.OBJECT)
    EE = Symbol("EE", 34, 1, SymbolBinding.GLOBAL, SymbolKind.OBJECT)
    FF = Symbol("FF", 34, 10, SymbolBinding.GLOBAL, SymbolKind.OBJECT)
    GG = Symbol("GG", 34, 2, SymbolBinding.GLOBAL, SymbolKind.OBJECT)
    BB2 = Symbol("BB", 36, 3, SymbolBinding.GLOBAL, SymbolKind.OBJECT)

    TEST_SYMS = [GG, BB, AA, BB2, CC, FF, DD, EE]

    def setUp(self):
        # This class tests both the SymbolIndex callable interface, and the
        # Symbol Finder API. While this seems like it duplicates code, it's
        # necessary to test both since they exercise different code paths: the
        # Symbol Finder API uses a more efficient fast path.
        self.finder = SymbolIndex(self.TEST_SYMS)
        self.prog = Program()
        self.prog.register_symbol_finder("test", self.finder, enable_index=0)

    def test_name_single(self):
        for sym in self.TEST_SYMS:
            if sym.name != "BB":
                self.assertEqual([sym], self.finder(self.prog, sym.name, None, True))
                self.assertEqual(sym, self.prog.symbol(sym.name))
                self.assertEqual([sym], self.finder(self.prog, sym.name, None, False))
                self.assertEqual([sym], self.prog.symbols(sym.name))

    def test_name_multiple(self):
        multi_result = self.finder(self.prog, "BB", None, False)
        self.assertEqual(2, len(multi_result))
        self.assertIn(self.BB, multi_result)
        self.assertIn(self.BB2, multi_result)

        multi_result = self.prog.symbols("BB")
        self.assertEqual(2, len(multi_result))
        self.assertIn(self.BB, multi_result)
        self.assertIn(self.BB2, multi_result)

        single_result = self.finder(self.prog, "BB", None, True)
        self.assertIn(single_result[0], (self.BB, self.BB2))

        single_result = self.prog.symbol("BB")
        self.assertIn(single_result, (self.BB, self.BB2))

    def test_addr(self):
        cases = {
            9: [],
            10: [self.AA],
            12: [self.AA, self.BB],
            13: [self.AA, self.CC],
            15: [self.CC],
            25: [],
            28: [self.DD],
            30: [self.DD],
            34: [self.EE, self.FF, self.GG],
            35: [self.FF, self.GG],
            36: [self.FF, self.BB2],
            43: [self.FF],
            44: [],
        }
        for address, expected in cases.items():
            # first, lookup by address alone and ensure we get all correct
            # candidates:
            multi_result = self.finder(self.prog, None, address, False)
            self.assertEqual(len(expected), len(multi_result))
            self.assertTrue(all(e in multi_result for e in expected))
            multi_result = self.prog.symbols(address)
            self.assertEqual(len(expected), len(multi_result))
            self.assertTrue(all(e in multi_result for e in expected))

            # next, ensure that the single lookup works as expected:
            if expected:
                single_result = self.finder(self.prog, None, address, True)
                self.assertEqual(1, len(single_result))
                self.assertIn(single_result[0], expected)
                single_result = self.prog.symbol(address)
                self.assertIn(single_result, expected)

            # Now, test that adding a name filter correctly filters:
            # This cannot be tested with the Program.symbol() API since only
            # one filter is allowed there.
            for sym in expected:
                self.assertEqual([sym], self.finder(self.prog, sym.name, address, True))
                self.assertEqual(
                    [sym], self.finder(self.prog, sym.name, address, False)
                )

            self.assertEqual([], self.finder(None, "MISSING", address, True))
            self.assertEqual([], self.finder(None, "MISSING", address, False))

    def test_all(self):
        result = self.finder(self.prog, None, None, True)
        self.assertEqual(1, len(result))
        self.assertIn(result[0], self.TEST_SYMS)
        result = self.finder(self.prog, None, None, False)
        self.assertEqual(len(self.TEST_SYMS), len(result))
        for sym in self.TEST_SYMS:
            self.assertIn(sym, result)
        result = self.prog.symbols()
        self.assertEqual(len(self.TEST_SYMS), len(result))
        for sym in self.TEST_SYMS:
            self.assertIn(sym, result)

    def test_empty_index(self):
        index = SymbolIndex([])
        # Check all the possible query patterns to ensure they can safely handle
        # an empty list.
        self.assertEqual([], index(self.prog, "name search", None, True))
        self.assertEqual([], index(self.prog, "name search", None, False))
        self.assertEqual([], index(self.prog, None, 0xFFFF, True))
        self.assertEqual([], index(self.prog, None, 0xFFFF, False))
        self.assertEqual([], index(self.prog, "name search", 0xFFFF, True))
        self.assertEqual([], index(self.prog, "name search", 0xFFFF, False))
