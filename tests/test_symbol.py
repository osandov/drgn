# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import itertools
import tempfile

from _drgn_util.elf import ET, PT, SHF, SHT, STB, STT
from drgn import Program, Symbol, SymbolBinding, SymbolIndex, SymbolKind
from tests import TestCase
from tests.elfwriter import ElfSection, ElfSymbol, create_elf_file


def create_elf_symbol_file(symbols):
    # Create a section for the symbols to reference and the corresponding
    # segment for address lookups. It must be SHF_ALLOC and must not be
    # SHT_NOBITS or SHT_NOTE for the file to be loadable.
    start = min(symbol.value for symbol in symbols) & ~7
    end = (max(symbol.value + max(symbol.size, 1) for symbol in symbols) + 7) & ~7
    size = end - start
    assert size <= 4096, "symbols are too far apart; file would be too large"
    sections = [
        ElfSection(
            name=".data",
            sh_type=SHT.PROGBITS,
            sh_flags=SHF.ALLOC,
            p_type=PT.LOAD,
            vaddr=start,
            memsz=size,
            data=bytes(size),
        ),
    ]
    symbols = [
        symbol._replace(
            shindex=len(sections) if symbol.shindex is None else symbol.shindex
        )
        for symbol in symbols
    ]
    return create_elf_file(ET.EXEC, sections, symbols), start, end


def elf_symbol_program(*modules):
    prog = Program()
    address_ranges = []
    for symbols in modules:
        with tempfile.NamedTemporaryFile() as f:
            contents, start, end = create_elf_symbol_file(symbols)
            f.write(contents)
            f.flush()
            for i, (other_start, other_end) in enumerate(address_ranges):
                assert (
                    end <= other_start or start >= other_end
                ), f"module {len(address_ranges)} overlaps module {i}"
            address_ranges.append((start, end))
            module = prog.extra_module(f.name, create=True)[0]
            module.address_range = (start, end)
            module.try_file(f.name, force=True)
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
