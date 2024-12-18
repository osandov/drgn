# Copyright (c) 2024 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later
import re
import tempfile
from unittest import TestCase

from drgn import Symbol, SymbolBinding, SymbolKind
from drgn.helpers.linux.kallsyms import (
    _load_builtin_kallsyms,
    _load_proc_kallsyms,
    load_module_kallsyms,
)
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod


def compare_local_symbols(self, finder, modules=False):
    expr = re.compile(
        r"(?P<address>[0-9a-f]+) (?P<kind>.) " r"(?P<name>[^\s]+)(\s+(?P<mod>\[\w+\]))?"
    )
    names = {}
    count = 0
    with open("/proc/kallsyms") as f:
        for line in f:
            match = expr.fullmatch(line.strip())
            self.assertIsNotNone(match, line)
            if match.group("mod") and not modules:
                break
            count += 1
            name = match.group("name")
            addr = int(match.group("address"), 16)
            names.setdefault(name, []).append((addr, match.group("kind"), name))

    for name, syms in names.items():
        res = finder(None, name, None, False)
        expected_addrs = sorted(t[0] for t in syms)
        found_addrs = sorted(s.address for s in res)
        self.assertEqual(expected_addrs, found_addrs)

    all_res = finder(None, None, None, False)
    self.assertEqual(count, len(all_res))


KALLSYMS_DATA = b"""\
0000000000000000 u null
0000000000000008 d local_data
0000000000000010 B global_bss
0000000000000020 v weak_symbol
0000000000000040 ? unknown
0000000000001000 T text [mymod]
0000000000002000 T modfunc1 [mymod2]
0000000000002010 T modfunc2 [mymod2]
0000000000002008 T modfunc3 [mymod2]
"""


class TestProcKallsyms(TestCase):
    def test_static_data(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(KALLSYMS_DATA)
            f.flush()
            finder = _load_proc_kallsyms(filename=f.name)

        syms = finder(None, None, None, False)
        expected = [
            Symbol("null", 0x0, 8, SymbolBinding.UNIQUE, SymbolKind.UNKNOWN),
            Symbol("local_data", 0x8, 8, SymbolBinding.UNKNOWN, SymbolKind.OBJECT),
            Symbol("global_bss", 0x10, 16, SymbolBinding.GLOBAL, SymbolKind.OBJECT),
            Symbol("weak_symbol", 0x20, 32, SymbolBinding.WEAK, SymbolKind.OBJECT),
            # this one has zero size since it is at the end of vmlinux
            Symbol("unknown", 0x40, 0, SymbolBinding.UNKNOWN, SymbolKind.UNKNOWN),
        ]
        self.assertEqual(syms, expected)

    def test_static_data_with_modules(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(KALLSYMS_DATA)
            f.flush()
            finder = _load_proc_kallsyms(filename=f.name, modules=True)

        syms = finder(None, None, None, False)
        expected = [
            Symbol("null", 0x0, 8, SymbolBinding.UNIQUE, SymbolKind.UNKNOWN),
            Symbol("local_data", 0x8, 8, SymbolBinding.UNKNOWN, SymbolKind.OBJECT),
            Symbol("global_bss", 0x10, 16, SymbolBinding.GLOBAL, SymbolKind.OBJECT),
            Symbol("weak_symbol", 0x20, 32, SymbolBinding.WEAK, SymbolKind.OBJECT),
            # this one has zero size since it is at the end of vmlinux
            Symbol("unknown", 0x40, 0, SymbolBinding.UNKNOWN, SymbolKind.UNKNOWN),
            # this one has zero size since it is at the end of a module
            Symbol("text", 0x1000, 0, SymbolBinding.GLOBAL, SymbolKind.FUNC),
            # this one has a non-zero size since it is within a module
            Symbol("modfunc1", 0x2000, 16, SymbolBinding.GLOBAL, SymbolKind.FUNC),
            # this one has a zero size since it is at the end of the file. It is
            # returned in sorted order by address despite kallsyms not
            # containing it in sorted order.
            Symbol("modfunc3", 0x2008, 0, SymbolBinding.GLOBAL, SymbolKind.FUNC),
            # this one has a zero size since it is followed by an out-of-order
            # symbol
            Symbol("modfunc2", 0x2010, 0, SymbolBinding.GLOBAL, SymbolKind.FUNC),
        ]
        self.assertEqual(syms, expected)


class TestBuiltinKallsyms(LinuxKernelTestCase):
    def test_builtin_kallsyms(self):
        if b"kallsyms_num_syms" not in self.prog["VMCOREINFO"].string_():
            self.skipTest("VMCOREINFO is missing necessary symbols")
        finder = _load_builtin_kallsyms(self.prog)
        compare_local_symbols(self, finder)

    @skip_unless_have_test_kmod
    def test_module_kallsyms(self):
        finder = load_module_kallsyms(self.prog)
        test_data = finder(None, "drgn_test_empty_list", None, True)[0]
        self.assertEqual("drgn_test_empty_list", test_data.name)
        self.assertEqual(SymbolKind.OBJECT, test_data.kind)
        self.assertIn(test_data.binding, (SymbolBinding.GLOBAL, SymbolBinding.UNKNOWN))
        size = self.prog.type("struct list_head").size
        self.assertEqual(size, test_data.size)
        address = self.prog.object("drgn_test_empty_list").address_
        self.assertEqual(address, test_data.address)
