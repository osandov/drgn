# Copyright (c) 2021, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn import SymbolBinding, SymbolKind
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod


class TestSymbol(LinuxKernelTestCase):
    def test_global_symbol(self):
        symbol = self.prog.symbol("jiffies")
        self.assertEqual(symbol.name, "jiffies")
        self.assertEqual(symbol.binding, SymbolBinding.GLOBAL)
        self.assertEqual(symbol.kind, SymbolKind.OBJECT)

    @skip_unless_have_test_kmod
    def test_module_function_symbol(self):
        symbol = self.prog.symbol("drgn_test_function")
        self.assertEqual(symbol.name, "drgn_test_function")
        self.assertEqual(symbol.binding, SymbolBinding.GLOBAL)
        self.assertEqual(symbol.kind, SymbolKind.FUNC)

        symbol = self.prog.symbol(symbol.address)
        self.assertEqual(symbol.name, "drgn_test_function")
        self.assertEqual(symbol.binding, SymbolBinding.GLOBAL)
        self.assertEqual(symbol.kind, SymbolKind.FUNC)

    @skip_unless_have_test_kmod
    def test_module_data_symbol(self):
        symbol = self.prog.symbol("drgn_test_data")
        self.assertEqual(symbol.name, "drgn_test_data")
        self.assertEqual(symbol.binding, SymbolBinding.GLOBAL)
        self.assertEqual(symbol.kind, SymbolKind.OBJECT)

        symbol = self.prog.symbol(symbol.address)
        self.assertEqual(symbol.name, "drgn_test_data")
        self.assertEqual(symbol.binding, SymbolBinding.GLOBAL)
        self.assertEqual(symbol.kind, SymbolKind.OBJECT)

    @skip_unless_have_test_kmod
    def test_module_rodata_symbol(self):
        symbol = self.prog.symbol("drgn_test_rodata")
        self.assertEqual(symbol.name, "drgn_test_rodata")
        self.assertEqual(symbol.binding, SymbolBinding.GLOBAL)
        self.assertEqual(symbol.kind, SymbolKind.OBJECT)

        symbol = self.prog.symbol(symbol.address)
        self.assertEqual(symbol.name, "drgn_test_rodata")
        self.assertEqual(symbol.binding, SymbolBinding.GLOBAL)
        self.assertEqual(symbol.kind, SymbolKind.OBJECT)
