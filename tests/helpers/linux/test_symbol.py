# Copyright (c) 2021, Oracle and/or its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

from drgn import SymbolBinding, SymbolKind
from tests.helpers.linux import LinuxHelperTestCase


class TestSymbol(LinuxHelperTestCase):
    def test_global_symbol(self):
        symbol = self.prog.symbol("jiffies")
        self.assertEqual(symbol.name, "jiffies")
        self.assertEqual(symbol.binding, SymbolBinding.GLOBAL)
        self.assertEqual(symbol.kind, SymbolKind.OBJECT)
