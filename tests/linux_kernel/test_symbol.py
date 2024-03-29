# Copyright (c) 2021, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn import SymbolBinding, SymbolKind
from tests.linux_kernel import LinuxKernelTestCase


class TestSymbol(LinuxKernelTestCase):
    def test_global_symbol(self):
        symbol = self.prog.symbol("jiffies")
        self.assertEqual(symbol.name, "jiffies")
        self.assertEqual(symbol.binding, SymbolBinding.GLOBAL)
        self.assertEqual(symbol.kind, SymbolKind.OBJECT)
