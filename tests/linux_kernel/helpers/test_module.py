# Copyright (c) 2022, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn.helpers.linux.module import (
    address_to_module,
    for_each_module,
    module_address_region,
)
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod


class TestModule(LinuxKernelTestCase):
    @skip_unless_have_test_kmod
    def test_address_to_module(self):
        symbol = self.prog.symbol("drgn_test_empty_list")
        module = address_to_module(self.prog, symbol.address)
        self.assertEqual(module.name.string_(), b"drgn_test")

    def test_layout_contains_symbol(self):
        for module in for_each_module(self.prog):
            layout = module_address_region(module)
            # We can't have any prior knowledge about the layout of the module,
            # but we can be nearly certain that the first address (a text
            # address) will have a symbol we can lookup. Most addresses don't
            # have a corresponding symbol, so the success of this operation
            # (without LookupError) does a halfay decent job at validating the
            # layout.
            self.prog.symbol(layout.base)
