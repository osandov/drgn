# Copyright (c) 2024 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later
from drgn.helpers.linux.module import (
    address_to_module,
    find_module,
    for_each_module,
    module_address_regions,
    module_percpu_region,
)
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod


class TestListModules(LinuxKernelTestCase):
    def test_for_each_module(self):
        sys_modules = set(line.split(maxsplit=1)[0] for line in open("/proc/modules"))
        drgn_modules = set()
        for module in for_each_module(self.prog):
            drgn_modules.add(module.name.string_().decode())

        self.assertEqual(sys_modules, drgn_modules)


@skip_unless_have_test_kmod
class TestModules(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = find_module(cls.prog, "drgn_test")

    def test_module_percpu_region(self):
        pcpu_addr = self.prog.symbol("drgn_test_percpu_static").address
        start, size = module_percpu_region(self.mod)
        if start == 0:
            self.skipTest("No module percpu region on !SMP")
        self.assertTrue(start <= pcpu_addr <= start + size)

    def test_module_address_regions(self):
        regions = module_address_regions(self.mod)

        def assertInRegions(addr):
            for start, size in regions:
                if start <= addr < start + size:
                    break
            else:
                self.fail(f"address {addr:x} not found in drgn_test module regions")

            self.assertEqual(address_to_module(self.prog, addr), self.mod)

        # function symbol (should be in .text)
        assertInRegions(self.prog.symbol("drgn_test_function").address)
        # variable symbol (should be in .data)
        assertInRegions(self.prog.symbol("drgn_test_empty_list").address)
        # constant variable (should be in .rodata)
        assertInRegions(self.prog.symbol("drgn_test_have_maple_tree").address)
