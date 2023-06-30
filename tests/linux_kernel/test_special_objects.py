# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os

import drgn
from tests.linux_kernel import LinuxKernelTestCase


class TestUts(LinuxKernelTestCase):
    def test_uts_release(self):
        self.assertEqual(
            self.prog["UTS_RELEASE"].string_().decode(), os.uname().release
        )

    def test_uts_release_no_debug_info(self):
        prog = drgn.Program()
        prog.set_kernel()
        self.assertEqual(prog["UTS_RELEASE"].string_().decode(), os.uname().release)


class TestVmcoreinfo(LinuxKernelTestCase):
    def test_vmcoreinfo(self):
        vmcoreinfo_data = dict(
            line.split("=", 1)
            for line in self.prog["VMCOREINFO"].string_().decode().strip().split("\n")
        )
        self.assertEqual(
            int(vmcoreinfo_data["SYMBOL(init_uts_ns)"], 16),
            self.prog.symbol("init_uts_ns").address,
        )

    def test_vmcoreinfo_no_debug_info(self):
        prog = drgn.Program()
        prog.set_kernel()
        vmcoreinfo_data = dict(
            line.split("=", 1)
            for line in prog["VMCOREINFO"].string_().decode().strip().split("\n")
        )
        self.assertEqual(
            vmcoreinfo_data["OSRELEASE"],
            os.uname().release,
        )
