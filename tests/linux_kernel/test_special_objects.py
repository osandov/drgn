# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os

from drgn import Object, ObjectNotFoundError, Program
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod


class TestJiffies(LinuxKernelTestCase):
    def test_jiffies(self):
        self.assertIdentical(
            self.prog["jiffies"],
            Object(
                self.prog,
                "volatile unsigned long",
                address=self.prog.symbol("jiffies").address,
            ),
        )


class TestUts(LinuxKernelTestCase):
    def test_uts_release(self):
        self.assertEqual(
            self.prog["UTS_RELEASE"].string_().decode(), os.uname().release
        )

    def test_uts_release_no_debug_info(self):
        prog = Program()
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
        prog = Program()
        prog.set_kernel()
        vmcoreinfo_data = dict(
            line.split("=", 1)
            for line in prog["VMCOREINFO"].string_().decode().strip().split("\n")
        )
        self.assertEqual(
            vmcoreinfo_data["OSRELEASE"],
            os.uname().release,
        )

    @skip_unless_have_test_kmod
    def test_constants(self):
        for constant in (
            "THREAD_SIZE",
            "NR_SECTION_ROOTS",
            "SECTIONS_PER_ROOT",
        ):
            with self.subTest(constant=constant):
                try:
                    expected = self.prog["drgn_test_" + constant].read_()
                except ObjectNotFoundError:
                    with self.assertRaises(ObjectNotFoundError):
                        self.prog[constant]
                else:
                    self.assertEqual(self.prog[constant], expected)
