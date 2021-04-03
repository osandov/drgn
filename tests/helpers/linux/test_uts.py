# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import os

import drgn
from tests.helpers.linux import LinuxHelperTestCase


class TestUts(LinuxHelperTestCase):
    def test_uts_release(self):
        self.assertEqual(
            self.prog["UTS_RELEASE"].string_().decode(), os.uname().release
        )

    def test_uts_release_no_debug_info(self):
        prog = drgn.Program()
        prog.set_kernel()
        self.assertEqual(prog["UTS_RELEASE"].string_().decode(), os.uname().release)
