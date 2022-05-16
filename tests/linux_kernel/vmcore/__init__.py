# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path
import unittest

import drgn
from tests import TestCase
from tests.linux_kernel import LinuxKernelTestCase

VMCORE_PATH = Path("/proc/vmcore")


@unittest.skipUnless(VMCORE_PATH.exists(), "not running in kdump")
class LinuxVMCoreTestCase(TestCase):
    prog = None

    @classmethod
    def setUpClass(cls):
        # We only want to create the Program once for all tests, so it's cached
        # as a class variable (in the base class).
        if LinuxVMCoreTestCase.prog is None:
            prog = drgn.Program()
            prog.set_core_dump(VMCORE_PATH)
            LinuxKernelTestCase._load_debug_info(prog)
            LinuxVMCoreTestCase.prog = prog
