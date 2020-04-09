import platform
import re
import unittest

from drgn.helpers.linux.mm import pgtable_l5_enabled
from tests.helpers.linux import LinuxHelperTestCase


class TestMm(LinuxHelperTestCase):
    @unittest.skipUnless(platform.machine() == "x86_64", "machine is not x86_64")
    def test_pgtable_l5_enabled(self):
        with open("/proc/cpuinfo", "r") as f:
            self.assertEqual(
                pgtable_l5_enabled(self.prog),
                bool(re.search(r"flags\s*:.*\bla57\b", f.read())),
            )
