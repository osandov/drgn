from pathlib import Path
import unittest

from drgn import Program, ProgramFlags

VMCORE_PATH = Path("/proc/vmcore")


@unittest.skipUnless(VMCORE_PATH.exists(), "not running in kdump")
class TestAttachToVMCore(unittest.TestCase):
    def test_attach_to_vmcore(self):
        prog = Program()
        prog.set_core_dump("/proc/vmcore")
        self.assertFalse(prog.flags & ProgramFlags.IS_LIVE)
        self.assertTrue(prog.flags & ProgramFlags.IS_LINUX_KERNEL)
