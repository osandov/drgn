import unittest

from drgn import Architecture, Platform


class TestPlatform(unittest.TestCase):
    def test_default_flags(self):
        Platform(Architecture.X86_64)
        self.assertRaises(ValueError, Platform, Architecture.UNKNOWN)
