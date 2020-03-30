from functools import cmp_to_key
import unittest

from util import Version, verrevcmp


class TestUtil(unittest.TestCase):
    def assertVersionSort(self, sorted_list):
        self.assertEqual(sorted(sorted_list, key=cmp_to_key(verrevcmp)), sorted_list)

    def test_verrevcmp(self):
        self.assertVersionSort(
            ["0~", "0", "1", "1.0", "1.1~rc1", "1.1~rc2", "1.1", "1.2", "1.12"]
        )
        self.assertVersionSort(["a", "."])
        self.assertVersionSort(["", "1"])
        self.assertVersionSort(["~", "~1"])
        self.assertVersionSort(["~~", "~~a", "~", "", "a"])

    def test_version(self):
        self.assertLess(Version("1.0"), Version("2.0"))
        self.assertLess(Version("5.6.0-rc6"), Version("5.6.0-rc7"))
        self.assertLess(Version("5.6.0-rc7"), Version("5.6.0"))
        self.assertLess(Version("5.6.0-rc7-vmtest2"), Version("5.6.0-vmtest1"))
        self.assertLess(Version("5.6.0-vmtest1"), Version("5.6.0-vmtest2"))
