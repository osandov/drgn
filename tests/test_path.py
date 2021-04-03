# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import itertools
import os.path
import unittest

from drgn import filename_matches
from tests.libdrgn import PathIterator, path_ends_with


# normpath("//") returns "//". See https://bugs.python.org/issue26329.
def my_normpath(path):
    path = os.path.normpath(path)
    if path[:2] == "//":
        return path[1:]
    else:
        return path


# Given a sequence of components, generate all of the possible combinations of
# joining or not joining those components with '/'.
def join_combinations(components):
    if len(components) > 1:
        for join in itertools.product([False, True], repeat=len(components) - 1):
            combination = [components[0]]
            for i in range(1, len(components)):
                if join[i - 1]:
                    combination[-1] += "/" + components[i]
                else:
                    combination.append(components[i])
            yield combination
    else:
        yield components


class TestPathIterator(unittest.TestCase):
    def assertComponents(self, path_components, expected, combinations=True):
        if combinations:
            cases = join_combinations(path_components)
        else:
            cases = (path_components,)
        for case in cases:
            with self.subTest(case=case):
                self.assertEqual(list(PathIterator(*case)), expected)

    def test_empty(self):
        self.assertEqual(list(PathIterator()), [])
        self.assertEqual(list(PathIterator("")), [])
        self.assertEqual(list(PathIterator("", "")), [])

    def test_simple(self):
        self.assertComponents(("a",), ["a"])
        self.assertComponents(("abc", "def"), ["def", "abc"])
        self.assertComponents(("abc", "def", "ghi"), ["ghi", "def", "abc"])

    def test_root(self):
        self.assertComponents(("/",), [""])
        self.assertComponents(("/", ""), [""])
        self.assertComponents(("", "/"), [""])
        self.assertComponents(("", "/", ""), [""])

    def test_absolute(self):
        self.assertComponents(("/root",), ["root", ""])
        self.assertComponents(("/./usr",), ["usr", ""])
        self.assertComponents(("/home", "user"), ["user", "home", ""])
        self.assertComponents(("foo", "/root"), ["root", ""], combinations=False)

    def test_redundant_slash(self):
        self.assertComponents(("a/",), ["a"])
        self.assertComponents(("a//",), ["a"])
        self.assertComponents(("//",), [""])
        self.assertComponents(("//a",), ["a", ""])
        self.assertComponents(("///a",), ["a", ""])

    def test_dot(self):
        self.assertComponents(("a", "."), ["a"])
        self.assertComponents((".", "a"), ["a"])
        self.assertComponents((".", "a", "."), ["a"])

    def test_dot_dot(self):
        self.assertComponents(("a", "b", ".."), ["a"])
        self.assertComponents(("a", "..", "b"), ["b"])

    def test_relative_dot_dot(self):
        self.assertComponents(("..", "one", "two"), ["two", "one", ".."])
        self.assertComponents(("one", "..", "..", "two"), ["two", ".."])
        self.assertComponents(("one", "two", "..", "..", ".."), [".."])

    def test_dot_dot_above_root(self):
        self.assertComponents(("/..", "one", "two"), ["two", "one", ""])
        self.assertComponents(("/one", "..", "..", "two"), ["two", ""])
        self.assertComponents(("/one", "two", "..", "..", ".."), [""])

    def test_current_directory(self):
        self.assertComponents((".",), [])
        self.assertComponents(("", "."), [], combinations=False)
        self.assertComponents((".", ""), [])
        self.assertComponents((".", "."), [])
        self.assertComponents(("foo", ".."), [])
        self.assertComponents(("a", "b", "..", ".."), [])

    def assertPathEndsWith(self, haystack, needle):
        self.assertTrue(path_ends_with(PathIterator(*haystack), PathIterator(*needle)))
        self.assertTrue(
            filename_matches(os.path.join(*haystack), os.path.join(*needle))
        )

    def assertNotPathEndsWith(self, haystack, needle):
        self.assertFalse(path_ends_with(PathIterator(*haystack), PathIterator(*needle)))
        self.assertFalse(
            filename_matches(os.path.join(*haystack), os.path.join(*needle))
        )

    def test_path_ends_with(self):
        self.assertPathEndsWith(("ab/cd/ef",), ("ef",))
        self.assertPathEndsWith(("ab/cd/ef",), ("cd/ef",))
        self.assertNotPathEndsWith(("ab/cd/ef",), ("d/ef",))
        self.assertNotPathEndsWith(("ab/cd", "/ef"), ("cd/ef",))
        self.assertPathEndsWith(("/abc",), ("abc",))
        self.assertNotPathEndsWith(("abc",), ("/abc",))
