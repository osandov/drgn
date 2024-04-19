# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn import filename_matches
from tests import TestCase


class TestFilenameMatches(TestCase):
    def test_filename_matches(self):
        self.assertTrue(filename_matches("ab/cd/ef", "ef"))
        self.assertTrue(filename_matches("ab/cd/ef", "cd/ef"))
        self.assertFalse(filename_matches("ab/cd/ef", "d/ef"))
        self.assertFalse(filename_matches("/ef", "cd/ef"))
        self.assertTrue(filename_matches("/abc", "abc"))
        self.assertFalse(filename_matches("abc", "/abc"))

    def test_empty(self):
        self.assertTrue(filename_matches("", ""))
        self.assertTrue(filename_matches("ab", ""))
        self.assertFalse(filename_matches("", "ab"))

    def test_one_component(self):
        self.assertTrue(filename_matches("ab", "ab"))
        self.assertFalse(filename_matches("ab", "cd"))

    def test_multiple_components(self):
        self.assertTrue(filename_matches("ab/cd/ef", "ef"))
        self.assertTrue(filename_matches("ab/cd/ef", "cd/ef"))
        self.assertFalse(filename_matches("ab/cd/ef", "cd"))
        self.assertFalse(filename_matches("ab/cd/ef", "ab/ef"))
        self.assertFalse(filename_matches("ef", "ab/cd/ef"))

    def test_component_substring(self):
        self.assertFalse(filename_matches("ab/cd/ef", "d/ef"))

    def test_absolute(self):
        self.assertTrue(filename_matches("/abc", "abc"))
        self.assertFalse(filename_matches("abc", "/abc"))
