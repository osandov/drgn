# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

import _drgn
import drgn


class TestModule(unittest.TestCase):
    def test_all(self):
        # At least for now, everything in the Python library should go in
        # __all__, so make sure that happens.
        from_python = {
            name
            for name in dir(drgn)
            if not name.startswith("_")
            and getattr(getattr(drgn, name), "__module__", "").startswith("drgn")
        }
        self.assertEqual(from_python - set(drgn.__all__), set())

    def test_bindings(self):
        # Make sure everything in the C extension (_drgn) is added to the
        # Python library (drgn).
        from_extension = {name for name in dir(_drgn) if not name.startswith("_")}
        self.assertEqual(from_extension - set(dir(drgn)), set())
        self.assertEqual(from_extension - set(drgn.__all__), set())
