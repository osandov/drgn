# Copyright (c) ByteDance, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path
import unittest

from drgn.helpers.linux.nodemask import for_each_node, for_each_online_node
from tests.helpers.linux import LinuxHelperTestCase, parse_range_list

NODE_PATH = Path("/sys/devices/system/node")


@unittest.skipUnless(NODE_PATH.exists(), "kernel does not support NUMA")
class TestNodeMask(LinuxHelperTestCase):
    def _test_for_each_node(self, func, name):
        self.assertEqual(
            list(func(self.prog)),
            sorted(parse_range_list((NODE_PATH / name).read_text())),
        )

    def test_for_each_node(self):
        self._test_for_each_node(for_each_node, "possible")

    def test_for_each_online_node(self):
        self._test_for_each_node(for_each_online_node, "online")
