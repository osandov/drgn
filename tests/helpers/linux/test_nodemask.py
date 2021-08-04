# Copyright (c) ByteDance, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path
import unittest

from drgn.helpers.linux.nodemask import for_each_node, for_each_online_node, node_state
from tests.helpers.linux import LinuxHelperTestCase, parse_range_list

NODE_PATH = Path("/sys/devices/system/node")


@unittest.skipUnless(NODE_PATH.exists(), "kernel does not support NUMA")
class TestNodeMask(LinuxHelperTestCase):
    @staticmethod
    def _parse_node_list(name):
        return parse_range_list((NODE_PATH / name).read_text())

    def _test_for_each_node(self, func, name):
        self.assertEqual(list(func(self.prog)), sorted(self._parse_node_list(name)))

    def test_for_each_node(self):
        self._test_for_each_node(for_each_node, "possible")

    def test_for_each_online_node(self):
        self._test_for_each_node(for_each_online_node, "online")

    def _test_node_state(self, state_name, file_name):
        possible = self._parse_node_list("possible")
        expected = self._parse_node_list(file_name)
        state = self.prog[state_name]
        for node in possible:
            self.assertEqual(node_state(node, state), node in expected)

    def test_node_state(self):
        self._test_node_state("N_NORMAL_MEMORY", "has_normal_memory")
        # N_GENERIC_INITIATOR was added in Linux kernel commit 894c26a1c274
        # ("ACPI: Support Generic Initiator only domains") (in v5.10). Most of
        # the time it is unset, so if it exists we can use it to test the unset
        # case.
        if (NODE_PATH / "has_generic_initiator").exists():
            self._test_node_state("N_GENERIC_INITIATOR", "has_generic_initiator")
