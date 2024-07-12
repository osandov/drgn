# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import unittest

from drgn.helpers.linux.stackdepot import stack_depot_fetch
from tests.linux_kernel import skip_unless_have_test_kmod
from tests.linux_kernel.test_stack_trace import LinuxKernelStackTraceTestCase


@skip_unless_have_test_kmod
class TestStackDepot(LinuxKernelStackTraceTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not cls.prog["drgn_test_have_stackdepot"]:
            raise unittest.SkipTest("kernel does not have stack depot")

    @skip_unless_have_test_kmod
    def test_stack_depot_fetch(self):
        self._test_drgn_test_kthread_trace(
            stack_depot_fetch(self.prog["drgn_test_stack_handle"])
        )
