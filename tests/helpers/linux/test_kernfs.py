# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import os

from drgn import cast
from drgn.helpers.linux.fs import fget
from drgn.helpers.linux.kernfs import kernfs_name, kernfs_path
from drgn.helpers.linux.pid import find_task
from tests.helpers.linux import LinuxHelperTestCase


class TestKernfs(LinuxHelperTestCase):
    def test_kernfs_name(self):
        with open("/sys/kernel/vmcoreinfo", "r") as f:
            file = fget(find_task(self.prog, os.getpid()), f.fileno())
            kn = cast("struct kernfs_node *", file.f_inode.i_private)
            self.assertEqual(kernfs_name(kn), b"vmcoreinfo")

    def test_kernfs_path(self):
        with open("/sys/kernel/vmcoreinfo", "r") as f:
            file = fget(find_task(self.prog, os.getpid()), f.fileno())
            kn = cast("struct kernfs_node *", file.f_inode.i_private)
            self.assertEqual(kernfs_path(kn), b"/kernel/vmcoreinfo")
