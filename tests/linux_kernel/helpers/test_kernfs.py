# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import os

from drgn import NULL, cast
from drgn.helpers.linux.fs import fget
from drgn.helpers.linux.kernfs import kernfs_name, kernfs_path, kernfs_walk
from drgn.helpers.linux.pid import find_task
from tests.linux_kernel import LinuxKernelTestCase


class TestKernfs(LinuxKernelTestCase):
    @classmethod
    def kernfs_node_from_fd(cls, fd):
        file = fget(find_task(cls.prog, os.getpid()), fd)
        return cast("struct kernfs_node *", file.f_inode.i_private)

    def test_kernfs_name(self):
        with open("/sys/kernel/vmcoreinfo", "r") as f:
            kn = self.kernfs_node_from_fd(f.fileno())
            self.assertEqual(kernfs_name(kn), b"vmcoreinfo")

    def test_kernfs_path(self):
        with open("/sys/kernel/vmcoreinfo", "r") as f:
            kn = self.kernfs_node_from_fd(f.fileno())
            self.assertEqual(kernfs_path(kn), b"/kernel/vmcoreinfo")

    def test_kernfs_walk(self):
        fds = []
        try:
            for path in ("/sys", "/sys/kernel", "/sys/kernel/vmcoreinfo"):
                fds.append(os.open(path, os.O_RDONLY))
            kns = [self.kernfs_node_from_fd(fd) for fd in fds]
            self.assertEqual(kernfs_walk(kns[0], ""), kns[0])
            self.assertEqual(kernfs_walk(kns[0], "/"), kns[0])
            self.assertEqual(kernfs_walk(kns[0], "kernel"), kns[1])
            self.assertEqual(kernfs_walk(kns[0], "kernel/vmcoreinfo"), kns[2])
            self.assertEqual(
                kernfs_walk(kns[0], "kernel/foobar"),
                NULL(self.prog, "struct kernfs_node *"),
            )
            self.assertEqual(
                kernfs_walk(kns[0], "kernel/foo/bar"),
                NULL(self.prog, "struct kernfs_node *"),
            )
        finally:
            for fd in fds:
                os.close(fd)
