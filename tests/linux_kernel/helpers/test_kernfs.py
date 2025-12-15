# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import os

from drgn import NULL, cast
from drgn.helpers.linux.fs import fget
from drgn.helpers.linux.kernfs import (
    kernfs_children,
    kernfs_name,
    kernfs_parent,
    kernfs_path,
    kernfs_root,
    kernfs_walk,
)
from drgn.helpers.linux.pid import find_task
from tests.linux_kernel import LinuxKernelTestCase


class TestKernfs(LinuxKernelTestCase):
    @classmethod
    def kernfs_node_from_fd(cls, fd):
        file = fget(find_task(cls.prog, os.getpid()), fd)
        return cast("struct kernfs_node *", file.f_inode.i_private)

    def test_kernfs_parent(self):
        with contextlib.ExitStack() as exit_stack:
            fd = os.open("/sys/kernel/vmcoreinfo", os.O_RDONLY)
            exit_stack.callback(os.close, fd)
            dfd = os.open("/sys/kernel", os.O_RDONLY)
            exit_stack.callback(os.close, dfd)
            self.assertEqual(
                kernfs_parent(self.kernfs_node_from_fd(fd)),
                self.kernfs_node_from_fd(dfd),
            )

    def test_kernfs_root(self):
        for path in ("/sys", "/sys/kernel", "/sys/kernel/vmcoreinfo"):
            with self.subTest(path=path):
                fd = os.open(path, os.O_RDONLY)
                try:
                    self.assertEqual(
                        kernfs_root(self.kernfs_node_from_fd(fd)),
                        self.prog["sysfs_root"],
                    )
                finally:
                    os.close(fd)

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

    def test_kernfs_walk_follow_symlinks(self):
        fds = []
        path = "/sys/block"
        if not os.path.exists(path):
            self.skipTest(f"{path} does not exist")
        try:
            fd = os.open(path, os.O_RDONLY)
            fds.append(fd)
            kn = self.kernfs_node_from_fd(fd)
            with os.scandir(path) as entries:
                entry = next((e for e in entries if e.is_symlink()), None)
                if not entry:
                    self.skipTest(f"No symlink entries found under {path}")
                sub_path = os.path.join(entry.path, "subsystem")
                fd = os.open(sub_path, os.O_RDONLY)
                fds.append(fd)
                target_kn = self.kernfs_node_from_fd(fd)
                rel_path = os.path.join(entry.name, "subsystem")
                self.assertEqual(
                    kernfs_walk(kn, rel_path),
                    target_kn,
                )
                self.assertNotEqual(
                    kernfs_walk(kn, rel_path, False),
                    target_kn,
                )
        finally:
            for fd in fds:
                os.close(fd)

    def test_kernfs_children(self):
        path = b"/sys/kernel"
        fd = os.open(path, os.O_RDONLY)
        try:
            parent_dev = os.fstat(fd).st_dev
            kn = self.kernfs_node_from_fd(fd)
            self.assertCountEqual(
                [kernfs_name(child) for child in kernfs_children(kn)], os.listdir(path)
            )

            for child in kernfs_children(kn):
                child_fd = os.open(
                    b"/sys/" + kernfs_path(child), os.O_PATH | os.O_NOFOLLOW
                )
                try:
                    if os.fstat(child_fd).st_dev == parent_dev:
                        self.assertEqual(child, self.kernfs_node_from_fd(child_fd))
                finally:
                    os.close(child_fd)
        finally:
            os.close(fd)

        # Check that calling kernfs_children() on a non-directory raises an
        # exception
        path = b"/sys/kernel/vmcoreinfo"
        fd = os.open(path, os.O_RDONLY)
        try:
            kn = self.kernfs_node_from_fd(fd)
            with self.assertRaises(ValueError) as context:
                kernfs_children(kn)
            self.assertEqual(str(context.exception), "not a directory")
        finally:
            os.close(fd)
