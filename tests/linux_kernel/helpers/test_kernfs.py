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
    sysfs_listdir,
    sysfs_lookup,
    sysfs_lookup_kobject,
    sysfs_lookup_node,
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

    def get_kernfs_nodes(self, paths):
        fds = [os.open(path, os.O_RDONLY) for path in paths]
        kns = [self.kernfs_node_from_fd(fd) for fd in fds]
        return fds, kns

    def test_sysfs_lookup_node(self):
        fds = []
        try:
            fds, kns = self.get_kernfs_nodes(
                ["/sys", "/sys/kernel", "/sys/kernel/vmcoreinfo"]
            )

            cases = [
                (kns[0], ["", "/", "sys", "/sys", "/sys/"]),
                (kns[1], ["kernel", "/sys/kernel", "sys/kernel", "  kernel  "]),
                (
                    kns[2],
                    [
                        "kernel/vmcoreinfo",
                        "/sys/kernel/vmcoreinfo",
                        "sys/kernel/vmcoreinfo",
                    ],
                ),
            ]

            for expected, paths in cases:
                for path in paths:
                    with self.subTest(path=path):
                        self.assertEqual(sysfs_lookup_node(self.prog, path), expected)

            self.assertEqual(
                sysfs_lookup_node(self.prog, "kernel/foobar"),
                NULL(self.prog, "struct kernfs_node *"),
            )

            self.assertEqual(
                kernfs_root(sysfs_lookup_node(self.prog, "kernel/vmcoreinfo")),
                kernfs_root(self.prog["sysfs_root_kn"]),
            )

        finally:
            for fd in fds:
                os.close(fd)

    def test_sysfs_lookup_kobject(self):
        fds = []
        try:
            fds, kns = self.get_kernfs_nodes(["/sys", "/sys/kernel"])

            kobj_root = cast("struct kobject *", kns[0].priv)
            kobj_kernel = cast("struct kobject *", kns[1].priv)

            root_cases = ["", "/", "sys", "/sys", "/sys/"]
            for path in root_cases:
                with self.subTest(path=path):
                    self.assertEqual(
                        sysfs_lookup_kobject(self.prog, path),
                        kobj_root,
                    )

            kernel_cases = ["kernel", "/sys/kernel", "sys/kernel", "  kernel  "]
            for path in kernel_cases:
                with self.subTest(path=path):
                    self.assertEqual(
                        sysfs_lookup_kobject(self.prog, path),
                        kobj_kernel,
                    )

            file_cases = [
                "kernel/vmcoreinfo",
                "/sys/kernel/vmcoreinfo",
                "sys/kernel/vmcoreinfo",
            ]

            for path in file_cases:
                with self.subTest(path=path):
                    self.assertEqual(
                        sysfs_lookup_kobject(self.prog, path),
                        kobj_kernel,
                    )

            self.assertEqual(
                sysfs_lookup_kobject(self.prog, "kernel"),
                sysfs_lookup_kobject(self.prog, "kernel/vmcoreinfo"),
            )

            self.assertIsNone(sysfs_lookup_kobject(self.prog, "kernel/foobar"))

        finally:
            for fd in fds:
                os.close(fd)

    def test_sysfs_lookup(self):
        fds = []
        try:
            fds, kns = self.get_kernfs_nodes(["/sys/kernel"])

            kobj_kernel = cast("struct kobject *", kns[0].priv)

            root_cases = ["", "/", "sys", "/sys", "/sys/"]
            for path in root_cases:
                with self.subTest(path=path):
                    self.assertIsNone(sysfs_lookup(self.prog, path))

            kernel_cases = ["kernel", "/sys/kernel", "sys/kernel", "  kernel  "]
            for path in kernel_cases:
                with self.subTest(path=path):
                    self.assertEqual(
                        sysfs_lookup(self.prog, path),
                        kobj_kernel,
                    )

            file_cases = [
                "kernel/vmcoreinfo",
                "/sys/kernel/vmcoreinfo",
                "sys/kernel/vmcoreinfo",
            ]

            for path in file_cases:
                with self.subTest(path=path):
                    self.assertEqual(
                        sysfs_lookup(self.prog, path),
                        kobj_kernel,
                    )

            self.assertEqual(
                sysfs_lookup(self.prog, "kernel"),
                sysfs_lookup(self.prog, "kernel/vmcoreinfo"),
            )

            self.assertIsNone(sysfs_lookup(self.prog, "kernel/foobar"))

            # Device case
            if "device_ktype" in self.prog:
                path = "/sys/block"
                if os.path.exists(path):
                    with os.scandir(path) as entries:
                        # Pick the first directory inside /sys/block (e.g., "sda", "loop0").
                        # These represent block devices, so we use one valid device entry
                        # to test sysfs_lookup() for device kobjects.
                        entry = next((e for e in entries if e.is_dir()), None)
                        if entry:
                            dev = sysfs_lookup(self.prog, entry.path[5:])
                            self.assertIsNotNone(dev)

        finally:
            for fd in fds:
                os.close(fd)

    def test_sysfs_listdir(self):
        path = "/sys/kernel"
        fd = os.open(path, os.O_RDONLY)
        try:
            expected = os.listdir(path)

            result = sysfs_listdir(self.prog, "kernel")

            self.assertCountEqual(result, expected)

        finally:
            os.close(fd)

        for path in ["kernel", "/sys/kernel", "sys/kernel", "  kernel  "]:
            with self.subTest(path=path):
                self.assertCountEqual(
                    sysfs_listdir(self.prog, path),
                    os.listdir("/sys/kernel"),
                )

        with self.assertRaises(ValueError) as context:
            sysfs_listdir(self.prog, "kernel/foobar")

        self.assertEqual(str(context.exception), "kernel/foobar: not found")

        with self.assertRaises(ValueError) as context:
            sysfs_listdir(self.prog, "kernel/vmcoreinfo")

        self.assertEqual(
            str(context.exception),
            "kernel/vmcoreinfo: not a directory",
        )
