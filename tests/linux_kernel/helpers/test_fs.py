# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import os.path
import tempfile

from drgn.helpers.linux.fs import (
    d_path,
    dentry_path,
    fget,
    for_each_file,
    for_each_mount,
    inode_path,
    inode_paths,
    mount_dst,
    path_lookup,
)
from drgn.helpers.linux.pid import find_task
from tests.linux_kernel import MS_BIND, LinuxKernelTestCase, mount, umount


class TestFs(LinuxKernelTestCase):
    def test_path_lookup(self):
        with tempfile.NamedTemporaryFile(prefix="drgn-tests-") as f:
            path = path_lookup(self.prog, os.path.abspath(f.name))
            self.assertEqual(
                path.dentry.d_name.name.string_(), os.fsencode(os.path.basename(f.name))
            )

    def test_path_lookup_bind_mount(self):
        with tempfile.NamedTemporaryFile(prefix="drgn-tests-") as f:
            old_mnt = path_lookup(self.prog, os.path.abspath(f.name)).mnt
            mount(f.name, f.name, "", MS_BIND)
            try:
                new_mnt = path_lookup(self.prog, os.path.abspath(f.name)).mnt
                self.assertNotEqual(old_mnt, new_mnt)
            finally:
                umount(f.name)

    def test_d_path(self):
        task = find_task(self.prog, os.getpid())
        self.assertEqual(d_path(task.fs.pwd.address_of_()), os.fsencode(os.getcwd()))

    def test_d_path_dentry_only(self):
        # Since d_path(dentry) picks an arbitrary mount containing the dentry,
        # this should be a directory that is unlikely to be bind mounted
        # anywhere else.
        with tempfile.NamedTemporaryFile(dir="/dev/shm") as f:
            dentry = fget(find_task(self.prog, os.getpid()), f.fileno()).f_path.dentry
            self.assertEqual(d_path(dentry), os.fsencode(f.name))

    def test_d_path_no_internal_mount(self):
        if not os.path.isdir("/sys/kernel/tracing"):
            self.skipTest("The /sys/kernel/tracing directory is not mounted")
        path = path_lookup(self.prog, "/sys/kernel/tracing/trace_pipe")
        # The first mount for this super block is usually MNT_INTERNAL, but we
        # don't want that one. Ensure we skip it.
        self.assertEqual(d_path(path.dentry), b"/sys/kernel/tracing/trace_pipe")

    def test_dentry_path(self):
        pwd = os.fsencode(os.getcwd())
        task = find_task(self.prog, os.getpid())
        self.assertTrue(pwd.endswith(dentry_path(task.fs.pwd.dentry)))

    def test_inode_paths(self):
        with tempfile.TemporaryDirectory(prefix="drgn-tests-") as dir:
            path1 = os.fsencode(os.path.abspath(os.path.join(dir, "a")))
            path2 = os.fsencode(os.path.abspath(os.path.join(dir, "b")))
            with open(path1, "w"):
                os.link(path1, path2)
                with open(path2, "r"):
                    inode = path_lookup(self.prog, path1).dentry.d_inode
                    paths = list(inode_paths(inode))
                    self.assertEqual(len(paths), 2)
                    self.assertTrue(
                        (path1.endswith(paths[0]) and path2.endswith(paths[1]))
                        or (path1.endswith(paths[1]) and path2.endswith(paths[0]))
                    )
                    self.assertIn(inode_path(inode), paths)

    def test_for_each_mount(self):
        with open("/proc/self/mounts", "rb") as f:
            self.assertEqual(
                {line.split()[1].decode("unicode-escape") for line in f},
                {os.fsdecode(mount_dst(mount)) for mount in for_each_mount(self.prog)},
            )

    def test_for_each_mount_cursor(self):
        fd = os.open("/proc/self/mounts", os.O_RDONLY)
        try:
            # Read a small amount of data so that we leave a cursor in the
            # middle of the mount list, on kernel versions where this happens.
            # Cursors were introduced in v5.8 with 9f6c61f96f2d9 ("proc/mounts:
            # add cursor"), and were eliminated in v6.8 with 2eea9ce4310d8
            # ("mounts: keep list of mounts in an rbtree"). They were marked
            # with the flag MNT_CURSOR, but that was only defined as a
            # preprocessor constant. It's easiest to detect cursors via their
            # NULL superblock, which should never be present.
            os.read(fd, 64)
            for mnt in for_each_mount(self.prog):
                self.assertNotEqual(mnt.mnt.mnt_sb.value_(), 0)
        finally:
            os.close(fd)

    def test_fget(self):
        with tempfile.NamedTemporaryFile(prefix="drgn-tests-") as f:
            file = fget(find_task(self.prog, os.getpid()), f.fileno())
            self.assertEqual(d_path(file.f_path), os.fsencode(os.path.abspath(f.name)))

    def test_for_each_file(self):
        task = find_task(self.prog, os.getpid())
        with os.scandir("/proc/self/fd") as dir:
            # NB: The call to for_each_file() comes first so that it will
            # include the scandir file descriptor.
            self.assertEqual(
                {fd for fd, file in for_each_file(task)},
                {int(entry.name) for entry in dir},
            )
