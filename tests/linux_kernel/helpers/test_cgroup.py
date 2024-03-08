# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import os
from pathlib import Path
import tempfile
import unittest

from drgn import NULL, cast
from drgn.helpers.linux.cgroup import (
    cgroup_get_from_path,
    cgroup_name,
    cgroup_parent,
    cgroup_path,
    css_for_each_child,
    css_for_each_descendant_pre,
    sock_cgroup_ptr,
)
from drgn.helpers.linux.fs import fget
from drgn.helpers.linux.pid import find_task
from tests.linux_kernel import (
    LinuxKernelTestCase,
    create_socket,
    fork_and_stop,
    iter_mounts,
)


@contextlib.contextmanager
def tmp_cgroups():
    for mnt in iter_mounts():
        if mnt.fstype == "cgroup2":
            break
    else:
        raise unittest.SkipTest("cgroup2 not mounted")

    parent = Path(tempfile.mkdtemp(prefix="drgn-tests-", dir=mnt.mount_point))
    try:
        child = parent / "child"
        child.mkdir()
        try:
            yield parent, child
        finally:
            child.rmdir()
    finally:
        parent.rmdir()


class TestCgroup(LinuxKernelTestCase):
    @classmethod
    def setUpClass(cls):
        # It'd be nice to just use addClassCleanup(), but that was added in
        # Python 3.8.
        cls.__cleanups = []
        try:
            super().setUpClass()

            cm = tmp_cgroups()
            parent_cgroup_dir, child_cgroup_dir = cm.__enter__()
            cls.__cleanups.append((cm.__exit__, None, None, None))

            cls.root_cgroup = cls.prog["cgrp_dfl_root"].cgrp.address_of_()

            with fork_and_stop() as pid:
                task = find_task(cls.prog, pid)

                cls.parent_cgroup_name = os.fsencode(parent_cgroup_dir.name)
                cls.parent_cgroup_path = b"/" + cls.parent_cgroup_name

                (parent_cgroup_dir / "cgroup.procs").write_text(str(pid))
                cls.parent_cgroup = task.cgroups.dfl_cgrp.read_()

                cls.child_cgroup_name = os.fsencode(child_cgroup_dir.name)
                cls.child_cgroup_path = (
                    cls.parent_cgroup_path + b"/" + cls.child_cgroup_name
                )

                (child_cgroup_dir / "cgroup.procs").write_text(str(pid))
                cls.child_cgroup = task.cgroups.dfl_cgrp.read_()
        except BaseException:
            for cleanup in reversed(cls.__cleanups):
                cleanup[0](*cleanup[1:])
            raise

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        for cleanup in reversed(cls.__cleanups):
            cleanup[0](*cleanup[1:])

    def test_cgroup_parent(self):
        self.assertEqual(cgroup_parent(self.child_cgroup), self.parent_cgroup)
        self.assertEqual(cgroup_parent(self.parent_cgroup), self.root_cgroup)
        self.assertEqual(
            cgroup_parent(self.root_cgroup), NULL(self.prog, "struct cgroup *")
        )

    def test_cgroup_name(self):
        self.assertEqual(cgroup_name(self.root_cgroup), b"/")
        self.assertEqual(cgroup_name(self.parent_cgroup), self.parent_cgroup_name)
        self.assertEqual(cgroup_name(self.child_cgroup), self.child_cgroup_name)

    def test_cgroup_path(self):
        self.assertEqual(cgroup_path(self.root_cgroup), b"/")
        self.assertEqual(cgroup_path(self.parent_cgroup), self.parent_cgroup_path)
        self.assertEqual(cgroup_path(self.child_cgroup), self.child_cgroup_path)

    def test_cgroup_get_from_path(self):
        self.assertEqual(cgroup_get_from_path(self.prog, "/"), self.root_cgroup)
        self.assertEqual(
            cgroup_get_from_path(self.prog, self.parent_cgroup_path), self.parent_cgroup
        )
        self.assertEqual(
            cgroup_get_from_path(self.prog, self.child_cgroup_path), self.child_cgroup
        )
        self.assertEqual(
            cgroup_get_from_path(self.prog, self.parent_cgroup_path + b"/foo"),
            NULL(self.prog, "struct cgroup *"),
        )

    def test_cgroup_socket(self):
        with create_socket() as sock:
            task = find_task(self.prog, os.getpid())
            file = fget(task, sock.fileno())
            sk = cast("struct socket *", file.private_data).sk
            self.assertEqual(sock_cgroup_ptr(sk.sk_cgrp_data), task.cgroups.dfl_cgrp)

    @staticmethod
    def _cgroup_iter_paths(fn, cgroup):
        return [cgroup_path(css.cgroup) for css in fn(cgroup.self.address_of_())]

    def test_css_for_each_child(self):
        children = self._cgroup_iter_paths(css_for_each_child, self.root_cgroup)
        self.assertIn(self.parent_cgroup_path, children)
        self.assertNotIn(self.child_cgroup_path, children)

        self.assertEqual(
            self._cgroup_iter_paths(css_for_each_child, self.parent_cgroup),
            [self.child_cgroup_path],
        )

        self.assertEqual(
            self._cgroup_iter_paths(css_for_each_child, self.child_cgroup), []
        )

    def test_css_for_each_descendant_pre(self):
        descendants = self._cgroup_iter_paths(
            css_for_each_descendant_pre, self.root_cgroup
        )
        self.assertEqual(descendants[0], b"/")
        self.assertIn(self.parent_cgroup_path, descendants)
        self.assertIn(self.child_cgroup_path, descendants)
        self.assertLess(
            descendants.index(self.parent_cgroup_path),
            descendants.index(self.child_cgroup_path),
        )

        self.assertEqual(
            self._cgroup_iter_paths(css_for_each_descendant_pre, self.parent_cgroup),
            [self.parent_cgroup_path, self.child_cgroup_path],
        )

        self.assertEqual(
            self._cgroup_iter_paths(css_for_each_descendant_pre, self.child_cgroup),
            [self.child_cgroup_path],
        )
