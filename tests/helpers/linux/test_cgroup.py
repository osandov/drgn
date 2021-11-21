# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import os
from pathlib import Path
import signal
import tempfile
import unittest

from drgn import NULL
from drgn.helpers.linux.cgroup import (
    cgroup_name,
    cgroup_parent,
    cgroup_path,
    css_for_each_child,
    css_for_each_descendant_pre,
)
from drgn.helpers.linux.pid import find_task
from tests.helpers.linux import (
    MS_NODEV,
    MS_NOEXEC,
    MS_NOSUID,
    LinuxHelperTestCase,
    fork_and_pause,
    mount,
    umount,
)


class TestCgroup(LinuxHelperTestCase):
    @classmethod
    def setUpClass(cls):
        # It'd be nice to just use addClassCleanup(), but that was added in
        # Python 3.8.
        cls.__cleanups = []
        try:
            super().setUpClass()

            # Don't enable cgroup2 on systems that aren't already using it (or
            # don't support it).
            cgroup2_enabled = False
            try:
                with open("/proc/self/cgroup", "rb") as f:
                    for line in f:
                        if line.startswith(b"0::"):
                            cgroup2_enabled = True
                            break
            except FileNotFoundError:
                pass
            if not cgroup2_enabled:
                raise unittest.SkipTest("cgroup2 not enabled")

            # It's easier to mount the cgroup2 filesystem than to find it.
            cgroup2_mount = Path(tempfile.mkdtemp(prefix="drgn-tests-"))
            cls.__cleanups.append((cgroup2_mount.rmdir,))
            mount("cgroup2", cgroup2_mount, "cgroup2", MS_NOSUID | MS_NODEV | MS_NOEXEC)
            cls.__cleanups.append((umount, cgroup2_mount))

            cls.root_cgroup = cls.prog["cgrp_dfl_root"].cgrp.address_of_()

            pid = fork_and_pause()
            try:
                task = find_task(cls.prog, pid)

                parent_cgroup_dir = Path(
                    tempfile.mkdtemp(prefix="drgn-tests-", dir=cgroup2_mount)
                )
                cls.__cleanups.append((parent_cgroup_dir.rmdir,))
                cls.parent_cgroup_name = os.fsencode(parent_cgroup_dir.name)
                cls.parent_cgroup_path = b"/" + cls.parent_cgroup_name

                (parent_cgroup_dir / "cgroup.procs").write_text(str(pid))
                cls.parent_cgroup = task.cgroups.dfl_cgrp.read_()

                child_cgroup_dir = parent_cgroup_dir / "child"
                child_cgroup_dir.mkdir()
                cls.__cleanups.append((child_cgroup_dir.rmdir,))
                cls.child_cgroup_name = os.fsencode(child_cgroup_dir.name)
                cls.child_cgroup_path = (
                    cls.parent_cgroup_path + b"/" + cls.child_cgroup_name
                )

                (child_cgroup_dir / "cgroup.procs").write_text(str(pid))
                cls.child_cgroup = task.cgroups.dfl_cgrp.read_()
            finally:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
        except:
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
