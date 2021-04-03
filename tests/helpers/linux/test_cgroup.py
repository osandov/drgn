# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import os

from drgn.helpers.linux.cgroup import (
    cgroup_name,
    cgroup_path,
    css_for_each_child,
    css_for_each_descendant_pre,
)
from drgn.helpers.linux.pid import find_task
from tests.helpers.linux import LinuxHelperTestCase


class TestCgroup(LinuxHelperTestCase):
    def setUp(self):
        super().setUp()
        try:
            with open("/proc/self/cgroup", "rb") as f:
                for line in f:
                    if line.startswith(b"0::"):
                        self.cgroup = line[3:].rstrip(b"\n")
                        break
                else:
                    self.skipTest("process is not using cgroup v2")
        except FileNotFoundError:
            self.skipTest("kernel does not support cgroup")

    def test_cgroup_name(self):
        task = find_task(self.prog, os.getpid())
        self.assertEqual(
            cgroup_name(task.cgroups.dfl_cgrp), os.path.basename(self.cgroup)
        )

    def test_cgroup_path(self):
        task = find_task(self.prog, os.getpid())
        self.assertEqual(cgroup_path(task.cgroups.dfl_cgrp), self.cgroup)

    def test_css_for_each_child(self):
        self.assertTrue(
            any(
                self.cgroup.startswith(cgroup_path(css.cgroup))
                for css in css_for_each_child(
                    self.prog["cgrp_dfl_root"].cgrp.self.address_of_()
                )
            )
        )

    def test_css_for_each_descendant_pre(self):
        self.assertTrue(
            any(
                cgroup_path(css.cgroup) == self.cgroup
                for css in css_for_each_descendant_pre(
                    self.prog["cgrp_dfl_root"].cgrp.self.address_of_()
                )
            )
        )
