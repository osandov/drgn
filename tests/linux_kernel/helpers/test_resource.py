# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import resource

from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.resource import Rlimit, task_rlimits
from tests.linux_kernel import LinuxKernelTestCase


class TestResource(LinuxKernelTestCase):
    def test_task_rlimits(self):
        expected = {}
        for name in (
            "CPU",
            "FSIZE",
            "DATA",
            "STACK",
            "CORE",
            "RSS",
            "NPROC",
            "NOFILE",
            "MEMLOCK",
            "AS",
            "LOCKS",
            "SIGPENDING",
            "MSGQUEUE",
            "NICE",
            "RTPRIO",
            "RTTIME",
        ):
            try:
                r = getattr(resource, "RLIMIT_" + name)
            except AttributeError:
                # RLIMIT_LOCKS was functional only briefly between Linux 2.4.0
                # and Linux 2.4.24, so the resource module doesn't define it.
                if name == "LOCKS":
                    r = 10
                else:
                    raise
            soft, hard = resource.getrlimit(r)
            expected[name] = Rlimit(
                None if soft == resource.RLIM_INFINITY else soft,
                None if hard == resource.RLIM_INFINITY else hard,
            )
        self.assertEqual(
            task_rlimits(find_task(self.prog, os.getpid())),
            expected,
        )
