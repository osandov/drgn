# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from pathlib import Path
import re

from drgn.helpers.linux.ioport import for_each_resource
from tests.linux_kernel import LinuxKernelTestCase


class TestIoport(LinuxKernelTestCase):
    def test_for_each_resource(self):
        resources = for_each_resource(self.prog["ioport_resource"].address_of_())
        next(resources)  # Skip the root.
        self.assertEqual(
            [resource.name.string_() for resource in resources],
            re.findall(b"[^:]* : (.*)", Path("/proc/ioports").read_bytes()),
        )
