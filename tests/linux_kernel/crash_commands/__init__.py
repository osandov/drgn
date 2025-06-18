# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import io
import types

from drgn.commands.crash import CRASH_COMMAND_NAMESPACE
from tests.linux_kernel import LinuxKernelTestCase


class CrashCommandTestCase(LinuxKernelTestCase):
    def run_crash_command(self, command):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            CRASH_COMMAND_NAMESPACE.run(self.prog, command)
        return types.SimpleNamespace(stdout=stdout.getvalue(), stderr=stderr.getvalue())
