# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import io
import types

from drgn.commands.crash import CRASH_COMMAND_NAMESPACE
from tests.linux_kernel import LinuxKernelTestCase


class CrashCommandTestCase(LinuxKernelTestCase):
    # Run a crash command and capture its stdout and stderr. By default, also
    # capture and check the output of the --drgn option.
    def run_crash_command(self, command, *, check_drgn_option=True):
        if check_drgn_option:
            drgn_option_stdout = self.check_crash_command_drgn_option(command)

        with contextlib.redirect_stdout(
            io.StringIO()
        ) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
            CRASH_COMMAND_NAMESPACE.run(self.prog, command)
        ret = types.SimpleNamespace(stdout=stdout.getvalue(), stderr=stderr.getvalue())

        if check_drgn_option:
            ret.drgn_option_stdout = drgn_option_stdout
        return ret

    # Check that running a crash command with the --drgn option outputs valid,
    # non-empty Python code and doesn't write anything to stderr, then return
    # the output.
    def check_crash_command_drgn_option(self, command):
        with contextlib.redirect_stdout(
            io.StringIO()
        ) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
            CRASH_COMMAND_NAMESPACE.run(self.prog, command + " --drgn")

        compile(stdout.getvalue(), command + " --drgn", "exec")

        self.assertTrue(stdout.getvalue())
        self.assertFalse(stderr.getvalue())

        return stdout.getvalue()
