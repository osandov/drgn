# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import io
import os
import sys
import types

from drgn.commands.crash import CRASH_COMMAND_NAMESPACE
from tests import with_default_prog
from tests.linux_kernel import LinuxKernelTestCase


class CrashCommandTestCaseBase:
    """A mix-in to add to a general test case class for testing crash commands"""

    # Run a crash command and capture its stdout and stderr.
    @classmethod
    def run_crash_command(cls, command):
        with contextlib.redirect_stdout(
            io.StringIO()
        ) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
            CRASH_COMMAND_NAMESPACE.run(cls.prog, command)
        return types.SimpleNamespace(stdout=stdout.getvalue(), stderr=stderr.getvalue())

    # Run a crash command with --drgn. Capture its stdout and check that it
    # doesn't write anything to stderr.
    #
    # mode must be "capture", "compile", or "exec".
    #
    # If mode is "compile" or "exec", check that it outputs valid, non-empty
    # Python code.
    #
    # If mode is "exec", also execute the code and capture any globals it sets.
    def run_crash_command_drgn_option(self, command, mode="exec"):
        assert mode in {"capture", "compile", "exec"}

        ret = self.run_crash_command(command + " --drgn")

        self.assertFalse(ret.stderr)

        if os.getenv("DRGN_TEST_LOG_CRASH_DRGN"):
            sys.stderr.write(
                f"""
{'=' * 88}
%crash {command} --drgn
{'-' * 88}
{ret.stdout}\
{'=' * 88}
"""
            )
            sys.stderr.flush()

        if mode == "compile" or mode == "exec":
            self.assertTrue(ret.stdout)
            ret.code = compile(ret.stdout, command + " --drgn", "exec")

        if mode == "exec":
            ret.globals = {"prog": self.prog}
            with with_default_prog(self.prog):
                exec(ret.stdout, ret.globals)

        return ret

    # Run a crash command with and without --drgn. mode is passed to
    # run_crash_command_drgn_option().
    def check_crash_command(self, command, mode="exec"):
        drgn_option = self.run_crash_command_drgn_option(command, mode)

        ret = self.run_crash_command(command)

        if os.getenv("DRGN_TEST_LOG_CRASH_OUTPUT"):
            sys.stderr.write(
                f"""
{'=' * 88}
%crash {command}
{'-' * 88}
{ret.stdout}\
{'=' * 88}
"""
            )
            sys.stderr.flush()

        ret.drgn_option = drgn_option
        return ret


class CrashCommandTestCase(CrashCommandTestCaseBase, LinuxKernelTestCase):
    pass
