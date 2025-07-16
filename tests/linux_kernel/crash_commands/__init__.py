# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import io
import os
import sys
import types

import drgn
from drgn.commands.crash import CRASH_COMMAND_NAMESPACE
from tests.linux_kernel import LinuxKernelTestCase


class CrashCommandTestCase(LinuxKernelTestCase):
    # Run a crash command and capture its stdout and stderr.
    def run_crash_command(self, command):
        with contextlib.redirect_stdout(
            io.StringIO()
        ) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
            CRASH_COMMAND_NAMESPACE.run(self.prog, command)
        return types.SimpleNamespace(stdout=stdout.getvalue(), stderr=stderr.getvalue())

    # Run a crash command with and without --drgn. Capture its stdout and
    # stderr, and check that --drgn doesn't write anything to stderr.
    #
    # If mode is "compile" or "exec", check that --drgn outputs valid,
    # non-empty Python code.
    #
    # If mode is "exec", also execute the code and capture any globals it sets.
    def check_crash_command(self, command, mode="exec"):
        assert mode in {"capture", "compile", "exec"}

        drgn_option = self.run_crash_command(command + " --drgn")

        self.assertFalse(drgn_option.stderr)

        if os.getenv("DRGN_TEST_LOG_CRASH_DRGN"):
            sys.stderr.write(
                f"""
{'=' * 88}
%crash {command} --drgn
{'-' * 88}
{drgn_option.stdout}\
{'=' * 88}
"""
            )
            sys.stderr.flush()

        if mode == "compile" or mode == "exec":
            self.assertTrue(drgn_option.stdout)
            drgn_option.code = compile(drgn_option.stdout, command + " --drgn", "exec")

        if mode == "exec":
            drgn_option.globals = {"prog": self.prog}
            try:
                old_default_prog = drgn.get_default_prog()
            except drgn.NoDefaultProgramError:
                old_default_prog = None
            try:
                drgn.set_default_prog(self.prog)
                exec(drgn_option.stdout, drgn_option.globals)
            finally:
                drgn.set_default_prog(old_default_prog)

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
