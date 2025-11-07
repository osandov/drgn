# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
from pathlib import Path
import re
import signal

from drgn import Object
from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.signal import (
    decode_sigset,
    sigaction_flags,
    signal_names,
    signal_numbers,
    sigpending_for_each,
    sigset_to_hex,
)
from tests.linux_kernel import LinuxKernelTestCase, fork_and_stop


class TestSignal(LinuxKernelTestCase):
    def test_sigpending_for_each(self):
        with fork_and_stop(
            signal.pthread_sigmask, signal.SIG_BLOCK, {signal.SIGUSR1, signal.SIGUSR2}
        ) as (pid, _):
            os.kill(pid, signal.SIGUSR1)
            os.kill(pid, signal.SIGUSR2)
            task = find_task(self.prog, pid)
            self.assertLessEqual(
                {signal.SIGUSR1, signal.SIGUSR2},
                {
                    sigqueue.info.si_signo.value_()
                    for sigqueue in sigpending_for_each(
                        task.signal.shared_pending.address_of_()
                    )
                },
            )

    def test_signal_names(self):
        for name, number in signal_names(self.prog).items():
            try:
                expected = getattr(signal, name)
            except AttributeError:
                continue
            if name == "SIGRTMIN":
                # glibc uses some real-time signals internally and adjusts
                # SIGRTMIN accordingly.
                self.assertLessEqual(number, expected)
            else:
                self.assertEqual(number, expected)

    def test_signal_numbers(self):
        number_to_names = signal_numbers(self.prog)
        for name, number in signal_names(self.prog).items():
            self.assertIn(name, number_to_names[number])

    def test_sigaction_flags(self):
        # We don't have a good way to validate the values from Python, so just
        # sanity check the dictionary.
        for flag, value in sigaction_flags(self.prog).items():
            self.assertRegex(flag, r"^SA_")
            self.assertIsInstance(value, int)

    def test_decode_sigset(self):
        with fork_and_stop(
            signal.pthread_sigmask, signal.SIG_BLOCK, {signal.SIGUSR1, signal.SIGUSR2}
        ) as (pid, _):
            os.kill(pid, signal.SIGUSR1)
            os.kill(pid, signal.SIGUSR2)
            task = find_task(self.prog, pid)
            sigset = task.signal.shared_pending.signal
            self.assertRegex(decode_sigset(sigset), r"^\{.*\bSIGUSR1,SIGUSR2\b.*\}$")
            self.assertRegex(
                decode_sigset(sigset.address_of_()), r"^\{.*\bSIGUSR1,SIGUSR2\b.*\}$"
            )

    def test_decode_sigset_value(self):
        self.assertEqual(
            decode_sigset(
                self.prog, (1 << (signal.SIGHUP - 1)) | (1 << (signal.SIGTERM - 1))
            ),
            "{SIGHUP,SIGTERM}",
        )

    def test_decode_sigset_integer_object(self):
        self.assertEqual(
            decode_sigset(
                self.prog,
                Object(
                    self.prog,
                    "unsigned long",
                    (1 << (signal.SIGHUP - 1)) | (1 << (signal.SIGTERM - 1)),
                ),
            ),
            "{SIGHUP,SIGTERM}",
        )

    def test_sigset_to_hex(self):
        with fork_and_stop(
            signal.pthread_sigmask, signal.SIG_BLOCK, {signal.SIGUSR1, signal.SIGUSR2}
        ) as (pid, _):
            os.kill(pid, signal.SIGUSR1)
            os.kill(pid, signal.SIGUSR2)
            task = find_task(self.prog, pid)
            expected = re.search(
                r"^ShdPnd:\s*([0-9a-f]+)",
                Path(f"/proc/{pid}/status").read_text(),
                flags=re.M,
            ).group(1)
            self.assertEqual(
                sigset_to_hex(task.signal.shared_pending.signal.address_of_()), expected
            )
