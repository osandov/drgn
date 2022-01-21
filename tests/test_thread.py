# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import os.path
from pathlib import Path
import platform
import re
import signal
import subprocess
import tempfile
from threading import Thread
from time import sleep
import unittest

from drgn import MissingDebugInfoError, Program
from tests import TestCase, fork_and_pause


class TestCoreDump(TestCase):
    TIDS = (
        2265413,
        2265414,
        2265415,
        2265416,
        2265417,
        2265418,
        2265419,
        2265420,
        2265421,
        2265422,
        2265423,
        2265424,
        2265425,
    )

    CRASHED_TID = 2265419

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        with tempfile.NamedTemporaryFile() as core_dump_file:
            try:
                subprocess.check_call(
                    [
                        "zstd",
                        "--quiet",
                        "--decompress",
                        "--stdout",
                        "tests/sample.coredump.zst",
                    ],
                    stdout=core_dump_file,
                )
            except FileNotFoundError:
                raise unittest.SkipTest("zstd not found")
            cls.prog = Program()
            cls.prog.set_core_dump(core_dump_file.name)

    def test_threads(self):
        self.assertSequenceEqual(
            sorted(thread.tid for thread in self.prog.threads()),
            self.TIDS,
        )

    def test_thread(self):
        for tid in self.TIDS:
            self.assertEqual(self.prog.thread(tid).tid, tid)
        self.assertRaises(LookupError, self.prog.thread, 99)

    def test_crashed_thread(self):
        self.assertEqual(self.prog.crashed_thread().tid, self.CRASHED_TID)


class TestPauseResumeMultithread(TestCase):
    def test_pause_resume_multithread(self):
        """
        We use a pipe for synchronization and the raw `os.fork()` interface
        instead of the standard library's `multiprocessing` module because the
        cleanup code in the `multiprocessing` module doesn't play nicely with
        our use of `ptrace` (in particular, it breaks some assertions that use
        `waitpid` and its associated macros).
        """
        NUM_THREADS = 12
        read, write = os.pipe()

        def child_main():
            os.close(0)
            os.close(1)
            os.close(read)
            threads = [Thread(target=sleep, args=(100,)) for _ in range(NUM_THREADS)]
            for thread in threads:
                thread.start()
            os.close(write)  # Synchronize with parent process

        pid = fork_and_pause(child_main)
        try:
            os.close(write)
            proc_path = Path(f"/proc/{pid}/task")
            with os.fdopen(read) as sync:
                """
                Synchronize with the child process, waiting until it's
                done spawning all of its threads.
                """
                sync.read()
            tasks = list(proc_path.iterdir())
            self.assertEqual(len(tasks), NUM_THREADS + 1)

            def grep(path, *patterns):
                with open(path, "r") as file:
                    lines = list(file)
                    for pattern in patterns:
                        pattern = re.compile(pattern)
                        self.assertTrue(
                            any(pattern.search(line) for line in lines),
                            "\n".join(lines),
                        )

            not_paused_pattern = r"State:.*(sleeping|running)"

            for task in tasks:
                grep(
                    task / "status",
                    not_paused_pattern,
                    r"TracerPid:[^\d]*0[^\d]*$",
                )

            prog = Program()
            prog.set_pid(pid)
            tracer_pid_pattern = fr"TracerPid:[^\d]{os.getpid()}[^\d]*$"

            def pause_then_resume(thread, status):
                grep(status, not_paused_pattern, tracer_pid_pattern)
                thread.pause()
                grep(status, r"State:.*tracing stop", tracer_pid_pattern)
                thread.resume()
                grep(status, not_paused_pattern, tracer_pid_pattern)

            for task in tasks:
                pause_then_resume(prog.thread(int(task.name)), task / "status")
            for thread in prog.threads():
                pause_then_resume(thread, proc_path / str(thread.tid) / "status")
        finally:
            os.kill(pid, signal.SIGINT)


class TestPauseResume(TestCase):
    def setUp(self):
        self.pid = fork_and_pause()
        self.prog = Program()
        self.prog.set_pid(self.pid)
        self.main_thread = self.prog.thread(self.pid)

    def tearDown(self):
        try:
            os.kill(self.pid, signal.SIGINT)
        except:
            pass

    def test_double_pause(self):
        self.main_thread.pause()
        self.assertRaisesRegex(
            ValueError,
            f"{self.main_thread.tid}.*is already paused",
            self.main_thread.pause,
        )

    def test_double_resume(self):
        self.main_thread.pause()
        self.main_thread.resume()
        self.assertRaisesRegex(
            ValueError,
            f"{self.main_thread.tid}.*has already been resumed or was never paused",
            self.main_thread.resume,
        )

    def test_resume_without_pause(self):
        self.assertRaisesRegex(
            ValueError,
            f"{self.main_thread.tid}.*has already been resumed or was never paused",
            self.main_thread.resume,
        )

    def test_pause_exited_thread(self):
        os.kill(self.main_thread.tid, signal.SIGTERM)
        """
        PTRACE_INTERRUPT (what `Thread.pause()` uses under the hood) competes
        with any signals that are sent at the same time, hence we sleep briefly
        to allow the signal to win the race.
        """
        sleep(0.1)
        self.assertRaisesRegex(
            ValueError, f"{self.main_thread.tid}.*has exited", self.main_thread.pause
        )


# Enable this for other architectures as they become supported
@unittest.skipUnless(
    platform.processor().startswith("x86"),
    f"stack traces for live processes are not currently supported on {platform.processor()}",
)
class TestStackTrace(TestCase):
    def test_stack_trace(self):
        with tempfile.NamedTemporaryFile() as executable, tempfile.NamedTemporaryFile(
            mode="w"
        ) as program:
            executable.close()
            program.write(
                """
                      static unsigned int global = 0;

                      void zero() { while(1) global++; }

                      void one() { zero(); }

                      void two() { one(); }

                      int main() { two(); }
                      """
            )
            program.flush()
            subprocess.check_call(
                (
                    "cc",
                    "-x",
                    "c",
                    "-Wall",
                    "-Werror",
                    "-g",
                    "-O0",
                    "-o",
                    executable.name,
                    program.name,
                )
            )
            try:
                process = subprocess.Popen((executable.name,))
                prog = Program()
                prog.set_pid(process.pid)
                try:
                    prog.load_default_debug_info()
                except MissingDebugInfoError:
                    pass
                # Hacky way to make sure the program has entered `zero()`
                while prog["global"].value_() == 0:
                    sleep(0.1)
                main_thread = prog.thread(process.pid)
                main_thread.pause()
                trace = main_thread.stack_trace()
                self.assertEqual(len(trace), 4, trace)
                self.assertEqual(trace[0].name, "zero")
                self.assertEqual(trace[1].name, "one")
                self.assertEqual(trace[2].name, "two")
                self.assertEqual(trace[3].name, "main")
            finally:
                process.kill()
                process.wait()

    def test_stack_trace_requires_pause(self):
        try:
            pid = fork_and_pause()
            prog = Program()
            prog.set_pid(pid)
            main_thread = prog.thread(pid)
            self.assertRaisesRegex(
                ValueError, "thread must be paused", main_thread.stack_trace
            )
        finally:
            os.kill(pid, signal.SIGTERM)
