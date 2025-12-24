# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import collections
import os
from pathlib import Path
import re
import threading

from drgn import Object
from drgn.commands.crash import _CRASH_FOREACH_SUBCOMMANDS
from drgn.helpers.common.format import double_quote_ascii_string
from drgn.helpers.linux.mm import TaskRss
from drgn.helpers.linux.pid import find_task
from tests.linux_kernel import (
    fork_and_stop,
    online_cpus,
    skip_if_highmem,
    skip_unless_have_full_mm_support,
)
from tests.linux_kernel.crash_commands import CrashCommandTestCase


def _quoted_comm(pid="self"):
    return double_quote_ascii_string(
        Path(f"/proc/{pid}/comm").read_bytes().rstrip(b"\n")
    )


class TestPs(CrashCommandTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.condition = threading.Condition()
        cls.threads = [threading.Thread(target=cls.thread_func) for _ in range(2)]
        cls.addClassCleanup(cls.cleanup_threads)
        for i, thread in enumerate(cls.threads):
            name = f"drgn_test_ps{i}"
            thread.name = name
            thread.start()

            # Since Python 3.14, the thread name will be set at the OS level,
            # but before that, we have to do it manually.
            comm_path = Path(f"/proc/{thread.native_id}/comm")
            if comm_path.read_text() != name + "\n":
                comm_path.write_text(name + "\n")

    @classmethod
    def thread_func(cls):
        with cls.condition:
            cls.condition.wait()

    @classmethod
    def cleanup_threads(cls):
        with cls.condition:
            cls.condition.notify_all()
        for thread in cls.threads:
            thread.join()

    def _test_drgn_common(self, cmd):
        for variable in (
            "task",
            "pid",
            "ppid",
            "comm",
        ):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)
        self.assertIsInstance(cmd.drgn_option.globals["cpu"], int)
        self.assertIsInstance(cmd.drgn_option.globals["state"], str)
        self.assertIsInstance(cmd.drgn_option.globals["mem_usage"], float)
        self.assertIsInstance(cmd.drgn_option.globals["vsize"], int)
        self.assertIsInstance(cmd.drgn_option.globals["rss"], TaskRss)

    def test_no_args(self):
        cmd = self.check_crash_command("ps")

        self.assertRegex(cmd.stdout, r"^\s*PID\s+PPID")
        for pid in [0, 1, os.getpid(), *(thread.native_id for thread in self.threads)]:
            self.assertRegex(cmd.stdout, rf"(?m)^>?\s*{pid}\b")

        self.assertIn("for_each_task(idle=True)", cmd.drgn_option.stdout)
        self.assertNotIn("continue", cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

    def test_pid(self):
        cmd = self.check_crash_command("ps -H 1")
        foreach_cmd = self.check_crash_command("foreach 1 ps -H", mode="capture")

        for c in (cmd, foreach_cmd):
            self.assertRegex(c.stdout, r"^>?\s*1\b.*\n$")

        self.assertIn("pid = 1", cmd.drgn_option.stdout)
        self.assertIn("find_task(pid)", cmd.drgn_option.stdout)
        self.assertNotIn("for_each_task", cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

        self.assertEqual(cmd.drgn_option.stdout, foreach_cmd.drgn_option.stdout)

    def test_pid_0(self):
        cmd = self.check_crash_command("ps -H 0")

        for line in cmd.stdout.splitlines(keepends=True):
            self.assertRegex(line, r"^>?\s*0\b.*\n$")

        self.assertIn("for_each_online_cpu(", cmd.drgn_option.stdout)
        self.assertIn("idle_task(", cmd.drgn_option.stdout)
        self.assertNotIn("for_each_task", cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

    def test_multiple_pids(self):
        cmd = self.check_crash_command(f"ps -H {os.getpid()} 1")

        self.assertRegex(cmd.stdout, rf"^>?\s*1\b.*\n>?\s*{os.getpid()}\b.*\n$")

        self.assertIn("pid = 1\n", cmd.drgn_option.stdout)
        self.assertIn(f"pid = {os.getpid()}\n", cmd.drgn_option.stdout)
        self.assertIn("find_task(pid)", cmd.drgn_option.stdout)
        self.assertNotIn("for_each_task", cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

    def test_invalid_pid(self):
        cmd = self.check_crash_command("ps -H 2147483647")

        self.assertIn("no such process with PID 2147483647", cmd.stdout)

    def test_task_struct(self):
        address = find_task(self.prog, 1).value_()
        cmd = self.check_crash_command(f"ps -H {address:#x}")

        self.assertRegex(cmd.stdout, r"^>?\s*1\b.*\n$")

        self.assertNotIn("for_each_task", cmd.drgn_option.stdout)
        self.assertIn(hex(address), cmd.drgn_option.stdout)
        self.assertIn('Object(prog, "struct task_struct *", ', cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

    def test_multiple_task_structs(self):
        cmd = self.check_crash_command(
            f"ps -H {find_task(self.prog, 1).value_():#x} {self.prog['init_task'].address_:#x}"
        )

        self.assertRegex(cmd.stdout, r"^>?\s*0\b.*\n>?\s*1\b.*\n$")

        self.assertNotIn("for_each_task", cmd.drgn_option.stdout)
        self.assertIn('Object(prog, "struct task_struct *", ', cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

    def test_invalid_task_struct(self):
        address = self.prog["init_task"].address_
        cmd = self.run_crash_command(f"ps -H {address + 1:#x}")

        self.assertIn(f"invalid task_struct: {address + 1:#x}", cmd.stdout)

    def test_pid_and_task_struct(self):
        address = self.prog["init_task"].address_
        cmd = self.check_crash_command(f"ps -H 1 {address:#x}")

        self.assertRegex(cmd.stdout, r"(?m)^>?\s*0\b")
        self.assertRegex(cmd.stdout, r"(?m)^>?\s*1\b")

        self.assertNotIn("for_each_task", cmd.drgn_option.stdout)
        self.assertIn("pid = 1", cmd.drgn_option.stdout)
        self.assertIn("find_task(pid)", cmd.drgn_option.stdout)
        self.assertIn(hex(address), cmd.drgn_option.stdout)
        self.assertIn('Object(prog, "struct task_struct *", ', cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

    def test_command_names(self):
        self_comm = Path("/proc/self/comm").read_bytes().rstrip(b"\n")
        similar_comm = self_comm + b"1" if len(self_comm) < 15 else self_comm[:-1]
        with fork_and_stop(Path("/proc/self/comm").write_bytes, similar_comm) as (
            pid,
            _,
        ):
            cmd = self.check_crash_command(
                f"ps -H {double_quote_ascii_string(self_comm)} {_quoted_comm(1)}"
            )

        self.assertRegex(cmd.stdout, r"(?m)^>?\s*1\b")
        self.assertRegex(cmd.stdout, rf"(?m)^>?\s*{os.getpid()}\b")
        self.assertNotRegex(cmd.stdout, rf"(?m)^>?\s*{pid}\b")

        self.assertIn("for_each_task(idle=True)", cmd.drgn_option.stdout)
        self.assertIn("comm_string not in ", cmd.drgn_option.stdout)
        self.assertIn("continue", cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

    def test_backslash_command_name(self):
        with fork_and_stop(Path("/proc/self/comm").write_bytes, b"drgn_test_ps") as (
            pid,
            _,
        ):
            cmd = self.check_crash_command(r"ps -H \drgn_test_ps")

        self.assertRegex(cmd.stdout, rf"(?m)^>?\s*{pid}\b")

        self.assertIn("for_each_task(idle=True)", cmd.drgn_option.stdout)
        self.assertIn('comm_string != "drgn_test_ps"', cmd.drgn_option.stdout)
        self.assertIn("continue", cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

    def test_command_name_regex(self):
        cmd = self.check_crash_command(r"ps -H 'drgn_test_ps[0-9]'")

        for pid in [thread.native_id for thread in self.threads]:
            self.assertRegex(cmd.stdout, rf"(?m)^>?\s*{pid}\b")

        self.assertIn("for_each_task(idle=True)", cmd.drgn_option.stdout)
        self.assertIn(
            're.search("drgn_test_ps[0-9]", comm_string)', cmd.drgn_option.stdout
        )
        self.assertIn("continue", cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

    def test_pid_and_command_name(self):
        cmd = self.check_crash_command(f"ps -H {_quoted_comm()} 1")

        self.assertRegex(cmd.stdout, r"(?m)^>?\s*1\b")
        self.assertRegex(cmd.stdout, rf"(?m)^>?\s*{os.getpid()}\b")

        self.assertIn("for_each_task(idle=True)", cmd.drgn_option.stdout)
        self.assertNotIn("find_task(", cmd.drgn_option.stdout)
        self.assertIn("task.pid.value_() == 1", cmd.drgn_option.stdout)
        self.assertIn("comm_string != ", cmd.drgn_option.stdout)
        self.assertIn("continue", cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

    def test_pid_and_task_struct_and_command_name(self):
        address = self.prog["init_task"].address_
        cmd = self.check_crash_command(f"ps -H {_quoted_comm()} 1 {address:#x}")

        self.assertRegex(cmd.stdout, r"(?m)^>?\s*0\b")
        self.assertRegex(cmd.stdout, r"(?m)^>?\s*1\b")
        self.assertRegex(cmd.stdout, rf"(?m)^>?\s*{os.getpid()}\b")

        self.assertIn("for_each_task(idle=True)", cmd.drgn_option.stdout)
        self.assertNotIn("find_task(", cmd.drgn_option.stdout)
        self.assertIn("task.pid.value_() == 1", cmd.drgn_option.stdout)
        self.assertIn(f"task.value_() == {address:#x}", cmd.drgn_option.stdout)
        self.assertIn("comm_string != ", cmd.drgn_option.stdout)
        self.assertIn("continue", cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

    def test_kernel(self):
        cmd = self.check_crash_command("ps -k")

        self.assertRegex(cmd.stdout, r"(?m)^>?\s*0\b")
        self.assertNotRegex(cmd.stdout, r"(?m)^>?\s*1\b")

        self.assertIn("for_each_task(idle=True)", cmd.drgn_option.stdout)
        self.assertIn("if not task_is_kthread(task):", cmd.drgn_option.stdout)
        self.assertIn("continue", cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

    def test_kernel_and_pid(self):
        cmd = self.check_crash_command("ps -H -k 0 2")

        self.assertRegex(cmd.stdout, r"(?:^>?\s*[02]\b.*\n)+")

        self.assertIn("for_each_online_cpu(", cmd.drgn_option.stdout)
        self.assertIn("idle_task(", cmd.drgn_option.stdout)
        self.assertIn("pid = 2", cmd.drgn_option.stdout)
        self.assertIn("find_task(pid)", cmd.drgn_option.stdout)
        self.assertNotIn("for_each_task", cmd.drgn_option.stdout)
        self.assertIn("if not task_is_kthread(task):", cmd.drgn_option.stdout)
        self.assertIn("continue", cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

    def test_kernel_and_user_pid(self):
        cmd = self.check_crash_command("ps -H -k 1")

        self.assertFalse(cmd.stdout)
        self.assertNotIn("ppid", cmd.drgn_option.globals)

    def test_user(self):
        cmd = self.check_crash_command("ps -u")

        self.assertRegex(cmd.stdout, r"(?m)^>?\s*1\b")
        self.assertNotRegex(cmd.stdout, r"(?m)^>?\s*0\b")

        self.assertIn("for_each_task()", cmd.drgn_option.stdout)
        self.assertIn("if task_is_kthread(task):", cmd.drgn_option.stdout)
        self.assertIn("continue", cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

    def test_user_and_pid(self):
        cmd = self.check_crash_command("ps -H -u 1")

        self.assertRegex(cmd.stdout, r"^>?\s*1\b.*\n$")

        self.assertIn("pid = 1", cmd.drgn_option.stdout)
        self.assertIn("find_task(pid)", cmd.drgn_option.stdout)
        self.assertNotIn("for_each_task", cmd.drgn_option.stdout)
        self.assertIn("if task_is_kthread(task):", cmd.drgn_option.stdout)
        self.assertIn("continue", cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

    def test_user_and_kernel_pid(self):
        cmd = self.check_crash_command("ps -H -u 0 2")

        self.assertFalse(cmd.stdout)
        self.assertNotIn("ppid", cmd.drgn_option.globals)

    def test_group_leader(self):
        cmd = self.check_crash_command("ps -G")

        self.assertRegex(cmd.stdout, rf"(?m)^>?\s*{os.getpid()}\b")
        self.assertNotRegex(cmd.stdout, rf"(?m)^>?\s*{self.threads[0].native_id}\b")

        self.assertIn("for_each_task(idle=True)", cmd.drgn_option.stdout)
        self.assertIn("if not thread_group_leader(task):", cmd.drgn_option.stdout)
        self.assertIn("continue", cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

    def test_group_leader_and_pid(self):
        cmd = self.check_crash_command(f"ps -H -G {os.getpid()}")
        foreach_cmd = self.check_crash_command(
            f"foreach {os.getpid()} ps -H -G", mode="capture"
        )

        for c in (cmd, foreach_cmd):
            self.assertRegex(c.stdout, rf"^>?\s*{os.getpid()}\b.*$")

        self.assertIn("find_task(pid)", cmd.drgn_option.stdout)
        self.assertNotIn("for_each_task", cmd.drgn_option.stdout)
        self.assertIn("if not thread_group_leader(task):", cmd.drgn_option.stdout)
        self.assertIn("task = task.group_leader", cmd.drgn_option.stdout)
        self.assertNotIn("continue", cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

        self.assertEqual(cmd.drgn_option.stdout, foreach_cmd.drgn_option.stdout)

    def test_group_leader_and_tid(self):
        cmd = self.check_crash_command(f"ps -H -G {self.threads[0].native_id}")

        self.assertRegex(cmd.stdout, rf"^>?\s*{os.getpid()}\b.*$")

        self.assertIn("find_task(pid)", cmd.drgn_option.stdout)
        self.assertNotIn("for_each_task", cmd.drgn_option.stdout)
        self.assertIn("if not thread_group_leader(task):", cmd.drgn_option.stdout)
        self.assertIn("task = task.group_leader", cmd.drgn_option.stdout)
        self.assertNotIn("continue", cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

    def test_group_leader_and_task_struct(self):
        address = find_task(self.prog, os.getpid()).value_()
        cmd = self.check_crash_command(f"ps -H -G {address:#x}")

        self.assertRegex(cmd.stdout, rf"^>?\s*{os.getpid()}\b.*$")

        self.assertNotIn("for_each_task", cmd.drgn_option.stdout)
        self.assertIn(hex(address), cmd.drgn_option.stdout)
        self.assertIn('Object(prog, "struct task_struct *", ', cmd.drgn_option.stdout)
        self.assertIn("if not thread_group_leader(task):", cmd.drgn_option.stdout)
        self.assertIn("task = task.group_leader", cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

    def test_group_leader_and_thread_task_struct(self):
        address = find_task(self.prog, self.threads[0].native_id).value_()
        cmd = self.check_crash_command(f"ps -H -G {address:#x}")

        self.assertRegex(cmd.stdout, rf"^>?\s*{os.getpid()}\b.*$")

        self.assertNotIn("for_each_task", cmd.drgn_option.stdout)
        self.assertIn(hex(address), cmd.drgn_option.stdout)
        self.assertIn('Object(prog, "struct task_struct *", ', cmd.drgn_option.stdout)
        self.assertIn("if not thread_group_leader(task):", cmd.drgn_option.stdout)
        self.assertIn("task = task.group_leader", cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

    def test_group_leader_and_command_name(self):
        cmd = self.check_crash_command(
            f"ps -H -G {_quoted_comm()} {_quoted_comm(self.threads[0].native_id)}"
        )

        self.assertRegex(cmd.stdout, rf"(?m)^>?\s*{os.getpid()}\b")
        self.assertNotRegex(cmd.stdout, rf"(?m)^>?\s*{self.threads[0].native_id}\b")

        self.assertIn("for_each_task(idle=True)", cmd.drgn_option.stdout)
        self.assertIn("if not thread_group_leader(task):", cmd.drgn_option.stdout)
        self.assertNotIn("task = task.group_leader", cmd.drgn_option.stdout)
        self.assertIn("comm_string not in ", cmd.drgn_option.stdout)
        self.assertIn("continue", cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

    def test_policy(self):
        with fork_and_stop() as pid1, fork_and_stop() as pid2:
            os.sched_setscheduler(pid1, os.SCHED_OTHER, os.sched_param(0))
            os.sched_setscheduler(pid2, os.SCHED_BATCH, os.sched_param(0))

            cmd = self.check_crash_command("ps -y BATCH")
            foreach_cmd = self.check_crash_command(
                "foreach ps -y BATCH", mode="capture"
            )

        for c in (cmd, foreach_cmd):
            self.assertRegex(c.stdout, rf"(?m)^>?\s*{pid2}\b")
            self.assertNotRegex(c.stdout, rf"(?m)^>?\s*{pid1}\b")

        self.assertIn("for_each_task(idle=True)", cmd.drgn_option.stdout)
        self.assertIn("if task.policy.value_() != ", cmd.drgn_option.stdout)
        self.assertIn("continue", cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

        self.assertEqual(cmd.drgn_option.stdout, foreach_cmd.drgn_option.stdout)

    def test_state(self):
        with fork_and_stop() as pid:
            cmd = self.check_crash_command("foreach R ps")

        self.assertNotRegex(cmd.stdout, rf"(?m)^>?\s*{pid}\b")

        self.assertIn("for_each_task(idle=True)", cmd.drgn_option.stdout)
        self.assertIn("if task_state_to_char(task) != ", cmd.drgn_option.stdout)
        self.assertIn("continue", cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

    def test_active(self):
        with fork_and_stop() as pid:
            cmd = self.check_crash_command("ps -A")
            foreach_cmd = self.check_crash_command("foreach active ps", mode="capture")

        for c in (cmd, foreach_cmd):
            self.assertNotRegex(c.stdout, rf"(?m)^>?\s*{pid}\b")

        self.assertIn("for_each_task(idle=True)", cmd.drgn_option.stdout)
        self.assertIn("if not task_on_cpu(task)", cmd.drgn_option.stdout)
        self.assertIn("continue", cmd.drgn_option.stdout)
        self._test_drgn_common(cmd)

        self.assertEqual(cmd.drgn_option.stdout, foreach_cmd.drgn_option.stdout)

    def _test_drgn_task_header(self, cmd):
        for variable in (
            "task",
            "pid",
            "command",
        ):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)
        self.assertIsInstance(cmd.drgn_option.globals["cpu"], int)

    def test_parents(self):
        with fork_and_stop() as pid:
            parents = [pid]
            current_pid = pid
            while current_pid != 0:
                ppid = int(
                    re.search(
                        r"^PPid:\s*([0-9]+)",
                        Path(f"/proc/{current_pid}/status").read_text(),
                        flags=re.M,
                    ).group(1)
                )
                parents.append(ppid)
                current_pid = ppid

            cmd = self.check_crash_command(f"ps -p {pid}")
            foreach_cmd = self.check_crash_command(
                f"foreach {pid} ps -p", mode="capture"
            )

        regex = ["^"]
        for i, expected_pid in enumerate(reversed(parents)):
            regex.append(" " * i + rf"PID: {expected_pid}\b.*\n")
        regex.append("$")
        for c in (cmd, foreach_cmd):
            self.assertRegex(c.stdout, "".join(regex))

        self.assertIn("task.parent", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["parent"].type_.type_name(), "struct task_struct *"
        )
        self._test_drgn_task_header(cmd)

        self.assertEqual(cmd.drgn_option.stdout, foreach_cmd.drgn_option.stdout)

    def test_children(self):
        with fork_and_stop() as pid1, fork_and_stop() as pid2:
            cmd = self.check_crash_command(f"ps -c {os.getpid()}")
            foreach_cmd = self.check_crash_command(
                f"foreach {os.getpid()} ps -c", mode="capture"
            )

        for c in (cmd, foreach_cmd):
            self.assertRegex(c.stdout, rf"^PID: {os.getpid()}\b")
            for pid in pid1, pid2:
                self.assertRegex(c.stdout, rf"(?m)^  PID: {pid}\b")

        self.assertIn("list_for_each_entry(", cmd.drgn_option.stdout)
        self.assertIn("task.children", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["child"].type_.type_name(), "struct task_struct *"
        )
        self._test_drgn_task_header(cmd)

        self.assertEqual(cmd.drgn_option.stdout, foreach_cmd.drgn_option.stdout)

    def test_no_children(self):
        with fork_and_stop() as pid:
            cmd = self.run_crash_command(f"ps -c {pid}")
        self.assertIn("(no children)", cmd.stdout)

    def test_times(self):
        cmd = self.check_crash_command(f"ps -t {os.getpid()}")
        foreach_cmd = self.check_crash_command(
            f"foreach {os.getpid()} ps -t", mode="capture"
        )

        for c in (cmd, foreach_cmd):
            self.assertRegex(
                c.stdout,
                r"(?m)^\s*RUN TIME: (?:[0-9] days, )?[0-9]{2}:[0-9]{2}:[0-9]{2}",
            )
            self.assertRegex(c.stdout, r"(?m)^\s*START TIME: [0-9]+$")
            self.assertRegex(c.stdout, r"(?m)^\s*UTIME: [0-9]+$")
            self.assertRegex(c.stdout, r"(?m)^\s*STIME: [0-9]+$")

        for variable in (
            "run_time",
            "start_time",
            "utime",
            "stime",
        ):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)
        self._test_drgn_task_header(cmd)

        self.assertEqual(cmd.drgn_option.stdout, foreach_cmd.drgn_option.stdout)

    def test_last_arrival_timestamp(self):
        cmd = self.check_crash_command("ps -l")
        foreach_cmd = self.check_crash_command("foreach ps -l", mode="capture")

        for c in (cmd, foreach_cmd):
            timestamps = []
            for line in c.stdout.splitlines():
                timestamps.append(
                    int(re.match(r"\[\s*([0-9]+)\] \[[A-Z]\]  PID: ", line).group(1))
                )
            self.assertEqual(timestamps, sorted(timestamps, reverse=True))

        self.assertIsInstance(cmd.drgn_option.globals["last_arrival"], Object)
        self.assertIsInstance(cmd.drgn_option.globals["state"], str)
        self._test_drgn_task_header(cmd)

        self.assertEqual(cmd.drgn_option.stdout, foreach_cmd.drgn_option.stdout)

    def test_last_arrival_elapsed(self):
        cmd = self.check_crash_command("ps -m")
        foreach_cmd = self.check_crash_command("foreach ps -m", mode="capture")

        for c in (cmd, foreach_cmd):
            for line in c.stdout.splitlines():
                self.assertRegex(
                    line,
                    r"^\[\s*[0-9]+ [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}\] \[[A-Z]\]  PID: ",
                )

        self.assertIn("task_since_last_arrival_ns(", cmd.drgn_option.stdout)
        self.assertIsInstance(cmd.drgn_option.globals["elapsed"], int)
        self.assertIsInstance(cmd.drgn_option.globals["state"], str)
        self._test_drgn_task_header(cmd)

        self.assertEqual(cmd.drgn_option.stdout, foreach_cmd.drgn_option.stdout)

    def test_last_arrival_cpus(self):
        cpu = min(online_cpus())
        cmd = self.run_crash_command(f"ps -l -C {cpu}")
        foreach_cmd = self.run_crash_command(f"foreach ps -l -C {cpu}")

        for c in (cmd, foreach_cmd):
            timestamps = []
            lines = c.stdout.splitlines()
            self.assertEqual(lines[0], f"CPU: {cpu}")
            for line in lines[1:]:
                timestamps.append(
                    int(
                        re.match(
                            rf"\[\s*([0-9]+)\] \[[A-Z]\]  PID: .*\bCPU: {cpu}\b", line
                        ).group(1)
                    )
                )
            self.assertEqual(timestamps, sorted(timestamps, reverse=True))

    @skip_unless_have_full_mm_support
    @skip_if_highmem
    def test_arguments(self):
        cmd = self.check_crash_command(f"ps -a {os.getpid()}")
        foreach_cmd = self.check_crash_command(
            f"foreach {os.getpid()} ps -a", mode="capture"
        )

        cmdline = Path("/proc/self/cmdline").read_text()
        if cmdline.endswith("\0"):
            cmdline = cmdline[:-1]
        cmdline = cmdline.replace("\0", " ")

        environ = Path("/proc/self/environ").read_text()
        if environ.endswith("\0"):
            environ = environ[:-1]
        environ = environ.replace("\0", "\n     ")

        for c in (cmd, foreach_cmd):
            self.assertRegex(c.stdout, rf"(?m)^ARG: {re.escape(cmdline)}$")
            self.assertRegex(c.stdout, rf"(?m)^ENV: {re.escape(environ)}$")

        self.assertIn("cmdline(", cmd.drgn_option.stdout)
        self.assertIn("environ(", cmd.drgn_option.stdout)
        self.assertIsInstance(cmd.drgn_option.globals["arg"], list)
        self.assertIsInstance(cmd.drgn_option.globals["env"], list)
        self._test_drgn_task_header(cmd)

        self.assertEqual(cmd.drgn_option.stdout, foreach_cmd.drgn_option.stdout)

    def test_thread_groups(self):
        cmd = self.check_crash_command("ps -g")
        foreach_cmd = self.check_crash_command("foreach ps -g", mode="capture")

        for c in (cmd, foreach_cmd):
            self.assertRegex(
                c.stdout,
                rf"(?m)^PID: {os.getpid()}\b.*\n(?:  PID: .*\n)*  PID: {self.threads[0].native_id}\b",
            )
            self.assertNotRegex(c.stdout, rf"(?m)^PID: {self.threads[0].native_id}\b")

        self.assertIn("if not thread_group_leader(task):", cmd.drgn_option.stdout)
        self.assertIn("continue", cmd.drgn_option.stdout)
        self.assertIn("for_each_task_in_group(", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["thread"].type_.type_name(), "struct task_struct *"
        )
        self._test_drgn_task_header(cmd)

        self.assertEqual(cmd.drgn_option.stdout, foreach_cmd.drgn_option.stdout)

    def test_thread_groups_and_pid(self):
        cmd = self.check_crash_command(f"ps -g {os.getpid()}")

        self.assertRegex(
            cmd.stdout,
            rf"(?m)^PID: {os.getpid()}\b.*\n(?:  PID: .*\n)*  PID: {self.threads[0].native_id}\b",
        )
        self.assertNotRegex(cmd.stdout, rf"(?m)^PID: {self.threads[0].native_id}\b")

        self.assertIn("if not thread_group_leader(task):", cmd.drgn_option.stdout)
        self.assertIn("task = task.group_leader", cmd.drgn_option.stdout)
        self.assertIn("for_each_task_in_group(", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["thread"].type_.type_name(), "struct task_struct *"
        )
        self._test_drgn_task_header(cmd)

    def test_thread_groups_no_threads(self):
        with fork_and_stop() as pid:
            cmd = self.run_crash_command(f"ps -g {pid}")

            self.assertIn("(no threads)", cmd.stdout)

    def test_thread_groups_and_tid(self):
        cmd = self.check_crash_command(f"ps -g {self.threads[-1].native_id}")

        self.assertRegex(
            cmd.stdout,
            rf"(?m)^PID: {os.getpid()}\b.*\n(?:  PID: .*\n)*  PID: {self.threads[0].native_id}\b",
        )
        self.assertNotRegex(cmd.stdout, rf"(?m)^PID: {self.threads[-1].native_id}\b")

        self.assertIn("if not thread_group_leader(task):", cmd.drgn_option.stdout)
        self.assertIn("task = task.group_leader", cmd.drgn_option.stdout)
        self.assertIn("for_each_task_in_group(", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["thread"].type_.type_name(), "struct task_struct *"
        )
        self._test_drgn_task_header(cmd)

    def test_thread_groups_and_command_name(self):
        cmd = self.check_crash_command(f"ps -g {_quoted_comm()}")

        self.assertRegex(
            cmd.stdout,
            rf"(?m)^PID: {os.getpid()}\b.*\n(?:  PID: .*\n)*  PID: {self.threads[0].native_id}\b",
        )
        self.assertNotRegex(cmd.stdout, rf"(?m)^PID: {self.threads[0].native_id}\b")

        self.assertIn("if not thread_group_leader(task):", cmd.drgn_option.stdout)
        self.assertIn("continue", cmd.drgn_option.stdout)
        self.assertNotIn("task = task.group_leader", cmd.drgn_option.stdout)
        self.assertIn("for_each_task_in_group(", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["thread"].type_.type_name(), "struct task_struct *"
        )
        self._test_drgn_task_header(cmd)

    def test_thread_groups_and_thread_command_name(self):
        cmd = self.check_crash_command(
            f"ps -g {_quoted_comm(self.threads[0].native_id)}"
        )

        self.assertNotRegex(cmd.stdout, rf"(?m)^PID: {os.getpid()}\b")
        self.assertNotRegex(cmd.stdout, rf"(?m)^PID: {self.threads[0].native_id}\b")

        self.assertIn("if not thread_group_leader(task):", cmd.drgn_option.stdout)
        self.assertIn("continue", cmd.drgn_option.stdout)
        self.assertNotIn("task = task.group_leader", cmd.drgn_option.stdout)
        self.assertIn("for_each_task_in_group(", cmd.drgn_option.stdout)
        self.assertNotIn("thread", cmd.drgn_option.globals)

    def test_rlimit(self):
        cmd = self.check_crash_command(f"ps -r {os.getpid()}")
        foreach_cmd = self.check_crash_command(
            f"foreach {os.getpid()} ps -r", mode="capture"
        )

        for c in (cmd, foreach_cmd):
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
                self.assertRegex(
                    c.stdout, rf"(?m)^\s*{name}(?:\s+(?:[0-9]+|\(unlimited\))){{2}}$"
                )

        self.assertIn("task_rlimits(", cmd.drgn_option.stdout)
        self.assertIsInstance(cmd.drgn_option.globals["rlimits"], dict)
        self._test_drgn_task_header(cmd)

        self.assertEqual(cmd.drgn_option.stdout, foreach_cmd.drgn_option.stdout)

    def test_summary(self):
        cmd = self.check_crash_command("ps -S")
        foreach_cmd = self.check_crash_command("foreach ps -S", mode="capture")

        for c in (cmd, foreach_cmd):
            self.assertRegex(c.stdout, r"^(?:\s*[A-Z]: [0-9]+)+$")

        self.assertIn("task_state_to_char(", cmd.drgn_option.stdout)
        self.assertIsInstance(cmd.drgn_option.globals["counter"], collections.Counter)

        self.assertEqual(cmd.drgn_option.stdout, foreach_cmd.drgn_option.stdout)


class TestForeach(CrashCommandTestCase):
    def test_help(self):
        # The actual functionality of foreach is tested in the individual
        # subcommands. This just tests that we properly document what
        # subcommands are supported.
        cmd = self.run_crash_command("help foreach")
        match = re.search(
            r"Currently,\s+((?:\*\*\w+\*\*,\s+)+)and\s+(\*\*\w+\*\*)\s+are\s+supported",
            cmd.stdout,
        )
        self.assertTrue(match)
        documented = (
            (match.group(1) + match.group(2)).replace("*", "").replace(",", "").split()
        )
        self.assertEqual(documented, sorted(_CRASH_FOREACH_SUBCOMMANDS))
