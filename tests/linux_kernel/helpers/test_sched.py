# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import os
from pathlib import Path
import resource
import signal
from threading import Condition, Thread
import time
import unittest

from drgn import container_of
from drgn.helpers.linux.cgroup import cgroup_get_from_path
from drgn.helpers.linux.cpumask import for_each_possible_cpu
from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.sched import (
    cfs_rq_for_each_entity,
    cpu_curr,
    cpu_rq,
    get_task_state,
    idle_task,
    loadavg,
    rq_for_each_fair_task,
    rq_for_each_rt_task,
    sched_entity_is_task,
    sched_entity_to_task,
    task_cpu,
    task_group_name,
    task_on_cpu,
    task_since_last_arrival_ns,
    task_state_to_char,
    task_thread_info,
    thread_group_leader,
)
from tests.linux_kernel import (
    LinuxKernelTestCase,
    fork_and_stop,
    proc_state,
    skip_unless_have_test_kmod,
    wait_until,
)
from tests.linux_kernel.helpers.test_cgroup import tmp_cgroup


@contextlib.contextmanager
def tmp_cgroup_with_cpu_controller():
    with tmp_cgroup() as cgroup_dir:
        if "cpu" not in (cgroup_dir / "cgroup.controllers").read_text().split():
            raise unittest.SkipTest("cgroup CPU controller not enabled")
        yield cgroup_dir


class TestSched(LinuxKernelTestCase):
    @skip_unless_have_test_kmod
    def test_task_thread_info(self):
        self.assertEqual(
            task_thread_info(self.prog["drgn_test_kthread"]),
            self.prog["drgn_test_kthread_info"],
        )

    def test_task_cpu(self):
        cpu = os.cpu_count() - 1
        with fork_and_stop(os.sched_setaffinity, 0, (cpu,)) as (pid, _):
            self.assertEqual(task_cpu(find_task(self.prog, pid)), cpu)

    def test_task_state_to_char(self):
        task = find_task(self.prog, os.getpid())
        self.assertEqual(task_state_to_char(task), "R")
        self.assertEqual(get_task_state(task), "R (running)")

        pid = os.fork()
        try:
            if pid == 0:
                try:
                    while True:
                        signal.pause()
                finally:
                    os._exit(1)

            task = find_task(self.prog, pid)

            wait_until(lambda: proc_state(pid) == "S")
            self.assertEqual(task_state_to_char(task), "S")
            self.assertEqual(get_task_state(task), "S (sleeping)")

            os.kill(pid, signal.SIGSTOP)
            wait_until(lambda: proc_state(pid) == "T")
            self.assertEqual(task_state_to_char(task), "T")

            os.kill(pid, signal.SIGKILL)
            wait_until(lambda: proc_state(pid) == "Z")
            self.assertEqual(task_state_to_char(task), "Z")
        finally:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)

    def test_task_on_cpu(self):
        task = find_task(self.prog, os.getpid())
        self.assertTrue(task_on_cpu(task))

        with fork_and_stop() as pid:
            task = find_task(self.prog, pid)
            self.assertFalse(task_on_cpu(task))

    def test_cpu_curr(self):
        task = find_task(self.prog, os.getpid())
        cpu = os.cpu_count() - 1
        old_affinity = os.sched_getaffinity(0)
        os.sched_setaffinity(0, (cpu,))
        try:
            self.assertEqual(cpu_curr(self.prog, cpu), task)
        finally:
            os.sched_setaffinity(0, old_affinity)

    def test_idle_task(self):
        for cpu in for_each_possible_cpu(self.prog):
            task = idle_task(self.prog, cpu)
            if cpu == 0:
                self.assertEqual(task, self.prog["init_task"].address_of_())
            else:
                self.assertEqual(task.comm.string_(), f"swapper/{cpu}".encode())

    def test_loadavg(self):
        values = loadavg(self.prog)
        self.assertEqual(len(values), 3)
        self.assertTrue(all(v >= 0.0 for v in values))

    def test_task_since_last_arrival_ns(self):
        with fork_and_stop() as pid:
            time.sleep(0.01)
            # Forcing the process to migrate also forces the rq clock to update
            # so we can get a reliable reading.
            affinity = os.sched_getaffinity(pid)
            if len(affinity) > 1:
                other_affinity = {affinity.pop()}
                os.sched_setaffinity(pid, affinity)
                os.sched_setaffinity(pid, other_affinity)
            task = find_task(self.prog, pid)
            self.assertGreaterEqual(task_since_last_arrival_ns(task), 10000000)

    def test_rq_for_each_fair_task(self):
        old_affinity = os.sched_getaffinity(0)
        cpu = max(old_affinity)
        os.sched_setaffinity(0, (cpu,))
        self.addCleanup(os.sched_setaffinity, 0, old_affinity)

        rq = cpu_rq(self.prog, cpu)
        pids = [task.pid.value_() for task in rq_for_each_fair_task(rq)]
        self.assertIn(os.getpid(), pids)

    def test_rq_for_each_rt_task(self):
        old_affinity = os.sched_getaffinity(0)
        cpu = max(old_affinity)
        os.sched_setaffinity(0, (cpu,))
        self.addCleanup(os.sched_setaffinity, 0, old_affinity)

        old_rlimit = resource.getrlimit(resource.RLIMIT_RTTIME)
        resource.setrlimit(
            resource.RLIMIT_RTTIME, (resource.RLIM_INFINITY, resource.RLIM_INFINITY)
        )
        self.addCleanup(resource.setrlimit, resource.RLIMIT_RTTIME, old_rlimit)

        old_scheduler = os.sched_getscheduler(0)
        old_param = os.sched_getparam(0)
        os.sched_setscheduler(0, os.SCHED_RR, os.sched_param(1))
        self.addCleanup(os.sched_setscheduler, 0, old_scheduler, old_param)

        rq = cpu_rq(self.prog, cpu)
        pids = [task.pid.value_() for task in rq_for_each_rt_task(rq)]
        self.assertIn(os.getpid(), pids)

    def test_sched_entity_is_task(self):
        task = find_task(self.prog, os.getpid())
        self.assertTrue(sched_entity_is_task(task.se.address_of_()))

    def test_sched_entity_is_task_false(self):
        with tmp_cgroup_with_cpu_controller() as cgroup_dir:
            cgrp = cgroup_get_from_path(self.prog, cgroup_dir.name)
            css = cgrp.subsys[self.prog["cpu_cgrp_id"]]
            task_group = container_of(css, "struct task_group", "css")
            cpu = min(os.sched_getaffinity(0))
            se = task_group.se[cpu].read_()
            self.assertFalse(sched_entity_is_task(se))

    def test_sched_entity_to_task(self):
        task = find_task(self.prog, os.getpid())
        self.assertEqual(sched_entity_to_task(task.se.address_of_()), task)

    def test_task_group_name(self):
        with tmp_cgroup_with_cpu_controller() as cgroup_dir:
            cgrp = cgroup_get_from_path(self.prog, cgroup_dir.name)
            css = cgrp.subsys[self.prog["cpu_cgrp_id"]]
            task_group = container_of(css, "struct task_group", "css")
            self.assertEqual(task_group_name(task_group), cgroup_dir.name.encode())

    def test_cfs_rq_for_each_entity(self):
        old_affinity = os.sched_getaffinity(0)
        cpu = max(old_affinity)
        self.addCleanup(os.sched_setaffinity, 0, old_affinity)
        os.sched_setaffinity(0, (cpu,))

        with tmp_cgroup_with_cpu_controller() as cgroup_dir:
            old_cgroup = (
                Path("/proc/self/cgroup").read_text().strip().partition("::")[2]
            )
            old_cgroup_procs = (
                cgroup_dir.parent / old_cgroup.lstrip("/") / "cgroup.procs"
            )
            (cgroup_dir / "cgroup.procs").write_text(str(os.getpid()))
            try:
                cgrp = cgroup_get_from_path(self.prog, cgroup_dir.name)
                css = cgrp.subsys[self.prog["cpu_cgrp_id"]]
                task_group = container_of(css, "struct task_group", "css")
                task_group_se = task_group.se[cpu].read_()

                task = find_task(self.prog, os.getpid())
                task_se = task.se.address_of_()

                entities = list(
                    cfs_rq_for_each_entity(cpu_rq(self.prog, cpu).cfs.address_of_())
                )
                self.assertIn((task_group_se, 0, True, False), entities)
                self.assertIn((task_se, 1, True, True), entities)
            finally:
                old_cgroup_procs.write_text(str(os.getpid()))

    def test_thread_group_leader(self):
        condition = Condition()

        def thread_func():
            with condition:
                condition.wait()

        thread = Thread(target=thread_func)
        try:
            thread.start()

            self.assertTrue(thread_group_leader(find_task(self.prog, os.getpid())))
            self.assertFalse(
                thread_group_leader(find_task(self.prog, thread.native_id))
            )
        finally:
            with condition:
                condition.notify_all()
            thread.join()
