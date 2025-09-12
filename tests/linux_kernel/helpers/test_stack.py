# Copyright (c) 2026 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.stack import StackKind, kernel_stack_trace
from tests.linux_kernel import (
    LinuxKernelTestCase,
    skip_unless_have_stack_tracing,
    skip_unless_have_test_kmod,
)


class TestStack(LinuxKernelTestCase):
    @skip_unless_have_test_kmod
    @skip_unless_have_stack_tracing
    def test_kernel_stack_trace(self):
        trace = kernel_stack_trace(self.prog["drgn_test_kthread"])
        self.assertEqual(trace.prog, self.prog)
        self.assertEqual(trace.segments[0].kind, StackKind.TASK)

    @skip_unless_have_test_kmod
    @skip_unless_have_stack_tracing
    def test_kernel_stack_trace_by_pid_object(self):
        trace = kernel_stack_trace(self.prog["drgn_test_kthread"].pid)
        self.assertEqual(trace.prog, self.prog)
        self.assertEqual(trace.segments[0].kind, StackKind.TASK)

    @skip_unless_have_test_kmod
    @skip_unless_have_stack_tracing
    def test_kernel_stack_trace_by_pid_int(self):
        trace = kernel_stack_trace(self.prog, int(self.prog["drgn_test_kthread"].pid))
        self.assertEqual(trace.prog, self.prog)
        self.assertEqual(trace.segments[0].kind, StackKind.TASK)

    @skip_unless_have_stack_tracing
    def test_kernel_stack_trace_user(self):
        task = find_task(self.prog, 1)
        try:
            trace = kernel_stack_trace(task)
        except ValueError as e:
            if "cannot unwind stack of running task" in str(e):
                self.skipTest("init task is currently on CPU")
            else:
                raise

        self.assertEqual(trace.prog, self.prog)
        self.assertEqual(trace.segments[0].kind, StackKind.TASK)

        # Not all architectures can unwind into the userspace frame. But if so,
        # we should categorize it correctly.
        if len(trace.segments) > 1:
            self.assertEqual(trace.segments[1].kind, StackKind.USER)
