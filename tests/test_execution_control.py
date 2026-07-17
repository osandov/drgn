# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import collections
import contextlib
import os
import signal

import drgn
from tests import TestCase


# TODO: unitfy with test_thread_finder.py
class SimpleThreadFinder(drgn.ThreadFinder):
    def __init__(self, num_threads: int = 10) -> None:
        self.num_threads = num_threads

    def threads(self, cache):
        for tid in range(1, self.num_threads + 1):
            yield cache.find_or_create(tid, 0)[0]

    def thread(self, cache, tid):
        if 1 <= tid <= self.num_threads:
            return cache.find_or_create(tid, 0)[0]
        return None

    def main_thread(self, cache):
        return cache.find_or_create(1, 0)[0]

    def thread_object(self, thread):
        return Object(thread.prog, "void *", thread.tid * 0x1000)

    def thread_name(self, thread):
        return f"thread-{thread.tid}"


class MockExecutionController(drgn.ExecutionController):
    def __init__(self) -> None:
        self._op_hooks = {
            # Complete attaches and detaches by default.
            "attach": lambda name, args, promise, result: True,
            "detach": lambda name, args, promise, result: True,
        }

    def _op(self, name, args, promise, result):
        hook = self._op_hooks.get(name)
        if hook is None:
            hook = self._op_hooks.get(None)
            if hook is None:
                promise.set_exception(Exception(f"unexpected {name} operation"))
                return
        if hook(name, args, promise, result):
            self._queue_call(lambda prog: promise.set_result(result))

    def _queue_call(self, fn):
        self._q.append(fn)
        os.write(self._pipe_w, b"\0")

    def _read_pipe(self, prog, fd, events):
        while True:
            try:
                os.read(fd, 1)
            except BlockingIOError:
                break
            self._q.popleft()(prog)

    def attach(self, prog, flags, promise):
        self._pipe_r, self._pipe_w = os.pipe()
        os.set_blocking(self._pipe_r, False)
        self._q = collections.deque()
        self._ops = None
        self._promises = None

        prog.register_fd(self._pipe_r, drgn.FdEvents.READ, self._read_pipe)
        self._op("attach", (flags,), promise, not (flags & drgn.AttachFlags.NON_STOP))

    def detach(self, prog, promise):
        self._op("detach", (), promise, None)

    def resume_threads(self, prog, actions, promise):
        self._op("resume_threads", (list(actions),), promise, None)

    def enable_breakpoint_sites(self, sites, promise):
        self._op("enable_breakpoint_sites", (list(sites),), promise, None)

    def disable_breakpoint_sites(self, sites, promise):
        self._op("disable_breakpoint_sites", (list(sites),), promise, None)


class ExecutionControlTestCase(TestCase):
    def setUp(self):
        super().setUp()
        self.prog = drgn.Program(platform=drgn.Platform(drgn.Architecture.X86_64))

        self._event_hooks = []
        self._unexpected_events = []
        self.prog.add_event_listener(self._event_listener)
        self.addCleanup(self._check_unexpected_events)

        self.prog.register_thread_finder("test", SimpleThreadFinder(), enable_index=0)
        self._ctrl = MockExecutionController()
        self.prog.register_execution_controller("test", self._ctrl, enable_index=0)

    # TODO: I think this is what we want self.prog.poll() to do by default.
    def poll_all(self, block=False):
        if block:
            self.prog.poll()
        while self.prog.poll(0):
            pass

    def poll_until(self, cond, *args):
        while not cond(args):
            self.poll_all(block=True)

    def queue_call(self, fn):
        self._ctrl._queue_call(fn)

    def _event_listener(self, prog, event):
        expected = False
        for hook in self._event_hooks:
            if hook(event):
                expected = True
        if not expected:
            self._unexpected_events.append(event)

    def _check_unexpected_events(self):
        if self._unexpected_events:
            try:
                if len(self._unexpected_events) == 1:
                    self.fail(f"unexpected event: {self._unexpected_events[0]!r}")
                else:
                    self.fail(f"unexpected events: {self._unexpected_events!r}")
            finally:
                self._unexpected_events.clear()

    @contextlib.contextmanager
    def hook_events(self, hook):
        self.poll_all()
        self._check_unexpected_events()

        self._event_hooks.append(hook)
        try:
            yield
            self.poll_all()
        finally:
            self._event_hooks.pop()

    @contextlib.contextmanager
    def capture_events(self):
        events = []

        def capture_event(event):
            events.append(event)
            return True

        with self.hook_events(capture_event):
            yield events

    # @contextlib.contextmanager
    # def capture_ops(self):
    #     assert self._ctrl._ops is None
    #     try:
    #         self._ctrl._ops = []
    #         self._ctrl._promises = []
    #         yield self._ops
    #     finally:
    #         self._ctrl._promises = None
    #         self._ctrl._ops = None

    # def complete_op(self, i):
    #     del self._ctrl._ops[i]
    #     promise, result = self._ctrl._promises.pop(i)
    #     self.queue_call(lambda prog: promise.set_result(result))

    @contextlib.contextmanager
    def hook_ops(self, hooks, replace=False):
        saved_hooks = self._ctrl._op_hooks

        try:
            if replace:
                self._ctrl._op_hooks = hooks
            else:
                self._ctrl._op_hooks = {**saved_hooks, **hooks}
            yield
        finally:
            self._ctrl._op_hooks = saved_hooks

    @contextlib.contextmanager
    def complete_ops(self):
        saved_hooks = self._ctrl._op_hooks

        ops = []

        def complete_hook(name, args, promise, result):
            ops.append((name, *args))
            return True

        try:
            self._ctrl._op_hooks = {None: complete_hook}
            yield ops
        finally:
            self._ctrl._op_hooks = saved_hooks


class TestLifecycle(ExecutionControlTestCase):
    def setUp(self):
        super().setUp()
        # Don't complete attach and detach by default for these tests.
        self._ctrl._op_hooks.clear()

    def test_attach_and_detach(self):
        self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHED)

        attach_state = []

        def attach_state_hook(name, args, promise, result):
            attach_state.append(self.prog.attach_state)
            return True

        with self.hook_ops({"attach": attach_state_hook}):
            self.prog.attach(drgn.AttachFlags.ALL_STOP)
        self.assertEqual(attach_state, [drgn.AttachState.ATTACHING])

        self.assertEqual(self.prog.attach_state, drgn.AttachState.ATTACHED)

        attach_state.clear()
        with self.hook_ops({"detach": attach_state_hook}):
            self.prog.detach()
        self.assertEqual(attach_state, [drgn.AttachState.DETACHING])

        self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHED)

    def test_attach_failure(self):
        def attach_hook(name, args, promise, result):
            promise.set_exception(Exception("foo"))
            return False

        with self.hook_ops({"attach": attach_hook}):
            self.assertRaisesRegex(
                Exception, "foo", self.prog.attach, drgn.AttachFlags.ALL_STOP
            )

        self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHED)

    def test_context_manager(self):
        with self.complete_ops() as ops:
            with self.prog.attach(drgn.AttachFlags.ALL_STOP):
                self.assertEqual(ops, [("attach", drgn.AttachFlags.ALL_STOP)])
                self.assertEqual(self.prog.attach_state, drgn.AttachState.ATTACHED)
                ops.clear()

            self.assertEqual(ops, [("detach",)])
            self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHED)

    def test_attach_synchronously(self):
        def complete_now(name, args, promise, result):
            promise.set_result(result)
            return False

        with self.hook_ops(
            {"attach": lambda name, args, promise, result: complete_now}
        ):
            self.prog.attach(drgn.AttachFlags.ALL_STOP)
        self.assertEqual(self.prog.attach_state, drgn.AttachState.ATTACHED)

        with self.complete_ops():
            self.prog.detach()
        self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHED)

    def test_program_exit(self):
        with self.complete_ops():
            self.prog.attach(drgn.AttachFlags.ALL_STOP)

        event_attach_state = []

        def event_hook(event):
            if not isinstance(event, drgn.ProgramExitEvent) or event.status != 0:
                return False
            event_attach_state.append(self.prog.attach_state)
            return True

        with self.hook_events(event_hook):
            self.queue_call(lambda prog: prog.notify_program_exit(0))

        self.assertEqual(event_attach_state, [drgn.AttachState.EXITED])
        self.assertEqual(self.prog.attach_state, drgn.AttachState.EXITED)

        with self.complete_ops():
            self.prog.detach()

        self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHED)

    def test_program_exit_during_detach(self):
        with self.complete_ops():
            self.prog.attach(drgn.AttachFlags.ALL_STOP)

        event_attach_state = []

        def event_hook(event):
            if not isinstance(event, drgn.ProgramExitEvent) or event.status != 0:
                return False
            event_attach_state.append(self.prog.attach_state)
            return True

        def exit_during_detach(name, args, promise, result):
            self.queue_call(lambda prog: prog.notify_program_exit(0))
            return True

        with self.hook_events(event_hook), self.hook_ops(
            {"detach": exit_during_detach}
        ):
            self.prog.detach()

        self.assertEqual(event_attach_state, [drgn.AttachState.DETACHING])
        self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHED)


class TestAllStop(ExecutionControlTestCase):
    def test_signal_stop(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.assertIsNone(self.prog.thread(1).stop_reason)

            self.queue_call(
                lambda prog: prog.notify_thread_stop(
                    prog.thread(1), signal.SIGWINCH, 0x1337
                )
            )
            with self.capture_events() as events:
                self.queue_call(lambda prog: prog.notify_all_stop())
            self.assertEqual(events, [drgn.ThreadStopEvent(self.prog.thread(1))])

            self.assertEqual(
                self.prog.thread(1).stop_reason, drgn.SignalStopReason(signal.SIGWINCH)
            )
            self.assertEqual(
                self.prog.thread(2).stop_reason, drgn.SyntheticStopReason()
            )

    def test_signal_stop_explicit(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.queue_call(
                lambda prog: prog.notify_thread_stop(
                    prog.thread(1), signal.SIGWINCH, 0x1337, drgn.SignalStopReason
                )
            )
            with self.capture_events() as events:
                self.queue_call(lambda prog: prog.notify_all_stop())
            self.assertEqual(events, [drgn.ThreadStopEvent(self.prog.thread(1))])

            self.assertEqual(
                self.prog.thread(1).stop_reason, drgn.SignalStopReason(signal.SIGWINCH)
            )
            self.assertEqual(
                self.prog.thread(2).stop_reason, drgn.SyntheticStopReason()
            )

    def test_signal_cont(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.queue_call(
                lambda prog: prog.notify_thread_stop(
                    prog.thread(1), signal.SIGWINCH, 0x1337
                )
            )
            with self.capture_events():
                self.queue_call(lambda prog: prog.notify_all_stop())

            with self.complete_ops() as ops:
                self.prog.thread(1).cont()

            self.assertEqual(
                ops,
                [
                    (
                        "resume_threads",
                        [
                            drgn.ContinueResumeAction(
                                self.prog.thread(1), signal.SIGWINCH
                            ),
                            drgn.ContinueResumeAction(None, 0),
                        ],
                    )
                ],
            )

            self.assertIsNone(self.prog.thread(1).stop_reason)
            self.assertIsNone(self.prog.thread(2).stop_reason)

    def test_signal_cont_suppress(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.queue_call(
                lambda prog: prog.notify_thread_stop(
                    prog.thread(1), signal.SIGWINCH, 0x1337
                )
            )
            with self.capture_events():
                self.queue_call(lambda prog: prog.notify_all_stop())

            with self.complete_ops() as ops:
                self.prog.thread(1).cont(sig=0)

            self.assertEqual(
                ops,
                [
                    (
                        "resume_threads",
                        [
                            drgn.ContinueResumeAction(self.prog.thread(1), 0),
                            drgn.ContinueResumeAction(None, 0),
                        ],
                    )
                ],
            )

            self.assertIsNone(self.prog.thread(1).stop_reason)
            self.assertIsNone(self.prog.thread(2).stop_reason)

    def test_signal_cont_suppress_by_default(self):
        for sig in (signal.SIGTRAP, signal.SIGINT):
            with self.subTest(sig=sig):
                with self.prog.attach(drgn.AttachFlags.ALL_STOP):
                    self.queue_call(
                        lambda prog: prog.notify_thread_stop(
                            prog.thread(1), sig, 0x1337
                        )
                    )
                    with self.capture_events():
                        self.queue_call(lambda prog: prog.notify_all_stop())

                    with self.complete_ops() as ops:
                        self.prog.thread(1).cont()

                    self.assertEqual(
                        ops,
                        [
                            (
                                "resume_threads",
                                [
                                    drgn.ContinueResumeAction(self.prog.thread(1), 0),
                                    drgn.ContinueResumeAction(None, 0),
                                ],
                            )
                        ],
                    )

                    self.assertIsNone(self.prog.thread(1).stop_reason)
                    self.assertIsNone(self.prog.thread(2).stop_reason)

    def test_simultaneous_stop(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.queue_call(
                lambda prog: prog.notify_thread_stop(
                    prog.thread(1), signal.SIGWINCH, 0x1337
                )
            )
            self.queue_call(
                lambda prog: prog.notify_thread_stop(
                    prog.thread(2), signal.SIGCHLD, 0xDEAD
                )
            )
            with self.capture_events() as events1:
                self.queue_call(lambda prog: prog.notify_all_stop())

            # We should get only one thread stop event, but both threads should
            # be stopped with a signal.
            self.assertEqual(len(events1), 1)
            self.assertIsInstance(events1[0], drgn.ThreadStopEvent)

            self.assertEqual(
                self.prog.thread(1).stop_reason, drgn.SignalStopReason(signal.SIGWINCH)
            )
            self.assertEqual(
                self.prog.thread(2).stop_reason, drgn.SignalStopReason(signal.SIGCHLD)
            )
            self.assertEqual(
                self.prog.thread(3).stop_reason, drgn.SyntheticStopReason()
            )

            # This shouldn't call any operations, but it should emit the other
            # thread stop event.
            with self.capture_events() as events2:
                events1[0].thread.cont()

            self.assertCountEqual(
                events1 + events2,
                [
                    drgn.ThreadStopEvent(self.prog.thread(1)),
                    drgn.ThreadStopEvent(self.prog.thread(2)),
                ],
            )

            # The thread we continued should now be in a synthetic stop, the
            # other one should still be stopped with a signal, and we should
            # get the other thread stop event.
            self.assertEqual(events1[0].thread.stop_reason, drgn.SyntheticStopReason())
            if events1[0].thread == self.prog.thread(1):
                self.assertEqual(
                    self.prog.thread(2).stop_reason,
                    drgn.SignalStopReason(signal.SIGCHLD),
                )
            else:
                self.assertEqual(
                    self.prog.thread(1).stop_reason,
                    drgn.SignalStopReason(signal.SIGWINCH),
                )
            self.assertEqual(
                self.prog.thread(3).stop_reason, drgn.SyntheticStopReason()
            )

            with self.complete_ops() as ops:
                events2[0].thread.cont()

            self.assertEqual(len(ops), 1)
            self.assertEqual(ops[0][0], "resume_threads")
            actions = ops[0][1]
            self.assertEqual(actions[-1], drgn.ContinueResumeAction(None, 0))
            self.assertCountEqual(
                actions[:-1],
                [
                    drgn.ContinueResumeAction(self.prog.thread(1), signal.SIGWINCH),
                    drgn.ContinueResumeAction(self.prog.thread(2), signal.SIGCHLD),
                ],
            )

            # After continuing again, everything should be resumed.
            self.assertIsNone(self.prog.thread(1).stop_reason)
            self.assertIsNone(self.prog.thread(2).stop_reason)
            self.assertIsNone(self.prog.thread(3).stop_reason)

    def test_simultaneous_stop_cont_other(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.queue_call(
                lambda prog: prog.notify_thread_stop(
                    prog.thread(1), signal.SIGWINCH, 0x1337
                )
            )
            self.queue_call(
                lambda prog: prog.notify_thread_stop(
                    prog.thread(2), signal.SIGCHLD, 0xDEAD
                )
            )
            with self.capture_events() as events1:
                self.queue_call(lambda prog: prog.notify_all_stop())
            event_thread = events1[0].thread

            # Continue the thread that we didn't get an event for. This
            # shouldn't call any operations and it should emit any events.
            self.prog.thread(2 if event_thread == self.prog.thread(1) else 1).cont()

            # The thread we continued should now be in a synthetic stop, and
            # the one we got the stop event for should still be stopped with a
            # signal.
            if event_thread == self.prog.thread(1):
                self.assertEqual(
                    self.prog.thread(1).stop_reason,
                    drgn.SignalStopReason(signal.SIGWINCH),
                )
                self.assertEqual(
                    self.prog.thread(2).stop_reason, drgn.SyntheticStopReason()
                )
            else:
                self.assertEqual(
                    self.prog.thread(1).stop_reason, drgn.SyntheticStopReason()
                )
                self.assertEqual(
                    self.prog.thread(2).stop_reason,
                    drgn.SignalStopReason(signal.SIGCHLD),
                )
            self.assertEqual(
                self.prog.thread(3).stop_reason, drgn.SyntheticStopReason()
            )

            with self.complete_ops() as ops:
                event_thread.cont()

            self.assertEqual(len(ops), 1)
            self.assertEqual(ops[0][0], "resume_threads")
            actions = ops[0][1]
            self.assertEqual(actions[-1], drgn.ContinueResumeAction(None, 0))
            self.assertCountEqual(
                actions[:-1],
                [
                    drgn.ContinueResumeAction(self.prog.thread(1), signal.SIGWINCH),
                    drgn.ContinueResumeAction(self.prog.thread(2), signal.SIGCHLD),
                ],
            )

            # After continuing the thread we got the stop event for, everything
            # should be resumed.
            self.assertIsNone(self.prog.thread(1).stop_reason)
            self.assertIsNone(self.prog.thread(2).stop_reason)
            self.assertIsNone(self.prog.thread(3).stop_reason)

    def test_breakpoint_stop(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            with self.complete_ops():
                site = self.prog.set_breakpoint(0x1337).sites[0]

            self.queue_call(
                lambda prog: prog.notify_thread_breakpoint(prog.thread(1), site)
            )
            with self.capture_events() as events:
                self.queue_call(lambda prog: prog.notify_all_stop())
            self.assertEqual(events, [drgn.ThreadStopEvent(self.prog.thread(1))])

            self.assertEqual(
                self.prog.thread(1).stop_reason, drgn.BreakpointStopReason(site)
            )
            self.assertEqual(
                self.prog.thread(2).stop_reason, drgn.SyntheticStopReason()
            )

    def test_breakpoint_cont(self):
        return  # TODO
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            with self.complete_ops():
                site = self.prog.set_breakpoint(0x1337).sites[0]

            self.queue_call(
                lambda prog: prog.notify_thread_breakpoint(prog.thread(1), site)
            )
            with self.capture_events():
                self.queue_call(lambda prog: prog.notify_all_stop())

            with self.capture_ops() as ops:
                self.prog.thread(1).cont()

                self.assertIsNone(prog.thread(1).stop_reason)
                self.assertIsNone(prog.thread(2).stop_reason)

                self.poll_until(bool, ops)
                self.assertEqual(ops, [("disable_breakpoint_sites", [site])])
                self.complete_op(0)

                self.poll_until(bool, ops)
                self.assertEqual(
                    ops,
                    [
                        (
                            "resume_threads",
                            [drgn.StepiResumeAction(self.prog.thread(1), 0)],
                        )
                    ],
                )
                self.complete_op(0)

            return  ###################################################

            self.queue_call(
                lambda prog: prog.notify_thread_stop(
                    prog.thread(1), signal.SIGTRAP, 0x1338
                )
            )
            self.assertEqual(events(), [])
            self.queue_call(lambda prog: prog.notify_all_stop())

            self.assertEqual(events(), [])
            self.assertEqual(
                ctrl.ops(),
                [
                    ("enable_breakpoint_sites", [site]),
                    ("resume_threads", [drgn.ContinueResumeAction(None, 0)]),
                ],
            )

            self.assertIsNone(prog.thread(1).stop_reason)
            self.assertIsNone(prog.thread(2).stop_reason)


class TestBreakpoints(ExecutionControlTestCase):
    def test_set(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            with self.complete_ops() as ops:
                site = self.prog.set_breakpoint(0x1337).sites[0]
            self.assertEqual(ops, [("enable_breakpoint_sites", [site])])

    def test_set_disabled(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.prog.set_breakpoint(0x1337, enable=False)

    def test_disable(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            with self.complete_ops():
                bp = self.prog.set_breakpoint(0x1337)
            site = bp.sites[0]

            with self.complete_ops() as ops:
                bp.disable()
            self.assertEqual(ops, [("disable_breakpoint_sites", [site])])
