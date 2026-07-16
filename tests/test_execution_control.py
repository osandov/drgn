# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import collections
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
        all_stop = not (flags & drgn.AttachFlags.NON_STOP)
        promise.set_result(all_stop)

    def detach(self, prog, promise):
        # This has to be queued, not completed immediately, so that all other
        # queued calls are done before detaching.
        self._queue_call(lambda prog: promise.set_result(None))

    def _op(self, promise, name, *args):
        if self._ops is None:
            promise.set_exception(Exception("unexpected operation"))
        else:
            self._ops.append((name, *args))
            if self._promises is None:
                self._queue_call(lambda prog: promise.set_result(None))
            else:
                self._promises.append(promise)

    def resume_threads(self, prog, actions, promise):
        self._op(promise, "resume_threads", list(actions))

    def enable_breakpoint_sites(self, sites, promise):
        self._op(promise, "enable_breakpoint_sites", list(sites))

    def disable_breakpoint_sites(self, sites, promise):
        self._op(promise, "disable_breakpoint_sites", list(sites))


class ExecutionControlTestCase(TestCase):
    def setUp(self):
        super().setUp()
        self.prog = drgn.Program(platform=drgn.Platform(drgn.Architecture.X86_64))

        self._events = None
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
        if self._events is None:
            self._unexpected_events.append(event)
        else:
            self._events.append(event)

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
    def capture_events(self):
        self.poll_all()
        self._check_unexpected_events()

        assert self._events is None
        try:
            self._events = []
            yield self._events
            self.poll_all()
        finally:
            self._events = None

    @contextlib.contextmanager
    def complete_ops(self):
        assert self._ctrl._ops is None
        try:
            self._ctrl._ops = []
            yield self._ctrl._ops
        finally:
            self._ctrl._ops = None

    @contextlib.contextmanager
    def capture_ops(self):
        assert self._ctrl._ops is None
        try:
            self._ctrl._ops = []
            self._ctrl._promises = []
            yield self._ops
        finally:
            self._ctrl._promises = None
            self._ctrl._ops = None

    def complete_op(self, i):
        del self._ctrl._ops[i]
        promise = self._ctrl._promises.pop(i)
        self.queue_call(lambda prog: promise.set_result(None))


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
            self.assertEqual(self.prog.thread(2).stop_reason, drgn.SyntheticStopReason())

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
            self.assertEqual(self.prog.thread(2).stop_reason, drgn.SyntheticStopReason())

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
                            drgn.ContinueResumeAction(self.prog.thread(1), signal.SIGWINCH),
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
            self.assertEqual(self.prog.thread(3).stop_reason, drgn.SyntheticStopReason())

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
                    self.prog.thread(2).stop_reason, drgn.SignalStopReason(signal.SIGCHLD)
                )
            else:
                self.assertEqual(
                    self.prog.thread(1).stop_reason, drgn.SignalStopReason(signal.SIGWINCH)
                )
            self.assertEqual(self.prog.thread(3).stop_reason, drgn.SyntheticStopReason())

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
                    self.prog.thread(1).stop_reason, drgn.SignalStopReason(signal.SIGWINCH)
                )
                self.assertEqual(self.prog.thread(2).stop_reason, drgn.SyntheticStopReason())
            else:
                self.assertEqual(self.prog.thread(1).stop_reason, drgn.SyntheticStopReason())
                self.assertEqual(
                    self.prog.thread(2).stop_reason, drgn.SignalStopReason(signal.SIGCHLD)
                )
            self.assertEqual(self.prog.thread(3).stop_reason, drgn.SyntheticStopReason())

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
            self.assertEqual(self.prog.thread(2).stop_reason, drgn.SyntheticStopReason())

    def test_breakpoint_cont(self):
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
                self.assertEqual(ops, [("resume_threads", [drgn.StepiResumeAction(self.prog.thread(1), 0)])])
                self.complete_op(0)

            return ###################################################

            self.queue_call(
                lambda prog: prog.notify_thread_stop(prog.thread(1), signal.SIGTRAP, 0x1338)
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
