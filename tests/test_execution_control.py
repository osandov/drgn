# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

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
    def queue_call(self, fn):
        self._q.append(fn)
        os.write(self._pipe_w, b"\0")

    def ops(self):
        ops = self._ops
        self._ops = []
        return ops

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
        self._ops = []

        prog.register_fd(self._pipe_r, drgn.FdEvents.READ, self._read_pipe)
        all_stop = not (flags & drgn.AttachFlags.NON_STOP)
        self.queue_call(lambda prog: promise.set_result(all_stop))

    def detach(self, prog, promise):
        self._ops.append(("detach",))
        promise.set_result(None)

    def resume_threads(self, prog, actions, promise):
        self._ops.append(("resume_threads", list(actions)))
        self.queue_call(lambda prog: promise.set_result(None))

    def enable_breakpoint_sites(self, sites, promise):
        self._ops.append(("enable_breakpoint_sites", list(sites)))
        self.queue_call(lambda prog: promise.set_result(None))

    def disable_breakpoint_sites(self, sites, promise):
        self._ops.append(("disable_breakpoint_sites", list(sites)))
        self.queue_call(lambda prog: promise.set_result(None))


def program_with_controller():
    prog = drgn.Program(platform=drgn.Platform(drgn.Architecture.X86_64))

    event_list = []
    prog.add_event_listener(lambda prog, event: event_list.append(event))

    def events():
        while prog.poll(timeout=0):
            pass
        event_list_copy = event_list.copy()
        event_list.clear()
        return event_list_copy

    prog.register_thread_finder("test", SimpleThreadFinder(), enable_index=0)
    ctrl = MockExecutionController()
    prog.register_execution_controller("test", ctrl, enable_index=0)
    return prog, ctrl, events


class TestAllStop(TestCase):
    def test_signal_stop(self):
        # TODO: move this to setUp()?
        prog, ctrl, events = program_with_controller()
        with prog.attach(drgn.AttachFlags.ALL_STOP):
            self.assertIsNone(prog.thread(1).stop_reason)

            ctrl.queue_call(
                lambda prog: prog.notify_thread_signal(prog.thread(1), signal.SIGWINCH)
            )
            ctrl.queue_call(lambda prog: prog.notify_all_stop())
            self.assertEqual(events(), [drgn.ThreadStopEvent(prog.thread(1))])
            self.assertEqual(
                prog.thread(1).stop_reason, drgn.SignalStopReason(signal.SIGWINCH)
            )
            self.assertEqual(prog.thread(2).stop_reason, drgn.SyntheticStopReason())

    def test_signal_cont(self):
        prog, ctrl, events = program_with_controller()
        with prog.attach(drgn.AttachFlags.ALL_STOP):
            ctrl.queue_call(
                lambda prog: prog.notify_thread_signal(prog.thread(1), signal.SIGWINCH)
            )
            ctrl.queue_call(lambda prog: prog.notify_all_stop())
            self.assertEqual(events(), [drgn.ThreadStopEvent(prog.thread(1))])

            prog.thread(1).cont()

            self.assertEqual(
                ctrl.ops(),
                [
                    (
                        "resume_threads",
                        [
                            drgn.ContinueResumeAction(prog.thread(1), signal.SIGWINCH),
                            drgn.ContinueResumeAction(None, 0),
                        ],
                    )
                ],
            )

            self.assertIsNone(prog.thread(1).stop_reason)
            self.assertIsNone(prog.thread(2).stop_reason)

    def test_signal_cont_suppress(self):
        prog, ctrl, events = program_with_controller()
        with prog.attach(drgn.AttachFlags.ALL_STOP):
            ctrl.queue_call(
                lambda prog: prog.notify_thread_signal(prog.thread(1), signal.SIGWINCH)
            )
            ctrl.queue_call(lambda prog: prog.notify_all_stop())
            self.assertEqual(events(), [drgn.ThreadStopEvent(prog.thread(1))])

            prog.thread(1).cont(sig=0)

            self.assertEqual(
                ctrl.ops(),
                [
                    (
                        "resume_threads",
                        [
                            drgn.ContinueResumeAction(prog.thread(1), 0),
                            drgn.ContinueResumeAction(None, 0),
                        ],
                    )
                ],
            )

            self.assertIsNone(prog.thread(1).stop_reason)
            self.assertIsNone(prog.thread(2).stop_reason)

    def test_signal_cont_suppress_by_default(self):
        for sig in (signal.SIGTRAP, signal.SIGINT):
            with self.subTest(sig=sig):
                prog, ctrl, events = program_with_controller()
                with prog.attach(drgn.AttachFlags.ALL_STOP):
                    ctrl.queue_call(
                        lambda prog: prog.notify_thread_signal(prog.thread(1), sig)
                    )
                    ctrl.queue_call(lambda prog: prog.notify_all_stop())
                    self.assertEqual(events(), [drgn.ThreadStopEvent(prog.thread(1))])

                    prog.thread(1).cont()

                    self.assertEqual(
                        ctrl.ops(),
                        [
                            (
                                "resume_threads",
                                [
                                    drgn.ContinueResumeAction(prog.thread(1), 0),
                                    drgn.ContinueResumeAction(None, 0),
                                ],
                            )
                        ],
                    )

                    self.assertIsNone(prog.thread(1).stop_reason)
                    self.assertIsNone(prog.thread(2).stop_reason)

    def test_simultaneous_stop(self):
        prog, ctrl, events = program_with_controller()
        with prog.attach(drgn.AttachFlags.ALL_STOP):
            ctrl.queue_call(
                lambda prog: prog.notify_thread_signal(prog.thread(1), signal.SIGWINCH)
            )
            ctrl.queue_call(
                lambda prog: prog.notify_thread_signal(prog.thread(2), signal.SIGCHLD)
            )
            ctrl.queue_call(lambda prog: prog.notify_all_stop())

            # We should get only one thread stop event, but both threads should
            # be stopped with a signal.
            events1 = events()
            self.assertEqual(len(events1), 1)
            self.assertIsInstance(events1[0], drgn.ThreadStopEvent)

            self.assertEqual(
                prog.thread(1).stop_reason, drgn.SignalStopReason(signal.SIGWINCH)
            )
            self.assertEqual(
                prog.thread(2).stop_reason, drgn.SignalStopReason(signal.SIGCHLD)
            )
            self.assertEqual(prog.thread(3).stop_reason, drgn.SyntheticStopReason())

            events1[0].thread.cont()

            # After continuing, we should get the other thread stop event. The
            # thread we continued should now be in a synthetic stop, and the
            # other one should still be stopped with a signal.
            events2 = events()
            self.assertCountEqual(
                events1 + events2,
                [
                    drgn.ThreadStopEvent(prog.thread(1)),
                    drgn.ThreadStopEvent(prog.thread(2)),
                ],
            )

            self.assertEqual(ctrl.ops(), [])

            self.assertEqual(events1[0].thread.stop_reason, drgn.SyntheticStopReason())
            if events1[0].thread == prog.thread(1):
                self.assertEqual(
                    prog.thread(2).stop_reason, drgn.SignalStopReason(signal.SIGCHLD)
                )
            else:
                self.assertEqual(
                    prog.thread(1).stop_reason, drgn.SignalStopReason(signal.SIGWINCH)
                )
            self.assertEqual(prog.thread(3).stop_reason, drgn.SyntheticStopReason())

            events2[0].thread.cont()

            # After continuing again, everything should be resumed.
            self.assertEqual(events(), [])

            ops = ctrl.ops()
            self.assertEqual(len(ops), 1)
            self.assertEqual(ops[0][0], "resume_threads")
            actions = ops[0][1]
            self.assertEqual(actions[-1], drgn.ContinueResumeAction(None, 0))
            self.assertCountEqual(
                actions[:-1],
                [
                    drgn.ContinueResumeAction(prog.thread(1), signal.SIGWINCH),
                    drgn.ContinueResumeAction(prog.thread(2), signal.SIGCHLD),
                ],
            )

            self.assertIsNone(prog.thread(1).stop_reason)
            self.assertIsNone(prog.thread(2).stop_reason)
            self.assertIsNone(prog.thread(3).stop_reason)

    def test_simultaneous_stop_cont_other(self):
        prog, ctrl, events = program_with_controller()
        with prog.attach(drgn.AttachFlags.ALL_STOP):
            ctrl.queue_call(
                lambda prog: prog.notify_thread_signal(prog.thread(1), signal.SIGWINCH)
            )
            ctrl.queue_call(
                lambda prog: prog.notify_thread_signal(prog.thread(2), signal.SIGCHLD)
            )
            ctrl.queue_call(lambda prog: prog.notify_all_stop())

            event_thread = events()[0].thread

            # Continue the thread that we didn't get an event for.
            prog.thread(2 if event_thread == prog.thread(1) else 1).cont()

            # Afterwards, we shouldn't get another event. The thread we
            # continued should now be in a synthetic stop, and the one we got
            # the stop event for should still be stopped with a signal.
            self.assertEqual(events(), [])
            self.assertEqual(ctrl.ops(), [])

            if event_thread == prog.thread(1):
                self.assertEqual(
                    prog.thread(1).stop_reason, drgn.SignalStopReason(signal.SIGWINCH)
                )
                self.assertEqual(prog.thread(2).stop_reason, drgn.SyntheticStopReason())
            else:
                self.assertEqual(prog.thread(1).stop_reason, drgn.SyntheticStopReason())
                self.assertEqual(
                    prog.thread(2).stop_reason, drgn.SignalStopReason(signal.SIGCHLD)
                )
            self.assertEqual(prog.thread(3).stop_reason, drgn.SyntheticStopReason())

            event_thread.cont()

            # After continuing the thread we got the stop event for, everything
            # should be resumed.
            self.assertEqual(events(), [])

            ops = ctrl.ops()
            self.assertEqual(len(ops), 1)
            self.assertEqual(ops[0][0], "resume_threads")
            actions = ops[0][1]
            self.assertEqual(actions[-1], drgn.ContinueResumeAction(None, 0))
            self.assertCountEqual(
                actions[:-1],
                [
                    drgn.ContinueResumeAction(prog.thread(1), signal.SIGWINCH),
                    drgn.ContinueResumeAction(prog.thread(2), signal.SIGCHLD),
                ],
            )

            self.assertIsNone(prog.thread(1).stop_reason)
            self.assertIsNone(prog.thread(2).stop_reason)
            self.assertIsNone(prog.thread(3).stop_reason)

    def test_breakpoint_stop(self):
        prog, ctrl, events = program_with_controller()
        with prog.attach(drgn.AttachFlags.ALL_STOP):
            bp = prog.set_breakpoint(0x1337)
            site = bp.sites[0]

            ctrl.queue_call(
                lambda prog: prog.notify_thread_breakpoint(prog.thread(1), site)
            )
            ctrl.queue_call(lambda prog: prog.notify_all_stop())
            self.assertEqual(events(), [drgn.ThreadStopEvent(prog.thread(1))])
            self.assertEqual(
                prog.thread(1).stop_reason, drgn.BreakpointStopReason(site)
            )
            self.assertEqual(prog.thread(2).stop_reason, drgn.SyntheticStopReason())

    def test_breakpoint_cont(self):
        prog, ctrl, events = program_with_controller()
        with prog.attach(drgn.AttachFlags.ALL_STOP):
            bp = prog.set_breakpoint(0x1337)
            site = bp.sites[0]

            ctrl.queue_call(
                lambda prog: prog.notify_thread_breakpoint(prog.thread(1), site)
            )
            ctrl.queue_call(lambda prog: prog.notify_all_stop())
            self.assertEqual(events(), [drgn.ThreadStopEvent(prog.thread(1))])

            prog.thread(1).cont()
            import pprint

            pprint.pprint(ctrl.ops())
