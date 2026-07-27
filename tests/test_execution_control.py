# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import collections
import contextlib
import os
import signal
import functools

import drgn
from tests import TestCase


# TODO: unify with test_thread_finder.py
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


QUEUE_PROMISE = object()
COMPLETE_PROMISE = object()


class MockExecutionController(drgn.ExecutionController):
    def __init__(self) -> None:
        # Queue attach and detach completions by default.
        self._op_hook = lambda name, args, promise, result: (
            QUEUE_PROMISE if name == "attach" or name == "detach" else False
        )

    def _op(self, name, args, promise, result):
        ret = self._op_hook(name, args, promise, result)
        if ret is QUEUE_PROMISE:
            self._queue_call(lambda prog: promise.set_result(result))
            return
        elif ret is COMPLETE_PROMISE:
            promise.set_result(result)
            return
        elif ret:
            return
        args_str = ", ".join([repr(arg) for arg in args])
        promise.set_exception(
            AssertionError(f"unexpected {name}({args_str}) operation")
        )

    def _queue_call(self, fn):
        self._q.append(fn)
        os.write(self._pipe_w, b"\1")

    def _queue_break(self):
        os.write(self._pipe_w, b"\0")

    def _read_pipe(self, prog, fd, events):
        while True:
            try:
                if not os.read(fd, 1)[0]:
                    return
            except BlockingIOError:
                return
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


Barrier = object()


class QueueCall:
    def __init__(self, fn):
        self._fn = fn


QueueBreak = object()


class ExpectOp:
    def __init__(self, pred):
        self._pred = pred


class ExpectEvent:
    def __init__(self, pred):
        self._pred = pred


class _Expect:
    def __init__(self, ctrl, l):
        self._ctrl = ctrl
        self._l = l
        self._i = 0
        self._pending = 0
        self.exception = None

    def done(self):
        return self._i >= len(self._l) and not self._pending

    def event_hook(self, event):
        try:
            if (
                self._i >= len(self._l)
                or not isinstance(self._l[self._i], ExpectEvent)
                or not self._l[self._i]._pred(event)
            ):
                raise AssertionError(f"unexpected {event} at step {self._i}")
        except Exception as e:
            self.exception = e
        self._i += 1
        return True

    def op_hook(self, name, args, promise, result):
        if self.exception is not None:
            e = self.exception
            promise.set_exception(self.exception)
            self.exception = None
            return True

        try:
            if (
                self._i >= len(self._l)
                or not isinstance(self._l[self._i], ExpectOp)
                or not (ret := self._l[self._i]._pred(name, args))
            ):
                args_str = ", ".join([repr(arg) for arg in args])
                raise AssertionError(
                    f"unexpected {name}({args_str}) operation at step {self._i}"
                )
        except Exception as e:
            self._i += 1
            promise.set_exception(e)
            return True

        self._i += 1
        self._pending += 1
        if ret == COMPLETE_PROMISE:
            self._complete_op(promise, result)
        else:
            self._ctrl._queue_call(lambda prog: self._complete_op(promise, result))
        return True

    def _complete_op(self, promise, result):
        self._complete_pending()
        promise.set_result(result)
        self._queue_next()

    def _do_call(self, fn, prog):
        self._complete_pending()
        fn(prog)
        self._queue_next()

    def _complete_stop(self, prog):
        self._complete_pending()
        self._queue_next()

    def _complete_pending(self):
        self._pending -= 1
        if self._pending == 0:
            while self._i < len(self._l) and self._l[self._i] is Barrier:
                self._i += 1

    def _queue_next(self):
        while self._i < len(self._l):
            if isinstance(self._l[self._i], QueueCall):
                fn = self._l[self._i]._fn
                self._i += 1
                self._pending += 1
                self._ctrl._queue_call(functools.partial(self._do_call, fn))
            elif self._l[self._i] is QueueBreak:
                self._i += 1
                self._pending += 1
                self._ctrl._queue_break()
                self._ctrl._queue_call(self._complete_stop)
            else:
                break


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

    def _check_unexpected_events(self):
        if self._unexpected_events:
            try:
                if len(self._unexpected_events) == 1:
                    self.fail(f"unexpected event: {self._unexpected_events[0]!r}")
                else:
                    self.fail(f"unexpected events: {self._unexpected_events!r}")
            finally:
                self._unexpected_events.clear()

    # TODO: I think this is what we want self.prog.poll() to do by default.
    def poll_all(self, block=False):
        if block:
            self.prog.poll()
        while self.prog.poll(0):
            pass
        self._check_unexpected_events()

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

    # TODO: get rid of hook_events and hook_ops?
    @contextlib.contextmanager
    def hook_events(self, hook):
        self.poll_all()

        self._event_hooks.append(hook)
        try:
            yield
            self.poll_all()
        finally:
            self._event_hooks.pop()

    def ignore_events(self):
        return self.hook_events(lambda event: True)

    # TODO: use expect as much as possible, and make it not be a per-name
    # hook?
    @contextlib.contextmanager
    def hook_ops(self, hook):
        self.poll_all()  # TODO: explain

        saved_hook = self._ctrl._op_hook
        try:
            self._ctrl._op_hook = hook
            yield
        finally:
            self._ctrl._op_hook = saved_hook

    def complete_ops(self):
        return self.hook_ops(lambda name, args, promise, result: QUEUE_PROMISE)

    @contextlib.contextmanager
    def expect(self, *ops):
        expect = _Expect(self._ctrl, ops)
        with self.hook_events(expect.event_hook), self.hook_ops(expect.op_hook):
            yield
            while not expect.done():
                if expect.exception is not None:
                    raise expect.exception
                self.poll_all(block=True)
        if expect.exception is not None:
            raise expect.exception


class TestLifecycle(ExecutionControlTestCase):
    def setUp(self):
        super().setUp()
        # Don't complete attach and detach by default for these tests.
        self._ctrl._op_hook = lambda name, args, promise, result: False

    def test_attach_and_detach(self):
        self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHED)

        def expect_attach(name, args):
            if name != "attach" or args != (drgn.AttachFlags.ALL_STOP,):
                return False
            self.assertEqual(self.prog.attach_state, drgn.AttachState.ATTACHING)
            return True

        with self.expect(ExpectOp(expect_attach)):
            self.prog.attach(drgn.AttachFlags.ALL_STOP)
            self.assertEqual(self.prog.attach_state, drgn.AttachState.ATTACHED)

        def expect_detach(name, args):
            if name != "detach":
                return False
            self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHING)
            return True

        with self.expect(ExpectOp(expect_detach)):
            self.prog.detach()
            self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHED)

    def test_attach_failure(self):
        def attach_failure(name, args):
            if name != "attach":
                return False
            raise Exception("foo")

        with self.expect(ExpectOp(attach_failure)):
            self.assertRaisesRegex(
                Exception, "foo", self.prog.attach, drgn.AttachFlags.ALL_STOP
            )

        self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHED)

    def test_context_manager(self):
        with self.expect(ExpectOp(lambda name, args: name == "attach")):
            cm = self.prog.attach(drgn.AttachFlags.ALL_STOP)
            cm.__enter__()

        self.assertEqual(self.prog.attach_state, drgn.AttachState.ATTACHED)

        with self.expect(ExpectOp(lambda name, args: name == "detach")):
            cm.__exit__(None, None, None)
            self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHED)

    def test_context_manager_exception(self):
        with self.assertRaisesRegex(Exception, "foo"), self.expect(
            ExpectOp(lambda name, args: name == "attach"),
            Barrier,
            ExpectOp(lambda name, args: name == "detach"),
        ), self.prog.attach(drgn.AttachFlags.ALL_STOP):
            raise Exception("foo")

    def test_attach_and_detach_synchronously(self):
        with self.expect(
            ExpectOp(lambda name, args: COMPLETE_PROMISE if name == "attach" else False)
        ):
            self.prog.attach(drgn.AttachFlags.ALL_STOP)
            self.assertEqual(self.prog.attach_state, drgn.AttachState.ATTACHED)

        with self.expect(
            ExpectOp(lambda name, args: COMPLETE_PROMISE if name == "detach" else False)
        ):
            self.prog.detach()
            self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHED)

    def test_program_exit(self):
        with self.complete_ops():
            self.prog.attach(drgn.AttachFlags.ALL_STOP)

        def exit_event(event):
            if not isinstance(event, drgn.ProgramExitEvent) or event.status != 0:
                return False
            self.assertEqual(self.prog.attach_state, drgn.AttachState.EXITED)
            return True

        with self.expect(ExpectEvent(exit_event)):
            self.queue_call(lambda prog: prog.notify_program_exit(0))

        self.assertEqual(self.prog.attach_state, drgn.AttachState.EXITED)

        with self.complete_ops():
            self.prog.detach()
            self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHED)

    def test_program_exit_during_attach(self):
        def exit_during_attach(name, args):
            if name != "attach":
                return False
            self.queue_call(lambda prog: prog.notify_program_exit(0))
            return True

        def exit_event(event):
            if not isinstance(event, drgn.ProgramExitEvent) or event.status != 0:
                return False
            self.assertEqual(self.prog.attach_state, drgn.AttachState.EXITED)
            return True

        with self.expect(ExpectOp(exit_during_attach), ExpectEvent(exit_event)):
            self.prog.attach()
            self.assertEqual(self.prog.attach_state, drgn.AttachState.EXITED)

    def test_program_exit_during_detach(self):
        with self.complete_ops():
            self.prog.attach(drgn.AttachFlags.ALL_STOP)

        def exit_during_detach(name, args):
            if name != "detach":
                return False
            self.queue_call(lambda prog: prog.notify_program_exit(0))
            return True

        def exit_event(event):
            if not isinstance(event, drgn.ProgramExitEvent) or event.status != 0:
                return False
            self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHING)
            return True

        with self.expect(ExpectOp(exit_during_detach), ExpectEvent(exit_event)):
            self.prog.detach()
            self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHED)

    def test_program_lost(self):
        with self.complete_ops():
            self.prog.attach(drgn.AttachFlags.ALL_STOP)

        def lost_event(event):
            if (
                not isinstance(event, drgn.ProgramLostEvent)
                or not isinstance(event.exception, BrokenPipeError)
                or event.exception.args != ("bye",)
            ):
                return False
            self.assertEqual(self.prog.attach_state, drgn.AttachState.LOST)
            return True

        with self.expect(ExpectEvent(lost_event)):
            self.queue_call(
                lambda prog: prog.notify_program_lost(BrokenPipeError("bye"))
            )

        self.assertEqual(self.prog.attach_state, drgn.AttachState.LOST)

        with self.complete_ops():
            self.prog.detach()

        self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHED)

    def test_program_lost_during_attach(self):
        def lost_during_attach(name, args):
            if name != "attach":
                return False
            self.queue_call(
                lambda prog: prog.notify_program_lost(BrokenPipeError("bye"))
            )
            return True

        def lost_event(event):
            if (
                not isinstance(event, drgn.ProgramLostEvent)
                or not isinstance(event.exception, BrokenPipeError)
                or event.exception.args != ("bye",)
            ):
                return False
            self.assertEqual(self.prog.attach_state, drgn.AttachState.LOST)
            return True

        with self.expect(ExpectOp(lost_during_attach), ExpectEvent(lost_event)):
            self.prog.attach()
            self.assertEqual(self.prog.attach_state, drgn.AttachState.LOST)

    def test_program_lost_during_detach(self):
        with self.complete_ops():
            self.prog.attach(drgn.AttachFlags.ALL_STOP)

        def lost_during_detach(name, args):
            if name != "detach":
                return False
            self.queue_call(
                lambda prog: prog.notify_program_lost(BrokenPipeError("bye"))
            )
            return True

        def lost_event(event):
            if (
                not isinstance(event, drgn.ProgramLostEvent)
                or not isinstance(event.exception, BrokenPipeError)
                or event.exception.args != ("bye",)
            ):
                return False
            self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHING)
            return True

        with self.expect(ExpectOp(lost_during_detach), ExpectEvent(lost_event)):
            self.prog.detach()
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

            def stop_event(event):
                if event != drgn.ThreadStopEvent(self.prog.thread(1)):
                    return False
                self.assertEqual(
                    event.thread.stop_reason, drgn.SignalStopReason(signal.SIGWINCH)
                )
                return True

            with self.expect(ExpectEvent(stop_event)):
                self.queue_call(lambda prog: prog.notify_all_stop())

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

            def stop_event(event):
                if event != drgn.ThreadStopEvent(self.prog.thread(1)):
                    return False
                self.assertEqual(
                    event.thread.stop_reason, drgn.SignalStopReason(signal.SIGWINCH)
                )
                return True

            with self.expect(ExpectEvent(stop_event)):
                self.queue_call(lambda prog: prog.notify_all_stop())

            self.assertEqual(
                self.prog.thread(1).stop_reason, drgn.SignalStopReason(signal.SIGWINCH)
            )
            self.assertEqual(
                self.prog.thread(2).stop_reason, drgn.SyntheticStopReason()
            )

    def test_signal_cont(self):
        for continue_tid, msg in (
            (1, "continuing stopped thread"),
            (2, "continuing unrelated thread"),
        ):
            with self.subTest(msg):
                with self.prog.attach(drgn.AttachFlags.ALL_STOP):
                    self.queue_call(
                        lambda prog: prog.notify_thread_stop(
                            prog.thread(1), signal.SIGWINCH, 0x1337
                        )
                    )
                    with self.ignore_events():
                        self.queue_call(lambda prog: prog.notify_all_stop())

                    with self.expect(
                        ExpectOp(
                            lambda name, args: name == "resume_threads"
                            and args
                            == (
                                [
                                    drgn.ContinueResumeAction(
                                        self.prog.thread(1), signal.SIGWINCH
                                    ),
                                    drgn.ContinueResumeAction(None, 0),
                                ],
                            )
                        )
                    ):
                        self.prog.thread(continue_tid).cont()

                        self.assertIsNone(self.prog.thread(1).stop_reason)
                        self.assertIsNone(self.prog.thread(2).stop_reason)

    def test_signal_cont_suppress(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.queue_call(
                lambda prog: prog.notify_thread_stop(
                    prog.thread(1), signal.SIGWINCH, 0x1337
                )
            )
            with self.ignore_events():
                self.queue_call(lambda prog: prog.notify_all_stop())

            with self.expect(
                ExpectOp(
                    lambda name, args: name == "resume_threads"
                    and args == ([drgn.ContinueResumeAction(None, 0)],)
                )
            ):
                self.prog.thread(1).cont(sig=0)

                self.assertIsNone(self.prog.thread(1).stop_reason)
                self.assertIsNone(self.prog.thread(2).stop_reason)

    def test_signal_cont_suppress_by_default(self):
        for continue_tid, sig, msg in (
            # The thread to continue and the signal are orthogonal, but it's
            # overkill to test all of the combinations.
            (1, signal.SIGTRAP, "continuing stopped thread"),
            (2, signal.SIGINT, "continuing unrelated thread"),
        ):
            with self.subTest(msg, sig=sig):
                with self.prog.attach(drgn.AttachFlags.ALL_STOP):
                    self.queue_call(
                        lambda prog: prog.notify_thread_stop(
                            prog.thread(1), sig, 0x1337
                        )
                    )
                    with self.ignore_events():
                        self.queue_call(lambda prog: prog.notify_all_stop())

                    with self.expect(
                        ExpectOp(
                            lambda name, args: name == "resume_threads"
                            and args == ([drgn.ContinueResumeAction(None, 0)],)
                        )
                    ):
                        self.prog.thread(continue_tid).cont()

                        self.assertIsNone(self.prog.thread(1).stop_reason)
                        self.assertIsNone(self.prog.thread(2).stop_reason)

    def test_signal_cont_different_signal(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.queue_call(
                lambda prog: prog.notify_thread_stop(
                    prog.thread(1), signal.SIGWINCH, 0x1337
                )
            )
            with self.ignore_events():
                self.queue_call(lambda prog: prog.notify_all_stop())

            with self.expect(
                ExpectOp(
                    lambda name, args: name == "resume_threads"
                    and args
                    == (
                        [
                            drgn.ContinueResumeAction(
                                self.prog.thread(1), signal.SIGUSR1
                            ),
                            drgn.ContinueResumeAction(None, 0),
                        ],
                    )
                )
            ):
                self.prog.thread(1).cont(sig=signal.SIGUSR1)

                self.assertIsNone(self.prog.thread(1).stop_reason)
                self.assertIsNone(self.prog.thread(2).stop_reason)

    def test_signal_cont_unrelated_thread_with_signal(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.queue_call(
                lambda prog: prog.notify_thread_stop(
                    prog.thread(1), signal.SIGWINCH, 0x1337
                )
            )
            with self.ignore_events():
                self.queue_call(lambda prog: prog.notify_all_stop())

            with self.expect(
                ExpectOp(
                    lambda name, args: name == "resume_threads"
                    and len(args) == 1
                    and args[0][-1] == drgn.ContinueResumeAction(None, 0)
                    and collections.Counter(args[0][:-1])
                    == collections.Counter(
                        [
                            drgn.ContinueResumeAction(
                                self.prog.thread(1), signal.SIGWINCH
                            ),
                            drgn.ContinueResumeAction(
                                self.prog.thread(2), signal.SIGUSR1
                            ),
                        ]
                    )
                )
            ):
                self.prog.thread(2).cont(sig=signal.SIGUSR1)

                self.assertIsNone(self.prog.thread(1).stop_reason)
                self.assertIsNone(self.prog.thread(2).stop_reason)

    def test_simultaneous_stop(self):
        for first_continue_idx, second_continue_idx, msg in (
            (0, 1, "continuing thread that got stop event"),
            (1, 0, "continuing other stopped thread"),
            (2, 2, "continuing unrelated thread"),
        ):
            with self.subTest(msg):
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

                    threads = None
                    signals = None

                    def event1(event):
                        nonlocal threads, signals
                        if not isinstance(event, drgn.ThreadStopEvent):
                            return False
                        # Index 0 is the thread we got the first event for,
                        # index 1 is the other stopped thread, and index 2 is
                        # an unrelated thread.
                        threads = [event.thread]
                        if event.thread == self.prog.thread(1):
                            threads.append(self.prog.thread(2))
                            signals = [signal.SIGWINCH, signal.SIGCHLD]
                        elif event.thread == self.prog.thread(2):
                            threads.append(self.prog.thread(1))
                            signals = [signal.SIGCHLD, signal.SIGWINCH]
                        else:
                            return False
                        threads.append(self.prog.thread(3))
                        return True

                    with self.expect(ExpectEvent(event1)):
                        self.queue_call(lambda prog: prog.notify_all_stop())

                    # It should look like only one thread stopped with a signal.
                    self.assertEqual(
                        threads[0].stop_reason, drgn.SignalStopReason(signals[0])
                    )
                    self.assertEqual(threads[1].stop_reason, drgn.SyntheticStopReason())
                    self.assertEqual(threads[2].stop_reason, drgn.SyntheticStopReason())

                    # This shouldn't call any operations, but it should emit
                    # the other thread stop event regardless of which thread we
                    # continue.
                    with self.expect(
                        ExpectEvent(
                            lambda event: event == drgn.ThreadStopEvent(threads[1])
                        )
                    ):
                        threads[first_continue_idx].cont()

                    # Now it should look like only the other thread stopped with a
                    # signal.
                    self.assertEqual(threads[0].stop_reason, drgn.SyntheticStopReason())
                    self.assertEqual(
                        threads[1].stop_reason, drgn.SignalStopReason(signals[1])
                    )
                    self.assertEqual(threads[2].stop_reason, drgn.SyntheticStopReason())

                    # This should resume all threads with the pending signals.
                    with self.expect(
                        ExpectOp(
                            lambda name, args: name == "resume_threads"
                            and len(args) == 1
                            and args[0][-1] == drgn.ContinueResumeAction(None, 0)
                            and collections.Counter(args[0][:-1])
                            == collections.Counter(
                                [
                                    drgn.ContinueResumeAction(
                                        self.prog.thread(1), signal.SIGWINCH
                                    ),
                                    drgn.ContinueResumeAction(
                                        self.prog.thread(2), signal.SIGCHLD
                                    ),
                                ]
                            )
                        )
                    ):
                        threads[second_continue_idx].cont()

                        self.assertIsNone(self.prog.thread(1).stop_reason)
                        self.assertIsNone(self.prog.thread(2).stop_reason)
                        self.assertIsNone(self.prog.thread(3).stop_reason)

    def test_simultaneous_stop_cont_different_signal(self):
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

            threads = None

            def event1(event):
                nonlocal threads
                if not isinstance(event, drgn.ThreadStopEvent):
                    return False
                # Index 0 is the thread we got the first event for, index 1 is
                # the other stopped thread.
                threads = [event.thread]
                if event.thread == self.prog.thread(1):
                    threads.append(self.prog.thread(2))
                elif event.thread == self.prog.thread(2):
                    threads.append(self.prog.thread(1))
                else:
                    return False
                return True

            with self.expect(ExpectEvent(event1)):
                self.queue_call(lambda prog: prog.notify_all_stop())

            with self.ignore_events():
                threads[0].cont(sig=signal.SIGUSR1)

            with self.expect(
                ExpectOp(
                    lambda name, args: name == "resume_threads"
                    and len(args) == 1
                    and args[0][-1] == drgn.ContinueResumeAction(None, 0)
                    and collections.Counter(args[0][:-1])
                    == collections.Counter(
                        [
                            drgn.ContinueResumeAction(threads[0], signal.SIGUSR1),
                            drgn.ContinueResumeAction(threads[1], signal.SIGUSR2),
                        ]
                    )
                )
            ):
                threads[1].cont(sig=signal.SIGUSR2)

                self.assertIsNone(self.prog.thread(1).stop_reason)
                self.assertIsNone(self.prog.thread(2).stop_reason)
                self.assertIsNone(self.prog.thread(3).stop_reason)

    def test_simultaneous_stop_cont_pending_with_different_signal(self):
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

            threads = None

            def event1(event):
                nonlocal threads
                if not isinstance(event, drgn.ThreadStopEvent):
                    return False
                # Index 0 is the thread we got the first event for, index 1 is
                # the other stopped thread.
                threads = [event.thread]
                if event.thread == self.prog.thread(1):
                    threads.append(self.prog.thread(2))
                elif event.thread == self.prog.thread(2):
                    threads.append(self.prog.thread(1))
                else:
                    return False
                return True

            with self.expect(ExpectEvent(event1)):
                self.queue_call(lambda prog: prog.notify_all_stop())

            with self.ignore_events():
                # SIGUSR1 is ignored because this still has a pending signal.
                threads[1].cont(sig=signal.SIGUSR1)

            with self.expect(
                ExpectOp(
                    lambda name, args: name == "resume_threads"
                    and len(args) == 1
                    and args[0][-1] == drgn.ContinueResumeAction(None, 0)
                    and collections.Counter(args[0][:-1])
                    == collections.Counter(
                        [
                            drgn.ContinueResumeAction(
                                self.prog.thread(1), signal.SIGWINCH
                            ),
                            drgn.ContinueResumeAction(
                                self.prog.thread(2), signal.SIGCHLD
                            ),
                        ]
                    )
                )
            ):
                threads[1].cont()

                self.assertIsNone(self.prog.thread(1).stop_reason)
                self.assertIsNone(self.prog.thread(2).stop_reason)
                self.assertIsNone(self.prog.thread(3).stop_reason)

    def test_simultaneous_stop_cont_unrelated_threads_with_signal(self):
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

            with self.ignore_events():
                self.queue_call(lambda prog: prog.notify_all_stop())

            with self.ignore_events():
                self.prog.thread(3).cont(sig=signal.SIGUSR1)

            with self.expect(
                ExpectOp(
                    lambda name, args: name == "resume_threads"
                    and len(args) == 1
                    and args[0][-1] == drgn.ContinueResumeAction(None, 0)
                    and collections.Counter(args[0][:-1])
                    == collections.Counter(
                        [
                            drgn.ContinueResumeAction(
                                self.prog.thread(1), signal.SIGWINCH
                            ),
                            drgn.ContinueResumeAction(
                                self.prog.thread(2), signal.SIGCHLD
                            ),
                            drgn.ContinueResumeAction(
                                self.prog.thread(3), signal.SIGUSR1
                            ),
                            drgn.ContinueResumeAction(
                                self.prog.thread(4), signal.SIGUSR2
                            ),
                        ]
                    )
                )
            ):
                self.prog.thread(4).cont(sig=signal.SIGUSR2)

                self.assertIsNone(self.prog.thread(1).stop_reason)
                self.assertIsNone(self.prog.thread(2).stop_reason)
                self.assertIsNone(self.prog.thread(3).stop_reason)
                self.assertIsNone(self.prog.thread(4).stop_reason)

    def test_breakpoint_stop(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            with self.complete_ops():
                site = self.prog.set_breakpoint(0x1337).sites[0]

            self.queue_call(
                lambda prog: prog.notify_thread_breakpoint(prog.thread(1), site)
            )

            def stop_event(event):
                if event != drgn.ThreadStopEvent(self.prog.thread(1)):
                    return False
                self.assertEqual(
                    event.thread.stop_reason, drgn.BreakpointStopReason(site)
                )
                return True

            with self.expect(ExpectEvent(stop_event)):
                self.queue_call(lambda prog: prog.notify_all_stop())

            self.assertEqual(
                self.prog.thread(1).stop_reason, drgn.BreakpointStopReason(site)
            )
            self.assertEqual(
                self.prog.thread(2).stop_reason, drgn.SyntheticStopReason()
            )

    def test_breakpoint_cont(self):
        for queue_break, msg in (
            ([], "completing step immediately"),
            ([QueueBreak], "completing step after break"),
        ):
            with self.subTest(msg=msg), self.prog.attach(drgn.AttachFlags.ALL_STOP):
                with self.complete_ops():
                    site = self.prog.set_breakpoint(0x1337).sites[0]

                self.queue_call(
                    lambda prog: prog.notify_thread_breakpoint(prog.thread(1), site)
                )
                with self.ignore_events():
                    self.queue_call(lambda prog: prog.notify_all_stop())

                with self.expect(
                    ExpectOp(
                        lambda name, args: name == "disable_breakpoint_sites"
                        and args == ([site],)
                    ),
                    Barrier,
                    ExpectOp(
                        lambda name, args: name == "resume_threads"
                        and args == ([drgn.StepiResumeAction(self.prog.thread(1), 0)],)
                    ),
                    Barrier,
                    *queue_break,
                    QueueCall(
                        lambda prog: prog.notify_thread_stop(
                            prog.thread(1), signal.SIGTRAP, 0x1338
                        )
                    ),
                    *queue_break,
                    QueueCall(lambda prog: prog.notify_all_stop()),
                    Barrier,
                    ExpectOp(
                        lambda name, args: name == "enable_breakpoint_sites"
                        and args == ([site],)
                    ),
                    Barrier,
                    ExpectOp(
                        lambda name, args: name == "resume_threads"
                        and args == ([drgn.ContinueResumeAction(None, 0)],)
                    ),
                ):
                    self.prog.thread(1).cont()

                    self.assertIsNone(self.prog.thread(1).stop_reason)
                    self.assertIsNone(self.prog.thread(2).stop_reason)

    def test_breakpoint_cont_signaled(self):
        assert False


class TestBreakpoints(ExecutionControlTestCase):
    def test_set(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            enabled_site = None

            def expect_enable(name, args):
                if (
                    name != "enable_breakpoint_sites"
                    or len(args) != 1
                    or len(args[0]) != 1
                ):
                    return False
                nonlocal enabled_site
                enabled_site = args[0][0]
                return True

            with self.expect(ExpectOp(expect_enable)):
                site = self.prog.set_breakpoint(0x1337).sites[0]
                self.assertTrue(site.enabled)
            self.assertEqual(enabled_site, site)

    def test_set_disabled(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            site = self.prog.set_breakpoint(0x1337, enable=False)
        self.assertFalse(site.enabled)

    def test_disable(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            with self.complete_ops():
                bp = self.prog.set_breakpoint(0x1337)
            site = bp.sites[0]

            with self.expect(
                ExpectOp(
                    lambda name, args: name == "disable_breakpoint_sites"
                    and args == ([site],)
                )
            ):
                bp.disable()
                self.assertFalse(site.enabled)
