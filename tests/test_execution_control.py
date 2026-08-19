# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import collections
import contextlib
import functools
import os
import signal
import time

import drgn
from tests import TestCase
from tests.libc import timerfd_create, timerfd_settime


_TIMEOUT = 1 # TODO: increase? move to controller?


# TODO: unify with test_thread_finder.py
class SimpleThreadFinder(drgn.ThreadFinder):
    def __init__(self, num_threads: int = 5) -> None:
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


class _ExpectNode:
    def __init__(self):
        self._next = None
        self._on = None

    @property
    def next(self):
        return self._next

    @next.setter
    def next(self, value):
        if isinstance(value, _TemporaryAndNode):
            value = _AndNode(value._nodes)
        if not isinstance(value, (_ExpectNode, _OrNode)):
            raise TypeError(f"expected node, not {type(value).__name__}")
        if self._next is not None:
            raise ValueError(f"next already set to {self._next}")
        self._next = value

    @property
    def on(self):
        return self._on

    @on.setter
    def on(self, value):
        if not callable(value):
            raise TypeError("expected callable")
        if self._on is not None:
            raise ValueError("on already set")
        self._on = value

    def __and__(self, other):
        if not isinstance(other, _ExpectNode) or isinstance(other, _AndNode):
            return NotImplemented
        return _TemporaryAndNode((self, other))

    def __or__(self, other):
        if not isinstance(other, _ExpectNode):
            return NotImplemented
        return _OrNode((self, other))

    def match(self, other):
        return other is self


class _TemporaryAndNode:
    def __init__(self, nodes):
        self._nodes = nodes

    def __and__(self, other):
        if isinstance(other, _ExpectNode) and not isinstance(other, _AndNode):
            return _TemporaryAndNode(self._nodes + (other,))
        elif isinstance(other, _TemporaryAndNode):
            return _TemporaryAndNode(self._nodes + other._nodes)
        else:
            return NotImplemented


class _AndNode(_ExpectNode):
    def __init__(self, nodes):
        super().__init__()
        self._nodes = nodes

    def __repr__(self):
        return "(" + " & ".join([repr(node) for node in self._nodes]) + ")"


class _OrNode:
    def __init__(self, nodes):
        self._nodes = nodes

    @property
    def next(self):
        raise AttributeError("| does not have next")

    @next.setter
    def next(self, value):
        raise AttributeError("| does not have next")

    @property
    def on(self):
        raise AttributeError("| does not have on")

    @on.setter
    def on(self, value):
        raise AttributeError("| does not have on")

    def __repr__(self):
        return "(" + " | ".join([repr(node) for node in self._nodes]) + ")"

    def __or__(self, other):
        if isinstance(other, _ExpectNode):
            return _OrNode(self._nodes + (other,))
        elif isinstance(other, _OrNode):
            return _OrNode(self._nodes + other._nodes)
        else:
            return NotImplemented


class _CallExpectNode(_ExpectNode):
    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs

    def _repr(self, class_name):
        if hasattr(self._fn, "__qualname__"):
            fn = self._fn.__qualname__
        else:
            fn = repr(self._fn)
        args = [fn]
        args += [repr(arg) for arg in self._args]
        args += [f"{key}={value!r}" for key, value in self._kwargs.items()]
        return f"{class_name}({', '.join(args)})"

    def __repr__(self):
        return self._repr(self.__class__.__name__)


class Call(_CallExpectNode):
    def __init__(self, fn, *args, **kwargs):
        super().__init__(fn, *args, **kwargs)
        self.done = _CallDone(fn, *args, **kwargs)


class _CallDone(_CallExpectNode):
    def __repr__(self):
        return self._repr("Call") + ".done"


class ControllerCall(_CallExpectNode):
    pass


class Op(_ExpectNode):
    def __init__(self, name, *args):
        super().__init__()
        self._name = name
        self._args = args
        self.done = _OpDone(name, *args)

    def __repr__(self):
        args = [repr(self._name)] + [repr(arg) for arg in self._args]
        return f"Op({', '.join(args)})"

    def _normalized_args(self):
        if self._name != "resume_threads" or not self._args or not self._args[0]:
            return self._args

        actions = self._args[0]
        default_action = None
        if actions[-1].thread is None:
            default_action = actions[-1]
            actions = actions[:-1]
        else:
            default_action = None

        return (
            (collections.Counter(actions), default_action),
            *self._args[1:],
        )

    def match(self, other):
        return isinstance(other, Op) and self._name == other._name and self._normalized_args() == other._normalized_args()


class _OpDone(_ExpectNode):
    def __init__(self, name, *args):
        super().__init__()
        self._name = name
        self._args = args

    def __repr__(self):
        return Op.__repr__(self) + ".done"


class Event(_ExpectNode):
    def __init__(self, type, *args):
        super().__init__()
        self._type = type
        self._args = args

    def __repr__(self):
        args = [f"{self._type.__module__}.{self._type.__qualname__}"] + [repr(arg) for arg in self._args]
        return f"Event({', '.join(args)})"

    def match(self, other):
        return isinstance(other, drgn.Event) and isinstance(other, self._type) and tuple(other) == self._args


class _ExpectExecutionController(drgn.ExecutionController):
    def __init__(self) -> None:
        self._graph = None
        self._in_expect = False
        self._event_errors = []
        self._pending_ops = {}

    def _expect(self, prog, graph):
        try:
            self._set_graph(graph)
            self._in_expect = True

            self._transition_controller_calls()

            while self._graph is not None:
                node = self._graph

                if isinstance(node, Call):
                    self._transition_graph(node)
                    node._fn(*node._args, **node._kwargs)
                    self._check_event_errors()
                    self._transition_graph(node.done)
                    self._transition_controller_calls()
                else:
                    assert not isinstance(node, (ControllerCall, _OpDone)), node
                    if not prog.poll(_TIMEOUT):
                        raise TimeoutError(f"timed out while waiting for {node}")
                    self._check_event_errors()

            while True:
                self._check_event_errors()
                if not prog.poll(0):
                    break
        finally:
            self._in_expect = False
            self._graph = None

    def _set_graph(self, node):
        self._graph = node
        if isinstance(node, _AndNode):
            self._and_remaining = list(node._nodes)

    def _transition_graph(self, o):
        top = self._graph
        if isinstance(top, _AndNode):
            for i, node in enumerate(self._and_remaining):
                if node.match(o):
                    break
            else:
                raise AssertionError("TODO")
            del self._and_remaining[i]
            assert node.next is None
            if node.on is not None:
                node.on()
            if self._and_remaining:
                return
            node = top
        elif isinstance(top, _OrNode):
            for node in top._nodes:
                if node.match(o):
                    break
            else:
                raise AssertionError(f"expected {top}, not {o}")
        elif top.match(o):
            node = top
        else:
            raise AssertionError(f"expected {top}, not {o}")

        print(node, "->", node.next)
        self._set_graph(node.next)
        if node.on is not None:
            node.on()
        return node

    def _transition_controller_calls(self):
        while True:
            node = self._graph

            if isinstance(node, ControllerCall):
                self._transition_graph(node)
                self._queue_call(node._fn, *node._args, **node._kwargs)
            elif isinstance(node, _OpDone):
                self._transition_graph(node)
                self._queue_complete_op(node)
            else:
                break

    def _event_listener(self, prog, event):
        if self._in_expect:
            try:
                self._transition_graph(event)
            except AssertionError as e:
                self._event_errors.append(e)

    def _check_event_errors(self):
        if self._event_errors:
            e = self._event_errors[0]  # TODO: exception group?
            self._event_errors.clear()
            raise e

    def _queue_call(self, fn, *args, **kwargs):
        self._q.append((fn, args, kwargs))
        os.write(self._pipe_w, b"\1")

    def _queue_break(self):  # TODO: still need this?
        os.write(self._pipe_w, b"\0")

    def _queue_complete_op(self, node):
        promise, result = self._pending_ops.pop(node)
        # TODO: clear timer?
        self._queue_call(promise.set_result, result)

    def _read_pipe(self, prog, fd, events):
        while True:
            try:
                if not os.read(fd, 1)[0]:
                    return
            except BlockingIOError:
                return
            fn, args, kwargs = self._q.popleft()
            fn(*args, **kwargs)

    def _timeout(self, prog, fd, events):
        while self._pending_ops:
            op, (promise, _) = self._pending_ops.popitem()
            promise.set_exception(TimeoutError(f"{op} timed out"))

    def _op(self, name, args, promise, result):
        if not self._in_expect:
            promise.set_result(result)
            return

        try:
            node = self._transition_graph(Op(name, *args))
        except AssertionError as e:
            promise.set_exception(e)
            return

        self._pending_ops[node.done] = (promise, result)
        timerfd_settime(self._timer, initial=_TIMEOUT)

        self._transition_controller_calls()

    def attach(self, prog, flags, promise):
        # TODO: close these
        self._pipe_r, self._pipe_w = os.pipe()
        self._timer = timerfd_create(time.CLOCK_MONOTONIC)
        os.set_blocking(self._pipe_r, False)
        self._q = collections.deque()

        prog.register_fd(self._pipe_r, drgn.FdEvents.READ, self._read_pipe)
        prog.register_fd(self._timer, drgn.FdEvents.READ, self._timeout)
        self._op("attach", (flags,), promise, not (flags & drgn.AttachFlags.NON_STOP))

    def detach(self, prog, promise):
        self._op("detach", (), promise, None)

    def stop_all_threads(self, prog, promise):
        self._op("stop_all_threads", (), promise, None)

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

        self.prog.register_thread_finder("test", SimpleThreadFinder(), enable_index=0)
        self._ctrl = _ExpectExecutionController()
        self.prog.add_event_listener(self._ctrl._event_listener)
        self.prog.register_execution_controller("test", self._ctrl, enable_index=0)

    def queue_call(self, fn, *args, **kwargs):
        self._ctrl._queue_call(fn, *args, **kwargs)

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

    def expect(self, *, start):
        self._ctrl._expect(self.prog, start)

    def all_stop(self):
        return {
            thread.tid: drgn.SyntheticStopReason()
            for thread in self.prog.threads()
        }

    def stopped_threads(self):
        return {
            thread.tid: stop_reason
            for thread in self.prog.threads()
            if (stop_reason := thread.stop_reason) is not None
        }

    def check_none_stopped(self):
        self.assertEqual(self.stopped_threads(), {})



class TestLifecycle(ExecutionControlTestCase):
    def setUp(self):
        super().setUp()
        # Don't complete attach and detach by default for these tests.
        self._ctrl._op_hook = lambda name, args, promise, result: False

    def test_attach_and_detach(self):
        self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHED)

        with self.expect(
            [
                ExpectOp("attach", drgn.AttachFlags.ALL_STOP).on(
                    lambda: self.assertEqual(self.prog.attach_state, drgn.AttachState.ATTACHING)
                )
            ]
        ):
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
            self.check_none_stopped()

            notify_thread_stop = ControllerCall(
                self.prog.notify_thread_stop, self.prog.thread(1), signal.SIGWINCH, 0x1337
            )
            stop_all_threads = Op("stop_all_threads")
            stop_event = Event(drgn.ThreadStopEvent, self.prog.thread(1))

            def check_stopped():
                self.assertEqual(
                    self.stopped_threads(),
                    {
                        **self.all_stop(),
                        1: drgn.SignalStopReason(signal.SIGWINCH),
                    }
                )

            notify_thread_stop.next = stop_all_threads
            stop_all_threads.next = stop_all_threads.done
            stop_all_threads.done.next = stop_event
            stop_event.on = check_stopped

            self.expect(start=notify_thread_stop)

            check_stopped()

    def test_signal_stop_explicit(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            def check_stop_reasons():
                self.assertEqual(
                    self.prog.thread(1).stop_reason,
                    drgn.SignalStopReason(signal.SIGWINCH),
                )
                self.assertEqual(
                    self.prog.thread(2).stop_reason, drgn.SyntheticStopReason()
                )
                return True

            with self.expect(
                ExpectOp(lambda name, args: name == "stop_all_threads"),
                Barrier,
                ExpectEvent(
                    lambda event: event == drgn.ThreadStopEvent(self.prog.thread(1))
                    and check_stop_reasons()
                ),
            ):
                self.queue_call(
                    lambda prog: prog.notify_thread_stop(
                        prog.thread(1), signal.SIGWINCH, 0x1337, drgn.SignalStopReason
                    )
                )

            check_stop_reasons()

    def test_signal_cont(self):
        for continue_tid, msg in (
            (1, "continuing stopped thread"),
            (2, "continuing unrelated thread"),
        ):
            with self.subTest(msg):
                with self.prog.attach(drgn.AttachFlags.ALL_STOP):
                    self.queue_call(
                        self.prog.notify_thread_stop, self.prog.thread(1), signal.SIGWINCH, 0x1337
                    )
                    while self.prog.poll(0):
                        pass

                    cont = Call(self.prog.thread(continue_tid).cont)
                    resume_threads = Op(
                        "resume_threads",
                        [
                            drgn.ContinueResumeAction(self.prog.thread(1), signal.SIGWINCH),
                            drgn.ContinueResumeAction(None, 0),
                        ]
                    )

                    cont.next = resume_threads
                    resume_threads.next = resume_threads.done
                    resume_threads.done.next = cont.done
                    cont.done.on = self.check_none_stopped

                    self.expect(start=cont)

    def test_signal_cont_suppress(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            with self.complete_ops(), self.ignore_events():
                self.queue_call(
                    lambda prog: prog.notify_thread_stop(
                        prog.thread(1), signal.SIGWINCH, 0x1337
                    )
                )

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
                    with self.complete_ops(), self.ignore_events():
                        self.queue_call(
                            lambda prog: prog.notify_thread_stop(
                                prog.thread(1), sig, 0x1337
                            )
                        )

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
            with self.complete_ops(), self.ignore_events():
                self.queue_call(
                lambda prog: prog.notify_thread_stop(
                    prog.thread(1), signal.SIGWINCH, 0x1337
                )
)

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
                self.prog.notify_thread_stop, self.prog.thread(1), signal.SIGWINCH, 0x1337
            )
            while self.prog.poll(0):
                pass

            cont = Call(self.prog.thread(2).cont, sig=signal.SIGUSR1)
            resume_threads = Op(
                "resume_threads",
                [
                    drgn.ContinueResumeAction(self.prog.thread(1), signal.SIGWINCH),
                    drgn.ContinueResumeAction(self.prog.thread(2), signal.SIGUSR1),
                    drgn.ContinueResumeAction(None, 0),
                ]
            )

            cont.next = resume_threads
            resume_threads.next = resume_threads.done
            resume_threads.done.next = cont.done
            cont.done.on = self.check_none_stopped

            self.expect(start=cont)

    def test_simultaneous_stop(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            notify_thread_stop1 = ControllerCall(
                self.prog.notify_thread_stop, self.prog.thread(1), signal.SIGWINCH, 0x1337
            )
            stop_all_threads = Op("stop_all_threads")
            notify_thread_stop2 = ControllerCall(
                self.prog.notify_thread_stop, self.prog.thread(2), signal.SIGCHLD, 0xDEAD
            )
            stop_event1_thread1 = Event(drgn.ThreadStopEvent, self.prog.thread(1))
            stop_event1_thread2 = Event(drgn.ThreadStopEvent, self.prog.thread(2))
            cont_thread1 = Call(self.prog.thread(1).cont)
            cont_thread2 = Call(self.prog.thread(2).cont)
            stop_event2_thread1 = Event(drgn.ThreadStopEvent, self.prog.thread(1))
            stop_event2_thread2 = Event(drgn.ThreadStopEvent, self.prog.thread(2))
            resume_threads = Op(
                "resume_threads",
                [
                    drgn.ContinueResumeAction(self.prog.thread(1), signal.SIGWINCH),
                    drgn.ContinueResumeAction(self.prog.thread(2), signal.SIGCHLD),
                ],
            )

            def check_stopped_thread1():
                self.assertEqual(
                    self.stopped_threads(),
                    {
                        **self.all_stop(),
                        1: drgn.SignalStopReason(signal.SIGWINCH),
                    }
                )

            def check_stopped_thread2():
                self.assertEqual(
                    self.stopped_threads(),
                    {
                        **self.all_stop(),
                        2: drgn.SignalStopReason(signal.SIGCHLD),
                    }
                )

            notify_thread_stop1.next = stop_all_threads
            stop_all_threads.next = notify_thread_stop2
            notify_thread_stop2.next = stop_all_threads.done
            stop_all_threads.done.next = stop_event1_thread1 | stop_event1_thread2

            stop_event1_thread1.on = check_stopped_thread1
            stop_event1_thread1.next = cont_thread1
            cont_thread1.next = cont_thread1.done & stop_event2_thread2 # TODO: is this right?
            cont_thread1.done.on = check_stopped_thread2
            stop_event2_thread2.on = check_stopped_thread2
            cont_thread1.next.next = cont_thread2
            cont_thread2.next = resume_threads
            resume_threads.next = resume_threads.done
            resume_threads.done.next = cont_thread2.done
            cont_thread2.done.on = self.check_none_stopped

            # TODO: stop_event1_thread2

            self.expect(start=notify_thread_stop1)

    def test_simultaneous_stop_old(self):
        for first_continue_idx, second_continue_idx, msg in (
            (0, 1, "continuing thread that got stop event"),
            (1, 0, "continuing other stopped thread"),
            (2, 2, "continuing unrelated thread"),
        ):
            with self.subTest(msg):
                with self.prog.attach(drgn.AttachFlags.ALL_STOP):
                    threads = None
                    signals = None

                    def check_stop_reasons1():
                        # It should look like only one thread stopped with a
                        # signal.
                        self.assertEqual(
                            threads[0].stop_reason, drgn.SignalStopReason(signals[0])
                        )
                        self.assertEqual(
                            threads[1].stop_reason, drgn.SyntheticStopReason()
                        )
                        self.assertEqual(
                            threads[2].stop_reason, drgn.SyntheticStopReason()
                        )
                        return True

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
                        return check_stop_reasons1()

                    with self.expect(
                        ExpectOp(lambda name, args: name == "stop_all_threads"),
                        Call(
                            lambda prog: prog.notify_thread_stop(
                                prog.thread(2), signal.SIGCHLD, 0xDEAD
                            )
                        ),
                        Barrier,
                        ExpectEvent(event1),
                    ):
                        self.queue_call(
                            lambda prog: prog.notify_thread_stop(
                                prog.thread(1), signal.SIGWINCH, 0x1337
                            )
                        )

                    check_stop_reasons1()

                    def check_stop_reasons2():
                        # Now it should look like only the other thread stopped
                        # with a signal.
                        self.assertEqual(
                            threads[0].stop_reason, drgn.SyntheticStopReason()
                        )
                        self.assertEqual(
                            threads[1].stop_reason, drgn.SignalStopReason(signals[1])
                        )
                        self.assertEqual(
                            threads[2].stop_reason, drgn.SyntheticStopReason()
                        )
                        return True

                    # This shouldn't call any operations, but it should emit
                    # the other thread stop event regardless of which thread we
                    # continue.
                    with self.expect(
                        ExpectEvent(
                            lambda event: event == drgn.ThreadStopEvent(threads[1])
                            and check_stop_reasons2()
                        )
                    ):
                        threads[first_continue_idx].cont()

                        check_stop_reasons2()

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

            def check_stop_reasons():
                self.assertEqual(
                    self.prog.thread(1).stop_reason, drgn.BreakpointStopReason(site)
                )
                self.assertEqual(
                    self.prog.thread(2).stop_reason, drgn.SyntheticStopReason()
                )
                return True

            with self.expect(
                ExpectEvent(
                    lambda event: event == drgn.ThreadStopEvent(self.prog.thread(1))
                    and check_stop_reasons()
                )
            ):
                self.queue_call(lambda prog: prog.notify_all_stop())

            check_stop_reasons()

    def test_breakpoint_cont(self):
        for queue_break, msg in (
            ([], "completing step immediately"),
            ([Break], "completing step after break"),
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
                    Call(
                        lambda prog: prog.notify_thread_stop(
                            prog.thread(1), signal.SIGTRAP, 0x1338
                        )
                    ),
                    *queue_break,
                    Call(lambda prog: prog.notify_all_stop()),
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
        def check_stop_reasons():
            self.assertEqual(
                self.prog.thread(1).stop_reason, drgn.SignalStopReason(signal.SIGSEGV)
            )
            self.assertEqual(
                self.prog.thread(2).stop_reason, drgn.SyntheticStopReason()
            )
            return True

        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
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
                Call(
                    lambda prog: prog.notify_thread_stop(
                        prog.thread(1), signal.SIGSEGV, 0x1337
                    )
                ),
                Call(lambda prog: prog.notify_all_stop()),
                ExpectOp(
                    lambda name, args: name == "enable_breakpoint_sites"
                    and args == ([site],)
                ),
                ExpectEvent(
                    lambda event: event == drgn.ThreadStopEvent(self.prog.thread(1))
                    and check_stop_reasons()
                ),
            ):
                self.prog.thread(1).cont()

                check_stop_reasons()

    def test_simultaneous_breakpoint(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            with self.complete_ops():
                site1 = self.prog.set_breakpoint(0x1337).sites[0]
                site2 = self.prog.set_breakpoint(0xDEAD).sites[0]

            self.queue_call(
                lambda prog: prog.notify_thread_breakpoint(prog.thread(1), site1)
            )
            self.queue_call(
                lambda prog: prog.notify_thread_breakpoint(prog.thread(2), site2)
            )

            threads = []
            sites = []

            def check_stop_reasons1():
                self.assertEqual(
                    threads[0].stop_reason, drgn.BreakpointStopReason(sites[0])
                )
                self.assertEqual(threads[1].stop_reason, drgn.SyntheticStopReason())
                self.assertEqual(threads[2].stop_reason, drgn.SyntheticStopReason())
                return True

            def stop_event1(event):
                if not isinstance(event, drgn.ThreadStopEvent):
                    return False
                threads.append(event.thread)
                if event.thread == self.prog.thread(1):
                    threads.append(self.prog.thread(2))
                    sites[:] = [site1, site2]
                elif event.thread == self.prog.thread(2):
                    threads.append(self.prog.thread(1))
                    sites[:] = [site2, site1]
                else:
                    return False
                threads.append(self.prog.thread(3))
                return check_stop_reasons1()

            with self.expect(ExpectEvent(stop_event1)):
                self.queue_call(lambda prog: prog.notify_all_stop())

            check_stop_reasons1()

            def check_stop_reasons2():
                self.assertEqual(threads[0].stop_reason, drgn.SyntheticStopReason())
                self.assertEqual(
                    threads[1].stop_reason, drgn.BreakpointStopReason(sites[1])
                )
                self.assertEqual(threads[2].stop_reason, drgn.SyntheticStopReason())
                return True

            with self.expect(
                ExpectOp(
                    lambda name, args: name == "disable_breakpoint_sites"
                    and args == ([sites[0]],)
                ),
                Barrier,
                ExpectOp(
                    lambda name, args: name == "resume_threads"
                    and args == ([drgn.StepiResumeAction(threads[0], 0)],)
                ),
                Barrier,
                Call(
                    lambda prog: prog.notify_thread_stop(
                        threads[0], signal.SIGTRAP, 0x1338
                    )
                ),
                Call(lambda prog: prog.notify_all_stop()),
                ExpectOp(
                    lambda name, args: name == "enable_breakpoint_sites"
                    and args == ([sites[0]],)
                ),
                ExpectEvent(
                    lambda event: event == drgn.ThreadStopEvent(threads[1])
                    and check_stop_reasons2()
                ),
            ):
                threads[0].cont()

                check_stop_reasons2()

            with self.expect(
                ExpectOp(
                    lambda name, args: name == "disable_breakpoint_sites"
                    and args == ([sites[1]],)
                ),
                Barrier,
                ExpectOp(
                    lambda name, args: name == "resume_threads"
                    and args == ([drgn.StepiResumeAction(threads[1], 0)],)
                ),
                Barrier,
                Call(
                    lambda prog: prog.notify_thread_stop(
                        threads[1], signal.SIGTRAP, 0x1338
                    )
                ),
                Call(lambda prog: prog.notify_all_stop()),
                ExpectOp(
                    lambda name, args: name == "enable_breakpoint_sites"
                    and args == ([sites[1]],)
                ),
                Barrier,
                ExpectOp(
                    lambda name, args: name == "resume_threads"
                    and args == ([drgn.ContinueResumeAction(None, 0)],)
                ),
            ):
                threads[1].cont()

                self.assertIsNone(threads[0].stop_reason)
                self.assertIsNone(threads[1].stop_reason)
                self.assertIsNone(threads[2].stop_reason)

    def test_simultaneous_breakpoint_cont_signaled(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            with self.complete_ops():
                site1 = self.prog.set_breakpoint(0x1337).sites[0]
                site2 = self.prog.set_breakpoint(0xF00D).sites[0]

            self.queue_call(
                lambda prog: prog.notify_thread_breakpoint(prog.thread(1), site1)
            )
            self.queue_call(
                lambda prog: prog.notify_thread_breakpoint(prog.thread(2), site2)
            )

            threads = []
            sites = []

            def check_stop_reasons1():
                self.assertEqual(
                    threads[0].stop_reason, drgn.BreakpointStopReason(sites[0])
                )
                self.assertEqual(threads[1].stop_reason, drgn.SyntheticStopReason())
                self.assertEqual(threads[2].stop_reason, drgn.SyntheticStopReason())
                return True

            def stop_event1(event):
                if not isinstance(event, drgn.ThreadStopEvent):
                    return False
                threads.append(event.thread)
                if event.thread == self.prog.thread(1):
                    threads.append(self.prog.thread(2))
                    sites[:] = [site1, site2]
                elif event.thread == self.prog.thread(2):
                    threads.append(self.prog.thread(1))
                    sites[:] = [site2, site1]
                else:
                    return False
                threads.append(self.prog.thread(3))
                return check_stop_reasons1()

            with self.expect(ExpectEvent(stop_event1)):
                self.queue_call(lambda prog: prog.notify_all_stop())

            check_stop_reasons1()

            threads2 = []
            reasons2 = []

            def check_stop_reasons2():
                self.assertEqual(threads2[0].stop_reason, reasons2[0])
                self.assertEqual(threads2[1].stop_reason, drgn.SyntheticStopReason())
                self.assertEqual(threads[2].stop_reason, drgn.SyntheticStopReason())
                return True

            def stop_event2(event):
                if not isinstance(event, drgn.ThreadStopEvent):
                    return False
                threads2.append(event.thread)
                if event.thread == threads[0]:
                    threads2.append(threads[1])
                    reasons2[:] = [
                        drgn.SignalStopReason(signal.SIGSEGV),
                        drgn.BreakpointStopReason(sites[1]),
                    ]
                elif event.thread == threads[1]:
                    threads2.append(threads[0])
                    reasons2[:] = [
                        drgn.BreakpointStopReason(sites[1]),
                        drgn.SignalStopReason(signal.SIGSEGV),
                    ]
                else:
                    return False
                return check_stop_reasons2()

            with self.expect(
                ExpectOp(
                    lambda name, args: name == "disable_breakpoint_sites"
                    and args == ([sites[0]],)
                ),
                Barrier,
                ExpectOp(
                    lambda name, args: name == "resume_threads"
                    and args == ([drgn.StepiResumeAction(threads[0], 0)],)
                ),
                Barrier,
                Call(
                    lambda prog: prog.notify_thread_stop(
                        threads[0], signal.SIGSEGV, 0xDEAD
                    )
                ),
                Call(lambda prog: prog.notify_all_stop()),
                ExpectOp(
                    lambda name, args: name == "enable_breakpoint_sites"
                    and args == ([sites[0]],)
                ),
                ExpectEvent(stop_event2),
            ):
                threads[0].cont()

                check_stop_reasons2()

            def check_stop_reasons3():
                self.assertEqual(threads2[0].stop_reason, drgn.SyntheticStopReason())
                self.assertEqual(threads2[1].stop_reason, reasons2[1])
                self.assertEqual(threads[2].stop_reason, drgn.SyntheticStopReason())
                return True

            if threads2[0] is threads[0]:
                msg = "signal first"
                expected = (
                    (
                        ExpectEvent(
                            lambda event: event == drgn.ThreadStopEvent(threads2[1])
                            and check_stop_reasons3()
                        ),
                    ),
                    (
                        ExpectOp(
                            lambda name, args: name == "disable_breakpoint_sites"
                            and args == ([sites[1]],)
                        ),
                        Barrier,
                        ExpectOp(
                            lambda name, args: name == "resume_threads"
                            and args == ([drgn.StepiResumeAction(threads[1], 0)],)
                        ),
                        Barrier,
                        Call(
                            lambda prog: prog.notify_thread_stop(
                                threads2[1], signal.SIGTRAP, 0xF000
                            )
                        ),
                        Call(lambda prog: prog.notify_all_stop()),
                        ExpectOp(
                            lambda name, args: name == "enable_breakpoint_sites"
                            and args == ([sites[1]],)
                        ),
                        Barrier,
                        ExpectOp(
                            lambda name, args: name == "resume_threads"
                            and args
                            == (
                                [
                                    drgn.ContinueResumeAction(
                                        threads2[0], signal.SIGSEGV
                                    ),
                                    drgn.ContinueResumeAction(None, 0),
                                ],
                            )
                        ),
                    ),
                )
            else:
                msg = "breakpoint first"
                expected = (
                    (
                        ExpectOp(
                            lambda name, args: name == "disable_breakpoint_sites"
                            and args == ([sites[1]],)
                        ),
                        Barrier,
                        ExpectOp(
                            lambda name, args: name == "resume_threads"
                            and args == ([drgn.StepiResumeAction(threads[1], 0)],)
                        ),
                        Barrier,
                        Call(
                            lambda prog: prog.notify_thread_stop(
                                threads2[0], signal.SIGTRAP, 0xF000
                            )
                        ),
                        Call(lambda prog: prog.notify_all_stop()),
                        ExpectOp(
                            lambda name, args: name == "enable_breakpoint_sites"
                            and args == ([sites[1]],)
                        ),
                        Barrier,
                        ExpectEvent(
                            lambda event: event == drgn.ThreadStopEvent(threads2[1])
                            and check_stop_reasons3()
                        ),
                    ),
                    (
                        ExpectOp(
                            lambda name, args: name == "resume_threads"
                            and args
                            == (
                                [
                                    drgn.ContinueResumeAction(
                                        threads2[1], signal.SIGSEGV
                                    ),
                                    drgn.ContinueResumeAction(None, 0),
                                ],
                            )
                        ),
                    ),
                )

            with self.subTest(msg):
                with self.expect(*expected[0]):
                    threads2[0].cont()

                    check_stop_reasons3()

                with self.expect(*expected[1]):
                    threads2[1].cont()

                    self.assertIsNone(threads[0].stop_reason)
                    self.assertIsNone(threads[1].stop_reason)
                    self.assertIsNone(threads[2].stop_reason)

    def test_breakpoint_cont_with_signal(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
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
                    and args
                    == ([drgn.StepiResumeAction(self.prog.thread(1), signal.SIGUSR1)],)
                ),
                Barrier,
                Call(
                    lambda prog: prog.notify_thread_stop(
                        prog.thread(1), signal.SIGTRAP, 0x1338
                    )
                ),
                Call(lambda prog: prog.notify_all_stop()),
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
                self.prog.thread(1).cont(sig=signal.SIGUSR1)

                self.assertIsNone(self.prog.thread(1).stop_reason)
                self.assertIsNone(self.prog.thread(2).stop_reason)


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
