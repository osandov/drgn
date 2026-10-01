# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import collections
import functools
import os
import signal
import time

import drgn
from tests import TestCase
from tests.libc import timerfd_create, timerfd_settime

_TIMEOUT = 1  # TODO: increase? move to controller?


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
        return drgn.Object(thread.prog, "void *", thread.tid * 0x1000)

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
        if not isinstance(other, (_ExpectNode, _OrNode)):
            return NotImplemented
        return _AndNode(self, other)

    def __or__(self, other):
        if not isinstance(other, _ExpectNode):
            return NotImplemented
        return _OrNode((self, other))

    def match(self, other):
        return other is self


class _AndNode(_ExpectNode):
    def __init__(self, node1, node2):
        super().__init__()
        self._node1 = node1
        self._node2 = node2

    def __repr__(self):
        return f"({self._node1!r} & {self._node2!r})"


class _OrNode:
    def __init__(self, nodes):
        # TODO: the matching code doesn't handle & inside of |: choosing
        # another alternative leaves the children of the & behind, and
        # matching a child of the & doesn't rule out the other alternatives.
        if any(isinstance(node, _AndNode) for node in nodes):
            raise TypeError("& inside of | is not supported")
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

    def __and__(self, other):
        if not isinstance(other, (_ExpectNode, _OrNode)):
            return NotImplemented
        return _AndNode(self, other)

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

    def __repr__(self):
        bound = getattr(self._fn, "__self__", None)
        if isinstance(bound, drgn.Thread):
            fn = f"{bound!r}.{self._fn.__name__}"
        elif hasattr(self._fn, "__qualname__"):
            fn = self._fn.__qualname__
        else:
            fn = repr(self._fn)
        args = [fn]
        args += [repr(arg) for arg in self._args]
        args += [f"{key}={value!r}" for key, value in self._kwargs.items()]
        return f"{self.__class__.__name__}({', '.join(args)})"


class Call(_CallExpectNode):
    pass


class ControllerCall(_CallExpectNode):
    pass


class Op(_ExpectNode):
    def __init__(self, name, *args):
        super().__init__()
        self._name = name
        self._args = args

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
        return (
            isinstance(other, Op)
            and self._name == other._name
            and self._normalized_args() == other._normalized_args()
        )


ANY = object()


class Return(_ExpectNode):
    def __init__(self, call, value):
        super().__init__()
        self._call = call
        self._value = value

    def __repr__(self):
        return f"Return({self._call!r}, {self._value!r})"

    def match(self, other):
        return other is self or (
            isinstance(other, Return)
            and self._call is other._call
            and (self._value is ANY or self._value == other._value)
        )


def _exceptions_eq(a, b):
    return type(a) is type(b) and a.args == b.args


class Raise(_ExpectNode):
    def __init__(self, call, exception):
        super().__init__()
        self._call = call
        self._exception = exception

    def __repr__(self):
        return f"Raise({self._call!r}, {self._exception!r})"

    def match(self, other):
        return other is self or (
            isinstance(other, Raise)
            and self._call is other._call
            and _exceptions_eq(self._exception, other._exception)
        )


class Event(_ExpectNode):
    def __init__(self, type, *args):
        super().__init__()
        self._type = type
        self._args = args

    def __repr__(self):
        args = [f"{self._type.__module__}.{self._type.__qualname__}"] + [
            repr(arg) for arg in self._args
        ]
        return f"Event({', '.join(args)})"

    def match(self, other):
        if type(other) is not self._type:
            return False
        args = self._args
        other_args = tuple(other)
        if self._type is drgn.ProgramLostEvent:
            if _exceptions_eq(args[0], other_args[0]):
                args = args[1:]
                other_args = other_args[1:]
            else:
                return False
        return other_args == args


class _ExpectExecutionController(drgn.ExecutionController):
    def __init__(self) -> None:
        self._current = {}
        self._trace = None
        self._event_errors = []
        self._pending_ops = {}

    def _expect(self, prog, graph):
        try:
            self._add_current(None, set(), set(), graph)
            self._trace = []

            self._transition_controller_calls()

            while self._current:
                for node in self._current:
                    if isinstance(node, Call):
                        self._transition_graph(node)
                        try:
                            ret = node._fn(*node._args, **node._kwargs)
                            done = Return(node, ret)
                        except AssertionError:
                            raise
                        except Exception as e:
                            done = Raise(node, e)
                        self._check_event_errors()
                        self._transition_graph(done)
                        self._transition_controller_calls()
                        break
                else:
                    if not prog.poll(_TIMEOUT):
                        raise TimeoutError("timed out while waiting for TODO")
                    self._check_event_errors()

            while True:
                self._check_event_errors()
                if not prog.poll(0):
                    break
        finally:
            self._trace = None
            self._current.clear()

    def _add_current(self, parent, siblings, or_siblings, node):
        if isinstance(node, _OrNode):
            for child in node._nodes:
                self._add_current(parent, siblings, or_siblings, child)
        else:
            siblings.add(node)
            or_siblings.add(node)
            self._current[node] = (parent, siblings, or_siblings)
            if isinstance(node, _AndNode):
                children = set()
                self._add_current(node, children, set(), node._node1)
                self._add_current(node, children, set(), node._node2)

    def _transition_graph(self, o):
        for node in self._current:
            if node.match(o):
                break
        else:
            expected = [
                repr(node) for node in self._current if not isinstance(node, _AndNode)
            ]
            if not expected:
                expected.append("None")
            if len(expected) > 2:
                expected[-1] = "or " + expected[-1]
                expected_str = ", ".join(expected)
            else:
                expected_str = " or ".join(expected)
            msg = [f"expected {expected_str}, not {o}"]
            if self._trace:
                msg.append(", after")
                for node in self._trace:
                    msg.append(f"\n    {node!r}")
            raise AssertionError("".join(msg))

        self._trace.append(node)

        def aux(node):
            if node.on is not None:
                node.on()

            parent, siblings, or_siblings = self._current[node]
            siblings -= or_siblings
            for sibling in or_siblings:
                del self._current[sibling]

            if node.next is not None:
                self._add_current(parent, siblings, set(), node.next)
            elif not siblings and parent is not None:
                return aux(parent)

        aux(node)
        return node

    def _transition_controller_calls(self):
        while True:
            for node in self._current:
                if isinstance(node, ControllerCall):
                    self._transition_graph(node)
                    self._queue_call(node._fn, *node._args, **node._kwargs)
                elif isinstance(node, (Return, Raise)) and isinstance(node._call, Op):
                    self._transition_graph(node)
                    self._queue_complete_op(node)
                else:
                    continue
                break
            else:
                break

    def _event_listener(self, prog, event):
        if self._trace is not None:
            try:
                self._transition_graph(event)
                self._transition_controller_calls()
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
        promise = self._pending_ops.pop(node._call)
        # TODO: clear timer?
        if isinstance(node, Return):
            self._queue_call(promise.set_result, node._value)
        else:
            self._queue_call(promise.set_exception, node._exception)

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
        os.read(fd, 8)
        while self._pending_ops:
            op, promise = self._pending_ops.popitem()
            promise.set_exception(TimeoutError(f"{op} timed out"))

    def _op(self, name, args, promise, default_result):
        if self._trace is None:
            promise.set_result(default_result)
            return

        try:
            node = self._transition_graph(Op(name, *args))
        except AssertionError as e:
            promise.set_exception(e)
            return

        self._pending_ops[node] = promise
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

    def interrupt_thread(self, thread, promise):
        self._op("interrupt_thread", (thread,), promise, None)

    def interrupt_any_thread(self, prog, promise):
        self._op("interrupt_any_thread", (), promise, None)

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

    def expect(self, *, start):
        self._ctrl._expect(self.prog, start)

    def all_stop(self):
        return {
            thread.tid: drgn.SyntheticStopReason() for thread in self.prog.threads()
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
    def test_attach_and_detach(self):
        self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHED)

        attach_call = Call(self.prog.attach, drgn.AttachFlags.ALL_STOP)
        attach_call.next = attach_op = Op("attach", drgn.AttachFlags.ALL_STOP)
        attach_op.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.ATTACHING
        )
        attach_op.next = attach_op_return = Return(attach_op, True)
        attach_op_return.next = attach_call_return = Return(attach_call, ANY)
        attach_call_return.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.ATTACHED
        )
        attach_call_return.next = detach_call = Call(self.prog.detach)
        detach_call.next = detach_op = Op("detach")
        detach_op.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.DETACHING
        )
        detach_op.next = detach_op_return = Return(detach_op, None)
        detach_op_return.next = detach_call_return = Return(detach_call, None)
        detach_call_return.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.DETACHED
        )

        self.expect(start=attach_call)

    def test_attach_failure(self):
        attach_call = Call(self.prog.attach, drgn.AttachFlags.ALL_STOP)
        attach_call.next = attach_op = Op("attach", drgn.AttachFlags.ALL_STOP)
        attach_op.next = attach_op_raise = Raise(attach_op, Exception("foo"))
        attach_op_raise.next = attach_call_raise = Raise(attach_call, Exception("foo"))
        attach_call_raise.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.DETACHED
        )

        self.expect(start=attach_call)

    def test_context_manager(self):
        cm = self.prog.attach(drgn.AttachFlags.ALL_STOP)

        enter_call = Call(cm.__enter__)
        enter_call.next = enter_call_return = Return(enter_call, None)
        enter_call_return.next = exit_call = Call(cm.__exit__, None, None, None)
        exit_call.next = detach_op = Op("detach")
        detach_op.next = detach_op_return = Return(detach_op, None)
        detach_op_return.next = exit_call_return = Return(exit_call, None)
        exit_call_return.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.DETACHED
        )

        self.expect(start=enter_call)

    def test_context_manager_exception(self):
        cm = self.prog.attach(drgn.AttachFlags.ALL_STOP)
        cm.__enter__()

        try:
            raise Exception("foo")
        except Exception as e:
            exit_call = Call(cm.__exit__, type(e), e, e.__traceback__)

        exit_call.next = detach_op = Op("detach")
        detach_op.next = detach_op_return = Return(detach_op, None)
        detach_op_return.next = exit_call_return = Return(exit_call, None)
        exit_call_return.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.DETACHED
        )

        self.expect(start=exit_call)

    def test_program_exit(self):
        self.prog.attach(drgn.AttachFlags.ALL_STOP)

        notify_exit = ControllerCall(self.prog.notify_program_exit, 0)
        notify_exit.next = exit_event = Event(drgn.ProgramExitEvent, 0)
        exit_event.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.EXITED
        )
        exit_event.next = detach_call = Call(self.prog.detach)
        detach_call.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.EXITED
        )
        detach_call.next = detach_op = Op("detach")
        detach_op.next = detach_op_return = Return(detach_op, None)
        detach_op_return.next = detach_call_return = Return(detach_call, None)
        detach_call_return.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.DETACHED
        )

        self.expect(start=notify_exit)

    def test_program_exit_during_attach(self):
        attach_call = Call(self.prog.attach, drgn.AttachFlags.ALL_STOP)
        attach_call.next = attach_op = Op("attach", drgn.AttachFlags.ALL_STOP)
        attach_op.next = notify_exit = ControllerCall(self.prog.notify_program_exit, 0)
        notify_exit.next = exit_event = Event(drgn.ProgramExitEvent, 0)
        exit_event.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.EXITED
        )
        exit_event.next = attach_op_return = Return(attach_op, True)
        attach_op_return.next = attach_call_return = Return(attach_call, ANY)
        attach_call_return.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.EXITED
        )

        self.expect(start=attach_call)

        self.prog.detach()
        self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHED)

    def test_program_exit_during_detach(self):
        self.prog.attach(drgn.AttachFlags.ALL_STOP)

        detach_call = Call(self.prog.detach)
        detach_call.next = detach_op = Op("detach")
        detach_op.next = notify_exit = ControllerCall(self.prog.notify_program_exit, 0)
        notify_exit.next = exit_event = Event(drgn.ProgramExitEvent, 0)
        exit_event.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.DETACHING
        )
        exit_event.next = detach_op_return = Return(detach_op, None)
        detach_op_return.next = detach_call_return = Return(detach_call, None)
        detach_call_return.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.DETACHED
        )

        self.expect(start=detach_call)

    def test_program_lost(self):
        self.prog.attach(drgn.AttachFlags.ALL_STOP)

        notify_lost = ControllerCall(
            self.prog.notify_program_lost, BrokenPipeError("bye")
        )
        notify_lost.next = lost_event = Event(
            drgn.ProgramLostEvent, BrokenPipeError("bye")
        )
        lost_event.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.LOST
        )
        lost_event.next = detach_call = Call(self.prog.detach)
        detach_call.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.LOST
        )
        detach_call.next = detach_op = Op("detach")
        detach_op.next = detach_op_return = Return(detach_op, None)
        detach_op_return.next = detach_call_return = Return(detach_call, None)
        detach_call_return.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.DETACHED
        )

        self.expect(start=notify_lost)

    def test_program_lost_during_attach(self):
        attach_call = Call(self.prog.attach, drgn.AttachFlags.ALL_STOP)
        attach_call.next = attach_op = Op("attach", drgn.AttachFlags.ALL_STOP)
        attach_op.next = notify_lost = ControllerCall(
            self.prog.notify_program_lost, BrokenPipeError("bye")
        )
        notify_lost.next = lost_event = Event(
            drgn.ProgramLostEvent, BrokenPipeError("bye")
        )
        lost_event.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.LOST
        )
        lost_event.next = attach_op_return = Return(attach_op, True)
        attach_op_return.next = attach_call_return = Return(attach_call, ANY)
        attach_call_return.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.LOST
        )

        self.expect(start=attach_call)

        self.prog.detach()
        self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHED)

    def test_program_lost_during_detach(self):
        self.prog.attach(drgn.AttachFlags.ALL_STOP)

        detach_call = Call(self.prog.detach)
        detach_call.next = detach_op = Op("detach")
        detach_op.next = notify_lost = ControllerCall(
            self.prog.notify_program_lost, BrokenPipeError("bye")
        )
        notify_lost.next = lost_event = Event(
            drgn.ProgramLostEvent, BrokenPipeError("bye")
        )
        lost_event.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.DETACHING
        )
        lost_event.next = detach_op_return = Return(detach_op, None)
        detach_op_return.next = detach_call_return = Return(detach_call, None)
        detach_call_return.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.DETACHED
        )

        self.expect(start=detach_call)


class TestAllStop(ExecutionControlTestCase):
    def _test_signal_stop(self, *reasons):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.check_none_stopped()

            def check_stopped():
                self.assertEqual(
                    self.stopped_threads(),
                    {
                        **self.all_stop(),
                        1: drgn.SignalStopReason(signal.SIGWINCH),
                    },
                )

            notify_thread_stop = ControllerCall(
                self.prog.notify_thread_stop,
                self.prog.thread(1),
                signal.SIGWINCH,
                0x1337,
                *reasons,
            )
            notify_thread_stop.next = stop_all_threads = Op("stop_all_threads")
            stop_all_threads.next = stop_all_threads_return = Return(
                stop_all_threads, None
            )
            stop_all_threads_return.next = stop_event = Event(
                drgn.ThreadStopEvent, self.prog.thread(1)
            )
            stop_event.on = check_stopped

            self.expect(start=notify_thread_stop)

            check_stopped()

    def test_signal_stop(self):
        self._test_signal_stop()

    def test_signal_stop_explicit(self):
        self._test_signal_stop(drgn.SignalStopReason)

    def test_signal_cont(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.queue_call(
                self.prog.notify_thread_stop,
                self.prog.thread(1),
                signal.SIGWINCH,
                0x1337,
            )
            while self.prog.poll(0):
                pass

            cont = Call(self.prog.thread(1).cont)
            cont.next = resume_threads = Op(
                "resume_threads",
                [
                    drgn.ContinueResumeAction(self.prog.thread(1), signal.SIGWINCH),
                    drgn.ContinueResumeAction(None, 0),
                ],
            )
            resume_threads.next = resume_threads_return = Return(resume_threads, None)
            resume_threads_return.next = cont_return = Return(cont, None)
            cont_return.on = self.check_none_stopped

            self.expect(start=cont)

    def test_signal_cont_unrelated_thread(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.queue_call(
                self.prog.notify_thread_stop,
                self.prog.thread(1),
                signal.SIGWINCH,
                0x1337,
            )
            while self.prog.poll(0):
                pass

            cont = Call(self.prog.thread(2).cont)
            cont.next = resume_threads = Op(
                "resume_threads",
                [
                    drgn.ContinueResumeAction(self.prog.thread(1), signal.SIGWINCH),
                    drgn.ContinueResumeAction(None, 0),
                ],
            )
            resume_threads.next = resume_threads_return = Return(resume_threads, None)
            resume_threads_return.next = cont_return = Return(cont, None)
            cont_return.on = self.check_none_stopped

            self.expect(start=cont)

    def test_signal_cont_suppress(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.queue_call(
                self.prog.notify_thread_stop,
                self.prog.thread(1),
                signal.SIGWINCH,
                0x1337,
            )
            while self.prog.poll(0):
                pass

            cont = Call(self.prog.thread(1).cont, sig=0)
            cont.next = resume_threads = Op(
                "resume_threads", [drgn.ContinueResumeAction(None, 0)]
            )
            resume_threads.next = resume_threads_return = Return(resume_threads, None)
            resume_threads_return.next = cont_return = Return(cont, None)
            cont_return.on = self.check_none_stopped

            self.expect(start=cont)

    def test_signal_cont_suppress_by_default(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.queue_call(
                self.prog.notify_thread_stop,
                self.prog.thread(1),
                signal.SIGTRAP,
                0x1337,
            )
            while self.prog.poll(0):
                pass

            cont = Call(self.prog.thread(1).cont)
            cont.next = resume_threads = Op(
                "resume_threads", [drgn.ContinueResumeAction(None, 0)]
            )
            resume_threads.next = resume_threads_return = Return(resume_threads, None)
            resume_threads_return.next = cont_return = Return(cont, None)
            cont_return.on = self.check_none_stopped

            self.expect(start=cont)

    def test_signal_cont_unrelated_thread_suppress_by_default(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.queue_call(
                self.prog.notify_thread_stop,
                self.prog.thread(1),
                # While we're testing the unrelated thread case, we might as
                # well test a different signal.
                signal.SIGINT,
                0x1337,
            )
            while self.prog.poll(0):
                pass

            cont = Call(self.prog.thread(2).cont)
            cont.next = resume_threads = Op(
                "resume_threads", [drgn.ContinueResumeAction(None, 0)]
            )
            resume_threads.next = resume_threads_return = Return(resume_threads, None)
            resume_threads_return.next = cont_return = Return(cont, None)
            cont_return.on = self.check_none_stopped

            self.expect(start=cont)

    def test_signal_cont_different_signal(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.queue_call(
                self.prog.notify_thread_stop,
                self.prog.thread(1),
                signal.SIGWINCH,
                0x1337,
            )
            while self.prog.poll(0):
                pass

            cont = Call(self.prog.thread(1).cont, sig=signal.SIGUSR1)
            cont.next = resume_threads = Op(
                "resume_threads",
                [
                    drgn.ContinueResumeAction(self.prog.thread(1), signal.SIGUSR1),
                    drgn.ContinueResumeAction(None, 0),
                ],
            )
            resume_threads.next = resume_threads_return = Return(resume_threads, None)
            resume_threads_return.next = cont_return = Return(cont, None)
            cont_return.on = self.check_none_stopped

            self.expect(start=cont)

    def test_signal_cont_unrelated_thread_with_signal(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.queue_call(
                self.prog.notify_thread_stop,
                self.prog.thread(1),
                signal.SIGWINCH,
                0x1337,
            )
            while self.prog.poll(0):
                pass

            cont = Call(self.prog.thread(2).cont, sig=signal.SIGUSR1)
            cont.next = resume_threads = Op(
                "resume_threads",
                [
                    drgn.ContinueResumeAction(self.prog.thread(1), signal.SIGWINCH),
                    drgn.ContinueResumeAction(self.prog.thread(2), signal.SIGUSR1),
                    drgn.ContinueResumeAction(None, 0),
                ],
            )
            resume_threads.next = resume_threads_return = Return(resume_threads, None)
            resume_threads_return.next = cont_return = Return(cont, None)
            cont_return.on = self.check_none_stopped

            self.expect(start=cont)

    def _test_simultaneous_stop(self, conts_and_resume_actions):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):

            def stop_event1(tid):
                other_tid = 2 if tid == 1 else 1
                (cont1_tid, cont1_sig), (cont2_tid, cont2_sig), resume_actions = (
                    conts_and_resume_actions(tid, other_tid)
                )

                event1 = Event(drgn.ThreadStopEvent, self.prog.thread(tid))
                event1.on = functools.partial(check_stopped_thread, tid)
                event1.next = cont1 = Call(
                    self.prog.thread(cont1_tid).cont, sig=cont1_sig
                )
                cont1_return = Return(cont1, None)
                event2 = Event(drgn.ThreadStopEvent, self.prog.thread(other_tid))
                cont1.next = cont1_return & event2
                cont1_return.on = functools.partial(check_stopped_thread, other_tid)
                event2.on = functools.partial(check_stopped_thread, other_tid)
                cont1.next.next = cont2 = Call(
                    self.prog.thread(cont2_tid).cont, sig=cont2_sig
                )
                cont2.next = resume_threads = Op("resume_threads", resume_actions)
                resume_threads.next = resume_threads_return = Return(
                    resume_threads, None
                )
                resume_threads_return.next = cont2_return = Return(cont2, None)
                cont2_return.on = self.check_none_stopped

                return event1

            def check_stopped_thread(tid):
                self.assertEqual(
                    self.stopped_threads(),
                    {
                        **self.all_stop(),
                        tid: drgn.SignalStopReason(
                            signal.SIGWINCH if tid == 1 else signal.SIGCHLD
                        ),
                    },
                )

            notify_thread_stop1 = ControllerCall(
                self.prog.notify_thread_stop,
                self.prog.thread(1),
                signal.SIGWINCH,
                0x1337,
            )
            notify_thread_stop1.next = stop_all_threads = Op("stop_all_threads")
            stop_all_threads.next = notify_thread_stop2 = ControllerCall(
                self.prog.notify_thread_stop,
                self.prog.thread(2),
                signal.SIGCHLD,
                0xDEAD,
            )
            notify_thread_stop2.next = stop_all_threads_return = Return(
                stop_all_threads, None
            )
            stop_all_threads_return.next = stop_event1(1) | stop_event1(2)

            self.expect(start=notify_thread_stop1)

    def test_simultaneous_stop(self):
        self._test_simultaneous_stop(
            lambda tid, other_tid: (
                (tid, -1),
                (other_tid, -1),
                [
                    drgn.ContinueResumeAction(self.prog.thread(1), signal.SIGWINCH),
                    drgn.ContinueResumeAction(self.prog.thread(2), signal.SIGCHLD),
                    drgn.ContinueResumeAction(None, 0),
                ],
            )
        )

    def test_simultaneous_stop_cont_pending_thread(self):
        self._test_simultaneous_stop(
            lambda tid, other_tid: (
                (other_tid, -1),
                (tid, -1),
                [
                    drgn.ContinueResumeAction(self.prog.thread(1), signal.SIGWINCH),
                    drgn.ContinueResumeAction(self.prog.thread(2), signal.SIGCHLD),
                    drgn.ContinueResumeAction(None, 0),
                ],
            )
        )

    def test_simultaneous_stop_cont_pending_thread_then_different_signal(self):
        self._test_simultaneous_stop(
            lambda tid, other_tid: (
                (other_tid, -1),
                # This thread was already resumed with its stop signal, but
                # an explicit signal overrides that.
                (tid, signal.SIGUSR1),
                [
                    drgn.ContinueResumeAction(self.prog.thread(tid), signal.SIGUSR1),
                    drgn.ContinueResumeAction(
                        self.prog.thread(other_tid),
                        signal.SIGWINCH if other_tid == 1 else signal.SIGCHLD,
                    ),
                    drgn.ContinueResumeAction(None, 0),
                ],
            )
        )

    def test_simultaneous_stop_cont_pending_thread_then_no_signal(self):
        self._test_simultaneous_stop(
            lambda tid, other_tid: (
                (other_tid, -1),
                (tid, 0),
                [
                    drgn.ContinueResumeAction(
                        self.prog.thread(other_tid),
                        signal.SIGWINCH if other_tid == 1 else signal.SIGCHLD,
                    ),
                    drgn.ContinueResumeAction(None, 0),
                ],
            )
        )

    def test_simultaneous_stop_cont_unrelated_thread(self):
        self._test_simultaneous_stop(
            lambda tid, other_tid: (
                (3, -1),
                (3, -1),
                [
                    drgn.ContinueResumeAction(self.prog.thread(1), signal.SIGWINCH),
                    drgn.ContinueResumeAction(self.prog.thread(2), signal.SIGCHLD),
                    drgn.ContinueResumeAction(None, 0),
                ],
            )
        )

    def test_simultaneous_stop_cont_different_signal(self):
        self._test_simultaneous_stop(
            lambda tid, other_tid: (
                (tid, signal.SIGUSR1),
                (other_tid, signal.SIGUSR2),
                [
                    drgn.ContinueResumeAction(self.prog.thread(tid), signal.SIGUSR1),
                    drgn.ContinueResumeAction(
                        self.prog.thread(other_tid), signal.SIGUSR2
                    ),
                    drgn.ContinueResumeAction(None, 0),
                ],
            )
        )

    def test_simultaneous_stop_cont_pending_with_different_signal(self):
        self._test_simultaneous_stop(
            lambda tid, other_tid: (
                # SIGUSR1 is ignored because this has a pending signal.
                (other_tid, signal.SIGUSR1),
                (other_tid, -1),
                [
                    drgn.ContinueResumeAction(self.prog.thread(1), signal.SIGWINCH),
                    drgn.ContinueResumeAction(self.prog.thread(2), signal.SIGCHLD),
                    drgn.ContinueResumeAction(None, 0),
                ],
            )
        )

    def test_simultaneous_stop_cont_unrelated_threads_with_signal(self):
        self._test_simultaneous_stop(
            lambda tid, other_tid: (
                (3, signal.SIGUSR1),
                (4, signal.SIGUSR2),
                [
                    drgn.ContinueResumeAction(self.prog.thread(1), signal.SIGWINCH),
                    drgn.ContinueResumeAction(self.prog.thread(2), signal.SIGCHLD),
                    drgn.ContinueResumeAction(self.prog.thread(3), signal.SIGUSR1),
                    drgn.ContinueResumeAction(self.prog.thread(4), signal.SIGUSR2),
                    drgn.ContinueResumeAction(None, 0),
                ],
            )
        )

    def _test_three_simultaneous_stops_cont_pending_thread(self, sig):
        sigs = {1: signal.SIGWINCH, 2: signal.SIGCHLD, 3: signal.SIGURG}

        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            notify_thread_stops = [
                ControllerCall(
                    self.prog.notify_thread_stop,
                    self.prog.thread(tid),
                    sigs[tid],
                    0x1000 * tid,
                )
                for tid in sigs
            ]

            def stop_event1(tid):
                # Continue a thread with an unreported stop. Its stop may be
                # reported next or last.
                tid2, tid3 = [other_tid for other_tid in sigs if other_tid != tid]

                event1 = Event(drgn.ThreadStopEvent, self.prog.thread(tid))
                event1.on = functools.partial(check_stopped_thread, tid)
                event1.next = cont1 = Call(self.prog.thread(tid3).cont, sig=sig)
                cont1_return = Return(cont1, None)
                cont1.next = cont1_return & (
                    stop_event2(tid2, tid3) | stop_event2(tid3, tid2)
                )

                return event1

            def stop_event2(tid, other_tid):
                event2 = Event(drgn.ThreadStopEvent, self.prog.thread(tid))
                event2.on = functools.partial(check_stopped_thread, tid)
                event2.next = cont2 = Call(self.prog.thread(tid).cont)
                cont2_return = Return(cont2, None)
                event3 = Event(drgn.ThreadStopEvent, self.prog.thread(other_tid))
                cont2.next = cont2_return & event3
                event3.on = functools.partial(check_stopped_thread, other_tid)
                cont2.next.next = cont3 = Call(self.prog.thread(other_tid).cont)
                cont3.next = resume_threads = Op(
                    "resume_threads",
                    [
                        drgn.ContinueResumeAction(self.prog.thread(i), sigs[i])
                        for i in sigs
                    ]
                    + [drgn.ContinueResumeAction(None, 0)],
                )
                resume_threads.next = resume_threads_return = Return(
                    resume_threads, None
                )
                resume_threads_return.next = cont3_return = Return(cont3, None)
                cont3_return.on = self.check_none_stopped

                return event2

            def check_stopped_thread(tid):
                self.assertEqual(
                    self.stopped_threads(),
                    {**self.all_stop(), tid: drgn.SignalStopReason(sigs[tid])},
                )

            notify_thread_stops[0].next = stop_all_threads = Op("stop_all_threads")
            stop_all_threads.next = notify_thread_stops[1]
            notify_thread_stops[1].next = notify_thread_stops[2]
            notify_thread_stops[2].next = stop_all_threads_return = Return(
                stop_all_threads, None
            )
            stop_all_threads_return.next = (
                stop_event1(1) | stop_event1(2) | stop_event1(3)
            )

            self.expect(start=notify_thread_stops[0])

    def test_three_simultaneous_stops_cont_pending_thread(self):
        self._test_three_simultaneous_stops_cont_pending_thread(-1)

    def test_three_simultaneous_stops_cont_pending_thread_with_signal(self):
        # SIGUSR1 is ignored because the thread has a pending signal.
        self._test_three_simultaneous_stops_cont_pending_thread(signal.SIGUSR1)

    def test_breakpoint_stop(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            site = self.prog.set_breakpoint(0x1337).sites[0]

            def check_stopped():
                self.assertEqual(
                    self.stopped_threads(),
                    {**self.all_stop(), 1: drgn.BreakpointStopReason(site)},
                )

            notify_thread_breakpoint = ControllerCall(
                self.prog.notify_thread_breakpoint, self.prog.thread(1), site
            )
            notify_thread_breakpoint.next = stop_all_threads = Op("stop_all_threads")
            stop_all_threads.next = stop_all_threads_return = Return(
                stop_all_threads, None
            )
            stop_all_threads_return.next = stop_event = Event(
                drgn.ThreadStopEvent, self.prog.thread(1)
            )
            stop_event.on = check_stopped

            self.expect(start=notify_thread_breakpoint)

            check_stopped()

    def _test_breakpoint_cont(self, step_sig, **kwargs):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            site = self.prog.set_breakpoint(0x1337).sites[0]
            self.queue_call(
                self.prog.notify_thread_breakpoint, self.prog.thread(1), site
            )
            while self.prog.poll(0):
                pass

            cont = Call(self.prog.thread(1).cont, **kwargs)
            cont.next = disable_breakpoint_sites = Op(
                "disable_breakpoint_sites", [site]
            )
            disable_breakpoint_sites.next = disable_breakpoint_sites_return = Return(
                disable_breakpoint_sites, None
            )
            disable_breakpoint_sites_return.next = step_thread = Op(
                "resume_threads",
                [drgn.StepiResumeAction(self.prog.thread(1), step_sig)],
            )
            # TODO: need to test the case where the program is lost or exits
            # while waiting.
            step_thread.next = step_thread_return = Return(step_thread, None)
            # TODO: queue break?
            step_thread_return.next = notify_stepped = ControllerCall(
                self.prog.notify_thread_stop,
                self.prog.thread(1),
                signal.SIGTRAP,
                0x1338,
            )
            notify_stepped.next = enable_breakpoint_sites = Op(
                "enable_breakpoint_sites", [site]
            )
            enable_breakpoint_sites.next = enable_breakpoint_sites_return = Return(
                enable_breakpoint_sites, None
            )
            enable_breakpoint_sites_return.next = resume_threads = Op(
                "resume_threads", [drgn.ContinueResumeAction(None, 0)]
            )
            resume_threads.next = resume_threads_return = Return(resume_threads, None)
            resume_threads_return.next = cont_return = Return(cont, None)
            cont_return.on = self.check_none_stopped

            self.expect(start=cont)

    def test_breakpoint_cont(self):
        self._test_breakpoint_cont(0)

    def test_breakpoint_cont_with_signal(self):
        self._test_breakpoint_cont(signal.SIGUSR1, sig=signal.SIGUSR1)

    def test_breakpoint_cont_signaled(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            site = self.prog.set_breakpoint(0x1337).sites[0]
            self.queue_call(
                self.prog.notify_thread_breakpoint, self.prog.thread(1), site
            )
            while self.prog.poll(0):
                pass

            def check_stopped():
                self.assertEqual(
                    self.stopped_threads(),
                    {
                        **self.all_stop(),
                        1: drgn.SignalStopReason(signal.SIGSEGV),
                    },
                )

            cont1 = Call(self.prog.thread(1).cont)
            cont1.next = disable_breakpoint_sites = Op(
                "disable_breakpoint_sites", [site]
            )
            disable_breakpoint_sites.next = disable_breakpoint_sites_return = Return(
                disable_breakpoint_sites, None
            )
            disable_breakpoint_sites_return.next = step_thread = Op(
                "resume_threads", [drgn.StepiResumeAction(self.prog.thread(1), 0)]
            )
            step_thread.next = step_thread_return = Return(step_thread, None)
            step_thread_return.next = notify_thread_stop = ControllerCall(
                self.prog.notify_thread_stop,
                self.prog.thread(1),
                signal.SIGSEGV,
                0x1337,
            )
            stop_event = Event(drgn.ThreadStopEvent, self.prog.thread(1))
            stop_event.on = check_stopped
            enable_breakpoint_sites = Op("enable_breakpoint_sites", [site])
            notify_thread_stop.next = stop_event & enable_breakpoint_sites
            enable_breakpoint_sites.next = enable_breakpoint_sites_return = Return(
                enable_breakpoint_sites, None
            )
            enable_breakpoint_sites_return.next = Return(cont1, None)
            notify_thread_stop.next.on = check_stopped
            notify_thread_stop.next.next = cont2 = Call(self.prog.thread(1).cont)
            cont2.next = resume_threads = Op(
                "resume_threads",
                [
                    drgn.ContinueResumeAction(self.prog.thread(1), signal.SIGSEGV),
                    drgn.ContinueResumeAction(None, 0),
                ],
            )
            resume_threads.next = resume_threads_return = Return(resume_threads, None)
            resume_threads_return.next = cont2_return = Return(cont2, None)
            cont2_return.on = self.check_none_stopped

            self.expect(start=cont1)

    def test_simultaneous_breakpoint(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            sites = {
                1: self.prog.set_breakpoint(0x1337).sites[0],
                2: self.prog.set_breakpoint(0xDEAD).sites[0],
            }

            def stop_event1(tid):
                other_tid = 2 if tid == 1 else 1

                event1 = Event(drgn.ThreadStopEvent, self.prog.thread(tid))
                event1.on = functools.partial(check_stopped_thread, tid)
                event1.next = cont1 = Call(self.prog.thread(tid).cont)
                cont1.next = disable_breakpoint_sites1 = Op(
                    "disable_breakpoint_sites", [sites[tid]]
                )
                disable_breakpoint_sites1.next = disable_breakpoint_sites1_return = (
                    Return(disable_breakpoint_sites1, None)
                )
                disable_breakpoint_sites1_return.next = step_thread1 = Op(
                    "resume_threads",
                    [drgn.StepiResumeAction(self.prog.thread(tid), 0)],
                )
                step_thread1.next = step_thread1_return = Return(step_thread1, None)
                step_thread1_return.next = notify_stepped1 = ControllerCall(
                    self.prog.notify_thread_stop,
                    self.prog.thread(tid),
                    signal.SIGTRAP,
                    sites[tid].address + 1,
                )
                event2 = Event(drgn.ThreadStopEvent, self.prog.thread(other_tid))
                event2.on = functools.partial(check_stopped_thread, other_tid)
                enable_breakpoint_sites1 = Op("enable_breakpoint_sites", [sites[tid]])
                notify_stepped1.next = event2 & enable_breakpoint_sites1
                enable_breakpoint_sites1.next = enable_breakpoint_sites1_return = (
                    Return(enable_breakpoint_sites1, None)
                )
                enable_breakpoint_sites1_return.next = Return(cont1, None)
                notify_stepped1.next.on = functools.partial(
                    check_stopped_thread, other_tid
                )
                notify_stepped1.next.next = cont2 = Call(
                    self.prog.thread(other_tid).cont
                )
                cont2.next = disable_breakpoint_sites2 = Op(
                    "disable_breakpoint_sites", [sites[other_tid]]
                )
                disable_breakpoint_sites2.next = disable_breakpoint_sites2_return = (
                    Return(disable_breakpoint_sites2, None)
                )
                disable_breakpoint_sites2_return.next = step_thread2 = Op(
                    "resume_threads",
                    [drgn.StepiResumeAction(self.prog.thread(other_tid), 0)],
                )
                step_thread2.next = step_thread2_return = Return(step_thread2, None)
                step_thread2_return.next = notify_stepped2 = ControllerCall(
                    self.prog.notify_thread_stop,
                    self.prog.thread(other_tid),
                    signal.SIGTRAP,
                    sites[other_tid].address + 1,
                )
                notify_stepped2.next = enable_breakpoint_sites2 = Op(
                    "enable_breakpoint_sites", [sites[other_tid]]
                )
                enable_breakpoint_sites2.next = enable_breakpoint_sites2_return = (
                    Return(enable_breakpoint_sites2, None)
                )
                enable_breakpoint_sites2_return.next = resume_threads = Op(
                    "resume_threads", [drgn.ContinueResumeAction(None, 0)]
                )
                resume_threads.next = resume_threads_return = Return(
                    resume_threads, None
                )
                resume_threads_return.next = cont2_return = Return(cont2, None)
                cont2_return.on = self.check_none_stopped

                return event1

            def check_stopped_thread(tid):
                self.assertEqual(
                    self.stopped_threads(),
                    {**self.all_stop(), tid: drgn.BreakpointStopReason(sites[tid])},
                )

            notify_thread_breakpoint1 = ControllerCall(
                self.prog.notify_thread_breakpoint, self.prog.thread(1), sites[1]
            )
            notify_thread_breakpoint1.next = stop_all_threads = Op("stop_all_threads")
            stop_all_threads.next = notify_thread_breakpoint2 = ControllerCall(
                self.prog.notify_thread_breakpoint, self.prog.thread(2), sites[2]
            )
            notify_thread_breakpoint2.next = stop_all_threads_return = Return(
                stop_all_threads, None
            )
            stop_all_threads_return.next = stop_event1(1) | stop_event1(2)

            self.expect(start=notify_thread_breakpoint1)

    def test_simultaneous_breakpoint_cont_signaled(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            sites = {
                1: self.prog.set_breakpoint(0x1337).sites[0],
                2: self.prog.set_breakpoint(0xF00D).sites[0],
            }

            def stop_event1(tid):
                other_tid = 2 if tid == 1 else 1

                event1 = Event(drgn.ThreadStopEvent, self.prog.thread(tid))
                event1.on = functools.partial(
                    check_stopped_thread, tid, drgn.BreakpointStopReason(sites[tid])
                )
                event1.next = cont1 = Call(self.prog.thread(tid).cont)
                cont1.next = disable_breakpoint_sites = Op(
                    "disable_breakpoint_sites", [sites[tid]]
                )
                disable_breakpoint_sites.next = disable_breakpoint_sites_return = (
                    Return(disable_breakpoint_sites, None)
                )
                disable_breakpoint_sites_return.next = step_thread = Op(
                    "resume_threads",
                    [drgn.StepiResumeAction(self.prog.thread(tid), 0)],
                )
                step_thread.next = step_thread_return = Return(step_thread, None)
                step_thread_return.next = notify_thread_stop = ControllerCall(
                    self.prog.notify_thread_stop,
                    self.prog.thread(tid),
                    signal.SIGSEGV,
                    0xDEAD,
                )
                enable_breakpoint_sites = Op("enable_breakpoint_sites", [sites[tid]])
                notify_thread_stop.next = (
                    signal_stop_event2(tid, other_tid)
                    | breakpoint_stop_event2(tid, other_tid)
                ) & enable_breakpoint_sites
                enable_breakpoint_sites.next = enable_breakpoint_sites_return = Return(
                    enable_breakpoint_sites, None
                )
                enable_breakpoint_sites_return.next = Return(cont1, None)

                return event1

            def signal_stop_event2(tid, other_tid):
                event2 = Event(drgn.ThreadStopEvent, self.prog.thread(tid))
                event2.on = functools.partial(
                    check_stopped_thread, tid, drgn.SignalStopReason(signal.SIGSEGV)
                )
                event2.next = cont2 = Call(self.prog.thread(tid).cont)
                cont2_return = Return(cont2, None)
                event3 = Event(drgn.ThreadStopEvent, self.prog.thread(other_tid))
                cont2.next = cont2_return & event3
                event3.on = functools.partial(
                    check_stopped_thread,
                    other_tid,
                    drgn.BreakpointStopReason(sites[other_tid]),
                )
                cont2.next.next = cont3 = Call(self.prog.thread(other_tid).cont)
                cont3.next = disable_breakpoint_sites = Op(
                    "disable_breakpoint_sites", [sites[other_tid]]
                )
                disable_breakpoint_sites.next = disable_breakpoint_sites_return = (
                    Return(disable_breakpoint_sites, None)
                )
                disable_breakpoint_sites_return.next = step_thread = Op(
                    "resume_threads",
                    [drgn.StepiResumeAction(self.prog.thread(other_tid), 0)],
                )
                step_thread.next = step_thread_return = Return(step_thread, None)
                step_thread_return.next = notify_stepped = ControllerCall(
                    self.prog.notify_thread_stop,
                    self.prog.thread(other_tid),
                    signal.SIGTRAP,
                    sites[other_tid].address + 1,
                )
                notify_stepped.next = enable_breakpoint_sites = Op(
                    "enable_breakpoint_sites", [sites[other_tid]]
                )
                enable_breakpoint_sites.next = enable_breakpoint_sites_return = Return(
                    enable_breakpoint_sites, None
                )
                enable_breakpoint_sites_return.next = resume_threads = Op(
                    "resume_threads",
                    [
                        drgn.ContinueResumeAction(
                            self.prog.thread(tid), signal.SIGSEGV
                        ),
                        drgn.ContinueResumeAction(None, 0),
                    ],
                )
                resume_threads.next = resume_threads_return = Return(
                    resume_threads, None
                )
                resume_threads_return.next = cont3_return = Return(cont3, None)
                cont3_return.on = self.check_none_stopped

                return event2

            def breakpoint_stop_event2(tid, other_tid):
                event2 = Event(drgn.ThreadStopEvent, self.prog.thread(other_tid))
                event2.on = functools.partial(
                    check_stopped_thread,
                    other_tid,
                    drgn.BreakpointStopReason(sites[other_tid]),
                )
                event2.next = cont2 = Call(self.prog.thread(other_tid).cont)
                cont2.next = disable_breakpoint_sites = Op(
                    "disable_breakpoint_sites", [sites[other_tid]]
                )
                disable_breakpoint_sites.next = disable_breakpoint_sites_return = (
                    Return(disable_breakpoint_sites, None)
                )
                disable_breakpoint_sites_return.next = step_thread = Op(
                    "resume_threads",
                    [drgn.StepiResumeAction(self.prog.thread(other_tid), 0)],
                )
                step_thread.next = step_thread_return = Return(step_thread, None)
                step_thread_return.next = notify_stepped = ControllerCall(
                    self.prog.notify_thread_stop,
                    self.prog.thread(other_tid),
                    signal.SIGTRAP,
                    sites[other_tid].address + 1,
                )
                event3 = Event(drgn.ThreadStopEvent, self.prog.thread(tid))
                event3.on = functools.partial(
                    check_stopped_thread, tid, drgn.SignalStopReason(signal.SIGSEGV)
                )
                enable_breakpoint_sites = Op(
                    "enable_breakpoint_sites", [sites[other_tid]]
                )
                notify_stepped.next = event3 & enable_breakpoint_sites
                enable_breakpoint_sites.next = enable_breakpoint_sites_return = Return(
                    enable_breakpoint_sites, None
                )
                enable_breakpoint_sites_return.next = Return(cont2, None)
                notify_stepped.next.next = cont3 = Call(self.prog.thread(tid).cont)
                cont3.next = resume_threads = Op(
                    "resume_threads",
                    [
                        drgn.ContinueResumeAction(
                            self.prog.thread(tid), signal.SIGSEGV
                        ),
                        drgn.ContinueResumeAction(None, 0),
                    ],
                )
                resume_threads.next = resume_threads_return = Return(
                    resume_threads, None
                )
                resume_threads_return.next = cont3_return = Return(cont3, None)
                cont3_return.on = self.check_none_stopped

                return event2

            def check_stopped_thread(tid, stop_reason):
                self.assertEqual(
                    self.stopped_threads(), {**self.all_stop(), tid: stop_reason}
                )

            notify_thread_breakpoint1 = ControllerCall(
                self.prog.notify_thread_breakpoint, self.prog.thread(1), sites[1]
            )
            notify_thread_breakpoint1.next = stop_all_threads = Op("stop_all_threads")
            stop_all_threads.next = notify_thread_breakpoint2 = ControllerCall(
                self.prog.notify_thread_breakpoint, self.prog.thread(2), sites[2]
            )
            notify_thread_breakpoint2.next = stop_all_threads_return = Return(
                stop_all_threads, None
            )
            stop_all_threads_return.next = stop_event1(1) | stop_event1(2)

            self.expect(start=notify_thread_breakpoint1)


class TestInterrupt(ExecutionControlTestCase):
    def _test_interrupt(self, interrupt_call, interrupt_op, tid):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):

            def check_stopped():
                self.assertEqual(
                    self.stopped_threads(),
                    {
                        **self.all_stop(),
                        tid: drgn.SignalStopReason(signal.SIGINT),
                    },
                )

            interrupt_call.next = interrupt_op
            interrupt_op.next = interrupt_op_return = Return(interrupt_op, None)
            interrupt_op_return.next = interrupt_call_return = Return(
                interrupt_call, None
            )
            # Interrupting is asynchronous: nothing is stopped until the stop
            # event.
            interrupt_call_return.on = self.check_none_stopped
            interrupt_call_return.next = notify_thread_stop = ControllerCall(
                self.prog.notify_thread_stop,
                self.prog.thread(tid),
                signal.SIGINT,
                0x1337,
            )
            notify_thread_stop.next = stop_all_threads = Op("stop_all_threads")
            stop_all_threads.next = stop_all_threads_return = Return(
                stop_all_threads, None
            )
            stop_all_threads_return.next = stop_event = Event(
                drgn.ThreadStopEvent, self.prog.thread(tid)
            )
            stop_event.on = check_stopped

            self.expect(start=interrupt_call)

            check_stopped()

    def test_interrupt_thread(self):
        self._test_interrupt(
            Call(self.prog.thread(2).interrupt),
            Op("interrupt_thread", self.prog.thread(2)),
            2,
        )

    def test_interrupt_any_thread(self):
        self._test_interrupt(
            Call(self.prog.interrupt_any_thread), Op("interrupt_any_thread"), 1
        )

    def _test_interrupt_failure(self, interrupt_call, interrupt_op):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            interrupt_call.next = interrupt_op
            interrupt_op.next = interrupt_op_raise = Raise(
                interrupt_op, Exception("foo")
            )
            interrupt_op_raise.next = interrupt_call_raise = Raise(
                interrupt_call, Exception("foo")
            )
            interrupt_call_raise.on = lambda: (
                self.assertEqual(self.prog.attach_state, drgn.AttachState.ATTACHED),
                self.check_none_stopped(),
            )

            self.expect(start=interrupt_call)

    def test_interrupt_thread_failure(self):
        self._test_interrupt_failure(
            Call(self.prog.thread(2).interrupt),
            Op("interrupt_thread", self.prog.thread(2)),
        )

    def test_interrupt_any_thread_failure(self):
        self._test_interrupt_failure(
            Call(self.prog.interrupt_any_thread), Op("interrupt_any_thread")
        )

    def test_interrupt_thread_not_attached(self):
        self.assertRaises(drgn.NotAttachedError, self.prog.thread(2).interrupt)

    def test_interrupt_any_thread_not_attached(self):
        self.assertRaises(drgn.NotAttachedError, self.prog.interrupt_any_thread)

    def _test_interrupt_program_exited(self, interrupt):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.queue_call(self.prog.notify_program_exit, 0)
            while self.prog.poll(0):
                pass

            self.assertRaises(drgn.ProgramExitedError, interrupt)

    def test_interrupt_thread_program_exited(self):
        self._test_interrupt_program_exited(self.prog.thread(2).interrupt)

    def test_interrupt_any_thread_program_exited(self):
        self._test_interrupt_program_exited(self.prog.interrupt_any_thread)

    def _test_interrupt_program_lost(self, interrupt):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.queue_call(self.prog.notify_program_lost, BrokenPipeError("bye"))
            while self.prog.poll(0):
                pass

            self.assertRaises(drgn.ProgramLostError, interrupt)

    def test_interrupt_thread_program_lost(self):
        self._test_interrupt_program_lost(self.prog.thread(2).interrupt)

    def test_interrupt_any_thread_program_lost(self):
        self._test_interrupt_program_lost(self.prog.interrupt_any_thread)

    def _test_interrupt_unsupported(self, name, interrupt):
        class Controller(_ExpectExecutionController):
            pass

        # Make it look like the method isn't implemented.
        setattr(Controller, name, getattr(drgn.ExecutionController, name))

        prog = drgn.Program(platform=drgn.Platform(drgn.Architecture.X86_64))
        prog.register_thread_finder("test", SimpleThreadFinder(), enable_index=0)
        prog.register_execution_controller("test", Controller(), enable_index=0)

        with prog.attach(drgn.AttachFlags.ALL_STOP):
            self.assertRaises(drgn.UnsupportedOperation, interrupt(prog))

    def test_interrupt_thread_unsupported(self):
        self._test_interrupt_unsupported(
            "interrupt_thread", lambda prog: prog.thread(2).interrupt
        )

    def test_interrupt_any_thread_unsupported(self):
        self._test_interrupt_unsupported(
            "interrupt_any_thread", lambda prog: prog.interrupt_any_thread
        )

    def test_attach_interrupt(self):
        flags = drgn.AttachFlags.ALL_STOP | drgn.AttachFlags.INTERRUPT

        def check_stopped():
            self.assertEqual(
                self.stopped_threads(),
                {
                    **self.all_stop(),
                    1: drgn.SignalStopReason(signal.SIGINT),
                },
            )

        attach_call = Call(self.prog.attach, flags)
        attach_call.next = attach_op = Op("attach", flags)
        attach_op.next = attach_op_return = Return(attach_op, True)
        attach_op_return.next = attach_call_return = Return(attach_call, ANY)
        attach_call_return.on = self.check_none_stopped
        attach_call_return.next = notify_thread_stop = ControllerCall(
            self.prog.notify_thread_stop,
            self.prog.thread(1),
            signal.SIGINT,
            0x1337,
        )
        notify_thread_stop.next = stop_all_threads = Op("stop_all_threads")
        stop_all_threads.next = stop_all_threads_return = Return(stop_all_threads, None)
        stop_all_threads_return.next = stop_event = Event(
            drgn.ThreadStopEvent, self.prog.thread(1)
        )
        stop_event.on = check_stopped

        self.expect(start=attach_call)

        check_stopped()

        self.prog.detach()


class CaptureBreakpointSite:
    def __eq__(self, other):
        if not isinstance(other, drgn.BreakpointSite):
            return NotImplemented
        self.site = other
        return True


class CaptureBreakpoint:
    def __eq__(self, other):
        if not isinstance(other, drgn.Breakpoint):
            return NotImplemented
        self.breakpoint = other
        return True


class TestBreakpoints(ExecutionControlTestCase):
    def check_breakpoints(
        self, *, enabled=(), disabled=(), removed=(), removed_sites=()
    ):
        self.assertCountEqual(self.prog.breakpoints(), [*enabled, *disabled])

        sites = {}
        for bps, bp_enabled in ((enabled, True), (disabled, False)):
            for bp in bps:
                self.assertEqual(bp.enabled, bp_enabled)
                self.assertFalse(bp.removed)
                for site in bp.sites:
                    entry = sites.setdefault(site.address, (site, [], []))
                    self.assertEqual(site, entry[0])
                    entry[1 if bp_enabled else 2].append(bp)
        self.assertCountEqual(
            self.prog.breakpoint_sites(), [entry[0] for entry in sites.values()]
        )
        for address, (site, site_enabled, site_disabled) in sites.items():
            self.assertEqual(self.prog.find_breakpoint_site(address), site)
            self.assertEqual(site.enabled, bool(site_enabled))
            self.assertFalse(site.removed)
            self.assertCountEqual(site.enabled_breakpoints(), site_enabled)
            self.assertCountEqual(site.disabled_breakpoints(), site_disabled)

        for bp in removed:
            self.assertFalse(bp.enabled)
            self.assertTrue(bp.removed)
        for site in removed_sites:
            self.assertFalse(site.enabled)
            self.assertTrue(site.removed)
            self.assertCountEqual(site.enabled_breakpoints(), [])
            self.assertCountEqual(site.disabled_breakpoints(), [])
            self.assertNotEqual(self.prog.find_breakpoint_site(site.address), site)

    def test_set(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            capture_site = CaptureBreakpointSite()
            capture_breakpoint = CaptureBreakpoint()

            set_breakpoint = Call(self.prog.set_breakpoint, 0x1337)
            set_breakpoint.next = enable_breakpoint_sites = Op(
                "enable_breakpoint_sites", [capture_site]
            )
            enable_breakpoint_sites.next = enable_breakpoint_sites_return = Return(
                enable_breakpoint_sites, None
            )
            enable_breakpoint_sites_return.next = set_breakpoint_return = Return(
                set_breakpoint, capture_breakpoint
            )
            set_breakpoint_return.on = lambda: (
                self.check_breakpoints(enabled=[capture_breakpoint.breakpoint]),
                self.assertEqual(
                    capture_breakpoint.breakpoint.sites[0], capture_site.site
                ),
            )

            self.expect(start=set_breakpoint)

    def test_set_disabled(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            capture_breakpoint = CaptureBreakpoint()

            set_breakpoint = Call(self.prog.set_breakpoint, 0x1337, enable=False)
            set_breakpoint.next = set_breakpoint_return = Return(
                set_breakpoint, capture_breakpoint
            )
            set_breakpoint_return.on = lambda: self.check_breakpoints(
                disabled=[capture_breakpoint.breakpoint]
            )

            self.expect(start=set_breakpoint)

    def test_enable(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            bp = self.prog.set_breakpoint(0x1337, enable=False)
            site = bp.sites[0]

            breakpoint_enable = Call(bp.enable)
            breakpoint_enable.next = enable_breakpoint_sites = Op(
                "enable_breakpoint_sites", [site]
            )
            enable_breakpoint_sites.on = lambda: self.check_breakpoints(disabled=[bp])
            enable_breakpoint_sites.next = enable_breakpoint_sites_return = Return(
                enable_breakpoint_sites, None
            )
            enable_breakpoint_sites_return.next = breakpoint_enable_return = Return(
                breakpoint_enable, None
            )
            breakpoint_enable_return.on = lambda: self.check_breakpoints(enabled=[bp])

            self.expect(start=breakpoint_enable)

    def test_enable_already_enabled(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            bp = self.prog.set_breakpoint(0x1337)

            breakpoint_enable = Call(bp.enable)
            breakpoint_enable.next = breakpoint_enable_return = Return(
                breakpoint_enable, None
            )
            breakpoint_enable_return.on = lambda: self.check_breakpoints(enabled=[bp])

            self.expect(start=breakpoint_enable)

    def test_enable_site_already_enabled(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            other_bp = self.prog.set_breakpoint(0x1337)
            bp = self.prog.set_breakpoint(0x1337, enable=False)

            breakpoint_enable = Call(bp.enable)
            breakpoint_enable.next = breakpoint_enable_return = Return(
                breakpoint_enable, None
            )
            breakpoint_enable_return.on = lambda: self.check_breakpoints(
                enabled=[other_bp, bp]
            )

            self.expect(start=breakpoint_enable)

    def test_enable_removed(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            bp = self.prog.set_breakpoint(0x1337, enable=False)
            site = bp.sites[0]
            bp.remove()

            self.assertRaises(ValueError, bp.enable)
            self.check_breakpoints(removed=[bp], removed_sites=[site])

    def test_disable(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            bp = self.prog.set_breakpoint(0x1337)
            site = bp.sites[0]

            breakpoint_disable = Call(bp.disable)
            breakpoint_disable.next = disable_breakpoint_sites = Op(
                "disable_breakpoint_sites", [site]
            )
            disable_breakpoint_sites.on = lambda: self.check_breakpoints(enabled=[bp])
            disable_breakpoint_sites.next = disable_breakpoint_sites_return = Return(
                disable_breakpoint_sites, None
            )
            disable_breakpoint_sites_return.next = breakpoint_disable_return = Return(
                breakpoint_disable, None
            )
            breakpoint_disable_return.on = lambda: self.check_breakpoints(disabled=[bp])

            self.expect(start=breakpoint_disable)

    def test_disable_already_disabled(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            bp = self.prog.set_breakpoint(0x1337, enable=False)

            breakpoint_disable = Call(bp.disable)
            breakpoint_disable.next = breakpoint_disable_return = Return(
                breakpoint_disable, None
            )
            breakpoint_disable_return.on = lambda: self.check_breakpoints(disabled=[bp])

            self.expect(start=breakpoint_disable)

    def test_disable_site_still_enabled(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            other_bp = self.prog.set_breakpoint(0x1337)
            bp = self.prog.set_breakpoint(0x1337)

            breakpoint_disable = Call(bp.disable)
            breakpoint_disable.next = breakpoint_disable_return = Return(
                breakpoint_disable, None
            )
            breakpoint_disable_return.on = lambda: self.check_breakpoints(
                enabled=[other_bp], disabled=[bp]
            )

            self.expect(start=breakpoint_disable)

    def test_disable_site_still_used(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            other_bp = self.prog.set_breakpoint(0x1337, enable=False)
            bp = self.prog.set_breakpoint(0x1337)
            site = bp.sites[0]

            breakpoint_disable = Call(bp.disable)
            breakpoint_disable.next = disable_breakpoint_sites = Op(
                "disable_breakpoint_sites", [site]
            )
            disable_breakpoint_sites.on = lambda: self.check_breakpoints(
                enabled=[bp], disabled=[other_bp]
            )
            disable_breakpoint_sites.next = disable_breakpoint_sites_return = Return(
                disable_breakpoint_sites, None
            )
            disable_breakpoint_sites_return.next = breakpoint_disable_return = Return(
                breakpoint_disable, None
            )
            breakpoint_disable_return.on = lambda: self.check_breakpoints(
                disabled=[other_bp, bp]
            )

            self.expect(start=breakpoint_disable)

    def test_remove(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            bp = self.prog.set_breakpoint(0x1337)
            site = bp.sites[0]

            breakpoint_remove = Call(bp.remove)
            breakpoint_remove.next = disable_breakpoint_sites = Op(
                "disable_breakpoint_sites", [site]
            )
            disable_breakpoint_sites.on = lambda: self.check_breakpoints(enabled=[bp])
            disable_breakpoint_sites.next = disable_breakpoint_sites_return = Return(
                disable_breakpoint_sites, None
            )
            disable_breakpoint_sites_return.next = breakpoint_remove_return = Return(
                breakpoint_remove, None
            )
            breakpoint_remove_return.on = lambda: self.check_breakpoints(
                removed=[bp], removed_sites=[site]
            )

            self.expect(start=breakpoint_remove)

    def test_remove_disabled(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            bp = self.prog.set_breakpoint(0x1337, enable=False)
            site = bp.sites[0]

            breakpoint_remove = Call(bp.remove)
            breakpoint_remove.next = breakpoint_remove_return = Return(
                breakpoint_remove, None
            )
            breakpoint_remove_return.on = lambda: self.check_breakpoints(
                removed=[bp], removed_sites=[site]
            )

            self.expect(start=breakpoint_remove)

    def test_remove_already_removed(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            bp = self.prog.set_breakpoint(0x1337)
            site = bp.sites[0]
            bp.remove()
            # This gets a new site at the same address.
            other_bp = self.prog.set_breakpoint(0x1337)

            breakpoint_remove = Call(bp.remove)
            breakpoint_remove.next = breakpoint_remove_return = Return(
                breakpoint_remove, None
            )
            breakpoint_remove_return.on = lambda: self.check_breakpoints(
                enabled=[other_bp], removed=[bp], removed_sites=[site]
            )

            self.expect(start=breakpoint_remove)

    def test_remove_site_still_enabled(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            other_bp = self.prog.set_breakpoint(0x1337)
            bp = self.prog.set_breakpoint(0x1337)

            breakpoint_remove = Call(bp.remove)
            breakpoint_remove.next = breakpoint_remove_return = Return(
                breakpoint_remove, None
            )
            breakpoint_remove_return.on = lambda: self.check_breakpoints(
                enabled=[other_bp], removed=[bp]
            )

            self.expect(start=breakpoint_remove)

    def test_remove_site_still_used(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            other_bp = self.prog.set_breakpoint(0x1337, enable=False)
            bp = self.prog.set_breakpoint(0x1337)
            site = bp.sites[0]

            breakpoint_remove = Call(bp.remove)
            breakpoint_remove.next = disable_breakpoint_sites = Op(
                "disable_breakpoint_sites", [site]
            )
            disable_breakpoint_sites.on = lambda: self.check_breakpoints(
                enabled=[bp], disabled=[other_bp]
            )
            disable_breakpoint_sites.next = disable_breakpoint_sites_return = Return(
                disable_breakpoint_sites, None
            )
            disable_breakpoint_sites_return.next = breakpoint_remove_return = Return(
                breakpoint_remove, None
            )
            breakpoint_remove_return.on = lambda: self.check_breakpoints(
                disabled=[other_bp], removed=[bp]
            )

            self.expect(start=breakpoint_remove)

    def check_site_breakpoints(self, site, enabled, disabled):
        self.assertCountEqual(site.enabled_breakpoints(), enabled)
        self.assertCountEqual(site.disabled_breakpoints(), disabled)

    def test_site_breakpoints(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            bp1 = self.prog.set_breakpoint(0x1337)
            bp2 = self.prog.set_breakpoint(0x1337, enable=False)
            bp3 = self.prog.set_breakpoint(0x1337)
            other_bp1 = self.prog.set_breakpoint(0xDEAD)
            other_bp2 = self.prog.set_breakpoint(0xF00D, enable=False)

            self.check_site_breakpoints(bp1.sites[0], [bp1, bp3], [bp2])
            self.check_site_breakpoints(other_bp1.sites[0], [other_bp1], [])
            self.check_site_breakpoints(other_bp2.sites[0], [], [other_bp2])

    def test_site_breakpoints_changed_during_iteration(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            bp1 = self.prog.set_breakpoint(0x1337)
            bp2 = self.prog.set_breakpoint(0x1337, enable=False)
            site = bp1.sites[0]

            for name, change in (
                ("set", lambda: self.prog.set_breakpoint(0x1337)),
                ("enable", bp2.enable),
                ("disable", bp2.disable),
                ("remove", bp2.remove),
            ):
                with self.subTest(change=name):
                    enabled_it = site.enabled_breakpoints()
                    disabled_it = site.disabled_breakpoints()
                    change()
                    self.assertRaises(RuntimeError, next, enabled_it)
                    self.assertRaises(RuntimeError, next, disabled_it)

    def test_site_breakpoints_other_site_changed_during_iteration(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            bp = self.prog.set_breakpoint(0x1337)
            site = bp.sites[0]

            it = site.enabled_breakpoints()
            other_bp = self.prog.set_breakpoint(0xDEAD)
            other_bp.disable()
            other_bp.enable()
            other_bp.remove()
            self.assertEqual(list(it), [bp])

    def test_breakpoints(self):
        self.assertCountEqual(self.prog.breakpoints(), [])

        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.assertCountEqual(self.prog.breakpoints(), [])

            bp1 = self.prog.set_breakpoint(0x1337)
            self.assertCountEqual(self.prog.breakpoints(), [bp1])

            # Same site.
            bp2 = self.prog.set_breakpoint(0x1337)
            # Disabled.
            bp3 = self.prog.set_breakpoint(0xDEAD, enable=False)
            self.assertCountEqual(self.prog.breakpoints(), [bp1, bp2, bp3])

    def test_breakpoints_changed_during_iteration(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            bp = self.prog.set_breakpoint(0x1337)

            for name, change in (
                ("set", lambda: self.prog.set_breakpoint(0xDEAD)),
                ("remove", bp.remove),
            ):
                with self.subTest(change=name):
                    it = self.prog.breakpoints()
                    change()
                    self.assertRaises(RuntimeError, next, it)

    def test_breakpoints_enabled_during_iteration(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            bp1 = self.prog.set_breakpoint(0x1337)
            bp2 = self.prog.set_breakpoint(0xDEAD, enable=False)

            # Enabling and disabling don't change the set of breakpoints.
            it = self.prog.breakpoints()
            bp1.disable()
            bp2.enable()
            self.assertCountEqual(it, [bp1, bp2])

    def test_find_breakpoint_site(self):
        self.assertIsNone(self.prog.find_breakpoint_site(0x1337))

        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.assertIsNone(self.prog.find_breakpoint_site(0x1337))

            bp1 = self.prog.set_breakpoint(0x1337)
            bp2 = self.prog.set_breakpoint(0x1337)
            bp3 = self.prog.set_breakpoint(0xDEAD, enable=False)

            self.assertEqual(self.prog.find_breakpoint_site(0x1337), bp1.sites[0])
            self.assertEqual(self.prog.find_breakpoint_site(0x1337), bp2.sites[0])
            self.assertEqual(self.prog.find_breakpoint_site(0xDEAD), bp3.sites[0])
            self.assertIsNone(self.prog.find_breakpoint_site(0x1338))

    def test_breakpoint_sites(self):
        self.assertCountEqual(self.prog.breakpoint_sites(), [])

        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.assertCountEqual(self.prog.breakpoint_sites(), [])

            bp1 = self.prog.set_breakpoint(0x1337)
            self.assertCountEqual(self.prog.breakpoint_sites(), [bp1.sites[0]])

            # Same site.
            self.prog.set_breakpoint(0x1337)
            self.assertCountEqual(self.prog.breakpoint_sites(), [bp1.sites[0]])

            # Disabled.
            bp3 = self.prog.set_breakpoint(0xDEAD, enable=False)
            self.assertCountEqual(
                self.prog.breakpoint_sites(), [bp1.sites[0], bp3.sites[0]]
            )

    def test_breakpoint_sites_changed_during_iteration(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            bp = self.prog.set_breakpoint(0x1337)

            for name, change in (
                ("set", lambda: self.prog.set_breakpoint(0xDEAD)),
                ("remove", bp.remove),
            ):
                with self.subTest(change=name):
                    it = self.prog.breakpoint_sites()
                    change()
                    self.assertRaises(RuntimeError, next, it)

    def test_breakpoint_sites_breakpoints_changed_during_iteration(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            bp1 = self.prog.set_breakpoint(0x1337)
            bp2 = self.prog.set_breakpoint(0xDEAD, enable=False)
            sites = [bp1.sites[0], bp2.sites[0]]

            # These change the breakpoints at a site but not the set of
            # sites.
            it = self.prog.breakpoint_sites()
            bp3 = self.prog.set_breakpoint(0x1337)
            bp1.disable()
            bp2.enable()
            bp3.remove()
            self.assertCountEqual(it, sites)
