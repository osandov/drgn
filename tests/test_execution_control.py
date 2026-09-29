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
        attach_op = Op("attach", drgn.AttachFlags.ALL_STOP)
        attach_op_return = Return(attach_op, True)
        attach_call_return = Return(attach_call, ANY)
        detach_call = Call(self.prog.detach)
        detach_op = Op("detach")
        detach_op_return = Return(detach_op, None)
        detach_call_return = Return(detach_call, None)

        attach_call.next = attach_op
        attach_op.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.ATTACHING
        )
        attach_op.next = attach_op_return
        attach_op_return.next = attach_call_return
        attach_call_return.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.ATTACHED
        )
        attach_call_return.next = detach_call
        detach_call.next = detach_op
        detach_op.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.DETACHING
        )
        detach_op.next = detach_op_return
        detach_op_return.next = detach_call_return
        detach_call_return.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.DETACHED
        )

        self.expect(start=attach_call)

    def test_attach_failure(self):
        attach_call = Call(self.prog.attach, drgn.AttachFlags.ALL_STOP)
        attach_op = Op("attach", drgn.AttachFlags.ALL_STOP)
        attach_op_raise = Raise(attach_op, Exception("foo"))
        attach_call_raise = Raise(attach_call, Exception("foo"))

        attach_call.next = attach_op
        attach_op.next = attach_op_raise
        attach_op_raise.next = attach_call_raise
        attach_call_raise.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.DETACHED
        )

        self.expect(start=attach_call)

    def test_context_manager(self):
        cm = self.prog.attach(drgn.AttachFlags.ALL_STOP)

        enter_call = Call(cm.__enter__)
        enter_call_return = Return(enter_call, None)
        exit_call = Call(cm.__exit__, None, None, None)
        detach_op = Op("detach")
        detach_op_return = Return(detach_op, None)
        exit_call_return = Return(exit_call, None)

        enter_call.next = enter_call_return
        enter_call_return.next = exit_call
        exit_call.next = detach_op
        detach_op.next = detach_op_return
        detach_op_return.next = exit_call_return
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
        detach_op = Op("detach")
        detach_op_return = Return(detach_op, None)
        exit_call_return = Return(exit_call, None)

        exit_call.next = detach_op
        detach_op.next = detach_op_return
        detach_op_return.next = exit_call_return
        exit_call_return.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.DETACHED
        )

        self.expect(start=exit_call)

    def test_program_exit(self):
        self.prog.attach(drgn.AttachFlags.ALL_STOP)

        notify_exit = ControllerCall(self.prog.notify_program_exit, 0)
        exit_event = Event(drgn.ProgramExitEvent, 0)
        detach_call = Call(self.prog.detach)
        detach_op = Op("detach")
        detach_op_return = Return(detach_op, None)
        detach_call_return = Return(detach_call, None)

        notify_exit.next = exit_event
        exit_event.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.EXITED
        )
        exit_event.next = detach_call
        detach_call.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.EXITED
        )
        detach_call.next = detach_op
        detach_op.next = detach_op_return
        detach_op_return.next = detach_call_return
        detach_call_return.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.DETACHED
        )

        self.expect(start=notify_exit)

    def test_program_exit_during_attach(self):
        attach_call = Call(self.prog.attach, drgn.AttachFlags.ALL_STOP)
        attach_op = Op("attach", drgn.AttachFlags.ALL_STOP)
        notify_exit = ControllerCall(self.prog.notify_program_exit, 0)
        exit_event = Event(drgn.ProgramExitEvent, 0)
        attach_op_return = Return(attach_op, True)
        attach_call_return = Return(attach_call, ANY)

        attach_call.next = attach_op
        attach_op.next = notify_exit
        notify_exit.next = exit_event
        exit_event.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.EXITED
        )
        exit_event.next = attach_op_return
        attach_op_return.next = attach_call_return
        attach_call_return.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.EXITED
        )

        self.expect(start=attach_call)

        self.prog.detach()
        self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHED)

    def test_program_exit_during_detach(self):
        self.prog.attach(drgn.AttachFlags.ALL_STOP)

        detach_call = Call(self.prog.detach)
        detach_op = Op("detach")
        notify_exit = ControllerCall(self.prog.notify_program_exit, 0)
        exit_event = Event(drgn.ProgramExitEvent, 0)
        detach_op_return = Return(detach_op, None)
        detach_call_return = Return(detach_call, None)

        detach_call.next = detach_op
        detach_op.next = notify_exit
        notify_exit.next = exit_event
        exit_event.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.DETACHING
        )
        exit_event.next = detach_op_return
        detach_op_return.next = detach_call_return
        detach_call_return.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.DETACHED
        )

        self.expect(start=detach_call)

    def test_program_lost(self):
        self.prog.attach(drgn.AttachFlags.ALL_STOP)

        notify_lost = ControllerCall(
            self.prog.notify_program_lost, BrokenPipeError("bye")
        )
        lost_event = Event(drgn.ProgramLostEvent, BrokenPipeError("bye"))
        detach_call = Call(self.prog.detach)
        detach_op = Op("detach")
        detach_op_return = Return(detach_op, None)
        detach_call_return = Return(detach_call, None)

        notify_lost.next = lost_event
        lost_event.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.LOST
        )
        lost_event.next = detach_call
        detach_call.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.LOST
        )
        detach_call.next = detach_op
        detach_op.next = detach_op_return
        detach_op_return.next = detach_call_return
        detach_call_return.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.DETACHED
        )

        self.expect(start=notify_lost)

    def test_program_lost_during_attach(self):
        attach_call = Call(self.prog.attach, drgn.AttachFlags.ALL_STOP)
        attach_op = Op("attach", drgn.AttachFlags.ALL_STOP)
        notify_lost = ControllerCall(
            self.prog.notify_program_lost, BrokenPipeError("bye")
        )
        lost_event = Event(drgn.ProgramLostEvent, BrokenPipeError("bye"))
        attach_op_return = Return(attach_op, True)
        attach_call_return = Return(attach_call, ANY)

        attach_call.next = attach_op
        attach_op.next = notify_lost
        notify_lost.next = lost_event
        lost_event.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.LOST
        )
        lost_event.next = attach_op_return
        attach_op_return.next = attach_call_return
        attach_call_return.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.LOST
        )

        self.expect(start=attach_call)

        self.prog.detach()
        self.assertEqual(self.prog.attach_state, drgn.AttachState.DETACHED)

    def test_program_lost_during_detach(self):
        self.prog.attach(drgn.AttachFlags.ALL_STOP)

        detach_call = Call(self.prog.detach)
        detach_op = Op("detach")
        notify_lost = ControllerCall(
            self.prog.notify_program_lost, BrokenPipeError("bye")
        )
        lost_event = Event(drgn.ProgramLostEvent, BrokenPipeError("bye"))
        detach_op_return = Return(detach_op, None)
        detach_call_return = Return(detach_call, None)

        detach_call.next = detach_op
        detach_op.next = notify_lost
        notify_lost.next = lost_event
        lost_event.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.DETACHING
        )
        lost_event.next = detach_op_return
        detach_op_return.next = detach_call_return
        detach_call_return.on = lambda: self.assertEqual(
            self.prog.attach_state, drgn.AttachState.DETACHED
        )

        self.expect(start=detach_call)


class TestAllStop(ExecutionControlTestCase):
    def _test_signal_stop(self, *reasons):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            self.check_none_stopped()

            notify_thread_stop = ControllerCall(
                self.prog.notify_thread_stop,
                self.prog.thread(1),
                signal.SIGWINCH,
                0x1337,
                *reasons,
            )
            stop_all_threads = Op("stop_all_threads")
            stop_all_threads_return = Return(stop_all_threads, None)
            stop_event = Event(drgn.ThreadStopEvent, self.prog.thread(1))

            def check_stopped():
                self.assertEqual(
                    self.stopped_threads(),
                    {
                        **self.all_stop(),
                        1: drgn.SignalStopReason(signal.SIGWINCH),
                    },
                )

            notify_thread_stop.next = stop_all_threads
            stop_all_threads.next = stop_all_threads_return
            stop_all_threads_return.next = stop_event
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
            resume_threads = Op(
                "resume_threads",
                [
                    drgn.ContinueResumeAction(self.prog.thread(1), signal.SIGWINCH),
                    drgn.ContinueResumeAction(None, 0),
                ],
            )
            resume_threads_return = Return(resume_threads, None)
            cont_return = Return(cont, None)

            cont.next = resume_threads
            resume_threads.next = resume_threads_return
            resume_threads_return.next = cont_return
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
            resume_threads = Op(
                "resume_threads",
                [
                    drgn.ContinueResumeAction(self.prog.thread(1), signal.SIGWINCH),
                    drgn.ContinueResumeAction(None, 0),
                ],
            )
            resume_threads_return = Return(resume_threads, None)
            cont_return = Return(cont, None)

            cont.next = resume_threads
            resume_threads.next = resume_threads_return
            resume_threads_return.next = cont_return
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
            resume_threads = Op("resume_threads", [drgn.ContinueResumeAction(None, 0)])
            resume_threads_return = Return(resume_threads, None)
            cont_return = Return(cont, None)

            cont.next = resume_threads
            resume_threads.next = resume_threads_return
            resume_threads_return.next = cont_return
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
            resume_threads = Op("resume_threads", [drgn.ContinueResumeAction(None, 0)])
            resume_threads_return = Return(resume_threads, None)
            cont_return = Return(cont, None)

            cont.next = resume_threads
            resume_threads.next = resume_threads_return
            resume_threads_return.next = cont_return
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
            resume_threads = Op("resume_threads", [drgn.ContinueResumeAction(None, 0)])
            resume_threads_return = Return(resume_threads, None)
            cont_return = Return(cont, None)

            cont.next = resume_threads
            resume_threads.next = resume_threads_return
            resume_threads_return.next = cont_return
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
            resume_threads = Op(
                "resume_threads",
                [
                    drgn.ContinueResumeAction(self.prog.thread(1), signal.SIGUSR1),
                    drgn.ContinueResumeAction(None, 0),
                ],
            )
            resume_threads_return = Return(resume_threads, None)
            cont_return = Return(cont, None)

            cont.next = resume_threads
            resume_threads.next = resume_threads_return
            resume_threads_return.next = cont_return
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
            resume_threads = Op(
                "resume_threads",
                [
                    drgn.ContinueResumeAction(self.prog.thread(1), signal.SIGWINCH),
                    drgn.ContinueResumeAction(self.prog.thread(2), signal.SIGUSR1),
                    drgn.ContinueResumeAction(None, 0),
                ],
            )
            resume_threads_return = Return(resume_threads, None)
            cont_return = Return(cont, None)

            cont.next = resume_threads
            resume_threads.next = resume_threads_return
            resume_threads_return.next = cont_return
            cont_return.on = self.check_none_stopped

            self.expect(start=cont)

    def _test_simultaneous_stop(self, conts_and_resume_actions):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            notify_thread_stop1 = ControllerCall(
                self.prog.notify_thread_stop,
                self.prog.thread(1),
                signal.SIGWINCH,
                0x1337,
            )
            stop_all_threads = Op("stop_all_threads")
            notify_thread_stop2 = ControllerCall(
                self.prog.notify_thread_stop,
                self.prog.thread(2),
                signal.SIGCHLD,
                0xDEAD,
            )
            stop_all_threads_return = Return(stop_all_threads, None)

            def stop_event1(tid):
                other_tid = 2 if tid == 1 else 1
                (cont1_tid, cont1_sig), (cont2_tid, cont2_sig), resume_actions = (
                    conts_and_resume_actions(tid, other_tid)
                )

                event1 = Event(drgn.ThreadStopEvent, self.prog.thread(tid))
                cont1 = Call(self.prog.thread(cont1_tid).cont, sig=cont1_sig)
                cont1_return = Return(cont1, None)
                event2 = Event(drgn.ThreadStopEvent, self.prog.thread(other_tid))
                cont2 = Call(self.prog.thread(cont2_tid).cont, sig=cont2_sig)
                resume_threads = Op("resume_threads", resume_actions)
                resume_threads_return = Return(resume_threads, None)
                cont2_return = Return(cont2, None)

                event1.on = functools.partial(check_stopped_thread, tid)
                event1.next = cont1
                cont1.next = cont1_return & event2
                cont1_return.on = functools.partial(check_stopped_thread, other_tid)
                event2.on = functools.partial(check_stopped_thread, other_tid)
                cont1.next.next = cont2
                cont2.next = resume_threads
                resume_threads.next = resume_threads_return
                resume_threads_return.next = cont2_return
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

            notify_thread_stop1.next = stop_all_threads
            stop_all_threads.next = notify_thread_stop2
            notify_thread_stop2.next = stop_all_threads_return
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
            stop_all_threads = Op("stop_all_threads")
            stop_all_threads_return = Return(stop_all_threads, None)

            def stop_event1(tid):
                # Continue a thread with an unreported stop. Its stop may be
                # reported next or last.
                tid2, tid3 = [other_tid for other_tid in sigs if other_tid != tid]

                event1 = Event(drgn.ThreadStopEvent, self.prog.thread(tid))
                cont1 = Call(self.prog.thread(tid3).cont, sig=sig)
                cont1_return = Return(cont1, None)

                event1.on = functools.partial(check_stopped_thread, tid)
                event1.next = cont1
                cont1.next = cont1_return & (
                    stop_event2(tid2, tid3) | stop_event2(tid3, tid2)
                )

                return event1

            def stop_event2(tid, other_tid):
                event2 = Event(drgn.ThreadStopEvent, self.prog.thread(tid))
                cont2 = Call(self.prog.thread(tid).cont)
                cont2_return = Return(cont2, None)
                event3 = Event(drgn.ThreadStopEvent, self.prog.thread(other_tid))
                cont3 = Call(self.prog.thread(other_tid).cont)
                resume_threads = Op(
                    "resume_threads",
                    [
                        drgn.ContinueResumeAction(self.prog.thread(i), sigs[i])
                        for i in sigs
                    ]
                    + [drgn.ContinueResumeAction(None, 0)],
                )
                resume_threads_return = Return(resume_threads, None)
                cont3_return = Return(cont3, None)

                event2.on = functools.partial(check_stopped_thread, tid)
                event2.next = cont2
                cont2.next = cont2_return & event3
                event3.on = functools.partial(check_stopped_thread, other_tid)
                cont2.next.next = cont3
                cont3.next = resume_threads
                resume_threads.next = resume_threads_return
                resume_threads_return.next = cont3_return
                cont3_return.on = self.check_none_stopped

                return event2

            def check_stopped_thread(tid):
                self.assertEqual(
                    self.stopped_threads(),
                    {**self.all_stop(), tid: drgn.SignalStopReason(sigs[tid])},
                )

            notify_thread_stops[0].next = stop_all_threads
            stop_all_threads.next = notify_thread_stops[1]
            notify_thread_stops[1].next = notify_thread_stops[2]
            notify_thread_stops[2].next = stop_all_threads_return
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

            notify_thread_breakpoint = ControllerCall(
                self.prog.notify_thread_breakpoint, self.prog.thread(1), site
            )
            stop_all_threads = Op("stop_all_threads")
            stop_all_threads_return = Return(stop_all_threads, None)
            stop_event = Event(drgn.ThreadStopEvent, self.prog.thread(1))

            def check_stopped():
                self.assertEqual(
                    self.stopped_threads(),
                    {**self.all_stop(), 1: drgn.BreakpointStopReason(site)},
                )

            notify_thread_breakpoint.next = stop_all_threads
            stop_all_threads.next = stop_all_threads_return
            stop_all_threads_return.next = stop_event
            stop_event.on = check_stopped

            self.expect(start=notify_thread_breakpoint)

            check_stopped()

    def test_breakpoint_cont(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            site = self.prog.set_breakpoint(0x1337).sites[0]
            self.queue_call(
                self.prog.notify_thread_breakpoint, self.prog.thread(1), site
            )
            while self.prog.poll(0):
                pass

            cont = Call(self.prog.thread(1).cont)
            disable_breakpoint_sites = Op("disable_breakpoint_sites", [site])
            disable_breakpoint_sites_return = Return(disable_breakpoint_sites, None)
            step_thread = Op(
                "resume_threads", [drgn.StepiResumeAction(self.prog.thread(1), 0)]
            )
            step_thread_return = Return(step_thread, None)
            # TODO: queue break?
            notify_stepped = ControllerCall(
                self.prog.notify_thread_stop,
                self.prog.thread(1),
                signal.SIGTRAP,
                0x1338,
            )
            enable_breakpoint_sites = Op("enable_breakpoint_sites", [site])
            enable_breakpoint_sites_return = Return(enable_breakpoint_sites, None)
            resume_threads = Op("resume_threads", [drgn.ContinueResumeAction(None, 0)])
            resume_threads_return = Return(resume_threads, None)
            cont_return = Return(cont, None)

            cont.next = disable_breakpoint_sites
            disable_breakpoint_sites.next = disable_breakpoint_sites_return
            disable_breakpoint_sites_return.next = step_thread
            # TODO: need to test the case where the program is lost or exits
            # while waiting.
            step_thread.next = step_thread_return
            step_thread_return.next = notify_stepped
            notify_stepped.next = enable_breakpoint_sites
            enable_breakpoint_sites.next = enable_breakpoint_sites_return
            enable_breakpoint_sites_return.next = resume_threads
            resume_threads.next = resume_threads_return
            resume_threads_return.next = cont_return
            cont_return.on = self.check_none_stopped

            self.expect(start=cont)

    def test_breakpoint_cont_signaled(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            site = self.prog.set_breakpoint(0x1337).sites[0]
            self.queue_call(
                self.prog.notify_thread_breakpoint, self.prog.thread(1), site
            )
            while self.prog.poll(0):
                pass

            cont1 = Call(self.prog.thread(1).cont)
            disable_breakpoint_sites = Op("disable_breakpoint_sites", [site])
            disable_breakpoint_sites_return = Return(disable_breakpoint_sites, None)
            step_thread = Op(
                "resume_threads", [drgn.StepiResumeAction(self.prog.thread(1), 0)]
            )
            step_thread_return = Return(step_thread, None)
            notify_thread_stop = ControllerCall(
                self.prog.notify_thread_stop,
                self.prog.thread(1),
                signal.SIGSEGV,
                0x1337,
            )
            stop_event = Event(drgn.ThreadStopEvent, self.prog.thread(1))
            enable_breakpoint_sites = Op("enable_breakpoint_sites", [site])
            enable_breakpoint_sites_return = Return(enable_breakpoint_sites, None)
            cont1_return = Return(cont1, None)
            cont2 = Call(self.prog.thread(1).cont)
            resume_threads = Op(
                "resume_threads",
                [
                    drgn.ContinueResumeAction(self.prog.thread(1), signal.SIGSEGV),
                    drgn.ContinueResumeAction(None, 0),
                ],
            )
            resume_threads_return = Return(resume_threads, None)
            cont2_return = Return(cont2, None)

            def check_stopped():
                self.assertEqual(
                    self.stopped_threads(),
                    {
                        **self.all_stop(),
                        1: drgn.SignalStopReason(signal.SIGSEGV),
                    },
                )

            cont1.next = disable_breakpoint_sites
            disable_breakpoint_sites.next = disable_breakpoint_sites_return
            disable_breakpoint_sites_return.next = step_thread
            step_thread.next = step_thread_return
            step_thread_return.next = notify_thread_stop
            stop_event.on = check_stopped
            notify_thread_stop.next = stop_event & enable_breakpoint_sites
            enable_breakpoint_sites.next = enable_breakpoint_sites_return
            enable_breakpoint_sites_return.next = cont1_return
            notify_thread_stop.next.on = check_stopped
            notify_thread_stop.next.next = cont2
            cont2.next = resume_threads
            resume_threads.next = resume_threads_return
            resume_threads_return.next = cont2_return
            cont2_return.on = self.check_none_stopped

            self.expect(start=cont1)

    def test_simultaneous_breakpoint(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            site1 = self.prog.set_breakpoint(0x1337).sites[0]
            site2 = self.prog.set_breakpoint(0xDEAD).sites[0]

            notify_thread_breakpoint1 = ControllerCall(
                self.prog.notify_thread_breakpoint, self.prog.thread(1), site1
            )
            stop_all_threads = Op("stop_all_threads")
            notify_thread_breakpoint2 = ControllerCall(
                self.prog.notify_thread_breakpoint, self.prog.thread(2), site2
            )
            stop_all_threads_return = Return(stop_all_threads, None)

            def stop_event1(tid):
                other_tid = 2 if tid == 1 else 1

                event1 = Event(drgn.ThreadStopEvent, self.prog.thread(tid))
                cont1 = Call(self.prog.thread(tid).cont)

            notify_thread_breakpoint1.next = stop_all_threads
            stop_all_threads.next = notify_thread_breakpoint2
            notify_thread_breakpoint2.next = stop_all_threads_return
            stop_all_threads_return.next = stop_event1(1) | stop_event1(2)

            self.expect(start=notify_thread_breakpoint1)

            return  # TODO

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
    def test_set(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            set_breakpoint = Call(self.prog.set_breakpoint, 0x1337)
            capture_site = CaptureBreakpointSite()
            enable_breakpoint_sites = Op("enable_breakpoint_sites", [capture_site])
            enable_breakpoint_sites_return = Return(enable_breakpoint_sites, None)
            capture_breakpoint = CaptureBreakpoint()
            set_breakpoint_return = Return(set_breakpoint, capture_breakpoint)

            set_breakpoint.next = enable_breakpoint_sites
            enable_breakpoint_sites.next = enable_breakpoint_sites_return
            enable_breakpoint_sites_return.next = set_breakpoint_return
            set_breakpoint_return.on = lambda: (
                self.assertTrue(capture_breakpoint.breakpoint.enabled),
                self.assertTrue(capture_breakpoint.breakpoint.sites[0].enabled),
                self.assertEqual(
                    capture_breakpoint.breakpoint.sites[0], capture_site.site
                ),
            )

            self.expect(start=set_breakpoint)

    def test_set_disabled(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            set_breakpoint = Call(self.prog.set_breakpoint, 0x1337, enable=False)
            capture_breakpoint = CaptureBreakpoint()
            set_breakpoint_return = Return(set_breakpoint, capture_breakpoint)

            set_breakpoint.next = set_breakpoint_return
            set_breakpoint_return.on = lambda: (
                self.assertFalse(capture_breakpoint.breakpoint.enabled),
                self.assertFalse(capture_breakpoint.breakpoint.sites[0].enabled),
            )

            self.expect(start=set_breakpoint)

    def test_disable(self):
        with self.prog.attach(drgn.AttachFlags.ALL_STOP):
            bp = self.prog.set_breakpoint(0x1337)
            site = bp.sites[0]

            breakpoint_disable = Call(bp.disable)
            disable_breakpoint_sites = Op("disable_breakpoint_sites", [site])
            disable_breakpoint_sites_return = Return(disable_breakpoint_sites, None)
            breakpoint_disable_return = Return(breakpoint_disable, None)

            breakpoint_disable.next = disable_breakpoint_sites
            disable_breakpoint_sites.next = disable_breakpoint_sites_return
            disable_breakpoint_sites_return.next = breakpoint_disable_return
            breakpoint_disable_return.on = lambda: (
                self.assertFalse(bp.enabled),
                self.assertFalse(site.enabled),
            )

            self.expect(start=breakpoint_disable)
