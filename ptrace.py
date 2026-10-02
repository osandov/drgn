# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Execution controller for a userspace process on x86-64 Linux using
:manpage:`ptrace(2)`.

Set up the program with :meth:`drgn.Program.set_pid()` (or ``drgn -p``) and
then call :func:`register()`.

This supports all-stop mode and non-stop mode, software breakpoints, and
threads being created and exiting.

All calls to :manpage:`ptrace(2)` and :manpage:`wait(2)` are made by a
dedicated thread, which is created when attaching. It only waits for the
threads that it is tracing, so it doesn't interfere with any child processes
of the rest of the process, and no signal handlers are changed. Everything
else happens in the thread that the program is used from: the tracer thread
passes on what it gets from :manpage:`wait(2)` through the program's event
loop.

The tracer thread waits for the threads that it is tracing with a blocking
call. To get its attention while it is doing that, it is sent
:data:`WAKEUP_SIGNAL` with :func:`signal.pthread_kill()`, which only goes to
that thread. This only interrupts the call if the signal has a handler, so one
that does nothing is installed while attached if there isn't one already.
Python only allows that from the main thread, so either attach from the main
thread or call :func:`install_wakeup_handler()` from the main thread first.

Limitations:

* Hardware breakpoints are not supported.
* Software breakpoints are visible when reading the program's memory.
* Child processes are not traced. If the process forks while it has software
  breakpoints, then the child gets a copy of them and will be killed by
  ``SIGTRAP`` if it reaches one.
* :manpage:`execve(2)` is not handled.
* The kernel sends ``SIGCHLD`` to this process whenever a thread being traced
  stops. It is ignored by default.
* :data:`WAKEUP_SIGNAL` can't be used for anything else in this process.
"""

import collections
import ctypes
import enum
import errno
import logging
import os
import signal
import threading
from typing import Any, Callable, Deque, Dict, List, Optional, Sequence, Set, Tuple

import drgn

logger = logging.getLogger("drgn.ptrace")

_WNOTHREAD = 0x20000000
_WALL = 0x40000000

_c = ctypes.CDLL(None, use_errno=True)

_waitid = _c.waitid
_waitid.restype = ctypes.c_int
_waitid.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_void_p, ctypes.c_int]

_ptrace = _c.ptrace
_ptrace.restype = ctypes.c_long
_ptrace.argtypes = [ctypes.c_long, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]

_tgkill = _c.tgkill
_tgkill.restype = ctypes.c_int
_tgkill.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]

WAKEUP_SIGNAL = signal.SIGRTMAX - 5
"""
Signal used to interrupt the tracer thread. This can be changed before
attaching.
"""

# How long to wait for the tracer thread to notice a call before sending it
# the signal again, in seconds. The signal is lost if it arrives right before
# the tracer thread starts waiting.
_WAKEUP_INTERVAL = 0.001

_P_ALL = 0

# x86 breakpoint instruction (int3).
_BREAKPOINT_INSTRUCTION = b"\xcc"

_CLD_EXITED = 1
_CLD_KILLED = 2
_CLD_DUMPED = 3

_SI_KERNEL = 0x80
_TRAP_BRKPT = 1
_TRAP_TRACE = 2

_STOP_SIGNALS = frozenset(
    (signal.SIGSTOP, signal.SIGTSTP, signal.SIGTTIN, signal.SIGTTOU)
)


class PtraceRequest(enum.IntEnum):
    CONT = 7
    SINGLESTEP = 9
    GETREGS = 12
    SETREGS = 13
    DETACH = 17
    GETEVENTMSG = 0x4201
    GETSIGINFO = 0x4202
    SEIZE = 0x4206
    INTERRUPT = 0x4207
    LISTEN = 0x4208
    PEEKSIGINFO = 0x4209


_RESUME_REQUESTS = frozenset(
    (PtraceRequest.CONT, PtraceRequest.SINGLESTEP, PtraceRequest.LISTEN)
)


class PtraceEvent(enum.IntEnum):
    CLONE = 3
    STOP = 128


class PtraceOption(enum.IntFlag):
    TRACECLONE = 1 << PtraceEvent.CLONE


class user_regs_struct(ctypes.Structure):
    _fields_ = (
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    )


# Names of the registers in drgn that are different from user_regs_struct.
_REGISTER_NAMES = {
    "eflags": "rflags",
    "fs_base": "fs.base",
    "gs_base": "gs.base",
}


class siginfo_t(ctypes.Structure):
    _fields_ = (
        ("si_signo", ctypes.c_int),
        ("si_errno", ctypes.c_int),
        ("si_code", ctypes.c_int),
        ("_pad", ctypes.c_int * 29),
    )


class ptrace_peeksiginfo_args(ctypes.Structure):
    _fields_ = (
        ("off", ctypes.c_uint64),
        ("flags", ctypes.c_uint32),
        ("nr", ctypes.c_int32),
    )


class _wait_siginfo_t(ctypes.Structure):
    _fields_ = (
        ("si_signo", ctypes.c_int),
        ("si_errno", ctypes.c_int),
        ("si_code", ctypes.c_int),
        ("_pad0", ctypes.c_int),
        ("si_pid", ctypes.c_int),
        ("si_uid", ctypes.c_uint),
        ("si_status", ctypes.c_int),
        ("_pad", ctypes.c_int * 25),
    )


_wakeup_handler_users = 0
_wakeup_handler_installed = False
_wakeup_handler_old: Any = None


def install_wakeup_handler() -> None:
    """
    Install the handler for :data:`WAKEUP_SIGNAL` if it doesn't already have
    one. This must be called from the main thread. It is called automatically
    when attaching.
    """
    global _wakeup_handler_users, _wakeup_handler_installed, _wakeup_handler_old
    if _wakeup_handler_users == 0:
        old = signal.getsignal(WAKEUP_SIGNAL)
        # Any handler will do.
        if old is None or old == signal.SIG_DFL or old == signal.SIG_IGN:
            try:
                signal.signal(WAKEUP_SIGNAL, lambda sig, frame: None)
            except ValueError:
                raise RuntimeError(
                    "the first attach must be from the main thread, "
                    "or install_wakeup_handler() must be called from the main thread first"
                ) from None
            _wakeup_handler_old = old
            _wakeup_handler_installed = True
    _wakeup_handler_users += 1


def uninstall_wakeup_handler() -> None:
    """
    Undo one call to :func:`install_wakeup_handler()`. The handler is removed
    when all of them have been undone.
    """
    global _wakeup_handler_users, _wakeup_handler_installed
    _wakeup_handler_users -= 1
    if _wakeup_handler_users == 0 and _wakeup_handler_installed:
        try:
            signal.signal(WAKEUP_SIGNAL, _wakeup_handler_old)
        except ValueError:
            # We're not in the main thread. It doesn't hurt to leave it.
            _wakeup_handler_users = 1
        else:
            _wakeup_handler_installed = False


def _raise_errno() -> None:
    err = ctypes.get_errno()
    raise OSError(err, os.strerror(err))


class _Call:
    def __init__(self, fn: Callable[..., Any], args: Tuple[Any, ...]) -> None:
        self.fn = fn
        self.args = args
        self.started = threading.Event()
        self.done = threading.Event()
        self.result: Any = None
        self.exc: Optional[BaseException] = None

    def run(self) -> None:
        self.started.set()
        try:
            self.result = self.fn(*self.args)
        except BaseException as e:
            self.exc = e
        self.done.set()


class _Tracer(threading.Thread):
    """
    Thread that makes all of the calls to :manpage:`ptrace(2)` and
    :manpage:`wait(2)`. The kernel requires the former to all come from the
    same thread.

    The methods without a leading underscore are called from other threads
    and run in this one.
    """

    def __init__(self, pid: int) -> None:
        super().__init__(name=f"drgn-ptrace-{pid}", daemon=True)
        self._pid = pid
        # Whether the process is a child of this process. If so, then
        # whoever created it expects to be able to wait for it, so we can't.
        with open(f"/proc/{pid}/stat", "rb") as f:
            self._is_child = (
                int(f.read().rpartition(b") ")[2].split()[1]) == os.getpid()
            )
        self._lock = threading.Lock()
        self._have_calls = threading.Condition(self._lock)
        self._calls: Deque[_Call] = collections.deque()
        self._quit = False
        # Whether this thread is waiting for the threads that it is tracing,
        # so it has to be interrupted to notice a call.
        self._waiting = False
        # Threads that are running and threads that are stopped. These are
        # only used by this thread.
        self._running: Set[int] = set()
        self._stopped: Set[int] = set()
        # Whether the process exited and we left it to be waited for.
        self._exited = False
        # Signals that threads stopped for while we were stopping them to
        # detach.
        self._detach_sigs: Dict[int, int] = {}
        # (thread ID, wait status, thread ID of new thread or 0)
        self.statuses: Deque[Tuple[int, int, int]] = collections.deque()
        # Becomes readable when there is anything in statuses.
        self.status_fd, self._status_write_fd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)

    def close(self) -> None:
        if self.is_alive():
            self._call(self._do_quit)
            self.join()
        if self.status_fd >= 0:
            os.close(self.status_fd)
            os.close(self._status_write_fd)
            self.status_fd = -1

    # Calls from other threads

    def _call(self, fn: Callable[..., Any], *args: Any) -> Any:
        call = _Call(fn, args)
        with self._lock:
            if not self.is_alive():
                raise RuntimeError("tracer thread is not running")
            self._calls.append(call)
            self._have_calls.notify()
        while True:
            with self._lock:
                waiting = self._waiting
            if waiting:
                assert self.ident is not None
                try:
                    signal.pthread_kill(self.ident, WAKEUP_SIGNAL)
                except ProcessLookupError:
                    pass
            # If it was about to start waiting, then that didn't do
            # anything, so we have to try again.
            if call.started.wait(_WAKEUP_INTERVAL):
                break
        call.done.wait()
        if call.exc is not None:
            raise call.exc
        return call.result

    def ptrace(
        self, request: PtraceRequest, tid: int, addr: int = 0, data: int = 0
    ) -> None:
        self._call(self._do_ptrace, request, tid, addr, data)

    def ptrace_get(
        self, request: PtraceRequest, tid: int, obj: "ctypes._CData"
    ) -> None:
        self._call(self._do_ptrace, request, tid, None, ctypes.byref(obj))

    def stop_all(self, breakpoints: Set[int]) -> None:
        """
        Get every thread ready to be detached from: stop the ones that
        aren't, including ones that the caller doesn't know about yet, and
        make sure that none of them are affected by a breakpoint that is about
        to be removed.

        :param breakpoints: Addresses of the breakpoints in the program.
        """
        self._call(self._do_stop_all, breakpoints)

    def detach_all(self, sigs: Dict[int, int]) -> None:
        """
        Detach from all threads. :meth:`stop_all()` must be called first.

        :param sigs: Signals to inject by thread ID.
        """
        self._call(self._do_detach_all, sigs)

    # Tracer thread

    def _do_quit(self) -> None:
        self._quit = True

    def _do_ptrace(
        self, request: PtraceRequest, tid: int, addr: Any, data: Any
    ) -> None:
        if _ptrace(request, tid, addr, data) == -1:
            _raise_errno()
        if request in _RESUME_REQUESTS or request == PtraceRequest.SEIZE:
            self._running.add(tid)
            self._stopped.discard(tid)
        elif request == PtraceRequest.DETACH:
            self._running.discard(tid)
            self._stopped.discard(tid)

    def _has_breakpoint_trap(self, tid: int) -> bool:
        # Return whether a thread has a SIGTRAP for a breakpoint instruction
        # that it hasn't stopped for yet. This happens if it stops because
        # it was interrupted right after executing the instruction.
        args = ptrace_peeksiginfo_args(0, 0, 16)
        siginfos = (siginfo_t * 16)()
        n = _ptrace(
            PtraceRequest.PEEKSIGINFO, tid, ctypes.byref(args), ctypes.byref(siginfos)
        )
        return any(
            siginfos[i].si_signo == signal.SIGTRAP
            and siginfos[i].si_code in (_SI_KERNEL, _TRAP_BRKPT)
            for i in range(max(n, 0))
        )

    def _wait_for_stop(self, tid: int, breakpoints: Set[int]) -> None:
        # Wait for a thread to stop, and then make sure that it won't be
        # affected by any breakpoint instructions that it executed.
        while True:
            try:
                _, status = os.waitpid(tid, _WALL)
            except ChildProcessError:
                break
            if not os.WIFSTOPPED(status):
                break
            self._stopped.add(tid)
            sig = os.WSTOPSIG(status)
            if status >> 16 == PtraceEvent.CLONE:
                # It created a thread that we're now tracing, too.
                msg = ctypes.c_ulong()
                if (
                    _ptrace(PtraceRequest.GETEVENTMSG, tid, None, ctypes.byref(msg))
                    == 0
                    and msg.value not in self._stopped
                ):
                    self._running.add(msg.value)
            elif status >> 16 == 0 and sig == signal.SIGTRAP:
                regs = user_regs_struct()
                if (
                    _ptrace(PtraceRequest.GETREGS, tid, None, ctypes.byref(regs)) == 0
                    and regs.rip - len(_BREAKPOINT_INSTRUCTION) in breakpoints
                ):
                    regs.rip -= len(_BREAKPOINT_INSTRUCTION)
                    _ptrace(PtraceRequest.SETREGS, tid, None, ctypes.byref(regs))
                else:
                    # It wasn't one of ours.
                    self._detach_sigs[tid] = sig
            elif status >> 16 == 0:
                # It got a signal that it still needs to get.
                self._detach_sigs[tid] = sig
            if not self._has_breakpoint_trap(tid):
                return
            # Let it stop for that.
            if _ptrace(PtraceRequest.CONT, tid, None, None) == -1:
                break
        self._stopped.discard(tid)

    def _do_stop_all(self, breakpoints: Set[int]) -> None:
        self.statuses.clear()
        self._detach_sigs.clear()
        for tid in list(self._stopped):
            if self._has_breakpoint_trap(tid) and (
                _ptrace(PtraceRequest.CONT, tid, None, None) == 0
            ):
                self._wait_for_stop(tid, breakpoints)
        while self._running:
            tid = self._running.pop()
            if _ptrace(PtraceRequest.INTERRUPT, tid, None, None) == 0:
                self._wait_for_stop(tid, breakpoints)

    def _do_detach_all(self, sigs: Dict[int, int]) -> None:
        for tid in list(self._stopped):
            sig = sigs.get(tid) or self._detach_sigs.get(tid, 0)
            if _ptrace(PtraceRequest.DETACH, tid, None, sig) == -1:
                err = ctypes.get_errno()
                if err != errno.ESRCH:
                    raise OSError(err, os.strerror(err))
            self._stopped.discard(tid)

    def _wait(self, block: bool) -> bool:
        # Wait for or check on the threads that we're tracing and nothing
        # else. Return whether we got anything.
        if self._exited:
            return False
        # Find out what happened without changing anything first. This is
        # not os.waitid() because that tries again if it is interrupted.
        info = _wait_siginfo_t()
        if (
            _waitid(
                _P_ALL,
                0,
                ctypes.byref(info),
                os.WEXITED
                | os.WSTOPPED
                | os.WNOWAIT
                | _WALL
                | _WNOTHREAD
                | (0 if block else os.WNOHANG),
            )
            == -1
        ):
            err = ctypes.get_errno()
            if err == errno.ECHILD:
                self._running.clear()
                self._stopped.clear()
            elif err != errno.EINTR:
                raise OSError(err, os.strerror(err))
            return False
        if info.si_pid == 0:
            return False

        if (
            self._is_child
            and info.si_pid == self._pid
            and info.si_code in (_CLD_EXITED, _CLD_KILLED, _CLD_DUMPED)
        ):
            # The thread group leader is always the last thread to exit.
            # Leave it for whoever created it.
            if info.si_code == _CLD_EXITED:
                status = info.si_status << 8
            else:
                status = info.si_status
            self._running.clear()
            self._stopped.clear()
            self._exited = True
            self._add_status(info.si_pid, status, 0)
            return True

        try:
            tid, status = os.waitpid(info.si_pid, _WALL | os.WNOHANG)
        except ChildProcessError:
            return True
        if tid == 0:
            return True

        self._running.discard(tid)
        new_tid = 0
        if os.WIFSTOPPED(status):
            self._stopped.add(tid)
            if status >> 16 == PtraceEvent.CLONE:
                msg = ctypes.c_ulong()
                if (
                    _ptrace(PtraceRequest.GETEVENTMSG, tid, None, ctypes.byref(msg))
                    == 0
                ):
                    new_tid = msg.value
                    # It starts out about to stop, and we may have already
                    # seen that.
                    if new_tid not in self._stopped:
                        self._running.add(new_tid)
        else:
            self._stopped.discard(tid)
        self._add_status(tid, status, new_tid)
        return True

    def _add_status(self, tid: int, status: int, new_tid: int) -> None:
        self.statuses.append((tid, status, new_tid))
        try:
            os.write(self._status_write_fd, b"\0")
        except BlockingIOError:
            # It's already readable.
            pass

    def run(self) -> None:
        try:
            while True:
                while True:
                    with self._lock:
                        if not self._calls:
                            break
                        call = self._calls.popleft()
                    call.run()
                if self._quit:
                    break
                if self._wait(False):
                    continue
                with self._lock:
                    if self._calls:
                        continue
                    if not self._running or self._exited:
                        # Nothing can happen until we do something, unless
                        # the process is killed.
                        self._have_calls.wait(1)
                        continue
                    self._waiting = True
                try:
                    self._wait(True)
                finally:
                    with self._lock:
                        self._waiting = False
        finally:
            with self._lock:
                calls = list(self._calls)
                self._calls.clear()
            for call in calls:
                call.exc = RuntimeError("tracer thread exited")
                call.started.set()
                call.done.set()


class _Tracee:
    def __init__(self, thread: drgn.Thread) -> None:
        self.thread = thread
        self.tid = thread.tid
        # Whether the thread is in a ptrace-stop.
        self.stopped = False
        # Whether we notified the program that the thread stopped and it
        # hasn't been resumed since.
        self.reported = False
        # If the thread is in a signal-delivery-stop, the signal. Only then
        # can a signal be injected when the thread is resumed.
        self.stop_sig = 0
        # Signal to inject when the thread is resumed if it isn't told
        # otherwise.
        self.pending_sig = 0
        # Signal that we sent to the thread that is to be delivered without
        # being reported.
        self.passthrough_sig = 0
        # Signal to inject when the thread is resumed unless it is told to
        # inject another one. This is passthrough_sig after the thread
        # stopped for it.
        self.forced_sig = 0
        # Whether we want the thread to stop. This is cleared whenever the
        # thread stops.
        self.stop_requested = False
        # Whether the thread was last resumed with PTRACE_SINGLESTEP.
        self.stepping = False
        # Whether the thread hasn't stopped for the first time yet.
        self.new = False
        # Whether an interrupt was requested with Thread.interrupt() or
        # Program.interrupt_any_thread().
        self.user_interrupt = False
        self.regs: Optional[user_regs_struct] = None


class PtraceExecutionController(drgn.ExecutionController):
    def __init__(self, prog: drgn.Program) -> None:
        super().__init__()
        self._prog = prog
        self._pid = 0
        self._tracer: Optional[_Tracer] = None
        self._tracees: Dict[int, _Tracee] = {}
        # What we got from wait() for threads that we haven't been told
        # about yet.
        self._early_statuses: Dict[int, int] = {}
        # Whether new threads should stay stopped. This is set by
        # stop_all_threads() and cleared when threads are resumed with a
        # default action.
        self._hold = False
        self._stop_all_promise: "Optional[drgn.Promise[None]]" = None
        self._detach_promise: "Optional[drgn.Promise[None]]" = None
        self._exit_status: Optional[int] = None
        # Original instructions of the breakpoints that are inserted.
        self._breakpoints: Dict[int, bytes] = {}
        self._mem_fd = -1

    # Setup

    def _open(self, pid: int) -> _Tracer:
        self._pid = pid
        self._hold = False
        self._exit_status = None
        self._tracees.clear()
        self._early_statuses.clear()
        self._breakpoints.clear()
        install_wakeup_handler()
        try:
            self._mem_fd = os.open(f"/proc/{pid}/mem", os.O_RDWR | os.O_CLOEXEC)
        except BaseException:
            uninstall_wakeup_handler()
            raise
        try:
            tracer = _Tracer(pid)
            try:
                tracer.start()
                self._prog.register_fd(
                    tracer.status_fd, drgn.FdEvents.READ, self._on_status
                )
            except BaseException:
                tracer.close()
                raise
        except BaseException:
            os.close(self._mem_fd)
            self._mem_fd = -1
            uninstall_wakeup_handler()
            raise
        self._tracer = tracer
        return tracer

    def _close(self) -> None:
        tracer = self._tracer
        if tracer is not None:
            self._tracer = None
            self._prog.unregister_fd(tracer.status_fd)
            tracer.close()
            uninstall_wakeup_handler()
            os.close(self._mem_fd)
            self._mem_fd = -1
            self._tracees.clear()
            self._early_statuses.clear()
            self._breakpoints.clear()
            self._hold = False
            self._stop_all_promise = None

    def _get_tracer(self) -> _Tracer:
        if self._tracer is None:
            raise drgn.NotAttachedError("not attached to process")
        return self._tracer

    def _thread_state(self, tid: int) -> Tuple[str, int]:
        # Return the state of a thread as a letter (or an empty string if it
        # doesn't exist) and the ID of the thread tracing it.
        state = ""
        tracer_tid = 0
        try:
            with open(f"/proc/{self._pid}/task/{tid}/status", "rb") as f:
                for line in f:
                    name, _, value = line.partition(b":")
                    if name == b"State":
                        state = value.split()[0].decode()
                    elif name == b"TracerPid":
                        tracer_tid = int(value)
        except (FileNotFoundError, ProcessLookupError):
            pass
        return state, tracer_tid

    def _seize_threads(self, tracer: _Tracer) -> None:
        # Threads can be created while we're doing this, so keep going until
        # we don't find any more.
        while True:
            found = False
            for name in os.listdir(f"/proc/{self._pid}/task"):
                tid = int(name)
                if tid in self._tracees:
                    continue
                try:
                    tracer.ptrace(PtraceRequest.SEIZE, tid, 0, PtraceOption.TRACECLONE)
                except ProcessLookupError:
                    # The thread exited.
                    continue
                except PermissionError:
                    # This is also what we get if the thread is exiting or
                    # if we're already tracing it because it was created by
                    # a thread that we were already tracing.
                    state, tracer_tid = self._thread_state(tid)
                    if state in ("Z", "X", ""):
                        continue
                    if tracer_tid != tracer.native_id:
                        raise
                    new = True
                else:
                    new = False
                tracee = _Tracee(self._prog.thread(tid))
                tracee.new = new
                self._tracees[tid] = tracee
                found = True
            if not found:
                break
        if not self._tracees:
            raise ProcessLookupError(errno.ESRCH, os.strerror(errno.ESRCH))

    # Threads

    def _tracee(self, thread: drgn.Thread) -> _Tracee:
        try:
            return self._tracees[thread.tid]
        except KeyError:
            raise LookupError(f"thread {thread.tid} is not being traced") from None

    def _regs(self, tracee: _Tracee) -> user_regs_struct:
        if tracee.regs is None:
            regs = user_regs_struct()
            self._get_tracer().ptrace_get(PtraceRequest.GETREGS, tracee.tid, regs)
            tracee.regs = regs
        return tracee.regs

    def _set_pc(self, tracee: _Tracee, pc: int) -> None:
        regs = self._regs(tracee)
        regs.rip = pc
        self._get_tracer().ptrace_get(PtraceRequest.SETREGS, tracee.tid, regs)

    def _find_register_state(
        self, thread: drgn.Thread, is_last: bool
    ) -> Optional[drgn.RegisterState]:
        tracee = self._tracees.get(thread.tid)
        if self._tracer is None or tracee is None or not tracee.stopped:
            return None
        regs_struct = self._regs(tracee)
        regs = drgn.RegisterState(self._prog, True)
        for name, _ in user_regs_struct._fields_:
            if name != "orig_rax":
                regs.set(_REGISTER_NAMES.get(name, name), getattr(regs_struct, name))
        regs.pc = regs_struct.rip
        return regs

    def _resume(self, tracee: _Tracee, step: bool, sig: Optional[int]) -> None:
        # Resume a thread. If sig is None, then inject the signal that the
        # thread is owed, if any.
        if not tracee.stopped:
            return
        if sig is None:
            sig = tracee.pending_sig
        if tracee.forced_sig:
            sig = sig or tracee.forced_sig
        elif sig and not tracee.stop_sig:
            # A signal can only be injected from a signal-delivery-stop.
            # Otherwise, we have to send it. We don't want to hear about it
            # when it arrives.
            if _tgkill(self._pid, tracee.tid, sig) == -1:
                _raise_errno()
            tracee.passthrough_sig = sig
            sig = 0
        try:
            self._get_tracer().ptrace(
                PtraceRequest.SINGLESTEP if step else PtraceRequest.CONT,
                tracee.tid,
                0,
                sig,
            )
        except ProcessLookupError:
            # The thread was killed. We'll find out when we wait for it.
            pass
        tracee.stopped = False
        tracee.reported = False
        tracee.stepping = step
        tracee.stop_sig = 0
        tracee.pending_sig = 0
        tracee.forced_sig = 0
        tracee.regs = None

    def _stopped_quietly(self, tracee: _Tracee, requested: bool) -> None:
        # The thread stopped for a reason that the program doesn't need to
        # know about.
        if tracee.user_interrupt and self._detach_promise is None:
            # It was asked to stop, and it did.
            self._report_stop(tracee, signal.SIGINT)
        elif not requested and self._detach_promise is None:
            # Resume it the same way that it was last resumed.
            self._resume(tracee, tracee.stepping, None)

    def _interrupt(self, tracee: _Tracee) -> bool:
        # Ask a thread to stop if it isn't already stopped. Return whether we
        # did.
        if tracee.stopped:
            return False
        # We always have to ask the kernel even if we already did. If the
        # thread stopped for another reason and we resumed it since then, the
        # kernel may or may not have forgotten depending on whether the
        # thread stopped before or after we asked.
        try:
            self._get_tracer().ptrace(PtraceRequest.INTERRUPT, tracee.tid)
        except ProcessLookupError:
            # The thread exited. We'll find out when we wait for it.
            return False
        tracee.stop_requested = True
        return True

    # Events

    def _on_status(self, prog: drgn.Program, fd: int, events: drgn.FdEvents) -> None:
        try:
            while os.read(fd, 4096):
                pass
        except BlockingIOError:
            pass
        self._handle_statuses()

    def _handle_statuses(self) -> None:
        while self._tracer is not None and self._tracer.statuses:
            tid, status, new_tid = self._tracer.statuses.popleft()
            tracee = self._tracees.get(tid)
            if tracee is None:
                # This is a new thread, and we haven't gotten to the thread
                # that created it yet.
                self._early_statuses[tid] = status
                continue
            try:
                self._handle_status(tracee, status, new_tid)
            except Exception as e:
                logger.exception("couldn't handle thread %d", tid)
                self._lost(e)
                return
        self._check_all_stopped()

    def _lost(self, exc: BaseException) -> None:
        tracer = self._tracer
        if tracer is not None:
            promises = [self._stop_all_promise, self._detach_promise]
            self._detach_promise = None
            try:
                self._detach_all()
            except Exception:
                logger.warning("couldn't detach", exc_info=True)
            self._close()
            for promise in promises:
                if promise is not None:
                    promise.set_exception(exc)
            self._prog.notify_program_lost(exc)

    def _handle_status(self, tracee: _Tracee, status: int, new_tid: int) -> None:
        logger.debug("thread %d: status %#x", tracee.tid, status)
        if not os.WIFSTOPPED(status):
            self._handle_exit(tracee, status)
            return

        tracee.stopped = True
        tracee.regs = None
        requested = tracee.stop_requested
        tracee.stop_requested = False
        sig = os.WSTOPSIG(status)
        event = status >> 16
        if event == PtraceEvent.STOP and sig in _STOP_SIGNALS:
            # Group-stop. Let the thread stay stopped like it would if we
            # weren't here.
            tracee.stopped = False
            tracee.stop_requested = requested
            self._get_tracer().ptrace(PtraceRequest.LISTEN, tracee.tid)
        elif event == PtraceEvent.STOP:
            # This is either because of PTRACE_INTERRUPT or it is the first
            # stop of a new thread.
            if tracee.new:
                tracee.new = False
                self._stopped_quietly(tracee, self._hold)
            else:
                # If we didn't ask for this, then we did before the thread
                # stopped for another reason, and it has been resumed since
                # then.
                self._stopped_quietly(tracee, requested)
        elif event:
            if new_tid and new_tid not in self._tracees:
                new_tracee = _Tracee(self._prog.thread(new_tid))
                new_tracee.new = True
                self._tracees[new_tid] = new_tracee
                early_status = self._early_statuses.pop(new_tid, None)
                if early_status is not None:
                    self._handle_status(new_tracee, early_status, 0)
            self._stopped_quietly(tracee, requested)
        elif sig == tracee.passthrough_sig:
            tracee.passthrough_sig = 0
            tracee.stop_sig = sig
            tracee.forced_sig = sig
            self._stopped_quietly(tracee, requested)
        elif sig == signal.SIGTRAP:
            self._handle_sigtrap(tracee, requested)
        else:
            tracee.stop_sig = sig
            tracee.pending_sig = sig
            self._report_stop(tracee, sig)

    def _handle_sigtrap(self, tracee: _Tracee, requested: bool) -> None:
        tracee.stop_sig = signal.SIGTRAP
        siginfo = siginfo_t()
        self._get_tracer().ptrace_get(PtraceRequest.GETSIGINFO, tracee.tid, siginfo)
        if siginfo.si_code == _TRAP_TRACE:
            self._report_stop(tracee, signal.SIGTRAP, drgn.StepStopReason)
            return
        if siginfo.si_code in (_SI_KERNEL, _TRAP_BRKPT):
            # The program counter is after the breakpoint instruction.
            address = self._regs(tracee).rip - len(_BREAKPOINT_INSTRUCTION)
            if address in self._breakpoints:
                self._set_pc(tracee, address)
                self._report_stop(tracee, signal.SIGTRAP, drgn.BreakpointStopReason)
                return
            try:
                instruction = os.pread(
                    self._mem_fd, len(_BREAKPOINT_INSTRUCTION), address
                )
            except OSError:
                instruction = b""
            if instruction != _BREAKPOINT_INSTRUCTION:
                # The thread hit one of our breakpoints right before we
                # removed it. Run the instruction that was there.
                self._set_pc(tracee, address)
                tracee.stop_sig = 0
                self._stopped_quietly(tracee, requested)
                return
        # The program has its own breakpoint instruction, or it was sent
        # SIGTRAP.
        tracee.pending_sig = signal.SIGTRAP
        self._report_stop(tracee, signal.SIGTRAP, drgn.SignalStopReason)

    def _report_stop(
        self, tracee: _Tracee, sig: int, reason: Optional[type] = None
    ) -> None:
        tracee.user_interrupt = False
        if self._detach_promise is not None:
            # The program doesn't want to know anymore.
            return
        tracee.reported = True
        # This can call back into us.
        self._prog.notify_thread_stop(
            tracee.thread, sig, self._regs(tracee).rip, reasons=reason
        )

    def _handle_exit(self, tracee: _Tracee, status: int) -> None:
        if os.WIFEXITED(status):
            status = os.WEXITSTATUS(status)
        elif os.WIFSIGNALED(status):
            status = -os.WTERMSIG(status)
        del self._tracees[tracee.tid]
        # The exit status of the process is the exit status of the thread
        # group leader, which is always the last one to be reported.
        if tracee.tid == self._pid or self._exit_status is None:
            self._exit_status = status
        if self._detach_promise is None:
            self._prog.notify_thread_exit(tracee.thread, status)
        if not self._tracees:
            promises = [self._stop_all_promise, self._detach_promise]
            detaching = self._detach_promise is not None
            self._detach_promise = None
            self._close()
            if not detaching:
                self._prog.notify_program_exit(self._exit_status)
            for promise in promises:
                if promise is not None:
                    promise.set_result(None)

    def _check_all_stopped(self) -> None:
        if self._tracer is None or not all(
            tracee.stopped for tracee in self._tracees.values()
        ):
            return
        if self._detach_promise is not None:
            self._finish_detaching()
        elif self._stop_all_promise is not None:
            promise = self._stop_all_promise
            self._stop_all_promise = None
            promise.set_result(None)

    # ExecutionController

    def attach(
        self, prog: drgn.Program, flags: drgn.AttachFlags, promise: "drgn.Promise[bool]"
    ) -> None:
        try:
            tracer = self._open(prog.main_thread().tid)
            try:
                self._seize_threads(tracer)
            except BaseException:
                try:
                    self._tracer = tracer
                    self._detach_all()
                finally:
                    self._close()
                raise
        except Exception as e:
            promise.set_exception(e)
            return
        promise.set_result(not (flags & drgn.AttachFlags.NON_STOP))
        if flags & drgn.AttachFlags.INTERRUPT:
            self._interrupt_any_thread()

    def detach(self, prog: drgn.Program, promise: "drgn.Promise[None]") -> None:
        if self._tracer is None:
            promise.set_result(None)
            return
        # Threads have to be stopped to be detached.
        self._detach_promise = promise
        try:
            for tracee in self._tracees.values():
                self._interrupt(tracee)
        except Exception as e:
            self._detach_promise = None
            promise.set_exception(e)
            return
        self._handle_statuses()

    def _finish_detaching(self) -> None:
        promise = self._detach_promise
        assert promise is not None
        self._detach_promise = None
        try:
            self._detach_all()
        except Exception as e:
            promise.set_exception(e)
            return
        self._close()
        promise.set_result(None)

    def _detach_all(self) -> None:
        tracer = self._get_tracer()
        # The breakpoints can't be removed until every thread is stopped and
        # past them.
        tracer.stop_all(set(self._breakpoints))
        for address, instruction in self._breakpoints.items():
            os.pwrite(self._mem_fd, instruction, address)
        self._breakpoints.clear()
        tracer.detach_all(
            {
                tracee.tid: tracee.forced_sig or tracee.pending_sig
                for tracee in self._tracees.values()
            }
        )

    def interrupt_thread(
        self, thread: drgn.Thread, promise: "drgn.Promise[None]"
    ) -> None:
        try:
            tracee = self._tracee(thread)
            if not tracee.stopped:
                tracee.user_interrupt = True
                self._interrupt(tracee)
        except Exception as e:
            promise.set_exception(e)
        else:
            promise.set_result(None)

    def _interrupt_any_thread(self) -> None:
        for tracee in self._tracees.values():
            if self._interrupt(tracee):
                tracee.user_interrupt = True
                break

    def interrupt_any_thread(
        self, prog: drgn.Program, promise: "drgn.Promise[None]"
    ) -> None:
        try:
            self._interrupt_any_thread()
        except Exception as e:
            promise.set_exception(e)
        else:
            promise.set_result(None)

    def stop_all_threads(
        self, prog: drgn.Program, promise: "drgn.Promise[None]"
    ) -> None:
        try:
            self._hold = True
            for tracee in self._tracees.values():
                self._interrupt(tracee)
        except Exception as e:
            promise.set_exception(e)
            return
        self._stop_all_promise = promise
        self._check_all_stopped()

    def resume_threads(
        self,
        prog: drgn.Program,
        actions: Sequence[drgn.ResumeAction],
        promise: "drgn.Promise[None]",
    ) -> None:
        try:
            tids = set()
            resume_all = False
            for action in actions:
                if action.thread is None:
                    resume_all = True
                    continue
                tids.add(action.thread.tid)
                tracee = self._tracees.get(action.thread.tid)
                # If we don't know about the thread, then it exited.
                if tracee is not None and not isinstance(action, drgn.StopResumeAction):
                    self._resume(
                        tracee, isinstance(action, drgn.StepiResumeAction), action.sig
                    )
            if resume_all:
                self._hold = False
                for tracee in list(self._tracees.values()):
                    if tracee.tid not in tids:
                        # The program wants the default action for a thread
                        # that it knows is stopped. For any other thread,
                        # we have to decide.
                        self._resume(tracee, False, 0 if tracee.reported else None)
        except Exception as e:
            promise.set_exception(e)
        else:
            promise.set_result(None)

    def enable_breakpoint_sites(
        self, sites: Sequence[drgn.BreakpointSite], promise: "drgn.Promise[None]"
    ) -> None:
        done: List[drgn.BreakpointSite] = []
        try:
            for site in sites:
                if site.hardware:
                    raise NotImplementedError("hardware breakpoints are not supported")
                instruction = os.pread(
                    self._mem_fd, len(_BREAKPOINT_INSTRUCTION), site.address
                )
                if len(instruction) != len(_BREAKPOINT_INSTRUCTION):
                    raise drgn.FaultError("could not read memory", site.address)
                os.pwrite(self._mem_fd, _BREAKPOINT_INSTRUCTION, site.address)
                self._breakpoints[site.address] = instruction
                done.append(site)
        except Exception as e:
            for site in done:
                try:
                    os.pwrite(
                        self._mem_fd,
                        self._breakpoints.pop(site.address),
                        site.address,
                    )
                except OSError:
                    logger.warning(
                        "couldn't remove breakpoint at 0x%x after error",
                        site.address,
                        exc_info=True,
                    )
            promise.set_exception(e)
        else:
            promise.set_result(None)

    def disable_breakpoint_sites(
        self, sites: Sequence[drgn.BreakpointSite], promise: "drgn.Promise[None]"
    ) -> None:
        done = []
        try:
            for site in sites:
                instruction = self._breakpoints.get(site.address)
                # If the process exited, then there is nothing to do.
                if instruction is not None and self._tracer is not None:
                    os.pwrite(self._mem_fd, instruction, site.address)
                    del self._breakpoints[site.address]
                    done.append((site, instruction))
        except Exception as e:
            for site, instruction in done:
                try:
                    os.pwrite(self._mem_fd, _BREAKPOINT_INSTRUCTION, site.address)
                    self._breakpoints[site.address] = instruction
                except OSError:
                    logger.warning(
                        "couldn't restore breakpoint at 0x%x after error",
                        site.address,
                        exc_info=True,
                    )
            promise.set_exception(e)
        else:
            promise.set_result(None)


def register(prog: drgn.Program) -> PtraceExecutionController:
    """
    Register and enable an execution controller for a userspace process on
    x86-64 Linux.

    :param prog: Program set up with :meth:`drgn.Program.set_pid()`.
    """
    if prog.platform is None or prog.platform.arch != drgn.Architecture.X86_64:
        raise ValueError("only x86-64 is supported")
    if (prog.flags & drgn.ProgramFlags.IS_LINUX_KERNEL) or not (
        prog.flags & drgn.ProgramFlags.IS_LIVE
    ):
        raise ValueError("only running userspace processes are supported")
    controller = PtraceExecutionController(prog)
    prog.register_execution_controller("ptrace", controller, enable_index=0)
    prog.register_register_state_finder(
        "ptrace", controller._find_register_state, enable_index=0
    )
    return controller


if __name__ == "__main__":
    from drgn.cli import run_interactive

    register(prog)
    run_interactive(prog)
