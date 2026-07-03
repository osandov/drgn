# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import collections
import ctypes
import dataclasses
import enum
import os
import signal

from _drgn_util.platform import SYS
import drgn
from drgn import Event, ExecutionController, Program

_WNOTHREAD = 0x20000000
_WALL = 0x40000000
_WCLONE = 0x80000000

_c = ctypes.CDLL(None, use_errno=True)

_tgkill = _c.tgkill
_tgkill.restype = ctypes.c_int
_tgkill.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]

_ptrace = _c.ptrace
_ptrace.restype = ctypes.c_long
_ptrace.argtypes = [ctypes.c_int, ctypes.c_int]

_syscall = _c.syscall
_syscall.restype = ctypes.c_long
_syscall.argtypes = [ctypes.c_long]


def _check_ctypes_syscall(ret, *args):
    if ret == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno), *args)
    return ret


def tgkill(tgid: int, tid: int, sig: int) -> None:
    _check_ctypes_syscall(_tgkill(tgid, tid, sig))


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


class PtraceRequest(enum.IntEnum):
    TRACEME = 0
    PEEKTEXT = 1
    PEEKDATA = 2
    PEEKUSR = 3
    POKETEXT = 4
    POKEDATA = 5
    POKEUSR = 6
    CONT = 7
    KILL = 8
    SINGLESTEP = 9
    ATTACH = 16
    DETACH = 17
    SYSCALL = 24
    SETOPTIONS = 0x4200
    GETEVENTMSG = 0x4201
    GETSIGINFO = 0x4202
    SETSIGINFO = 0x4203
    GETREGSET = 0x4204
    SETREGSET = 0x4205
    SEIZE = 0x4206
    INTERRUPT = 0x4207
    LISTEN = 0x4208
    PEEKSIGINFO = 0x4209
    GETSIGMASK = 0x420A
    SETSIGMASK = 0x420B
    SECCOMP_GET_FILTER = 0x420C
    SECCOMP_GET_METADATA = 0x420D
    GET_SYSCALL_INFO = 0x420E
    SET_SYSCALL_INFO = 0x4212
    GET_RSEQ_CONFIGURATION = 0x420F
    SET_SYSCALL_USER_DISPATCH_CONFIG = 0x4210
    GET_SYSCALL_USER_DISPATCH_CONFIG = 0x4211


class PtraceEvent(enum.IntEnum):
    FORK = 1
    VFORK = 2
    CLONE = 3
    EXEC = 4
    VFORK_DONE = 5
    EXIT = 6
    SECCOMP = 7
    STOP = 128


class PtraceOption(enum.IntFlag):
    TRACESYSGOOD = 1
    TRACEFORK = 1 << PtraceEvent.FORK
    TRACEVFORK = 1 << PtraceEvent.VFORK
    TRACECLONE = 1 << PtraceEvent.CLONE
    TRACEEXEC = 1 << PtraceEvent.EXEC
    TRACEVFORKDONE = 1 << PtraceEvent.VFORK_DONE
    TRACEEXIT = 1 << PtraceEvent.EXIT
    TRACESECCOMP = 1 << PtraceEvent.SECCOMP
    EXITKILL = 1 << 20
    SUSPEND_SECCOMP = 1 << 21


def ptrace(op: PtraceRequest, pid: int, addr: int = 0, data: int = 0) -> None:
    _check_ctypes_syscall(_ptrace(op, pid, ctypes.c_ulong(addr), ctypes.c_ulong(data)))


def ptrace_geteventmsg(pid: int) -> int:
    data = ctypes.c_ulong()
    _check_ctypes_syscall(_ptrace(op, pid, ctypes.c_ulong(0), ctypes.byref(data)))
    return data.value


def ptrace_getsiginfo(pid: int):
    siginfo = siginfo_t()
    _check_ctypes_syscall(
        _ptrace(PtraceRequest.GETSIGINFO, pid, ctypes.c_ulong(0), ctypes.byref(siginfo))
    )
    return siginfo


class _perf_event_attr_sample_period_or_freq(ctypes.Union):
    _fields_ = (
        ("sample_period", ctypes.c_uint64),
        ("sample_freq", ctypes.c_uint64),
    )


class _perf_event_attr_wakeup_events_or_watermark(ctypes.Union):
    _fields_ = (
        ("wakeup_events", ctypes.c_uint32),
        ("wakeup_watermark", ctypes.c_uint32),
    )


class _perf_event_attr_config1(ctypes.Union):
    _fields_ = (
        ("bp_addr", ctypes.c_uint64),
        ("kprobe_func", ctypes.c_uint64),
        ("uprobe_path", ctypes.c_uint64),
        ("config1", ctypes.c_uint64),
    )


class _perf_event_attr_config2(ctypes.Union):
    _fields_ = (
        ("bp_len", ctypes.c_uint64),
        ("kprobe_addr", ctypes.c_uint64),
        ("probe_offset", ctypes.c_uint64),
        ("config2", ctypes.c_uint64),
    )


class perf_event_attr(ctypes.Structure):
    _fields_ = (
        ("type", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("config", ctypes.c_uint64),
        ("_sample_period_or_freq", _perf_event_attr_sample_period_or_freq),
        ("sample_type", ctypes.c_uint64),
        ("read_format", ctypes.c_uint64),
        ("_bitfields1", ctypes.c_uint64),
        ("_wakeup_events_or_watermark", _perf_event_attr_wakeup_events_or_watermark),
        ("bp_type", ctypes.c_uint32),
        ("_config1", _perf_event_attr_config1),
        ("_config2", _perf_event_attr_config2),
        ("branch_sample_type", ctypes.c_uint64),
        ("sample_regs_user", ctypes.c_uint64),
        ("sample_stack_user", ctypes.c_uint32),
        ("clockid", ctypes.c_int32),
        ("sample_regs_intr", ctypes.c_uint64),
        ("aux_watermark", ctypes.c_uint32),
        ("sample_max_stack", ctypes.c_uint16),
        ("__reserved2", ctypes.c_uint16),
        ("aux_sample_size", ctypes.c_uint32),
        ("__reserved3", ctypes.c_uint32),
        ("sig_data", ctypes.c_uint64),
        ("config3", ctypes.c_uint64),
    )
    _anonymous_ = (
        "_sample_period_or_freq",
        "_wakeup_events_or_watermark",
        "_config1",
        "_config2",
    )


PERF_FLAG_FD_NO_GROUP = 1 << 0
PERF_FLAG_FD_OUTPUT = 1 << 1
PERF_FLAG_PID_CGROUP = 1 << 2
PERF_FLAG_FD_CLOEXEC = 1 << 3


def perf_event_open(attr, pid, cpu, group_fd=-1, flags=PERF_FLAG_FD_CLOEXEC):
    attr.size = ctypes.sizeof(perf_event_attr)
    return _check_ctypes_syscall(
        _syscall(
            SYS["perf_event_open"],
            ctypes.byref(attr),
            ctypes.c_int(pid),
            ctypes.c_int(cpu),
            ctypes.c_int(group_fd),
            ctypes.c_ulong(flags),
        )
    )


class _sifields_sigfault_perf(ctypes.Structure):
    _fields_ = (
        ("_data", ctypes.c_ulong),
        ("_type", ctypes.c_uint32),
        ("_flags", ctypes.c_uint32),
    )


class _sifields_sigfault_union(ctypes.Union):
    _fields_ = (("_perf", _sifields_sigfault_perf),)


class _sifields_sigfault(ctypes.Structure):
    _fields_ = (
        ("addr", ctypes.c_void_p),
        ("_union", _sifields_sigfault_union),
    )
    _anonymous_ = ("_union",)


class _sifields(ctypes.Union):
    _fields_ = (("_sigfault", _sifields_sigfault),)


class _siginfo_struct(ctypes.Structure):
    _fields_ = (
        ("si_signo", ctypes.c_int),
        ("si_errno", ctypes.c_int),
        ("si_code", ctypes.c_int),
        ("_sifields", _sifields),
    )


class siginfo_t(ctypes.Structure):
    _fields_ = (
        ("_struct", _siginfo_struct),
        ("_si_pad", ctypes.c_int * 32),
    )
    _anonymous_ = ("_struct",)


class PtraceExecutionController(ExecutionController):
    def __init__(self) -> None:
        self._tracees = {}
        self._ptrace_stopped = set()
        self._all_stopping_events = {}

    # TODO: pass attach flags instead?
    def attach(self, prog: Program, flags: drgn.AttachFlags) -> bool:
        all_stop = bool(flags & drgn.AttachFlags.NON_STOP)
        self._pid = prog.main_thread().tid
        for thread in prog.threads():
            try:
                ptrace(PtraceRequest.SEIZE, thread.tid, 0, PtraceOption.TRACECLONE)
            except ProcessLookupError:
                # Raced with thread exit.
                continue
            self._tracees[thread.tid] = thread
        # TODO: do we even want this?
        if flags & drgn.AttachFlags.INTERRUPT:
            self.interrupt_any_thread()
        return all_stop

    def detach(self, prog: Program) -> None:
        for thread in self._tracees.values():
            try:
                ptrace(PtraceRequest.DETACH, thread.tid)
            except ProcessLookupError:
                # TODO: threads need to be stopped???
                pass

    def interrupt_thread(self, thread: Thread) -> None:
        tgkill(self._pid, thread.tid, signal.SIGINT)

    def interrupt_any_thread(self, prog: Program) -> None:
        # Note: guarantee is we get at least one ThreadSignalEvent or
        # ProgramExitEvent after this (not necessarily for a specific signal,
        # could be BreakpointEvent, could be another intervening signal or
        # not).
        os.kill(self._pid, signal.SIGINT)

    def resume_all_threads(
        self, prog: Program, threads: Sequence[Tuple[Thread, int]]
    ) -> None:
        self.resume_only_threads(prog, threads)
        for thread in self._ptrace_stopped:
            ptrace(PtraceRequest.CONT, thread.tid, 0, 0)
        self._ptrace_stopped.clear()

    def resume_only_threads(
        self, prog: Program, threads: Sequence[Tuple[Thread, int]]
    ) -> None:
        for thread, sig in threads:
            ptrace(PtraceRequest.CONT, thread.tid, 0, sig)
            self._ptrace_stopped.remove(thread)

    def set_breakpoint_site(
        self, site: drgn.BreakpointSite, hardware: Optional[bool]
    ) -> bool:
        assert hardware is None or hardware
        thread_fds = {}
        try:
            for tid in self._tracees:
                attr = perf_event_attr()
                attr.type = 5  # PERF_TYPE_BREAKPOINT
                attr.bp_type = 4  # HW_BREAKPOINT_X
                attr.bp_addr = site.address
                attr.bp_len = ctypes.sizeof(ctypes.c_long)  # TODO: only on x86?
                attr.sample_period = 1
                # TODO: define these as bitfields in ctypes
                attr._bitfields1 = (
                    (1 << 5)  # exclude_kernel
                    | (1 << 6)  # exclude_hv
                    | (1 << 36)  # remove_on_exec
                    | (1 << 37)  # sigtrap
                )
                fd = perf_event_open(attr, tid, -1)
                thread_fds[tid] = fd
        except BaseException:
            for fd in thread_fds.values():
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise
        site._controller_data = thread_fds
        return True

    def remove_breakpoint_site(self, site: drgn.BreakpointSite) -> None:
        for fd in site._controller_data.values():
            try:
                os.close(fd)
            except OSError:
                pass

    def queue_events(self, prog: Program, block: bool) -> Event:
        while True:
            pid, wstatus = os.waitpid(-1, (0 if block else os.WNOHANG) | _WALL)
            if pid == 0:
                return
            if os.WIFSTOPPED(wstatus):
                try:
                    thread = self._tracees[pid]
                except KeyError:
                    assert False, "TODO"
                    thread = prog.thread(pid)
                    self._tracees[pid] = thread
                    if wstatus >> 8 == (PtraceEvent.STOP << 8) | signal.SIGTRAP:
                        # Initial ptrace-stop of new thread.
                        # TODO: thread creation event?
                        # TODO: install breakpoints.
                        ptrace(PtraceRequest.CONT, pid, 0, 0)
                        continue
                else:
                    if wstatus >> 8 == (PtraceEvent.CLONE << 8) | signal.SIGTRAP:
                        # PTRACE_EVENT_CLONE stop of parent thread.
                        ptrace(PtraceRequest.CONT, pid, 0, 0)
                        continue

                if (
                    wstatus >> 8 == signal.SIGTRAP
                    and (siginfo := ptrace_getsiginfo(pid)).si_code == 6
                ):  # TRAP_PERF
                    event = drgn.BreakpointEvent(
                        thread,
                        signal.SIGTRAP,
                        prog.breakpoint_site(siginfo._sifields._sigfault.addr),
                    )
                elif wstatus >> 8 == (PtraceEvent.STOP << 8) | signal.SIGTRAP:
                    if not self._all_stopping_events:
                        # PTRACE_INTERRUPT must have arrived after the thread
                        # stopped for another reason. Ignore it.
                        continue
                    event = None
                else:
                    event = drgn.ThreadSignalEvent(thread, os.WSTOPSIG(wstatus))

                self._ptrace_stopped.add(thread)
                if prog.all_stop:
                    if not self._all_stopping_events:
                        for tracee_tid in self._tracees:
                            if tracee_tid != pid:
                                ptrace(PtraceRequest.INTERRUPT, tracee_tid)
                    self._all_stopping_events[thread] = event
                    if len(self._ptrace_stopped) < len(self._tracees):
                        continue
                    for thread, event in self._all_stopping_events.items():
                        if event is not None:
                            prog.queue_event(event)
                    self._all_stopping_events.clear()
                else:
                    prog.queue_event(event)
            elif os.WIFEXITED(wstatus) or os.WIFSIGNALED(wstatus):
                status = (
                    os.WEXITSTATUS(wstatus)
                    if os.WIFEXITED(wstatus)
                    else -os.WTERMSIG(wstatus)
                )
                try:
                    thread = self._tracees.pop(pid)
                except KeyError:
                    continue
                self._ptrace_stopped.discard(thread)
                # TODO: _all_stopping_events?
                prog.queue_event(drgn.ThreadExitEvent(thread, status))
                if not self._tracees:
                    # Main thread exit event always comes last.
                    prog.queue_event(drgn.ProgramExitEvent(status))
            else:
                assert False, f"Unknown wstatus {hex(wstatus)} from thread {pid}"
            break


def ptrace_register_state(thread: Thread) -> Optional[RegisterState]:
    thread.prog.sync_events()
    if not thread.stopped():
        return None  # TODO: error with more information?

    regs_struct = user_regs_struct()
    try:
        _check_ctypes_syscall(
            _ptrace(12, thread.tid, ctypes.c_ulong(0), ctypes.byref(regs_struct))
        )
    except ProcessLookupError:
        return None

    regs = drgn.RegisterState(thread.prog, interrupted=True)
    for reg in (
        "rax",
        "rdx",
        "rcx",
        "rbx",
        "rsi",
        "rdi",
        "rbp",
        "rsp",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
        "rip",
        "es",
        "cs",
        "ss",
        "ds",
        "fs",
        "gs",
    ):
        regs.set(reg, getattr(regs_struct, reg))
    regs.set("rflags", regs_struct.eflags)
    regs.set("fs.base", regs_struct.fs_base)
    regs.set("gs.base", regs_struct.gs_base)
    regs.pc = regs_struct.rip
    return regs


def decode_wstatus(wstatus):
    if os.WIFEXITED(wstatus):
        return f"EXITED with {os.WEXITSTATUS(wstatus)}"
    if os.WIFSIGNALED(wstatus):
        sig = signal.Signals(os.WTERMSIG(wstatus)).name
        return f"SIGNALED with {sig}"
    elif os.WIFSTOPPED(wstatus):
        sig = signal.Signals(os.WSTOPSIG(wstatus)).name
        for event in PtraceEvent:
            if wstatus & (event.value << 16):
                return f"STOPPED with {sig} (PTRACE_EVENT_{event.name})"
        return f"STOPPED with {sig}"
    else:
        assert False


if __name__ == "__main__":
    # import time
    # import sys
    # pid = int(sys.argv[1])
    # ptrace(PtraceRequest.SEIZE, pid, 0, PtraceOption(0))

    # os.kill(pid, signal.SIGINT)
    # _, wstatus = os.waitpid(-1, _WALL)
    # print(decode_wstatus(wstatus))

    controller = PtraceExecutionController()
    prog.register_execution_controller("ptrace", controller, enable_index=0)
    prog.register_register_state_finder("ptrace", ptrace_register_state, enable_index=0)
    prog.attach(all_stop=False)

    thread = prog.main_thread()
    thread.interrupt()
    while True:
        event = prog.get_event()
        print(event)
        if isinstance(event, drgn.ProgramExitedError):
            break
        if isinstance(event, drgn.ThreadSignalEvent):
            if event.thread != thread:
                event.thread.resume()
                continue
            event.thread.resume(sig=signal.SIGUSR1)

    # prog.set_breakpoint(prog.symbol("drgn_object_copy").address)

    # while True:
    #     event = prog.get_event()
    #     print(event)

    #     if isinstance(event, drgn.BreakpointEvent):
    #         print(event.thread.stack_trace())

    #     if isinstance(event, drgn.ThreadSignalEvent):
    #         input("> ")
    #         event.thread.resume()
