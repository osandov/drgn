# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Execution controller for breakpoints on the running Linux kernel on x86-64
using the ``drgn_breakpoint`` kernel module (see ``drgn_breakpoint/``).

Load the module, set up the program for the running kernel (e.g., with
:meth:`drgn.Program.set_kernel()` or ``drgn -k``), and then call
:func:`register()`.

A breakpoint is a kprobe that diverts the thread that hit it to code in the
module that can sleep, which it does until it is told to continue. This finds
out about it by reading from the module's device, ``/dev/drgn_breakpoint``.

Since the debugger is running on the kernel that it is debugging:

* Only the thread that hit a breakpoint stops, so this only supports non-stop
  mode.
* Threads can't be interrupted or stepped. They can only stop at breakpoints.
* A thread only stops at a breakpoint if it can sleep there. In particular, it
  doesn't if it has interrupts or preemption disabled. :meth:`stats()` returns
  how many times that happened.
* Threads of a process that is using the module never stop.
* A thread that is killed while it is stopped is reported as having exited.
* Only software breakpoints are supported, and only where the kernel allows
  kprobes.
* There are no signals. Signals passed when resuming are ignored.
* Two debuggers can't have a breakpoint at the same address.

If the debugger exits without detaching, then the breakpoints are removed and
any stopped threads carry on, unless another process inherited the debugger's
file descriptor for the device, in which case that doesn't happen until that
process closes it.
"""

import errno
import fcntl
import logging
import os
import signal
import struct
from typing import Dict, NamedTuple, Optional, Sequence, Tuple

import drgn

logger = logging.getLogger("drgn.kprobe")

DEVICE_PATH = "/dev/drgn_breakpoint"

# These match drgn_breakpoint/drgn_breakpoint.h.
_IOC_WRITE = 1
_IOC_READ = 2


def _IOC(direction: int, nr: int, size: int) -> int:
    return (direction << 30) | (size << 16) | (0xDB << 8) | nr


_ADDRESS_STRUCT = struct.Struct("=Q")
# struct drgn_breakpoint_add
_ADD_STRUCT = struct.Struct("=QII")
_STATS_STRUCT = struct.Struct("=QQQ")
_TID_STRUCT = struct.Struct("=I")
# struct drgn_breakpoint_event up to regs.
_EVENT_STRUCT = struct.Struct("=IIIIQ")

_ADD = _IOC(_IOC_WRITE, 0, _ADD_STRUCT.size)
_REMOVE = _IOC(_IOC_WRITE, 1, _ADDRESS_STRUCT.size)
_GET_STATS = _IOC(_IOC_READ | _IOC_WRITE, 2, _STATS_STRUCT.size)
_RESUME = _IOC(_IOC_WRITE, 3, _TID_STRUCT.size)
_DETACH = _IOC(0, 4, 0)

_ATOMIC = 1 << 0

_EVENT_STOPPED = 0
_EVENT_KILLED = 1

# struct pt_regs.
_PT_REGS_STRUCT = struct.Struct("=21Q")
_PT_REGS_REGISTERS = (
    "r15",
    "r14",
    "r13",
    "r12",
    "rbp",
    "rbx",
    "r11",
    "r10",
    "r9",
    "r8",
    "rax",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    None,  # orig_rax
    "rip",
    "cs",
    "rflags",
    "rsp",
    "ss",
)


class BreakpointStats(NamedTuple):
    hits: int
    """Number of times that a thread stopped at the breakpoint."""
    skipped: int
    """
    Number of times that a thread got to the breakpoint but didn't stop
    because it couldn't.
    """


class BreakpointOptions(NamedTuple):
    tid: int = 0
    """If not 0, the only thread that stops, by thread ID."""
    atomic: bool = False
    """
    Stop even if the thread can't sleep (unless it is handling an interrupt).
    This is for holding a thread in the middle of a race.

    In that case, the thread spins, so its CPU does nothing else until the
    thread is resumed. While any thread is doing that, breakpoints can't be
    added or removed.
    """


class _StoppedThread:
    def __init__(self, thread: drgn.Thread, regs: Tuple[int, ...]) -> None:
        self.thread = thread
        self.regs = regs


class KprobeExecutionController(drgn.ExecutionController):
    def __init__(self, prog: drgn.Program) -> None:
        super().__init__()
        self._prog = prog
        self._device = -1
        # Stopped threads by thread ID.
        self._stopped: Dict[int, _StoppedThread] = {}
        # Enabled sites by address.
        self._sites: Dict[int, drgn.BreakpointSite] = {}
        self.options: Dict[int, BreakpointOptions] = {}
        """
        Options for breakpoint sites by address. These apply when the site is
        enabled.
        """

    def _open(self) -> None:
        device = os.open(DEVICE_PATH, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            self._prog.register_fd(device, drgn.FdEvents.READ, self._on_events)
        except BaseException:
            os.close(device)
            raise
        self._device = device

    def _close(self) -> None:
        if self._device < 0:
            return
        try:
            # Closing it does this, too, but not if another process
            # inherited our file descriptor.
            fcntl.ioctl(self._device, _DETACH)
        finally:
            self._prog.unregister_fd(self._device)
            os.close(self._device)
            self._device = -1
            self._stopped.clear()
            self._sites.clear()

    def _check_attached(self) -> None:
        if self._device < 0:
            raise drgn.NotAttachedError("not attached to kernel")

    def _on_events(self, prog: drgn.Program, fd: int, events: drgn.FdEvents) -> None:
        while self._device >= 0:
            try:
                data = os.read(self._device, _EVENT_STRUCT.size + _PT_REGS_STRUCT.size)
            except BlockingIOError:
                break
            type, tid, cpu, _, address = _EVENT_STRUCT.unpack_from(data)
            if type == _EVENT_STOPPED:
                logger.debug(
                    "thread %d hit breakpoint at 0x%x on CPU %d", tid, address, cpu
                )
                try:
                    # If the breakpoint was removed since the thread hit it,
                    # then nobody wants to know.
                    site = self._sites[address]
                    thread = prog.thread(tid)
                except LookupError as e:
                    if not isinstance(e, KeyError):
                        logger.warning("couldn't stop thread %d: %s", tid, e)
                    self._resume(tid)
                    continue
                self._stopped[tid] = _StoppedThread(
                    thread, _PT_REGS_STRUCT.unpack_from(data, _EVENT_STRUCT.size)
                )
                prog.notify_thread_breakpoint(thread, site)
            elif type == _EVENT_KILLED:
                logger.debug("thread %d was killed", tid)
                stopped = self._stopped.pop(tid, None)
                if stopped is not None:
                    prog.notify_thread_exit(stopped.thread, -signal.SIGKILL)

    def _add(self, address: int) -> None:
        options = self.options.get(address, BreakpointOptions())
        fcntl.ioctl(
            self._device,
            _ADD,
            _ADD_STRUCT.pack(address, _ATOMIC if options.atomic else 0, options.tid),
        )

    def _resume(self, tid: int) -> None:
        self._stopped.pop(tid, None)
        try:
            fcntl.ioctl(self._device, _RESUME, _TID_STRUCT.pack(tid))
        except ProcessLookupError:
            # It was killed, and we haven't been told yet.
            pass

    def _find_register_state(
        self, thread: drgn.Thread, is_last: bool
    ) -> Optional[drgn.RegisterState]:
        stopped = self._stopped.get(thread.tid)
        if stopped is None:
            return None
        regs = drgn.RegisterState(self._prog, True)
        for name, value in zip(_PT_REGS_REGISTERS, stopped.regs):
            if name is not None:
                regs.set(name, value)
            if name == "rip":
                regs.pc = value
        return regs

    def stats(self, address: int) -> BreakpointStats:
        """
        Get how many times the breakpoint site at an address has been hit
        since it was last enabled.
        """
        self._check_attached()
        _, hits, skipped = _STATS_STRUCT.unpack(
            fcntl.ioctl(self._device, _GET_STATS, _STATS_STRUCT.pack(address, 0, 0))
        )
        return BreakpointStats(hits, skipped)

    # ExecutionController

    def attach(
        self, prog: drgn.Program, flags: drgn.AttachFlags, promise: "drgn.Promise[bool]"
    ) -> None:
        try:
            if flags & drgn.AttachFlags.ALL_STOP:
                raise ValueError(
                    "the running kernel can only be debugged in non-stop mode"
                )
            if flags & drgn.AttachFlags.INTERRUPT:
                raise ValueError("the running kernel can't be interrupted")
            self._open()
        except Exception as e:
            promise.set_exception(e)
        else:
            promise.set_result(False)

    def detach(self, prog: drgn.Program, promise: "drgn.Promise[None]") -> None:
        try:
            self._close()
        except Exception as e:
            promise.set_exception(e)
        else:
            promise.set_result(None)

    def resume_threads(
        self,
        prog: drgn.Program,
        actions: Sequence[drgn.ResumeAction],
        promise: "drgn.Promise[None]",
    ) -> None:
        try:
            self._check_attached()
            resume = []
            for action in actions:
                if action.thread is None or isinstance(action, drgn.StopResumeAction):
                    continue
                if isinstance(action, drgn.StepiResumeAction):
                    raise NotImplementedError("stepping is not supported")
                if action.thread.tid in self._stopped:
                    resume.append(action.thread.tid)
            for tid in resume:
                self._resume(tid)
        except Exception as e:
            promise.set_exception(e)
        else:
            promise.set_result(None)

    def enable_breakpoint_sites(
        self, sites: Sequence[drgn.BreakpointSite], promise: "drgn.Promise[None]"
    ) -> None:
        done = []
        try:
            self._check_attached()
            for site in sites:
                if site.hardware:
                    raise NotImplementedError("hardware breakpoints are not supported")
                try:
                    self._add(site.address)
                except OSError as e:
                    if e.errno == errno.EBUSY:
                        raise ValueError(
                            f"can't set breakpoint at 0x{site.address:x}: "
                            "another debugger has one there, "
                            "or a thread is stopped where it can't sleep"
                        ) from None
                    if e.errno in (errno.EINVAL, errno.EILSEQ, errno.ENOENT):
                        raise ValueError(
                            f"can't set breakpoint at 0x{site.address:x}: "
                            "the kernel doesn't allow it there"
                        ) from None
                    raise
                # The kernel gets the thread past the breakpoint when it is
                # resumed.
                site.needs_step_over = False
                self._sites[site.address] = site
                done.append(site)
        except Exception as e:
            for site in done:
                del self._sites[site.address]
                try:
                    fcntl.ioctl(
                        self._device, _REMOVE, _ADDRESS_STRUCT.pack(site.address)
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
                # If we're not attached, then they're already gone.
                if site.address in self._sites and self._device >= 0:
                    fcntl.ioctl(
                        self._device, _REMOVE, _ADDRESS_STRUCT.pack(site.address)
                    )
                    del self._sites[site.address]
                    done.append(site)
        except Exception as e:
            for site in done:
                try:
                    self._add(site.address)
                    self._sites[site.address] = site
                except OSError:
                    logger.warning(
                        "couldn't restore breakpoint at 0x%x after error",
                        site.address,
                        exc_info=True,
                    )
            promise.set_exception(e)
        else:
            promise.set_result(None)


def register(prog: drgn.Program) -> KprobeExecutionController:
    """
    Register and enable an execution controller for the running Linux kernel
    on x86-64.

    :param prog: Program set up with :meth:`drgn.Program.set_kernel()`.
    """
    if prog.platform is None or prog.platform.arch != drgn.Architecture.X86_64:
        raise ValueError("only x86-64 is supported")
    flags = (
        drgn.ProgramFlags.IS_LINUX_KERNEL
        | drgn.ProgramFlags.IS_LIVE
        | drgn.ProgramFlags.IS_LOCAL
    )
    if (prog.flags & flags) != flags:
        raise ValueError("only the running Linux kernel is supported")
    controller = KprobeExecutionController(prog)
    prog.register_execution_controller("kprobe", controller, enable_index=0)
    prog.register_register_state_finder(
        "kprobe", controller._find_register_state, enable_index=0
    )
    return controller


if __name__ == "__main__":
    from drgn.cli import run_interactive

    register(prog)
    run_interactive(prog)
