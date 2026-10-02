# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Execution controllers for a Linux kernel on x86-64 using the GDB Remote Serial
Protocol to talk to either QEMU's GDB stub or the kernel's own stub, KGDB.

Set up the program for the kernel (e.g., with
:meth:`drgn.Program.set_qemu_qmp()` or ``drgn --qemu``) and then call
:func:`register()`.

For QEMU, run it with ``-gdb unix:/path/to/sock,server=on,wait=off`` (or
``-gdb tcp::1234``). For KGDB, boot the kernel with ``kgdboc=`` and connect to
the other end of that serial port.

Both stubs can only stop and resume all CPUs together, so:

* The program is always in all-stop mode.
* There are no signals. Stops are reported as ``SIGINT`` (interrupted) or
  ``SIGTRAP`` (breakpoint or step), and signals passed when resuming are
  ignored.
* Nothing can be done while the program is running other than what is noted
  below. Anything else fails with :class:`drgn.NotStoppedError`.

QEMU's stub has one "thread" per CPU:

* A stop on a CPU is reported for the task that is running on that CPU.
* Only a task that is running on a CPU can be stepped.
* The program can be interrupted and detached from while it is running.

KGDB's threads are tasks:

* Only the task that stopped can be stepped. No other CPUs run while it steps.
* KGDB can't be interrupted by the debugger. The kernel has to enter it by
  itself (e.g., a breakpoint, a panic, or ``echo g > /proc/sysrq-trigger``).
  This means that attaching waits until the kernel has entered KGDB, and
  detaching is not possible while the kernel is running.

Everything is driven by the program's event loop. Each operation is a *task*: a
generator that yields a request whenever it needs to wait for the stub and is
resumed with the reply. Tasks run one at a time in the order that they were
started so that their requests aren't interleaved.
"""

import collections
import errno
import logging
import re
import signal
import socket
import time
from typing import (
    Any,
    Callable,
    Deque,
    Dict,
    Generator,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

import drgn
from drgn.helpers.linux.sched import cpu_curr, idle_task, task_cpu

logger = logging.getLogger("drgn.gdb_rsp")

# How long to wait for the stub when something needs an answer synchronously.
_SYNC_TIMEOUT = 10.0
_MAX_RETRANSMITS = 3

# Registers at the beginning of the reply to a "g" packet for x86-64 and their
# sizes in bytes, in order. These are the same for every x86-64 stub. The
# registers after them (segment bases, control registers, floating point
# registers, etc.) depend on the target description, which we don't parse.
_X86_64_G_REGISTERS = (
    ("rax", 8),
    ("rbx", 8),
    ("rcx", 8),
    ("rdx", 8),
    ("rsi", 8),
    ("rdi", 8),
    ("rbp", 8),
    ("rsp", 8),
    ("r8", 8),
    ("r9", 8),
    ("r10", 8),
    ("r11", 8),
    ("r12", 8),
    ("r13", 8),
    ("r14", 8),
    ("r15", 8),
    ("rip", 8),
    ("rflags", 4),
    ("cs", 4),
    ("ss", 4),
    ("ds", 4),
    ("es", 4),
    ("fs", 4),
    ("gs", 4),
)
_X86_64_G_RIP_OFFSET = 16 * 8
_X86_64_G_RIP_NUMBER = 16
# KGDB doesn't return all of the registers above, but we at least need the
# ones up to the program counter.
_X86_64_G_REGISTERS_MIN_SIZE = _X86_64_G_RIP_OFFSET + 8

# The protocol has its own signal numbers. These are the ones that exist on
# Linux.
_GDB_SIGNALS = {
    1: signal.SIGHUP,
    2: signal.SIGINT,
    3: signal.SIGQUIT,
    4: signal.SIGILL,
    5: signal.SIGTRAP,
    6: signal.SIGABRT,
    8: signal.SIGFPE,
    9: signal.SIGKILL,
    10: signal.SIGBUS,
    11: signal.SIGSEGV,
    12: signal.SIGSYS,
    13: signal.SIGPIPE,
    14: signal.SIGALRM,
    15: signal.SIGTERM,
    16: signal.SIGURG,
    17: signal.SIGSTOP,
    18: signal.SIGTSTP,
    19: signal.SIGCONT,
    20: signal.SIGCHLD,
    21: signal.SIGTTIN,
    22: signal.SIGTTOU,
    23: signal.SIGIO,
    24: signal.SIGXCPU,
    25: signal.SIGXFSZ,
    26: signal.SIGVTALRM,
    27: signal.SIGPROF,
    28: signal.SIGWINCH,
    30: signal.SIGUSR1,
    31: signal.SIGUSR2,
    32: signal.SIGPWR,
}


class GdbRspError(Exception):
    """Error reported by or while talking to a GDB stub."""


class _Send:
    """Yielded by a task to send a packet and wait for it to be acknowledged."""

    def __init__(self, data: bytes) -> None:
        self.data = data


class _WaitForStop:
    """
    Yielded by a task to wait for the stop reply of a running program instead
    of it being reported.
    """


# A task yields bytes to send a packet and wait for the reply, which it is
# resumed with. It can also yield one of the above.
_Request = Union[bytes, _Send, _WaitForStop]
_Task = Generator[_Request, Any, Any]


class _RunningTask:
    def __init__(
        self,
        task: _Task,
        on_done: Callable[[Any], None],
        on_error: Callable[[BaseException], None],
    ) -> None:
        self.task = task
        self.on_done = on_done
        self.on_error = on_error
        # Packet that we're waiting for an acknowledgement of.
        self.unacked: Optional[bytes] = None
        self.retransmits = 0
        self.wants_reply = False
        self.wants_stop = False


def _escape(data: bytes) -> bytes:
    return re.sub(rb"[#$}*]", lambda match: b"}%c" % (match.group()[0] ^ 0x20), data)


def _unescape(data: bytes) -> bytes:
    if b"}" not in data and b"*" not in data:
        return data
    ret = bytearray()
    i = 0
    while i < len(data):
        c = data[i]
        i += 1
        if c == 0x7D and i < len(data):  # '}'
            ret.append(data[i] ^ 0x20)
            i += 1
        elif c == 0x2A and i < len(data) and ret:  # '*'
            ret.extend(ret[-1:] * (data[i] - 29))
            i += 1
        else:
            ret.append(c)
    return bytes(ret)


def _resolve_address(address: str) -> List[Tuple[int, Any]]:
    # This is the same format as drgn.Program.set_qemu_qmp().
    match = re.fullmatch(r"([^/.:][^:]*)?:([0-9]+)", address)
    if match and 1 <= int(match.group(2)) <= 65535:
        # Note that this blocks.
        return [
            (family, sockaddr)
            for family, _, _, _, sockaddr in socket.getaddrinfo(
                match.group(1) or "localhost",
                int(match.group(2)),
                type=socket.SOCK_STREAM,
            )
        ]
    return [(socket.AF_UNIX, address)]


def _parse_thread_id(thread_id: bytes) -> int:
    # QEMU always uses the multiprocess syntax (pPID.TID) even if we don't ask
    # for it. KGDB has negative thread IDs, which it sends as 32- or 64-bit
    # two's complement.
    value = int(thread_id.rpartition(b".")[2], 16)
    if value > 0x7FFFFFFF:
        value = (value & 0xFFFFFFFF) - 0x100000000
    return value


def _unexpected_reply(reply: bytes, what: str) -> GdbRspError:
    return GdbRspError(
        f"GDB stub returned {reply.decode(errors='replace')!r} for {what}"
    )


class GdbRspExecutionController(drgn.ExecutionController):
    """
    Common parts of the execution controllers. This can't be used by itself;
    see :class:`QemuGdbExecutionController` and
    :class:`KgdbExecutionController`.
    """

    def __init__(self, prog: drgn.Program, address: str) -> None:
        super().__init__()
        self._prog = prog
        self._address = address
        self._sock: Optional[socket.socket] = None
        self._connected = False
        # Whether we finished attaching.
        self._attached = False
        self._recv_buf = bytearray()
        self._send_buf = bytearray()
        self._fd_events = drgn.FdEvents(0)
        self._current: Optional[_RunningTask] = None
        self._queue: Deque[_RunningTask] = collections.deque()
        # Whether we resumed the program and haven't gotten a stop reply yet.
        self._running = False
        # Whether we sent an interrupt and haven't gotten a stop reply yet.
        self._interrupting = False
        # Stub's thread ID that was last selected for "g".
        self._g_thread_id: Optional[int] = None
        # Cached reply to "g" by the stub's thread ID. This is only valid
        # while stopped.
        self._registers: Dict[int, bytes] = {}
        # Stub's thread ID that last stopped.
        self._stop_thread_id: Optional[int] = None
        # Whether we last resumed the program by stepping.
        self._stepped = False
        # Addresses of software breakpoints that are in the program.
        self._software_breakpoints: Set[int] = set()

    # Connection

    def _open(
        self,
        addresses: List[Tuple[int, Any]],
        on_done: Callable[[], None],
        on_error: Callable[[BaseException], None],
    ) -> None:
        # Connect to the first address that works.
        family, address = addresses[0]
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.setblocking(False)
            if family != socket.AF_UNIX:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            err = sock.connect_ex(address)
        except BaseException:
            sock.close()
            raise

        def failed(err: int) -> None:
            self._close()
            if len(addresses) > 1:
                try:
                    self._open(addresses[1:], on_done, on_error)
                except Exception as e:
                    on_error(e)
            else:
                on_error(OSError(err, errno.errorcode.get(err, "unknown error")))

        def connected() -> None:
            self._connected = True
            self._set_fd_events()
            on_done()

        def on_writable(prog: drgn.Program, fd: int, events: drgn.FdEvents) -> None:
            err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err:
                failed(err)
            else:
                connected()

        self._sock = sock
        self._connected = False
        self._recv_buf.clear()
        self._send_buf.clear()
        self._running = False
        self._interrupting = False
        self._invalidate_registers()
        if err == 0:
            self._fd_events = drgn.FdEvents.READ
            self._prog.register_fd(sock.fileno(), self._fd_events, self._on_ready)
            connected()
        elif err == errno.EINPROGRESS:
            self._fd_events = drgn.FdEvents.WRITE
            self._prog.register_fd(sock.fileno(), self._fd_events, on_writable)
        else:
            self._sock = None
            sock.close()
            if len(addresses) > 1:
                self._open(addresses[1:], on_done, on_error)
            else:
                raise OSError(err, errno.errorcode.get(err, "unknown error"))

    def _close(self) -> None:
        # Close the connection. This doesn't do anything about tasks.
        sock = self._sock
        if sock is not None:
            self._sock = None
            self._connected = False
            self._attached = False
            self._recv_buf.clear()
            self._send_buf.clear()
            self._running = False
            self._interrupting = False
            self._invalidate_registers()
            self._prog.unregister_fd(sock.fileno())
            sock.close()

    def _fail_tasks(self, exc: BaseException, current: bool) -> None:
        tasks = list(self._queue)
        self._queue.clear()
        if current and self._current is not None:
            tasks.insert(0, self._current)
            self._current = None
        for running_task in tasks:
            running_task.task.close()
            running_task.on_error(exc)

    def _lost(self, exc: BaseException) -> None:
        if self._sock is not None:
            attached = self._attached
            self._close()
            self._fail_tasks(exc, True)
            # If we were still attaching, then attaching failed instead.
            if attached:
                self._prog.notify_program_lost(exc)

    def _set_fd_events(self) -> None:
        if self._sock is not None and self._connected:
            events = drgn.FdEvents.READ
            if self._send_buf:
                events |= drgn.FdEvents.WRITE
            if events != self._fd_events:
                self._fd_events = events
                self._prog.modify_fd(self._sock.fileno(), events, self._on_ready)

    def _write(self, data: bytes) -> None:
        # Send as much as we can and leave the rest for when the socket is
        # writable.
        assert self._sock is not None
        self._send_buf += data
        while self._send_buf:
            try:
                n = self._sock.send(self._send_buf)
            except (BlockingIOError, InterruptedError):
                break
            del self._send_buf[:n]
        self._set_fd_events()

    def _on_ready(self, prog: drgn.Program, fd: int, events: drgn.FdEvents) -> None:
        sock = self._sock
        if sock is None:
            return
        try:
            if self._send_buf:
                self._write(b"")
            # Note that this may be called recursively if something we call
            # polls the program, so we can't assume anything about the state
            # after calling anything outside of this class.
            while self._sock is sock:
                try:
                    data = sock.recv(65536)
                except (BlockingIOError, InterruptedError):
                    break
                if not data:
                    raise ConnectionError("GDB stub closed the connection")
                self._recv_buf += data
                self._process_input()
        except OSError as e:
            if self._sock is sock:
                self._lost(e)

    def _process_input(self) -> None:
        buf = self._recv_buf
        while buf and self._sock is not None:
            c = buf[0]
            if c == 0x2B:  # '+'
                del buf[0]
                self._handle_ack()
            elif c == 0x2D:  # '-'
                del buf[0]
                self._handle_nack()
            elif c == 0x24:  # '$'
                end = buf.find(b"#")
                if end < 0 or len(buf) < end + 3:
                    break
                data = bytes(buf[1:end])
                checksum = bytes(buf[end + 1 : end + 3])
                del buf[: end + 3]
                try:
                    valid = int(checksum, 16) == sum(data) % 256
                except ValueError:
                    valid = False
                if valid:
                    logger.debug("<- %r", data)
                    self._write(b"+")
                    self._handle_packet(_unescape(data))
                else:
                    logger.debug("<- %r (bad checksum %r)", data, checksum)
                    self._write(b"-")
            else:
                # Garbage.
                del buf[0]

    # Tasks

    def _start(
        self,
        task: _Task,
        on_done: Callable[[Any], None],
        on_error: Callable[[BaseException], None],
    ) -> None:
        self._queue.append(_RunningTask(task, on_done, on_error))
        self._run_tasks()

    def _run_tasks(self) -> None:
        while self._current is None and self._queue:
            self._current = self._queue.popleft()
            self._resume_task(None, None)

    def _resume_task(self, value: Any, exc: Optional[BaseException]) -> None:
        # Run the current task until it needs to wait for something or it
        # finishes.
        current = self._current
        assert current is not None
        current.unacked = None
        current.retransmits = 0
        current.wants_reply = False
        current.wants_stop = False
        try:
            if exc is None:
                request = current.task.send(value)
            else:
                request = current.task.throw(exc)
            if isinstance(request, _WaitForStop):
                current.wants_stop = True
                return
            if self._sock is None:
                raise drgn.NotAttachedError("not connected to GDB stub")
            if isinstance(request, _Send):
                data = request.data
            else:
                data = request
                current.wants_reply = True
            logger.debug("-> %r", data)
            data = _escape(data)
            current.unacked = b"$%b#%02x" % (data, sum(data) % 256)
            self._write(current.unacked)
        except StopIteration as e:
            self._current = None
            current.on_done(e.value)
        except OSError as e:
            if self._sock is not None:
                self._lost(e)
            else:
                self._current = None
                current.task.close()
                current.on_error(e)
        except Exception as e:
            self._current = None
            current.task.close()
            current.on_error(e)
        else:
            return
        self._run_tasks()

    def _run_sync(self, task: _Task) -> Any:
        # Run a task and wait for it to finish.
        result: List[Tuple[Any, Optional[BaseException]]] = []
        self._start(
            task,
            lambda value: result.append((value, None)),
            lambda exc: result.append((None, exc)),
        )
        deadline = time.monotonic() + _SYNC_TIMEOUT
        while not result:
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                raise GdbRspError("timed out waiting for GDB stub")
            self._prog.poll(timeout)
        value, exc = result[0]
        if exc is not None:
            raise exc
        return value

    def _handle_ack(self) -> None:
        current = self._current
        if current is not None and current.unacked is not None:
            current.unacked = None
            if not current.wants_reply:
                self._resume_task(None, None)

    def _handle_nack(self) -> None:
        current = self._current
        if current is not None and current.unacked is not None:
            if current.retransmits < _MAX_RETRANSMITS:
                current.retransmits += 1
                self._write(current.unacked)
            else:
                self._resume_task(None, GdbRspError("GDB stub did not accept packet"))

    def _handle_packet(self, packet: bytes) -> None:
        current = self._current
        if current is not None and current.wants_reply:
            self._resume_task(packet, None)
        elif packet[:1] in (b"T", b"S", b"W", b"X"):
            if not self._running and packet[:1] in (b"T", b"S"):
                logger.warning("ignoring unexpected stop from GDB stub: %r", packet)
            elif current is not None and current.wants_stop:
                self._running = False
                self._interrupting = False
                self._resume_task(packet, None)
            elif packet[:1] in (b"W", b"X"):
                self._handle_exit(packet)
            else:
                self._handle_stop(packet)
        elif packet[:1] == b"O" and packet != b"OK":
            # Console output.
            logger.info(
                "%s", bytes.fromhex(packet[1:].decode()).decode(errors="replace")
            )
        else:
            logger.warning("ignoring unexpected packet from GDB stub: %r", packet)

    def _check_stopped(self) -> None:
        if self._running:
            raise drgn.NotStoppedError("program is running")

    def _request_ok(self, data: bytes) -> _Task:
        reply = yield data
        if reply != b"OK":
            raise _unexpected_reply(reply, repr(data.decode(errors="replace")))

    # Threads and registers

    def _stub_thread(self, thread_id: int) -> drgn.Thread:
        """Return the thread for one of the stub's thread IDs."""
        raise NotImplementedError()

    def _stub_thread_id(self, thread: drgn.Thread) -> Optional[int]:
        """
        Return the stub's thread ID for a thread that is running on a CPU, or
        ``None`` if it isn't running on one.
        """
        raise NotImplementedError()

    def _format_thread_id(self, thread_id: int) -> bytes:
        """Return one of the stub's thread IDs as it is sent in a packet."""
        raise NotImplementedError()

    def _thread_cpu(self, thread: drgn.Thread) -> Optional[int]:
        # Return the CPU that a thread is running on, or None if it isn't
        # running on one.
        task = thread.object
        cpu = task_cpu(task)
        if cpu_curr(self._prog, cpu).value_() == task.value_():
            return cpu
        return None

    def _invalidate_registers(self) -> None:
        self._g_thread_id = None
        self._registers.clear()

    def _read_registers(self, thread_id: int) -> _Task:
        self._check_stopped()
        try:
            return self._registers[thread_id]
        except KeyError:
            pass
        if self._g_thread_id != thread_id:
            yield from self._request_ok(b"Hg" + self._format_thread_id(thread_id))
            self._g_thread_id = thread_id
        # Note that we can't use "p" to get only the registers that we need:
        # as of QEMU 8.2, it returns stale values after the CPU has run.
        reply = yield b"g"
        try:
            registers = bytes.fromhex(reply.decode())
        except ValueError:
            registers = b""
        if len(registers) < _X86_64_G_REGISTERS_MIN_SIZE:
            raise _unexpected_reply(reply, "registers")
        self._registers[thread_id] = registers
        return registers

    def _write_pc(self, thread_id: int, pc: int) -> _Task:
        registers = yield from self._read_registers(thread_id)
        value = pc.to_bytes(8, "little")
        yield from self._request_ok(
            b"P%x=%s" % (_X86_64_G_RIP_NUMBER, value.hex().encode())
        )
        self._registers[thread_id] = (
            registers[:_X86_64_G_RIP_OFFSET]
            + value
            + registers[_X86_64_G_RIP_OFFSET + 8 :]
        )

    def _find_register_state(
        self, thread: drgn.Thread, is_last: bool
    ) -> Optional[drgn.RegisterState]:
        # The Linux kernel register state finder can only get the registers
        # of tasks that are scheduled out. While we're stopped, we can get the
        # registers of the tasks that are running from the CPUs.
        if self._sock is None or self._running:
            return None
        thread_id = self._stub_thread_id(thread)
        if thread_id is None:
            return None
        registers = self._registers.get(thread_id)
        if registers is None:
            registers = self._run_sync(self._read_registers(thread_id))
        regs = drgn.RegisterState(self._prog, True)
        offset = 0
        for name, size in _X86_64_G_REGISTERS:
            if offset + size > len(registers):
                break
            value = int.from_bytes(registers[offset : offset + size], "little")
            regs.set(name, value)
            if name == "rip":
                regs.pc = value
            offset += size
        return regs

    # Stops

    def _handle_exit(self, packet: bytes) -> None:
        status = int(packet[1:3], 16)
        if packet[:1] == b"X":
            status = -int(_GDB_SIGNALS.get(status, status))
        self._close()
        self._fail_tasks(drgn.ProgramExitedError("program exited"), True)
        self._prog.notify_program_exit(status)

    def _read_stop(self, packet: bytes) -> _Task:
        # Parse a stop reply and return the thread, signal, and program
        # counter.
        if packet[:1] not in (b"T", b"S"):
            raise _unexpected_reply(packet, "stop reason")
        sig = int(packet[1:3], 16)
        sig = int(_GDB_SIGNALS.get(sig, sig))
        value = None
        if packet[:1] == b"T":
            for pair in packet[3:].split(b";"):
                name, _, value = pair.partition(b":")
                if name == b"thread":
                    break
            else:
                value = None
        if value is None:
            reply = yield b"qC"
            if not reply.startswith(b"QC"):
                raise _unexpected_reply(reply, "current thread")
            value = reply[2:]
        thread_id = _parse_thread_id(value)
        self._stop_thread_id = thread_id

        registers = yield from self._read_registers(thread_id)
        pc = int.from_bytes(
            registers[_X86_64_G_RIP_OFFSET : _X86_64_G_RIP_OFFSET + 8], "little"
        )
        pc = yield from self._fix_stop_pc(thread_id, sig, pc)
        return self._stub_thread(thread_id), sig, pc

    def _fix_stop_pc(self, thread_id: int, sig: int, pc: int) -> _Task:
        """
        Fix the program counter of a thread that stopped if necessary and
        return it.
        """
        return pc
        yield

    def _handle_stop(self, packet: bytes) -> None:
        self._running = False
        self._interrupting = False
        self._invalidate_registers()

        def on_done(result: Tuple[drgn.Thread, int, int]) -> None:
            self._prog.notify_thread_stop(*result)

        # If we can't report the stop, then we can't continue.
        self._start(self._read_stop(packet), on_done, self._lost)

    def _resume(self, packet: bytes, step: bool) -> _Task:
        # The program is considered running from when we ask until we get a
        # stop reply.
        self._running = True
        self._stepped = step
        self._invalidate_registers()
        try:
            yield _Send(packet)
        except BaseException:
            self._running = False
            raise

    # ExecutionController

    def _attach(self, flags: drgn.AttachFlags) -> _Task:
        """
        Task that attaches to the stub once we're connected. If
        :attr:`drgn.AttachFlags.INTERRUPT` was given, then it returns the
        thread that stopped and its program counter. Otherwise, it resumes
        the program.
        """
        raise NotImplementedError()

    def _detach(self) -> _Task:
        """Task that detaches from the stub."""
        raise NotImplementedError()

    def _resume_packet(
        self, actions: Sequence[drgn.ResumeAction]
    ) -> Tuple[bytes, bool]:
        """
        Return the packet for the given actions and whether it steps, or an
        empty packet if there is nothing to do.
        """
        raise NotImplementedError()

    def attach(
        self,
        prog: drgn.Program,
        flags: drgn.AttachFlags,
        promise: "drgn.Promise[bool]",
    ) -> None:
        def on_done(result: Optional[Tuple[drgn.Thread, int]]) -> None:
            self._attached = True
            promise.set_result(True)
            if result is not None:
                # Report this the same way as if we had attached and then
                # interrupted.
                thread, pc = result
                prog.notify_thread_stop(thread, signal.SIGINT, pc)

        def on_error(exc: BaseException) -> None:
            self._close()
            promise.set_exception(exc)

        try:
            if flags & drgn.AttachFlags.NON_STOP:
                raise ValueError("non-stop mode is not supported")
            self._software_breakpoints.clear()
            self._open(
                _resolve_address(self._address),
                lambda: self._start(self._attach(flags), on_done, on_error),
                on_error,
            )
        except Exception as e:
            on_error(e)

    def detach(self, prog: drgn.Program, promise: "drgn.Promise[None]") -> None:
        def on_done(result: None) -> None:
            self._close()
            self._fail_tasks(drgn.NotAttachedError("detached from program"), False)
            promise.set_result(None)

        if self._sock is None:
            promise.set_result(None)
        else:
            self._start(self._detach(), on_done, promise.set_exception)

    def stop_all_threads(
        self, prog: drgn.Program, promise: "drgn.Promise[None]"
    ) -> None:
        # The stub always stops all CPUs.
        promise.set_result(None)

    def resume_threads(
        self,
        prog: drgn.Program,
        actions: Sequence[drgn.ResumeAction],
        promise: "drgn.Promise[None]",
    ) -> None:
        def task() -> _Task:
            self._check_stopped()
            packet, step = self._resume_packet(actions)
            if packet:
                yield from self._resume(packet, step)

        self._start(task(), promise.set_result, promise.set_exception)

    def _set_breakpoint_sites(
        self,
        sites: Sequence[drgn.BreakpointSite],
        insert: bool,
        promise: "drgn.Promise[None]",
    ) -> None:
        def set_site(site: drgn.BreakpointSite, insert: bool) -> _Task:
            # The last field is the size of the breakpoint instruction.
            yield from self._request_ok(
                b"%c%d,%x,1"
                % (
                    b"Z" if insert else b"z",
                    1 if site.hardware else 0,
                    site.address,
                )
            )
            if not site.hardware:
                if insert:
                    self._software_breakpoints.add(site.address)
                else:
                    self._software_breakpoints.discard(site.address)

        def task() -> _Task:
            self._check_stopped()
            done = []
            try:
                for site in sites:
                    yield from set_site(site, insert)
                    done.append(site)
            except Exception:
                for site in done:
                    try:
                        yield from set_site(site, not insert)
                    except Exception:
                        logger.warning(
                            "couldn't %s breakpoint at 0x%x after error",
                            "remove" if insert else "restore",
                            site.address,
                            exc_info=True,
                        )
                raise

        self._start(task(), promise.set_result, promise.set_exception)

    def enable_breakpoint_sites(
        self, sites: Sequence[drgn.BreakpointSite], promise: "drgn.Promise[None]"
    ) -> None:
        self._set_breakpoint_sites(sites, True, promise)

    def disable_breakpoint_sites(
        self, sites: Sequence[drgn.BreakpointSite], promise: "drgn.Promise[None]"
    ) -> None:
        self._set_breakpoint_sites(sites, False, promise)


class QemuGdbExecutionController(GdbRspExecutionController):
    """Execution controller for QEMU's GDB stub."""

    def _stub_thread(self, thread_id: int) -> drgn.Thread:
        # QEMU has one process whose threads are the CPUs numbered from 1.
        return self._prog.thread_from_object(cpu_curr(self._prog, thread_id - 1))

    def _stub_thread_id(self, thread: drgn.Thread) -> Optional[int]:
        cpu = self._thread_cpu(thread)
        if cpu is None:
            return None
        return cpu + 1

    def _format_thread_id(self, thread_id: int) -> bytes:
        return b"p1.%x" % thread_id

    def _attach(self, flags: drgn.AttachFlags) -> _Task:
        yield b"qSupported:vContSupported+"
        # QEMU stops the guest when we connect. This returns a placeholder
        # SIGTRAP stop.
        packet = yield b"?"
        if not (flags & drgn.AttachFlags.INTERRUPT):
            yield from self._resume(b"vCont;c", False)
            return None
        thread, _, pc = yield from self._read_stop(packet)
        return thread, pc

    def _detach(self) -> _Task:
        if self._running:
            if not self._interrupting:
                self._interrupting = True
                self._write(b"\x03")
            packet = yield _WaitForStop()
            if packet[:1] in (b"W", b"X"):
                return
        # This removes all breakpoints and resumes the guest.
        yield from self._request_ok(b"D;1")

    def _resume_packet(
        self, actions: Sequence[drgn.ResumeAction]
    ) -> Tuple[bytes, bool]:
        resume_all = any(action.thread is None for action in actions)
        vcont: List[bytes] = []
        step = False
        for action in actions:
            if action.thread is None:
                continue
            thread_id = self._stub_thread_id(action.thread)
            if isinstance(action, drgn.StepiResumeAction):
                if thread_id is None:
                    raise ValueError(
                        f"thread {action.thread.tid} is not running on a CPU"
                    )
                vcont.append(b"s:" + self._format_thread_id(thread_id))
                step = True
            elif not resume_all and thread_id is not None:
                vcont.append(b"c:" + self._format_thread_id(thread_id))
        if resume_all:
            vcont.append(b"c")
        if not vcont:
            return b"", False
        return b"vCont;" + b";".join(vcont), step

    def interrupt_any_thread(
        self, prog: drgn.Program, promise: "drgn.Promise[None]"
    ) -> None:
        try:
            if self._sock is None:
                raise drgn.NotAttachedError("not connected to GDB stub")
            # Anything sent while the guest is running stops it, so only send
            # one interrupt per stop.
            if self._running and not self._interrupting:
                self._interrupting = True
                self._write(b"\x03")
        except OSError as e:
            self._lost(e)
            promise.set_exception(e)
        except Exception as e:
            promise.set_exception(e)
        else:
            promise.set_result(None)


class KgdbExecutionController(GdbRspExecutionController):
    """
    Execution controller for KGDB.

    Note that this doesn't implement ``interrupt_any_thread()`` because KGDB
    can't be interrupted by the debugger.
    """

    def _stub_thread(self, thread_id: int) -> drgn.Thread:
        # KGDB's thread IDs are PIDs, except that the idle task of CPU N is
        # -(N + 2).
        if thread_id <= -2:
            return self._prog.thread_from_object(idle_task(self._prog, -thread_id - 2))
        return self._prog.thread(thread_id)

    def _stub_thread_id(self, thread: drgn.Thread) -> Optional[int]:
        # KGDB can also return the registers of a task that isn't running, but
        # it only knows a few of them, so we leave those to the Linux kernel
        # register state finder.
        cpu = self._thread_cpu(thread)
        if cpu is None:
            return None
        return thread.tid or -(cpu + 2)

    def _format_thread_id(self, thread_id: int) -> bytes:
        if thread_id < 0:
            return b"-%x" % -thread_id
        return b"%x" % thread_id

    def _fix_stop_pc(self, thread_id: int, sig: int, pc: int) -> _Task:
        # After a software breakpoint, KGDB leaves the program counter after
        # the breakpoint instruction and expects the debugger to move it back.
        # A step never executes a breakpoint instruction, so if we stepped to
        # the instruction after a breakpoint, we got there another way.
        if (
            sig == signal.SIGTRAP
            and not self._stepped
            and (pc - 1) in self._software_breakpoints
        ):
            pc -= 1
            yield from self._write_pc(thread_id, pc)
        return pc

    def _attach(self, flags: drgn.AttachFlags) -> _Task:
        # If the kernel is in kdb, then this also makes it switch to KGDB. If
        # the kernel is running, then this isn't answered until it enters
        # KGDB.
        packet = yield b"?"
        if not (flags & drgn.AttachFlags.INTERRUPT):
            yield from self._resume(b"c", False)
            return None
        thread, _, pc = yield from self._read_stop(packet)
        return thread, pc

    def _detach(self) -> _Task:
        if self._running:
            raise drgn.NotStoppedError(
                "can't detach from KGDB while the kernel is running"
            )
        # This removes all breakpoints and resumes the kernel.
        yield from self._request_ok(b"D")

    def _resume_packet(
        self, actions: Sequence[drgn.ResumeAction]
    ) -> Tuple[bytes, bool]:
        packet = b""
        for action in actions:
            if isinstance(action, drgn.StepiResumeAction):
                if (
                    self._stop_thread_id is None
                    or self._stub_thread_id(action.thread) != self._stop_thread_id
                ):
                    raise ValueError(
                        f"thread {action.thread.tid} is not the thread that stopped"
                    )
                packet = b"s"
            elif action.thread is None and not packet:
                packet = b"c"
        return packet, packet == b"s"


_TARGETS = {
    "qemu": QemuGdbExecutionController,
    "kgdb": KgdbExecutionController,
}


def register(
    prog: drgn.Program, address: str, target: str = "qemu"
) -> GdbRspExecutionController:
    """
    Register and enable an execution controller for a Linux kernel on x86-64.

    :param prog: Program for the kernel (e.g., set up with
        :meth:`drgn.Program.set_qemu_qmp()`).
    :param address: Address of the stub in the same format as
        :meth:`drgn.Program.set_qemu_qmp()`.
    :param target: ``"qemu"`` for QEMU's GDB stub or ``"kgdb"`` for KGDB.
    """
    try:
        controller_type = _TARGETS[target]
    except KeyError:
        raise ValueError(f"unknown target {target!r}") from None
    if prog.platform is None or prog.platform.arch != drgn.Architecture.X86_64:
        raise ValueError("only x86-64 is supported")
    if not (prog.flags & drgn.ProgramFlags.IS_LINUX_KERNEL):
        raise ValueError("only the Linux kernel is supported")
    controller = controller_type(prog, address)
    prog.register_execution_controller("gdbrsp", controller, enable_index=0)
    prog.register_register_state_finder(
        "gdbrsp", controller._find_register_state, enable_index=0
    )
    return controller


if __name__ == "__main__":
    import argparse

    from drgn.cli import run_interactive

    parser = argparse.ArgumentParser(
        description="control execution of a Linux kernel over the GDB Remote Serial Protocol"
    )
    parser.add_argument(
        "--target",
        choices=sorted(_TARGETS),
        default="qemu",
        help="kind of stub to connect to (default: %(default)s)",
    )
    parser.add_argument("address", help="address of the stub")
    args = parser.parse_args()
    register(prog, args.address, args.target)
    run_interactive(prog)
