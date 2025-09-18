#!/usr/bin/env python3
# SPDX-FileCopyrightText: Omar Sandoval <osandov@osandov.com>
# SPDX-License-Identifier: MIT

import argparse
import contextlib
import enum
import errno
import fcntl
from functools import partial
import os
import pty
import selectors
import signal
import socket
import struct
import sys
import termios
import tty
from typing import Any, Callable, Dict, Iterator, Optional, Set, TYPE_CHECKING, Union


if TYPE_CHECKING:
    from typing import Protocol

    class HasFileno(Protocol):
        def fileno(self) -> int:
            ...

    FileDescriptorLike = Union[int, HasFileno]


DEFAULT_PORT = 32254  # rsh uses port 514, this is -514 % 2**15 :)


class Multiplexer:
    class File:
        def __init__(
            self, multiplexer: "Multiplexer", fileobj: "FileDescriptorLike"
        ) -> None:
            self.multiplexer = multiplexer
            self.fileobj = fileobj
            self._read_cb: Optional[Callable[[bytes], Any]] = None
            self._write_buf = bytearray()

        @property
        def read_cb(self) -> Optional[Callable[[bytes], Any]]:
            return self._read_cb

        @read_cb.setter
        def read_cb(self, callback: Optional[Callable[[bytes], Any]]) -> None:
            if bool(self._read_cb) != bool(callback):
                self.multiplexer._to_modify.add(self)
            self._read_cb = callback

        def write(self, buf: bytes) -> None:
            if not buf:
                return
            if not self._write_buf:
                self.multiplexer._pending_writes.add(self)
                self.multiplexer._to_modify.add(self)
            self._write_buf.extend(buf)

    def __init__(self) -> None:
        # EpollSelector doesn't allow regular files.
        self._sel = selectors.PollSelector()
        self._files: Dict["FileDescriptorLike", Multiplexer.File] = {}
        self._pending_writes: Set[Multiplexer.File] = set()
        self._pending_signals: Set[Callable[[], Any]] = set()
        self._signal_r: Optional[int] = None
        self._signal_w: Optional[int] = None
        self._old_wakeup_fd: Optional[int] = None
        self._to_modify: Set[Multiplexer.File] = set()
        self.done = False

    def close(self) -> None:
        if self._old_wakeup_fd is not None:
            signal.set_wakeup_fd(self._old_wakeup_fd)
        if self._signal_r is not None:
            os.close(self._signal_r)
        if self._signal_w is not None:
            os.close(self._signal_w)
        self._sel.close()

    def __enter__(self) -> "Multiplexer":
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        self.close()

    def open(self, fileobj: "FileDescriptorLike") -> "Multiplexer.File":
        try:
            return self._files[fileobj]
        except KeyError:
            file = Multiplexer.File(self, fileobj)
            self._files[fileobj] = file
            return file

    def signal(self, signalnum: int, handler: Callable[[int], Any]) -> None:
        if self._signal_r is None:
            self._signal_r, self._signal_w = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
            if sys.version_info >= (3, 7):
                self._old_wakeup_fd = signal.set_wakeup_fd(
                    self._signal_w, warn_on_full_buffer=False
                )
            else:
                self._old_wakeup_fd = signal.set_wakeup_fd(self._signal_w)
            self.open(self._signal_r).read_cb = lambda buf: None
        pending = partial(handler, signalnum)
        signal.signal(
            signalnum, lambda signum, frame: self._pending_signals.add(pending)
        )

    def _modify(self, file: "Multiplexer.File") -> None:
        events = 0
        if file.read_cb:
            events |= selectors.EVENT_READ
        if file._write_buf:
            events |= selectors.EVENT_WRITE
        if events:
            try:
                old_events = self._sel.get_key(file.fileobj)
            except KeyError:
                self._sel.register(file.fileobj, events, file)
            else:
                self._sel.modify(file.fileobj, events, file)
        else:
            with contextlib.suppress(KeyError):
                self._sel.unregister(file.fileobj)

    def run(self) -> None:
        while True:
            while self._pending_signals:
                self._pending_signals.pop()()
            if self.done and not self._pending_writes:
                break
            for file in self._to_modify:
                self._modify(file)
            self._to_modify.clear()
            for key, mask in self._sel.select():
                file = key.data
                if mask & selectors.EVENT_READ:
                    try:
                        buf = os.read(key.fd, 4096)
                    except OSError as e:
                        if e.errno == errno.EIO:
                            buf = b""
                        else:
                            raise
                    assert file.read_cb is not None
                    file.read_cb(buf)
                    if not buf:
                        file.read_cb = None
                if mask & selectors.EVENT_WRITE:
                    written = os.write(key.fd, file._write_buf)
                    del file._write_buf[:written]
                    if not file._write_buf:
                        self._pending_writes.remove(file)
                        self._to_modify.add(file)


class Rrsh:
    @enum.unique
    class Event(enum.IntEnum):
        EXIT = 0
        WINCH = 1

    class State(enum.Enum):
        WAITING = enum.auto()
        DATA = enum.auto()
        EVENT = enum.auto()
        WSTATUS = enum.auto()
        WINSZ = enum.auto()

    def __init__(self) -> None:
        self._state = Rrsh.State.WAITING
        self._data_remaining = 0
        self._command_buf = bytearray()

        self.on_data: Callable[[bytes], Any] = lambda buf: None
        self.on_exit: Callable[[int], Any] = lambda wstatus: None
        self.on_winch: Callable[[int, int], Any] = lambda columns, lines: None

        self.wstatus = None

    def feed(self, buf: bytes) -> None:
        i = 0
        while i < len(buf):
            if self._state == Rrsh.State.WAITING:
                if buf[i]:
                    self._state = Rrsh.State.DATA
                    self._data_remaining = buf[i]
                else:
                    self._state = Rrsh.State.EVENT
                i += 1
            elif self._state == Rrsh.State.DATA:
                n = min(self._data_remaining, len(buf) - i)
                self.on_data(buf[i : i + n])
                self._data_remaining -= n
                if self._data_remaining == 0:
                    self._state = Rrsh.State.WAITING
                i += n
            elif self._state == Rrsh.State.EVENT:
                if buf[i] == Rrsh.Event.EXIT:
                    self._state = Rrsh.State.WSTATUS
                elif buf[i] == Rrsh.Event.WINCH:
                    self._state = Rrsh.State.WINSZ
                else:
                    raise ValueError(f"unknown command {buf[i]}")
                i += 1
            elif self._state == Rrsh.State.WSTATUS:
                n = min(2 - len(self._command_buf), len(buf) - i)
                self._command_buf.extend(buf[i : i + n])
                if len(self._command_buf) == 2:
                    (wstatus,) = struct.unpack("!H", self._command_buf)
                    self.on_exit(wstatus)
                    self._command_buf.clear()
                    self._state = Rrsh.State.WAITING
                i += n
            else:  # self._state == Rrsh.State.WINSZ
                n = min(4 - len(self._command_buf), len(buf) - i)
                self._command_buf.extend(buf[i : i + n])
                if len(self._command_buf) == 4:
                    self.on_winch(*struct.unpack("!HH", self._command_buf))
                    self._command_buf.clear()
                    self._state = Rrsh.State.WAITING
                i += n

    @staticmethod
    def write_data(file: Multiplexer.File, buf: bytes) -> None:
        for i in range(0, len(buf), 255):
            n = min(len(buf) - i, 255)
            file.write(bytes((n,)))
            file.write(buf[i : i + n])


def log(*args: Any, **kwds: Any) -> None:
    print(*args, file=sys.stderr, end="\r\n", **kwds)


def decode_wstatus(wstatus: int, verbose: bool) -> int:
    if os.WIFEXITED(wstatus):
        exit_status = os.WEXITSTATUS(wstatus)
        if verbose:
            log(f"Command exited with status {exit_status}")
        return exit_status
    else:
        termsig = os.WTERMSIG(wstatus)
        if verbose:
            try:
                signame = signal.Signals(termsig).name
            except ValueError:
                signame = str(termsig)
            log(f"Command was terminated by signal {signame}")
        return 128 + termsig


@contextlib.contextmanager
def raw_stdio() -> Iterator[None]:
    try:
        old_stdin_attr = termios.tcgetattr(sys.stdin)
        stdin_isatty = True
    except termios.error:
        stdin_isatty = False
    old_stdin_flags = fcntl.fcntl(sys.stdin, fcntl.F_GETFD)
    old_stdout_flags = fcntl.fcntl(sys.stdout, fcntl.F_GETFD)
    try:
        if stdin_isatty:
            tty.setraw(sys.stdin)
        fcntl.fcntl(sys.stdin, fcntl.F_SETFD, old_stdin_flags | os.O_NONBLOCK)
        fcntl.fcntl(sys.stdout, fcntl.F_SETFD, old_stdout_flags | os.O_NONBLOCK)
        yield
    finally:
        fcntl.fcntl(sys.stdout, fcntl.F_SETFD, old_stdout_flags)
        fcntl.fcntl(sys.stdin, fcntl.F_SETFD, old_stdin_flags)
        if stdin_isatty:
            termios.tcsetattr(sys.stdin, termios.TCSAFLUSH, old_stdin_attr)


def server(args: argparse.Namespace) -> None:
    tokens = args.address.rsplit(":", 1)
    host = tokens[0] if len(tokens) > 0 else ""
    port = tokens[1] if len(tokens) > 1 else ""
    family, _, _, _, address = socket.getaddrinfo(
        host or "::", port or DEFAULT_PORT, proto=socket.IPPROTO_TCP
    )[0]
    ssock = socket.socket(family, socket.SOCK_STREAM)
    try:
        with contextlib.suppress(socket.error):
            ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            with contextlib.suppress(socket.error):
                ssock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        ssock.bind(address)
        ssock.listen()
        if args.verbose:
            log(f"Listening on {ssock.getsockname()}")
        while True:
            sock, peername = ssock.accept()
            with sock:
                if args.verbose:
                    log(f"Connection from {peername}")
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                sock.setblocking(False)
                with raw_stdio(), Multiplexer() as multiplexer:
                    exit_status = 1

                    def on_exit(wstatus: int) -> None:
                        nonlocal exit_status
                        exit_status = decode_wstatus(wstatus, args.verbose)

                    rrsh = Rrsh()
                    # Data read from the socket is written to stdout.
                    rrsh.on_data = multiplexer.open(sys.stdout).write
                    rrsh.on_exit = on_exit

                    def read_sock(buf: bytes) -> None:
                        if buf:
                            rrsh.feed(buf)
                        else:
                            if args.verbose:
                                log(f"{peername} disconnected")
                            multiplexer.done = True

                    sock_file = multiplexer.open(sock)
                    sock_file.read_cb = read_sock

                    # Data read from stdin is written to the socket.
                    multiplexer.open(sys.stdin).read_cb = partial(
                        Rrsh.write_data, sock_file
                    )

                    def send_winch(signalnum: int) -> None:
                        try:
                            columns, lines = os.get_terminal_size()
                        except OSError:
                            pass
                        else:
                            sock_file.write(
                                struct.pack(
                                    "!BBHH", 0, Rrsh.Event.WINCH, columns, lines
                                )
                            )

                    multiplexer.signal(signal.SIGWINCH, send_winch)
                    # Send the initial size.
                    send_winch(signal.SIGWINCH)

                    multiplexer.run()
            if args.verbose:
                log(f"Disconnected from {peername}")
            if not args.keep_open:
                sys.exit(exit_status)
    finally:
        ssock.close()


def client(args: argparse.Namespace) -> None:
    tokens = args.address.rsplit(":", 1)
    host = tokens[0] if len(tokens) > 0 else ""
    port = tokens[1] if len(tokens) > 1 else ""
    if not args.command:
        args.command = ["sh", "-i"]
    with socket.create_connection((host or None, port or DEFAULT_PORT)) as sock:
        peername = sock.getpeername()
        if args.verbose:
            print(f"Connected to {peername} from {sock.getsockname()}", file=sys.stderr)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setblocking(False)
        pid, pty_fd = pty.fork()
        if pid == 0:
            os.execvp(args.command[0], args.command)
        try:
            os.set_blocking(pty_fd, False)
            with Multiplexer() as multiplexer:
                pty_file = multiplexer.open(pty_fd)

                rrsh = Rrsh()
                # Data read from the socket is written to the pseudoterminal.
                rrsh.on_data = pty_file.write
                rrsh.on_winch = lambda columns, lines: fcntl.ioctl(
                    pty_fd,
                    termios.TIOCSWINSZ,
                    struct.pack("HHHH", lines, columns, 0, 0),
                )

                def read_sock(buf: bytes) -> None:
                    if buf:
                        rrsh.feed(buf)
                    else:
                        if args.verbose:
                            log(f"{peername} disconnected")
                        multiplexer.done = True

                sock_file = multiplexer.open(sock)
                sock_file.read_cb = read_sock

                # Data read from the pseudoterminal is written to the socket.
                pty_file.read_cb = partial(Rrsh.write_data, sock_file)

                exit_status = 1

                def send_exit(signalnum: int) -> None:
                    while True:
                        try:
                            wpid, wstatus = os.waitpid(-1, os.WNOHANG)
                        except ChildProcessError:
                            break
                        if not wpid:
                            break
                        elif wpid == pid:
                            nonlocal exit_status
                            exit_status = decode_wstatus(wstatus, args.verbose)
                            sock_file.write(
                                struct.pack("!BBH", 0, Rrsh.Event.EXIT, wstatus)
                            )
                            multiplexer.done = True

                multiplexer.signal(signal.SIGCHLD, send_exit)

                multiplexer.run()
        finally:
            os.close(pty_fd)
    if args.verbose:
        log(f"Disconnected from {peername}")
    sys.exit(exit_status)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="""\
Reverse remote shell

This program is like rsh, but in reverse: the client executes the command and
the server controls it. This is useful for getting an interactive shell in
situations where the machine of interest is not publicly accessible by, e.g.,
SSH, but it can run arbitrary commands and access the internet.

Note that the connection is not authenticated or encrypted (which is why it's
not rssh).
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="log extra information to standard error",
    )

    subparsers = parser.add_subparsers(
        title="mode", dest="mode", description="mode to run in"
    )
    subparsers.required = True

    parser_server = subparsers.add_parser("server", help="listen for client connection")
    parser_server.add_argument(
        "address",
        metavar="[address][:[port]]",
        default="",
        nargs="?",
        help=f"address (default: any) and port (default: {DEFAULT_PORT}) to listen on",
    )
    parser_server.add_argument(
        "-k",
        "--keep-open",
        action="store_true",
        help="keep listening after a client disconnects",
    )
    parser_server.set_defaults(func=server)

    parser_client = subparsers.add_parser(
        "client", help="run command and connect to server"
    )
    parser_client.add_argument(
        "address",
        metavar="[address][:[port]]",
        default="",
        help=f"address and port (default: {DEFAULT_PORT}) to connect to",
    )
    parser_client.add_argument(
        "command", nargs=argparse.REMAINDER, help="command to run (default: sh -i)"
    )
    parser_client.set_defaults(func=client)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
