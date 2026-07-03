# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import collections
import functools
import socket
import sys
from typing import Sequence

import drgn
from drgn import ExecutionController
from drgn.helpers.linux.sched import cpu_curr, task_cpu
from drgn.internal.repl import print_above_prompt

print_above_prompt = print


class GdbRspExecutionController(ExecutionController):
    def __init__(self, address, target) -> None:
        super().__init__()
        self._address = address
        self._target = target

    def attach(
        self, prog: drgn.Program, flags: drgn.AttachFlags, promise: drgn.Promise[bool]
    ) -> None:
        if flags & drgn.AttachFlags.NON_STOP:
            raise ValueError("non-stop mode is not supported")
        self._attach_flags = flags

        self._state = "IDLE"

        self._recv_buf = bytearray(8192)
        self._recv_view = memoryview(self._recv_buf)
        self._recv_head = 0
        self._recv_tail = 0
        self._recv_cursor = 0

        self._send_buf = bytearray()
        self._send_pos = 0

        self._attach_promise = promise

        self._sock = socket.socket(
            socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_NONBLOCK
        )
        prog.register_fd(self._sock.fileno(), drgn.FdEvents.WRITE, self._connect)

    def _connect(self, prog: Program, fd: int, events: drgn.FdEvents) -> None:
        try:
            self._sock.connect(self._address)
        except BlockingIOError:
            return

        self._attach_promise.set_result(True)
        self._attach_promise = None

        self._send_packet(b"qSupported", self._on_qsupported_reply)
        prog.modify_fd(fd, drgn.FdEvents.WRITE, self._ready)

    def _on_qsupported_reply(self, prog: drgn.Program, reply: bytes) -> None:
        self._send_packet(
            b"?" if (self._attach_flags & drgn.AttachFlags.INTERRUPT) else b"C",
            self._on_stop_reply,
        )

    def detach(self) -> None:
        pass

    def interrupt_any_thread(
        self, prog: drgn.Program, promise: drgn.Promise[None]
    ) -> None:
        assert self._state == "WANT_REPLY", self._state
        assert not self._send_buf
        promise.set_result(None)
        self._send_buf.append(3)
        self._ready(prog, self._sock.fileno(), 0)

    def resume_threads(
        self,
        prog: drgn.Program,
        actions: Sequence[drgn.ResumeAction],
        promise: drgn.Promise[None],
    ) -> None:
        packet = bytearray(b"vCont")
        for action in actions:
            if isinstance(action, drgn.ContinueResumeAction):
                if action.sig:
                    packet.extend(b";C%02x" % action.sig)
                else:
                    packet.extend(b";c")
                if action.thread:
                    packet.extend(b":%d" % self._thread_rsp_tid(action.thread))
        self._send_packet(
            packet, self._on_stop_reply, lambda prog: promise.set_result(None)
        )
        self._ready(prog, self._sock.fileno(), 0)

    def _send_breakpoint_packet(
        self,
        packet: bytes,
        sites: Sequence[drgn.BreakpointSite],
        i: int,
        promise: drgn.Promise[None],
    ) -> None:
        site = sites[i]
        self._send_packet(
            b"%s%d,%x,1" % (packet, 1 if site.hardware else 0, site.address),
            lambda prog, reply: self._on_breakpoint_reply(
                packet, reply, sites, i, promise
            ),
        )

    def _on_breakpoint_reply(
        self,
        packet: bytes,
        reply: bytes,
        sites: Sequence[drgn.BreakpointSite],
        i: int,
        promise: drgn.Promise[None],
    ) -> None:
        if reply != b"OK":
            # TODO: need to unwind anything we already did.
            promise.set_exception(Exception(reply))
            return
        i += 1
        if i >= len(sites):
            promise.set_result(None)
            return
        self._send_breakpoint_packet(packet, sites, i, promise)

    def enable_breakpoint_sites(
        self, sites: Sequence[drgn.BreakpointSite], promise: drgn.Promise[None]
    ) -> None:
        self._send_breakpoint_packet(b"Z", sites, 0, promise)
        self._ready(prog, self._sock.fileno(), 0)

    def disable_breakpoint_sites(
        self, sites: Sequence[drgn.BreakpointSite], promise: drgn.Promise[None]
    ) -> None:
        self._send_breakpoint_packet(b"z", sites, 0, promise)
        self._ready(prog, self._sock.fileno(), 0)

    def _thread_rsp_tid(self, thread: drgn.Thread) -> int:
        if self._target == "kgdb":
            tid = thread.tid
            if not tid:
                return -(task_cpu(thread.object) + 2)
            return tid
        elif self._target == "qemu":
            return task_cpu(thread.object) + 1
        else:
            return thread.tid

    def _thread_from_rsp_tid(self, prog: drgn.Program, tid: int) -> drgn.Thread:
        if self._target == "kgdb":
            if tid <= -2:
                return prog.thread_from_object(idle_task(prog, -tid - 2))
        elif self._target == "qemu":
            return prog.thread_from_object(cpu_curr(prog, tid - 1))
        return prog.thread(tid)

    def _on_stop_reply(self, prog: drgn.Program, reply) -> None:
        assert reply[0] == 83 or reply[0] == 84  # 'S' or 'T':

        sig = int(reply[1:3], 16)
        tid = None
        if reply[0] == 84:
            for n, _, r in [pair.partition(b":") for pair in reply[3:].split(b";")]:
                if n == b"thread":
                    tid = int(r, 16)

        self._stop_reply_next(sig, tid)

    def _on_qc_reply(self, sig: int, prog: drgn.Program, reply: bytes) -> None:
        # TODO: "Any other reply implies the old thread ID."?
        assert reply.startswith(b"QC"), packet
        tid = int(packet[2:], 16)
        self._stop_reply_next(sig, tid)

    def _on_g_reply(self, sig: int, tid: int, prog: drgn.Program, reply: bytes) -> None:
        pc = int.from_bytes(bytes.fromhex(reply)[128:136], "little")
        prog.notify_thread_unknown_stop(self._thread_from_rsp_tid(prog, tid), sig, pc)
        prog.notify_all_stop()

    def _stop_reply_next(self, sig: int, tid: Optional[int]) -> None:
        if tid is None:
            self._send_packet(b"qC", functools.partial(self._on_qc_reply, sig))
        else:
            self._send_packet(b"g", functools.partial(self._on_g_reply, sig, tid))

    def _recv_more(self) -> bool:
        if self._recv_head == self._recv_tail:
            self._recv_head = self._recv_tail = 0
        if self._recv_tail == len(self._recv_buf):
            new_buf = bytearray(len(self._recv_buf) * 2)
            new_buf[: self._recv_tail - self._recv_head] = self._recv_view[
                self._recv_head : self._recv_tail
            ]
            self._recv_view.release()
            self._recv_buf = new_buf
            self._recv_view = memoryview(new_buf)
            self._recv_tail -= self._recv_head
            self._recv_head = 0

        try:
            n = self._sock.recv_into(self._recv_view[self._recv_tail :])
        except BlockingIOError:
            return False
        if not n:
            raise Exception("lost connection")
        self._recv_tail += n
        return True

    def _send_packet(self, data: bytes, on_reply, on_ack=None) -> None:
        print_above_prompt(f"-> {data}")

        if 35 in data:
            raise ValueError("packet data contains '#'")
        if 36 in data:
            raise ValueError("packet data contains '$'")

        assert self._state == "IDLE"
        assert self._send_buf == b"" or self._send_buf == b"+"
        self._send_packet_pos = len(self._send_buf)
        self._send_buf.extend(b"$%s#%02x" % (data, sum(data) % 256))
        self._on_ack = on_ack
        self._on_reply = on_reply
        self._state = "WANT_ACK"

    def _ready(self, prog: Program, fd: int, events: drgn.FdEvents) -> None:
        while True:
            while self._send_pos < len(self._send_buf):
                try:
                    self._send_pos += self._sock.send(self._send_buf[self._send_pos :])
                except BlockingIOError:
                    prog.modify_fd(fd, drgn.FdEvents.WRITE)
                    return

            if (
                self._recv_head + self._recv_cursor >= self._recv_tail
                and not self._recv_more()
            ):
                prog.modify_fd(fd, drgn.FdEvents.READ)
                return

            if self._state == "WANT_ACK":
                assert self._recv_cursor == 0
                c = self._recv_buf[self._recv_head]
                if c == 43:  # '+'
                    self._recv_head += 1
                    self._send_buf.clear()
                    self._send_pos = 0
                    self._state = "WANT_REPLY"
                    on_ack = self._on_ack
                    self._on_ack = None
                    if on_ack is not None:
                        on_ack(prog)
                elif c == 45:  # '-'
                    self._recv_head += 1
                    self._send_pos = self._send_packet_pos
                elif c == 37:  # '%'
                    raise Exception("TODO: notification packets")
                else:
                    # Ignore garbage (e.g., kdb banner).
                    self._recv_head += 1
            elif self._state == "WANT_REPLY":
                assert self._recv_cursor == 0
                c = self._recv_buf[self._recv_head]
                if c == 36:  # '$'
                    self._recv_head += 1
                    self._state = "WANT_REPLY_DATA"
                elif c == 37:  # '%'
                    raise Exception("TODO: notification packets")
                else:
                    raise Exception(f"unknown packet in {self._state} state")
            elif self._state == "WANT_REPLY_DATA":
                i = self._recv_buf.find(
                    b"#", self._recv_head + self._recv_cursor, self._recv_tail
                )
                if i < 0:
                    self._recv_cursor = self._recv_tail - self._recv_head
                else:
                    self._recv_cursor = i - self._recv_head
                    self._packet_data_end = self._recv_cursor
                    self._state = "WANT_REPLY_END"
            elif self._state == "WANT_REPLY_END":
                if self._recv_tail - (self._recv_head + self._packet_data_end) < 3:
                    self._recv_cursor = self._recv_tail - self._recv_head
                else:
                    if (
                        self._recv_buf[self._recv_head + self._packet_data_end] != 35
                    ):  # '#'
                        raise Exception("expected #")
                    try:
                        checksum = int(
                            self._recv_buf[
                                self._recv_head
                                + self._packet_data_end
                                + 1 : self._recv_head
                                + self._packet_data_end
                                + 3
                            ],
                            16,
                        )
                    except ValueError:
                        raise Exception("invalid checksum")
                    reply = self._recv_view[
                        self._recv_head : self._recv_head + self._packet_data_end
                    ]

                    self._recv_head += self._packet_data_end + 3
                    self._recv_cursor = 0

                    # TODO: interrupt_any_thread() breaks this assumption.
                    # assert not self._send_buf
                    # assert self._send_pos == 0
                    self._send_buf.clear()
                    self._send_pos = 0
                    if sum(reply) % 256 == checksum:
                        reply = bytes(reply)
                        print_above_prompt(f"<- {reply}")
                        self._send_buf.append(43)  # '+'
                        self._state = "IDLE"
                        on_reply = self._on_reply
                        self._on_reply = None
                        on_reply(prog, reply)
                    else:
                        print(
                            "warning: response has bad checksum; requesting retransmission",
                            file=sys.stderr,
                        )
                        self._send_buf.append(45)  # '-'
                        self._state = "WANT_REPLY"
            else:
                assert False, self._state


def register(prog: drgn.Program, address) -> None:
    controller = GdbRspExecutionController(address, "qemu")
    prog.register_execution_controller("gdbrsp", controller, enable_index=0)
    # prog.register_register_state_finder("gdbrsp", controller._thread_register_state, enable_index=-1)


def _event_listener(prog: drgn.Program, event: drgn.Event) -> None:
    print(event)


if __name__ == "__main__":
    # prog.add_event_listener(_event_listener)
    register(prog, sys.argv[1])

    events = collections.deque()
    with prog.add_event_listener(lambda prog, event: events.append(event)):
        prog.attach(drgn.AttachFlags.INTERRUPT)
        print(f"Attached with all_stop={prog.all_stop}")
        bp = None
        hit = 0
        while True:
            while not events:
                prog.poll()

            event = events.popleft()
            print(event)

            if isinstance(event, drgn.ThreadStopEvent):
                print(event.thread.stop_reason)

                if bp is None:
                    bp = prog.set_breakpoint(
                        prog.symbol("execdomains_proc_show").address
                    )
                    print(bp)
                    event.thread.cont()
                elif hit == 0:
                    bp.disable()
                    hit += 1
                    event.thread.cont()
