# Copyright (c) Daniel Thompson <daniel@redfelineninja.org.uk>
# SPDX-License-Identifier: LGPL-2.1-or-later

import ctypes
import multiprocessing
import socket
import time

from drgn import Architecture, PlatformFlags, Program, ProgramFlags, host_platform
from tests import TestCase

# These are captured replies from gdbserver/aarch64.
#
# Currently we do not need lookup tables for other architectures because
# drgn has limited support for other architectures. We can test memory
# reads on all (64-bit) architectures using this lookup table. More lookup
# tables will be required once other architectures are able to decode
# register data.
aarch64_lookup = {
    b"$?#3f": b'$T051d:40eef* 7f0*";1f:40eef* 7f0*";20:64075*"0*";thread:21cd;core:0;#c7',
    b"$g#67": b'$010**d8ef*!7f0*"e8ef*!7f0*"54075*"0*"0081fff77f0*"ddda0d494bedb2c17820f9f77f0*"49564154450*"d70**20*K240**57c10**f0fff77f0*"030**f00cfdf77f0*"8000f9f77f0*"00c0190*&d8ef*!7f0*"010**d0fd565* 0*"54075*"0*"e8ef*!7f0*"98dbfff77f0*228e0fff77f0*"d0fd565* 0*240eef* 7f0*"4077e1f77f0*"40eef* 7f0*"64075*"0*(80*=2e2f68656c6c6f005348454c4c3d2f6200330*&cc0*(330* ff0*4ff003*=0*!c0*"0030*}0*}0*}0*}0*}0*}0*}0*}0*v87fff77f0*2#76',
    b"$m7fffffee40,16#63": b'$60eef* 7f0*"4077e1f77f0*"d8ef*!7f00#c6',
    b"$m7fffffee60,16#65": b'$70ef*!7f0*"1878e1f77f0*"f00cfdf77f00#47',
    b"$m7fffffef70,16#67": b'$0*,70065*"0*.#5c',
}


class GdbMockProcess(multiprocessing.Process):
    def __init__(self):
        super().__init__(daemon=True)
        self.bound = multiprocessing.Value(ctypes.c_bool, False)
        self.lookup = aarch64_lookup

    def start(self):
        super().start()
        while not self.bound.value:
            time.sleep(0.01)

    def run(self):
        buf = b""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 65432))
            self.bound.value = True
            s.listen()
            conn, addr = s.accept()
            with conn:
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    buf += data

                    i = buf.find(b"$")
                    if i < 0:
                        buf = b""
                        continue
                    if i > 0:
                        buf = buf[i:]

                    i = buf.find(b"#")
                    if i < 0 or len(buf) <= i + 2:
                        continue

                    packet = buf[: i + 3]
                    buf = buf[i + 3 :]

                    conn.sendall(b"+")
                    if packet in self.lookup:
                        conn.sendall(self.lookup[packet])
                    else:
                        # $#00 means unsupported
                        conn.sendall(b"$#00")

    def clean_up(self):
        TIMEOUT = 5.0

        self.join(TIMEOUT)
        if self.is_alive():
            self.terminate()
            self.join(TIMEOUT)
            if self.is_alive():
                self.kill()
                self.join(TIMEOUT)


class TestGdbRemote(TestCase):
    def setUp(self):
        self.gdbmock = GdbMockProcess()
        self.gdbmock.start()
        self.conn_str = "localhost:65432"

        self.prog = Program()

    def tearDown(self):
        # Provide socket closure (to encourage the thread terminate cleanly)
        del self.prog
        self.gdbmock.clean_up()

    def test_program_set_gdbremote(self):
        prog = self.prog
        self.assertIsNone(prog.platform)
        self.assertFalse(prog.flags & ProgramFlags.IS_GDBREMOTE)

        prog.set_gdbremote(self.conn_str)
        self.assertEqual(prog.platform, host_platform)
        self.assertTrue(prog.flags & ProgramFlags.IS_GDBREMOTE)

        # Port 51 is for the obsolete IMP protocol and reserved since
        # 2013 meaning we can be fairly confident nobody is using it
        # (although that only matters if this test fails)
        self.assertRaisesRegex(
            ValueError,
            "program memory was already initialized",
            prog.set_gdbremote,
            "localhost:51",
        )

    def test_gdbremote_read(self):
        self.prog.set_gdbremote(self.conn_str)
        if not (self.prog.platform.flags & PlatformFlags.IS_64_BIT):
            self.skipTest("gdbremote test data only supports 64-bit platforms")
        val = self.prog.read(0x7FFFFFEE40, 16)
        self.assertEqual(
            val, b"`\xee\xff\xff\x7f\x00\x00\x00@w\xe1\xf7\x7f\x00\x00\x00"
        )

    def test_gdbremote_getregs(self):
        self.prog.set_gdbremote(self.conn_str)
        if self.prog.platform.arch != Architecture.AARCH64:
            self.skipTest("register packet decoding is not implemented for this arch")

        t = self.prog.threads().__next__()
        regs = t.stack_trace()[0].registers()
        self.assertEqual(regs["x0"], 1)
        self.assertEqual(regs["sp"], 0x7FFFFFEE40)
        self.assertEqual(regs["pstate"], 0x80000000)
