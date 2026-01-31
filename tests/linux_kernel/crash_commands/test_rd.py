# Copyright (c) 2025, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import ctypes
import math
import os
import tempfile

from drgn import Architecture, FaultError, PlatformFlags
from drgn.helpers.linux.pid import find_task
from tests.linux_kernel import skip_if_highmem, skip_unless_have_test_kmod
from tests.linux_kernel.crash_commands import CrashCommandTestCase


class TestRd(CrashCommandTestCase):
    def setUp(self):
        self.w = self.prog.address_size() * 2

    def test_no_options(self):
        address = self.prog["init_task"].address_
        cmd = self.check_crash_command(f"rd {address:x}")
        self.assertRegex(cmd.stdout, rf"^{address:{self.w}x}:")
        self.assertRegex(cmd.stdout, r"[0-9a-f]{" + str(self.w) + "}")

    def test_count(self):
        address = self.prog["init_task"].address_
        cmd = self.check_crash_command(f"rd -64 {address:x} 3")
        lines = cmd.stdout.splitlines()
        self.assertGreaterEqual(len(lines), 2)
        self.assertRegex(lines[0], rf"^{address:{self.w}x}:")

    def test_format_decimal(self):
        address = self.prog["init_task"].address_
        cmd = self.check_crash_command(f"rd -d {address:x}")
        self.assertRegex(cmd.stdout, rf"^{address:{self.w}x}:")
        # Should have decimal numbers
        self.assertRegex(cmd.stdout, r"\b-?\d+\b")

    def test_units(self):
        data = b"Linux ve"
        address = self.prog.symbol("linux_banner").address
        if self.prog.platform.flags & PlatformFlags.IS_LITTLE_ENDIAN:
            endian = "little"
        else:
            endian = "big"
        for unit in (1, 2, 4, 8):
            with self.subTest(unit=unit):
                count = 8 // unit
                cmd = self.check_crash_command(f"rd -{unit * 8} linux_banner {count}")
                value_list = []
                for i in range(count):
                    int_bytes = data[i * unit : (i + 1) * unit]
                    value_list.append(int.from_bytes(int_bytes, byteorder=endian))
                values = " ".join(f"{v:0{unit * 2}x}" for v in value_list)
                self.assertRegex(
                    cmd.stdout,
                    rf"^{address:{self.w}x}:  {values} +Linux ve$",
                )

    def test_network_byte_order(self):
        data = b"Linux ve"
        address = self.prog.symbol("linux_banner").address
        for unit in (2, 4, 8):
            with self.subTest(unit=unit):
                count = 8 // unit
                cmd = self.check_crash_command(
                    f"rd -{unit * 8} -N linux_banner {count}"
                )
                value_list = []
                for i in range(count):
                    int_bytes = data[i * unit : (i + 1) * unit]
                    value_list.append(int.from_bytes(int_bytes, byteorder="big"))
                values = " ".join(f"{v:0{unit * 2}x}" for v in value_list)
                self.assertRegex(
                    cmd.stdout,
                    rf"^{address:{self.w}x}:  {values} +Linux ve$",
                )

    def test_ascii(self):
        cmd = self.check_crash_command("rd -a linux_banner")
        address = self.prog.symbol("linux_banner").address
        self.assertRegex(cmd.stdout, rf"{address:{self.w}x}:  Linux version")
        lines = cmd.stdout.strip().split("\n")

        # The ascii variant formats output over multiple lines, breaking at 79
        # characters. The linux banner is good test data for this, because it
        # has no special whitespace and it is generally rather long. While we
        # don't necessarily care about the specific line break point, it is good
        # to verify that we get roughly the expected amount of output, as a
        # smoke test.
        string = self.prog["linux_banner"].string_()
        chars_per_line = 79 - self.w - 3
        line_count = math.ceil(len(string) / chars_per_line)
        self.assertEqual(len(lines), line_count)

    def test_ascii_count(self):
        cmd = self.check_crash_command("rd -a linux_banner 5")
        address = self.prog.symbol("linux_banner").address
        self.assertEqual(cmd.stdout.strip(), f"{address:x}:  Linux")

    def test_ascii_offset(self):
        address = self.prog.symbol("linux_banner").address
        cmd = self.check_crash_command("rd -o 4 -a linux_banner")
        self.assertRegex(cmd.stdout, f"^{address + 4:{self.w}x}:  x version.*")

    def test_symbol(self):
        address = self.prog["init_task"].address_
        cmd = self.check_crash_command("rd init_task")
        self.assertRegex(cmd.stdout, rf"^{address:{self.w}x}:")

    def test_annotate_symbols(self):
        address = self.prog["slab_caches"].prev.value_()
        cmd = self.check_crash_command(f"rd -s {address:x} 2")
        self.assertRegex(cmd.stdout, rf"^{address:{self.w}x}:  slab_caches\+0")

    @skip_unless_have_test_kmod
    def test_annotate_slab(self):
        address = self.prog.symbol("drgn_test_small_slab_objects").address
        cmd = self.check_crash_command("rd -S drgn_test_small_slab_objects 2")
        if self.prog["drgn_test_slob"]:
            self.assertRegex(
                cmd.stdout,
                rf"^{address:{self.w}x}:  \[unknown slab object\] +\[unknown slab object\]",
            )
        else:
            self.assertRegex(
                cmd.stdout,
                rf"^{address:{self.w}x}:  \[drgn_test_small\] +\[drgn_test_small\]",
            )

    @skip_unless_have_test_kmod
    def test_annotate_slab_verbose(self):
        address = self.prog.symbol("drgn_test_small_slab_objects").address
        cmd = self.check_crash_command("rd -SS drgn_test_small_slab_objects 2")
        if self.prog["drgn_test_slob"]:
            self.assertRegex(
                cmd.stdout,
                rf"^{address:{self.w}x}:  \[[0-9a-f]+:unknown slab object\] +\[[0-9a-f]+:unknown slab object\]",
            )
        else:
            self.assertRegex(
                cmd.stdout,
                rf"^{address:{self.w}x}:  \[[0-9a-f]+:drgn_test_small\] +\[[0-9a-f]+:drgn_test_small\]",
            )

    def test_reverse(self):
        address = self.prog["init_task"].address_
        cmd = self.check_crash_command(f"rd -R {address:x} 2")
        unit = self.prog.address_size()
        start_addr = address - unit
        self.assertRegex(cmd.stdout, rf"^{start_addr:{self.w}x}:  [0-9a-f]+ [0-9a-f]+")

    def test_raw(self):
        address = self.prog["init_task"].address_
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_file = f.name
            cmd = self.check_crash_command(f"rd -r {temp_file} {address:x} 16")
            self.assertIn("16 bytes copied", cmd.stdout)
            self.assertTrue(os.path.exists(temp_file))
            with open(temp_file, "rb") as f:
                data = f.read()
                self.assertEqual(len(data), 16)

    @skip_if_highmem
    def test_ascii_user(self):
        string = "hello, world!"
        buf = ctypes.create_string_buffer(string.encode("ascii"))
        address = ctypes.addressof(buf)
        self.prog.config["crash_context"] = find_task(self.prog, os.getpid())

        # On s390x, the user and kernel address spaces occupy the same range, so
        # we cannot detect whether an address is a user address. Explicitly pass
        # the hint here.
        need_hint = self.prog.platform.arch == Architecture.S390X

        expected_value = f"{address:{self.w}x}:  hello world, I am a string!"

        if not need_hint:
            with self.subTest("without -u hint"):
                cmd = self.check_crash_command(f"rd -a -o {self.w} 0x{address:x}")
                self.assertEqual(cmd.stdout.strip(), expected_value)
                self.assertIn("access_process_vm", cmd.drgn_option)
            self.assertNotIn("prog.read", cmd.drgn_option)
        with self.subTest("with -u hint"):
            cmd = self.check_crash_command(f"rd -u -a -o {self.w} 0x{address:x}")
            self.assertEqual(cmd.stdout.strip(), expected_value)
            self.assertIn("access_process_vm", cmd.drgn_option)
            self.assertNotIn("prog.read", cmd.drgn_option)

    def check_failing_command(self, command, exc_type):
        # Directly running the command should fail
        with self.assertRaises(exc_type):
            self.run_crash_command(command)

        # The drgn option should generate valid code that compiles
        self.run_crash_command_drgn_option(command, mode="compile")

        # But the code should also fail with the same error as the command
        with self.assertRaises(exc_type):
            self.run_crash_command_drgn_option(command, mode="exec")

    def test_not_existing_symbol(self):
        self.check_failing_command("rd this_symbol_does_not_exist", LookupError)

    def test_fault(self):
        self.check_failing_command("rd -u 0", FaultError)
