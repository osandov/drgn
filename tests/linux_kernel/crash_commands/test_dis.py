# Copyright (c) IBM Corp. 2026
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Tests for crash dis command."""

from tests import skip_unless_have_capstone
from tests.linux_kernel.crash_commands import CrashCommandTestCase

_CHECK_REGEX_DECIMAL = r"(?m)^0x[0-9a-f]+ <__schedule\+\d+>: "
_CHECK_REGEX_HEX = r"(?m)^0x[0-9a-f]+ <__schedule\+0x[0-9a-f]+>: "


@skip_unless_have_capstone
class TestDis(CrashCommandTestCase):
    def test_dis_decimal(self):
        cmd = self.check_crash_command("dis __schedule")
        self.assertRegex(cmd.stdout, r"^0x[0-9a-f]+ <__schedule>: ")
        self.assertRegex(cmd.stdout, _CHECK_REGEX_DECIMAL)
        self.assertIn('disasm("__schedule"', cmd.drgn_option.stdout)
        self.assertIn("offset_base=10", cmd.drgn_option.stdout)
        self.assertNotIn("num_insns", cmd.drgn_option.stdout)

    def test_dis_decimal_addr(self):
        symbol = self.prog.symbol("__schedule")
        cmd = self.check_crash_command(f"dis {symbol.address:x}")
        self.assertRegex(cmd.stdout, _CHECK_REGEX_DECIMAL)
        self.assertIn(f"disasm({symbol.address:#x}", cmd.drgn_option.stdout)
        self.assertIn("offset_base=10", cmd.drgn_option.stdout)
        self.assertNotIn("num_insns", cmd.drgn_option.stdout)

    def test_dis_decimal_offset(self):
        symbol = self.prog.symbol("__schedule")
        for address in (f"{symbol.address + 4:x}", "__schedule+4"):
            with self.subTest(address=address):
                cmd = self.check_crash_command(f"dis {address}")
                self.assertRegex(
                    cmd.stdout, rf"^{symbol.address + 4:#x} <__schedule\+4>: .*\n$"
                )
                self.assertIn("num_insns=1", cmd.drgn_option.stdout)

    def test_dis_decimal_forward(self):
        cmd = self.check_crash_command("dis -f __schedule+4")
        self.assertRegex(cmd.stdout, r"^0x[0-9a-f]+ <__schedule\+4>: .*\n0x")
        self.assertIn('mode="from"', cmd.drgn_option.stdout)

    def test_dis_decimal_reverse(self):
        cmd = self.check_crash_command("dis -r __schedule+20")
        self.assertRegex(cmd.stdout, r"^0x[0-9a-f]+ <__schedule>: ")
        self.assertIn('mode="up_to"', cmd.drgn_option.stdout)

    def test_dis_decimal_reverse_with_length(self):
        cmd = self.check_crash_command("dis -r __schedule+20 2")
        self.assertEqual(len(cmd.stdout.splitlines()), 2)
        self.assertIn('mode="up_to"', cmd.drgn_option.stdout)
        self.assertIn("num_insns=2", cmd.drgn_option.stdout)

    def test_dis_decimal_explicit(self):
        cmd = self.check_crash_command("dis -d __schedule")
        self.assertRegex(cmd.stdout, _CHECK_REGEX_DECIMAL)

    def test_dis_decimal_explicit_forward(self):
        cmd = self.check_crash_command("dis -f -d __schedule")
        self.assertRegex(cmd.stdout, _CHECK_REGEX_DECIMAL)

    def test_dis_decimal_explicit_with_length(self):
        cmd = self.check_crash_command("dis -d __schedule 4")
        self.assertRegex(cmd.stdout, _CHECK_REGEX_DECIMAL)
        self.assertEqual(len(cmd.stdout.splitlines()), 4)

    def test_dis_decimal_explicit_forward_with_length(self):
        cmd = self.check_crash_command("dis -f -d __schedule 4")
        self.assertRegex(cmd.stdout, _CHECK_REGEX_DECIMAL)
        self.assertEqual(len(cmd.stdout.splitlines()), 4)

    def test_dis_hexadecimal(self):
        cmd = self.check_crash_command("dis -x __schedule")
        self.assertRegex(cmd.stdout, _CHECK_REGEX_HEX)
        self.assertIn('disasm("__schedule"', cmd.drgn_option.stdout)
        self.assertNotIn("offset_base=10", cmd.drgn_option.stdout)

    def test_dis_hexadecimal_with_length(self):
        cmd = self.check_crash_command("dis -x __schedule 20")
        self.assertRegex(cmd.stdout, _CHECK_REGEX_HEX)
        self.assertEqual(len(cmd.stdout.splitlines()), 20)

    def test_dis_radix(self):
        self.addCleanup(self.prog.config.pop, "crash_radix", None)
        self.run_crash_command("set radix 16")
        cmd = self.check_crash_command("dis __schedule")
        self.assertRegex(cmd.stdout, _CHECK_REGEX_HEX)
        self.assertNotIn("offset_base=10", cmd.drgn_option.stdout)
