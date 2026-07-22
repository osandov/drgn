from tests.linux_kernel.crash_commands import CrashCommandTestCase

_CHECK_REGEX_DECIMAL = r"0x[0-9a-fA-F]+ <__schedule\+\d+>"
_CHECK_REGEX_HEX = r"0x[0-9a-fA-F]+ <__schedule\+0x[0-9a-fA-F]+>"


class TestDis(CrashCommandTestCase):
    def test_dis_decimal(self):
        cmd = self.check_crash_command("dis __schedule")
        self.assertRegex(cmd.stdout, _CHECK_REGEX_DECIMAL)

    def test_dis_decimal_addr(self):
        symbol = self.prog.symbol("__schedule")
        cmd = self.check_crash_command(f"dis 0x{symbol.address:x}")
        self.assertRegex(cmd.stdout, _CHECK_REGEX_DECIMAL)

    def test_dis_decimal_forward(self):
        cmd = self.check_crash_command("dis -f __schedule")
        self.assertRegex(cmd.stdout, _CHECK_REGEX_DECIMAL)

    def test_dis_decimal_reverse(self):
        symbol = self.prog.symbol("__schedule")
        cmd = self.check_crash_command(f"dis -r 0x{symbol.address+20:x}")
        self.assertRegex(cmd.stdout, _CHECK_REGEX_DECIMAL)

    def test_dis_decimal_explicit(self):
        cmd = self.check_crash_command("dis -d __schedule")
        self.assertRegex(cmd.stdout, _CHECK_REGEX_DECIMAL)

    def test_dis_decimal_explicit_forward(self):
        cmd = self.check_crash_command("dis -f -d __schedule")
        self.assertRegex(cmd.stdout, _CHECK_REGEX_DECIMAL)

    def test_dis_decimal_explicit_with_length(self):
        cmd = self.check_crash_command("dis -d __schedule 20")
        self.assertRegex(cmd.stdout, _CHECK_REGEX_DECIMAL)

    def test_dis_decimal_explicit_forward_with_length(self):
        cmd = self.check_crash_command("dis -f -d __schedule 20")
        self.assertRegex(cmd.stdout, _CHECK_REGEX_DECIMAL)

    def test_dis_hexadecimal(self):
        cmd = self.check_crash_command("dis -x __schedule")
        self.assertRegex(cmd.stdout, _CHECK_REGEX_HEX)

    def test_dis_hexadecimal_with_length_with_length(self):
        cmd = self.check_crash_command("dis -x __schedule 20")
        self.assertRegex(cmd.stdout, _CHECK_REGEX_HEX)
