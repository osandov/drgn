from tests.linux_kernel import skip_unless_have_test_kmod
from tests.linux_kernel.crash_commands import CrashCommandTestCase

class TestDis(CrashCommandTestCase):
    @skip_unless_have_test_kmod
    def test_dis_decimal(self):
        cmd = self.check_crash_command(f"dis drgn_test_kthread_fn")
        for line in cmd.stdout:
            self.assertRegex(line, r"^[0-9a-fA-F]+ <drgn_test_kthread\+\d+>")
