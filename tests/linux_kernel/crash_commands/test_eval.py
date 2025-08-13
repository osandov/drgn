# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from pathlib import Path
import re
import tempfile

from drgn import Object
from drgn.commands.crash import CRASH_COMMAND_NAMESPACE
from tests.linux_kernel import possible_cpus, skip_unless_have_test_kmod
from tests.linux_kernel.crash_commands import CrashCommandTestCase


class TestEval(CrashCommandTestCase):
    def test_value(self):
        cmd = self.check_crash_command("eval 10")
        self.assertRegex(cmd.stdout, r"\bhexadecimal: a\b")
        self.assertRegex(cmd.stdout, r"\bdecimal: 10\b")
        self.assertRegex(cmd.stdout, r"\boctal: 12\b")
        self.assertRegex(cmd.stdout, r"\bbinary: 0*1010\b")

        self.assertIdentical(
            cmd.drgn_option.globals["value"], Object(self.prog, "unsigned long", 10)
        )
        self.assertIdentical(
            cmd.drgn_option.globals["signed"], Object(self.prog, "long", 10)
        )
        self.assertIsInstance(cmd.drgn_option.globals["in_units"], str)
        self.assertEqual(cmd.drgn_option.globals["in_hex"], "0xa")
        self.assertEqual(cmd.drgn_option.globals["in_octal"], "0o12")
        self.assertEqual(cmd.drgn_option.globals["in_binary"], "0b1010")

    def test_negate(self):
        cmd = self.check_crash_command("eval -99")
        self.assertRegex(cmd.stdout, r"\bhexadecimal: f+9d\b")
        self.assertRegex(cmd.stdout, r"\bdecimal: [0-9]+  \(-99\)")

        self.assertIdentical(
            cmd.drgn_option.globals["value"], Object(self.prog, "unsigned long", -99)
        )
        self.assertIdentical(
            cmd.drgn_option.globals["signed"], Object(self.prog, "long", -99)
        )

    def test_invert(self):
        cmd = self.check_crash_command("eval ~99")
        self.assertRegex(cmd.stdout, r"\bhexadecimal: f+9c\b")
        self.assertRegex(cmd.stdout, r"\bdecimal: [0-9]+  \(-100\)")

        self.assertIdentical(
            cmd.drgn_option.globals["value"], Object(self.prog, "unsigned long", ~99)
        )
        self.assertIdentical(
            cmd.drgn_option.globals["signed"], Object(self.prog, "long", ~99)
        )

    def test_multiple_unary(self):
        cmd = self.check_crash_command("eval -~--99")
        self.assertRegex(cmd.stdout, r"\bhexadecimal: 64\b")
        self.assertRegex(cmd.stdout, r"\bdecimal: 100\b")

        self.assertIdentical(
            cmd.drgn_option.globals["value"], Object(self.prog, "unsigned long", 100)
        )
        self.assertIdentical(
            cmd.drgn_option.globals["signed"], Object(self.prog, "long", 100)
        )

    def test_units(self):
        for value, in_units in (
            (1024, "1K"),
            (1024 * 1024, "1M"),
            (1024 * 1024 * 1024, "1G"),
        ):
            for expr in (str(value), in_units, in_units.lower()):
                with self.subTest(expr=expr):
                    cmd = self.check_crash_command("eval " + expr)
                    self.assertRegex(
                        cmd.stdout, rf"\bhexadecimal: {value:x}  \({in_units}B\)"
                    )
                    self.assertEqual(cmd.drgn_option.globals["in_units"], in_units)

    def test_negate_with_unit(self):
        cmd = self.check_crash_command("eval -1k")
        self.assertRegex(cmd.stdout, r"\bdecimal: [0-9]+  \(-1024\)")
        self.assertIdentical(
            cmd.drgn_option.globals["value"], Object(self.prog, "unsigned long", -1024)
        )

    def test_bits_set(self):
        cmd = self.check_crash_command("eval -b 10")
        self.assertRegex(cmd.stdout, r"\bbits set: 3 1\n")
        self.assertIdentical(cmd.drgn_option.globals["bits_set"], [1, 3])

    def test_long_long(self):
        cmd = self.check_crash_command("eval -l 10")
        self.assertRegex(
            cmd.stdout,
            r"\bbinary: 0000000000000000000000000000000000000000000000000000000000001010\b",
        )
        self.assertIdentical(
            cmd.drgn_option.globals["value"],
            Object(self.prog, "unsigned long long", 10),
        )

    def test_bits_set_and_long_long(self):
        cmd = self.check_crash_command("eval -bl 10")
        self.assertRegex(
            cmd.stdout,
            r"\bbinary: 0000000000000000000000000000000000000000000000000000000000001010\b",
        )
        self.assertRegex(cmd.stdout, r"\bbits set: 3 1\n")
        self.assertIdentical(cmd.drgn_option.globals["bits_set"], [1, 3])
        self.assertIdentical(
            cmd.drgn_option.globals["value"],
            Object(self.prog, "unsigned long long", 10),
        )

    def test_negative_b(self):
        cmd = self.check_crash_command("eval -b")
        self.assertRegex(cmd.stdout, r"\bdecimal: [0-9]+  \(-11\)")
        self.assertNotIn("bits set", cmd.stdout)
        self.assertIdentical(
            cmd.drgn_option.globals["value"], Object(self.prog, "unsigned long", -0xB)
        )

    def test_bits_set_in_negative_b(self):
        cmd = self.check_crash_command("eval -b -b")
        self.assertRegex(cmd.stdout, r"\bdecimal: [0-9]+  \(-11\)")
        self.assertIn("bits set", cmd.stdout)
        self.assertIn("bits_set", cmd.drgn_option.globals)

    def test_binary(self):
        for expr, result in (
            ("3 + 4", 7),
            ("4 - 3", 1),
            ("12 & 5", 4),
            ("(12 | 5)", 13),
            ("12 ^ 5", 9),
            ("12 * 5", 60),
            ("12 % 5", 2),
            ("16 / 5", 3),
            ("(3 << 5)", 96),
            ("(100 >> 1)", 50),
        ):
            cmd = self.check_crash_command("eval " + expr)
            self.assertRegex(cmd.stdout, rf"\bdecimal: {result}\b")
            self.assertIdentical(
                cmd.drgn_option.globals["value"],
                Object(self.prog, "unsigned long", result),
            )

    def test_pipe(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "file"
            CRASH_COMMAND_NAMESPACE.run(self.prog, f"eval (12 | 5) | grep 13 > {path}")
            self.assertRegex(path.read_text(), r"\bdecimal: 13\b")

    def test_redirect(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "file"
            CRASH_COMMAND_NAMESPACE.run(self.prog, f"eval (3 << 5) >> {path}")
            self.assertRegex(path.read_text(), r"\bdecimal: 96\b")


class TestP(CrashCommandTestCase):
    def test_object(self):
        cmd = self.check_crash_command("p jiffies")
        self.assertRegex(cmd.stdout, r"jiffies = \([^)]+\)[0-9]+")
        self.assertIdentical(cmd.drgn_option.globals["object"], self.prog["jiffies"])

    @skip_unless_have_test_kmod
    def test_cpuspec(self):
        cmd = self.check_crash_command("p drgn_test_percpu_structs:a")
        matches = re.findall(
            r"^per_cpu\(drgn_test_percpu_structs, ([0-9]+)\) = \(struct drgn_test_percpu_struct\)\{",
            cmd.stdout,
            flags=re.MULTILINE,
        )
        cpus = sorted(possible_cpus())
        self.assertEqual([int(match) for match in matches], cpus)
        self.assertIn("per_cpu(", cmd.drgn_option.stdout)
        self.assertEqual(cmd.drgn_option.globals["object"].cpu, max(cpus))

    def test_member(self):
        cmd = self.check_crash_command("p init_task.pid")
        self.assertRegex(cmd.stdout, r"init_task\.pid = \([^)]*\)0")
        self.assertIn(".pid", cmd.drgn_option.stdout)
        self.assertIdentical(
            cmd.drgn_option.globals["object"], self.prog["init_task"].pid
        )

    @skip_unless_have_test_kmod
    def test_radix(self):
        self.addCleanup(self.prog.config.pop, "crash_radix", None)

        self.run_crash_command("set radix 16")
        cmd = self.run_crash_command("p drgn_test_singular_list_entry")
        self.assertRegex(cmd.stdout, r"value = \([^)]+\)0x0")

        cmd = self.run_crash_command("p -d drgn_test_singular_list_entry")
        self.assertRegex(cmd.stdout, r"value = \([^)]+\)0\b")

        self.run_crash_command("set radix 10")
        cmd = self.run_crash_command("p drgn_test_singular_list_entry")
        self.assertRegex(cmd.stdout, r"value = \([^)]+\)0\b")

        cmd = self.run_crash_command("p -x drgn_test_singular_list_entry")
        self.assertRegex(cmd.stdout, r"value = \([^)]+\)0x0")
