# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import signal
import unittest

import drgn
from drgn import Object, sizeof
from drgn.helpers.linux.mm import follow_phys
from tests.linux_kernel import (
    skip_unless_have_full_mm_support,
    skip_unless_have_test_kmod,
)
from tests.linux_kernel.crash_commands import CrashCommandTestCase


@skip_unless_have_test_kmod
class TestSearch(CrashCommandTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.subject = cls.prog["drgn_test_search_subject"]
        cls.subject_args = f"-s {cls.subject.address_:x} -l {sizeof(cls.subject)}"

    def test_long(self):
        cmd = self.check_crash_command(f"search {self.subject_args} deadbeef")
        self.assertRegex(
            cmd.stdout, rf"(?m)^\s*{self.subject.l.address_:x}:\s+deadbeef$"
        )

        self.assertIn("search_memory_word(0xdeadbeef)", cmd.drgn_option.stdout)
        self.assertEqual(cmd.drgn_option.globals["address"], self.subject.l.address_)
        self.assertEqual(cmd.drgn_option.globals["value"], 0xDEADBEEF)

    def test_int(self):
        cmd = self.check_crash_command(f"search {self.subject_args} -w deadb00")
        self.assertRegex(
            cmd.stdout, rf"(?m)^\s*{self.subject.i.address_:x}:\s+deadb00$"
        )

        self.assertIn("search_memory_u32(0xdeadb00)", cmd.drgn_option.stdout)
        self.assertEqual(cmd.drgn_option.globals["address"], self.subject.i.address_)
        self.assertEqual(cmd.drgn_option.globals["value"], 0xDEADB00)

    def test_short(self):
        cmd = self.check_crash_command(f"search {self.subject_args} -h b0ba")
        self.assertRegex(cmd.stdout, rf"(?m)^\s*{self.subject.s.address_:x}:\s+b0ba$")

        self.assertIn("search_memory_u16(0xb0ba)", cmd.drgn_option.stdout)
        self.assertEqual(cmd.drgn_option.globals["address"], self.subject.s.address_)
        self.assertEqual(cmd.drgn_option.globals["value"], 0xB0BA)

    def test_multiple(self):
        cmd = self.check_crash_command(f"search {self.subject_args} deadbeef fee1dead")
        self.assertRegex(
            cmd.stdout, rf"(?m)^\s*{self.subject.l.address_:x}:\s+deadbeef$"
        )
        self.assertRegex(
            cmd.stdout, rf"(?m)^\s*{self.subject.l2.address_:x}:\s+fee1dead$"
        )

        self.assertIn(
            "search_memory_word(0xdeadbeef, 0xfee1dead)", cmd.drgn_option.stdout
        )
        self.assertIn(
            cmd.drgn_option.globals["address"],
            (self.subject.l.address_, self.subject.l2.address_),
        )
        self.assertIn(cmd.drgn_option.globals["value"], (0xDEADBEEF, 0xFEE1DEAD))

    @unittest.skipUnless(drgn._with_pcre2, "built without pcre2 support")
    def test_string(self):
        cmd = self.check_crash_command(f"search {self.subject_args} -c 'hello, world!'")
        self.assertRegex(
            cmd.stdout,
            rf"(?m)^\s*{self.subject.c.address_:x}:\s+hello, world!\.{{43}}$",
        )

        self.assertIn('search_memory("hello, world!")', cmd.drgn_option.stdout)
        self.assertEqual(cmd.drgn_option.globals["address"], self.subject.c.address_)

    @unittest.skipUnless(drgn._with_pcre2, "built without pcre2 support")
    def test_multiple_strings(self):
        cmd = self.check_crash_command(
            f"search {self.subject_args} -c 'hello, world!' 'goodbye, world!'"
        )
        self.assertRegex(
            cmd.stdout,
            rf"(?m)^\s*{self.subject.c.address_:x}:\s+hello, world!\.{{43}}$",
        )
        self.assertRegex(
            cmd.stdout,
            rf"(?m)^\s*{self.subject.c2.address_:x}:\s+goodbye, world!\.{{41}}$",
        )

        self.assertIn(
            'search_memory_regex(rb"hello,\\ world!|goodbye,\\ world!")',
            cmd.drgn_option.stdout,
        )
        self.assertIn(
            cmd.drgn_option.globals["address"],
            (self.subject.c.address_, self.subject.c2.address_),
        )
        self.assertIn(
            cmd.drgn_option.globals["value"], (b"hello, world!", b"goodbye, world!")
        )

    def test_context(self):
        cmd = self.check_crash_command(f"search {self.subject_args} fee1dead -x 1")
        self.assertRegex(
            cmd.stdout, rf"(?m)^\s*{self.subject.l2.address_:x}:\s+fee1dead$"
        )
        self.assertIn("deadbeef", cmd.stdout)
        self.assertIn("deadb00", cmd.stdout)

        self.assertIn("search_memory_word(0xfee1dead)", cmd.drgn_option.stdout)
        self.assertEqual(cmd.drgn_option.globals["address"], self.subject.l2.address_)
        self.assertEqual(cmd.drgn_option.globals["value"], 0xFEE1DEAD)
        # Note: we don't do anything in the --drgn output for -x.

    def test_ignore_mask(self):
        cmd = self.check_crash_command(
            f"search {self.subject_args} 0e000e00 -m f0fff0ff"
        )
        self.assertRegex(
            cmd.stdout, rf"(?m)^\s*{self.subject.l.address_:x}:\s+deadbeef$"
        )
        self.assertRegex(
            cmd.stdout, rf"(?m)^\s*{self.subject.l2.address_:x}:\s+fee1dead$"
        )

        self.assertIn(
            "search_memory_word(0xe000e00, ignore_mask=0xf0fff0ff)",
            cmd.drgn_option.stdout,
        )
        self.assertIn(
            cmd.drgn_option.globals["address"],
            (self.subject.l.address_, self.subject.l2.address_),
        )
        self.assertIn(cmd.drgn_option.globals["value"], (0xDEADBEEF, 0xFEE1DEAD))

    def test_symbols(self):
        cmd = self.check_crash_command(
            f"search -s drgn_test_search_subject -l {sizeof(self.subject)} drgn_test_function"
        )
        sym_address = self.prog.symbol("drgn_test_function").address
        self.assertRegex(
            cmd.stdout,
            rf"(?m)^\s*{self.subject.func.address_:x}:\s+{sym_address:x}\s+\(drgn_test_function\)$",
        )

        self.assertIn(
            'search_memory_word(prog.symbol("drgn_test_function").address)',
            cmd.drgn_option.stdout,
        )
        self.assertIn(
            'prog.symbol("drgn_test_search_subject").address', cmd.drgn_option.stdout
        )
        self.assertEqual(cmd.drgn_option.globals["address"], self.subject.func.address_)
        self.assertEqual(cmd.drgn_option.globals["value"], sym_address)

    def test_end(self):
        start = self.subject.address_
        end = start + sizeof(self.subject)
        cmd = self.check_crash_command(f"search -s {start:x} -e {end:x} deadbeef")
        self.assertRegex(
            cmd.stdout, rf"(?m)^\s*{self.subject.l.address_:x}:\s+deadbeef$"
        )

        self.assertIn("search_memory_word(0xdeadbeef)", cmd.drgn_option.stdout)
        self.assertIn(
            f"set_address_range(min_address={start:#x}, max_address={end:#x} - 1)",
            cmd.drgn_option.stdout,
        )
        self.assertEqual(cmd.drgn_option.globals["address"], self.subject.l.address_)
        self.assertEqual(cmd.drgn_option.globals["value"], 0xDEADBEEF)

    @skip_unless_have_full_mm_support
    def test_physical(self):
        subject = self.prog["drgn_test_search_subject2"]
        address = follow_phys(self.prog["init_mm"].address_of_(), subject).value_()
        cmd = self.check_crash_command(
            f"search -p -s {address:x} -l {sizeof(subject[0])} 12345678"
        )
        self.assertRegex(cmd.stdout, rf"(?m)^\s*{address:x}:\s+12345678$")

        self.assertIn("search_memory_word(0x12345678)", cmd.drgn_option.stdout)
        self.assertIn("physical=True", cmd.drgn_option.stdout)
        self.assertEqual(cmd.drgn_option.globals["address"], address)
        self.assertEqual(cmd.drgn_option.globals["value"], 0x12345678)

    def test_task_stacks(self):
        value = self.prog["drgn_test_small_slab_objects"][0].value_()
        cmd = self.check_crash_command(f"search -t {value:x}")
        # drgn_test_kthread gets truncated to 16 bytes (including the null
        # terminator).
        self.assertIn("drgn_test_kthre", cmd.stdout)

        self.assertIn(f"search_memory_word({value:#x})", cmd.drgn_option.stdout)
        self.assertIn("for_each_task(", cmd.drgn_option.stdout)
        self.assertIn("set_address_range(stack", cmd.drgn_option.stdout)
        self.assertIsInstance(cmd.drgn_option.globals["task"], Object)

    def test_active_task_stacks(self):
        # We don't have a good way to exercise this, so just test that it runs.
        self.check_crash_command("search -T deadbeef")

    def test_no_start_or_end(self):
        def handler(signum, frame):
            raise TimeoutError()

        old_handler = signal.signal(signal.SIGALRM, handler)
        self.addCleanup(signal.signal, signal.SIGALRM, old_handler)

        try:
            # We don't want to wait to search all of memory, so just run the
            # code for a short time.
            signal.setitimer(signal.ITIMER_REAL, 0.1)
            self.run_crash_command_drgn_option("search deadbeef")
        except TimeoutError:
            pass
