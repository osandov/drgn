# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from pathlib import Path
import re

from drgn import offsetof, reinterpret
from tests.linux_kernel import parse_range_list, skip_unless_have_test_kmod
from tests.linux_kernel.crash_commands import CrashCommandTestCase

POSSIBLE_CPUS_PATH = Path("/sys/devices/system/cpu/possible")


class TestStruct(CrashCommandTestCase):
    def test_type(self):
        cmd = self.check_crash_command("struct list_head")
        self.assertIn("struct list_head {", cmd.stdout)
        self.assertRegex(cmd.stdout, "(?m)^SIZE: [0-9]+$")
        self.assertEqual(
            cmd.drgn_option.globals["type"].type_name(), "struct list_head"
        )
        self.assertIsInstance(cmd.drgn_option.globals["size"], int)

    def test_type_member(self):
        cmd = self.check_crash_command("struct list_head.next")
        self.assertIn("typeof_member", cmd.stdout)
        self.assertIn("offsetof", cmd.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["member_type"].type_name(), "struct list_head *"
        )
        self.assertIsInstance(cmd.drgn_option.globals["offset"], int)

    @skip_unless_have_test_kmod
    def test_address(self):
        address = self.prog["drgn_test_singular_list"].address_
        cmd = self.check_crash_command(f"struct list_head {address:x}")
        self.assertIn("(struct list_head){", cmd.stdout)
        self.assertIn(
            'Object(prog, "struct list_head", address=0x', cmd.drgn_option.stdout
        )
        self.assertIdentical(
            cmd.drgn_option.globals["object"], self.prog["drgn_test_singular_list"]
        )

    @skip_unless_have_test_kmod
    def test_symbol(self):
        cmd = self.check_crash_command("struct list_head drgn_test_singular_list")
        self.assertIn("(struct list_head){", cmd.stdout)
        self.assertIn(
            "object = prog['drgn_test_singular_list']", cmd.drgn_option.stdout
        )
        self.assertIdentical(
            cmd.drgn_option.globals["object"], self.prog["drgn_test_singular_list"]
        )

    @skip_unless_have_test_kmod
    def test_symbol_wrong_type(self):
        cmd = self.check_crash_command("struct hlist_head drgn_test_singular_list")
        self.assertIn("(struct hlist_head){", cmd.stdout)
        self.assertIn("prog.symbol", cmd.drgn_option.stdout)
        self.assertIdentical(
            cmd.drgn_option.globals["object"],
            reinterpret("struct hlist_head", self.prog["drgn_test_singular_list"]),
        )

    def test_cpuspec(self):
        cmd = self.check_crash_command("struct rq runqueues:a")
        cpus = sorted(parse_range_list(POSSIBLE_CPUS_PATH.read_text()))
        matches = re.findall(
            r"^\[([0-9]+)\]: [0-9a-f]+\n\(struct rq\)\{", cmd.stdout, flags=re.MULTILINE
        )
        self.assertEqual([int(match) for match in matches], cpus)
        self.assertEqual(cmd.drgn_option.globals["pcpu_object"].cpu, cpus[-1])

    def test_member(self):
        cmd = self.check_crash_command("struct task_struct.pid init_task")
        self.assertRegex(cmd.stdout, r"pid = \([^)]*\)0")
        self.assertIn(".pid", cmd.drgn_option.stdout)
        self.assertEqual(cmd.drgn_option.globals["object"], 0)

    def test_member_and_cpuspec(self):
        cmd = self.check_crash_command("struct rq.cpu runqueues:a")
        cpus = sorted(parse_range_list(POSSIBLE_CPUS_PATH.read_text()))
        matches = re.findall(r"cpu = \([^)]*\)([0-9]+)", cmd.stdout, flags=re.MULTILINE)
        self.assertEqual([int(match) for match in matches], cpus)
        self.assertEqual(cmd.drgn_option.globals["pcpu_object"], cpus[-1])

    @skip_unless_have_test_kmod
    def test_container_of_address(self):
        address = hex(self.prog["drgn_test_singular_list"].next)
        cmd = self.check_crash_command(
            f"struct drgn_test_list_entry {address} -l drgn_test_list_entry.node"
        )
        self.assertIn("(struct drgn_test_list_entry){", cmd.stdout)
        self.assertIn(".value = (int)0,", cmd.stdout)
        self.assertIn("container_of(", cmd.drgn_option.stdout)
        self.assertIdentical(
            cmd.drgn_option.globals["object"],
            self.prog["drgn_test_singular_list_entry"],
        )

    @skip_unless_have_test_kmod
    def test_container_of_address_wrong_type(self):
        address = hex(self.prog["drgn_test_singular_list"].next)
        cmd = self.check_crash_command(
            f"struct hlist_head {address} -l drgn_test_list_entry.node"
        )
        self.assertIn("(struct hlist_head){", cmd.stdout)
        self.assertIn("container_of(", cmd.drgn_option.stdout)
        self.assertIn("reinterpret(", cmd.drgn_option.stdout)
        self.assertIdentical(
            cmd.drgn_option.globals["object"],
            reinterpret(
                "struct hlist_head", self.prog["drgn_test_singular_list_entry"]
            ),
        )

    @skip_unless_have_test_kmod
    def test_address_and_offset(self):
        address = hex(self.prog["drgn_test_singular_list"].next)
        offset = offsetof(self.prog.type("struct drgn_test_list_entry"), "node")
        cmd = self.check_crash_command(
            f"struct drgn_test_list_entry {address} -l {offset}"
        )
        self.assertIn("(struct drgn_test_list_entry){", cmd.stdout)
        self.assertIn(".value = (int)0,", cmd.stdout)
        self.assertIn(f"- {offset}", cmd.drgn_option.stdout)
        self.assertIdentical(
            cmd.drgn_option.globals["object"],
            self.prog["drgn_test_singular_list_entry"],
        )

    @skip_unless_have_test_kmod
    def test_container_of_address_with_member(self):
        address = hex(self.prog["drgn_test_singular_list"].next)
        cmd = self.check_crash_command(
            f"struct drgn_test_list_entry.value {address} -l drgn_test_list_entry.node"
        )
        self.assertIn("(int)0", cmd.stdout)
        self.assertIn("container_of(", cmd.drgn_option.stdout)
        self.assertIdentical(
            cmd.drgn_option.globals["object"],
            self.prog["drgn_test_singular_list_entry"].value,
        )

    def test_invalid_structure_name(self):
        self.assertRaisesRegex(
            ValueError,
            "invalid structure name",
            self.check_crash_command,
            "struct 1234",
        )

    def test_invalid_member(self):
        self.assertRaisesRegex(
            ValueError,
            "invalid member name",
            self.check_crash_command,
            "struct rq.[1]",
        )
        self.assertRaisesRegex(
            ValueError,
            "invalid member name",
            self.check_crash_command,
            "struct rq.2",
        )
