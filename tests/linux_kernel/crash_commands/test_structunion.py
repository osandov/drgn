# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import re

from drgn import Object, offsetof, reinterpret
from drgn.commands import CommandError, CommandNotFoundError
from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.sched import task_thread_info
from tests.linux_kernel import possible_cpus, skip_unless_have_test_kmod
from tests.linux_kernel.crash_commands import CrashCommandTestCase


class TestStruct(CrashCommandTestCase):
    def test_type(self):
        cmd = self.check_crash_command("struct list_head")
        self.assertIn("struct list_head {", cmd.stdout)
        self.assertRegex(cmd.stdout, "(?m)^SIZE: [0-9]+$")
        self.assertEqual(
            cmd.drgn_option.globals["type"].type_name(), "struct list_head"
        )
        self.assertIsInstance(cmd.drgn_option.globals["size"], int)

    def test_typedef(self):
        # atomic_t is a typedef of an anonymous struct. Crash allows this.
        cmd = self.check_crash_command("struct atomic_t")
        self.assertIn("} atomic_t", cmd.stdout)
        self.assertIn('prog.type("atomic_t")', cmd.drgn_option.stdout)
        self.assertEqual(cmd.drgn_option.globals["type"].type_name(), "atomic_t")

    def test_not_found(self):
        self.assertRaises(
            LookupError, self.run_crash_command, "struct drgn_test_non_existent"
        )

    def test_not_found_drgn_option(self):
        cmd = self.run_crash_command_drgn_option(
            "struct drgn_test_non_existent", mode="compile"
        )
        self.assertIn('prog.type("struct drgn_test_non_existent")', cmd.stdout)

    @skip_unless_have_test_kmod
    def test_union(self):
        self.assertRaises(LookupError, self.run_crash_command, "struct drgn_test_union")

    @skip_unless_have_test_kmod
    def test_anonymous_union(self):
        self.assertRaises(
            LookupError, self.run_crash_command, "struct drgn_test_anonymous_union"
        )

    def test_type_member(self):
        cmd = self.check_crash_command("struct list_head.next")
        self.assertRegex(cmd.stdout, r"\[[0-9]+\] struct list_head \*next;")
        self.assertEqual(
            cmd.drgn_option.globals["next_type"].type_name(), "struct list_head *"
        )
        self.assertIsInstance(cmd.drgn_option.globals["next_offset"], int)

    def test_type_multiple_members(self):
        cmd = self.check_crash_command("struct list_head.next,prev")
        self.assertRegex(cmd.stdout, r"\[[0-9]+\] struct list_head \*next;")
        self.assertRegex(cmd.stdout, r"\[[0-9]+\] struct list_head \*prev;")
        self.assertEqual(
            cmd.drgn_option.globals["next_type"].type_name(), "struct list_head *"
        )
        self.assertIsInstance(cmd.drgn_option.globals["next_offset"], int)
        self.assertEqual(
            cmd.drgn_option.globals["prev_type"].type_name(), "struct list_head *"
        )
        self.assertIsInstance(cmd.drgn_option.globals["prev_offset"], int)

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
            'object = prog["drgn_test_singular_list"]', cmd.drgn_option.stdout
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

    def test_member(self):
        cmd = self.check_crash_command("struct task_struct.pid init_task")
        self.assertRegex(cmd.stdout, r"pid = \([^)]*\)0")
        self.assertIn(".pid", cmd.drgn_option.stdout)
        self.assertIdentical(cmd.drgn_option.globals["object"], self.prog["init_task"])
        self.assertEqual(cmd.drgn_option.globals["pid"], 0)

    def test_multiple_members(self):
        cmd = self.check_crash_command("struct task_struct.pid,tgid init_task")
        self.assertRegex(cmd.stdout, r"pid = \([^)]*\)0")
        self.assertRegex(cmd.stdout, r"tgid = \([^)]*\)0")
        self.assertIn(".pid", cmd.drgn_option.stdout)
        self.assertIn(".tgid", cmd.drgn_option.stdout)
        self.assertIdentical(cmd.drgn_option.globals["object"], self.prog["init_task"])
        self.assertEqual(cmd.drgn_option.globals["pid"], 0)
        self.assertEqual(cmd.drgn_option.globals["tgid"], 0)

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
    def test_container_of_address_with_member(self):
        address = hex(self.prog["drgn_test_singular_list"].next)
        cmd = self.check_crash_command(
            f"struct drgn_test_list_entry.value {address} -l drgn_test_list_entry.node"
        )
        self.assertIn("(int)0", cmd.stdout)
        self.assertIn("container_of(", cmd.drgn_option.stdout)
        self.assertIdentical(
            cmd.drgn_option.globals["object"],
            self.prog["drgn_test_singular_list_entry"],
        )
        self.assertIdentical(
            cmd.drgn_option.globals["value"],
            self.prog["drgn_test_singular_list_entry"].value,
        )

    @skip_unless_have_test_kmod
    def test_positional_count(self):
        cmd = self.check_crash_command(
            "struct drgn_test_list_entry drgn_test_list_entries 3"
        )
        self.assertEqual(cmd.stdout.count("(struct drgn_test_list_entry){"), 3)
        self.assertIn("for object in pointer[:3]", cmd.drgn_option.stdout)
        self.assertIdentical(
            cmd.drgn_option.globals["object"], self.prog["drgn_test_list_entries"][2]
        )

    @skip_unless_have_test_kmod
    def test_count_option(self):
        cmd = self.check_crash_command(
            "struct drgn_test_list_entry drgn_test_list_entries -c 3"
        )
        self.assertEqual(cmd.stdout.count("(struct drgn_test_list_entry){"), 3)
        self.assertIn("for object in pointer[:3]", cmd.drgn_option.stdout)
        self.assertIdentical(
            cmd.drgn_option.globals["object"], self.prog["drgn_test_list_entries"][2]
        )

    @skip_unless_have_test_kmod
    def test_negative_count(self):
        address = self.prog["drgn_test_list_entries"][2].address_
        cmd = self.check_crash_command(
            f"struct drgn_test_list_entry {hex(address)} -c -3"
        )
        self.assertEqual(cmd.stdout.count("(struct drgn_test_list_entry){"), 3)
        self.assertIn("for object in pointer[-2:1]", cmd.drgn_option.stdout)
        self.assertIdentical(
            cmd.drgn_option.globals["object"], self.prog["drgn_test_list_entries"][2]
        )

    @skip_unless_have_test_kmod
    def test_count_with_member(self):
        cmd = self.check_crash_command(
            "struct drgn_test_list_entry.value drgn_test_list_entries 3"
        )
        self.assertEqual(cmd.stdout.count("(int)"), 3)
        self.assertIn("for object in pointer[:3]", cmd.drgn_option.stdout)
        self.assertIn("    value = object.value", cmd.drgn_option.stdout)
        self.assertIdentical(
            cmd.drgn_option.globals["value"],
            self.prog["drgn_test_list_entries"][2].value,
        )

    @skip_unless_have_test_kmod
    def test_count_with_offset(self):
        address = self.prog["drgn_test_list_entries"][0].value.address_
        offset = offsetof(self.prog.type("struct drgn_test_list_entry"), "value")
        cmd = self.check_crash_command(
            f"struct drgn_test_list_entry {hex(address)} -l {offset} -c 3"
        )
        self.assertEqual(cmd.stdout.count("(struct drgn_test_list_entry){"), 3)
        self.assertIn(f"- {offset}", cmd.drgn_option.stdout)
        self.assertIn("for object in pointer[:3]", cmd.drgn_option.stdout)
        self.assertIdentical(
            cmd.drgn_option.globals["object"], self.prog["drgn_test_list_entries"][2]
        )

    @skip_unless_have_test_kmod
    def test_count_with_container_of(self):
        address = self.prog["drgn_test_list_entries"][0].value.address_
        cmd = self.check_crash_command(
            f"struct drgn_test_list_entry {hex(address)} -l drgn_test_list_entry.value -c 3"
        )
        self.assertEqual(cmd.stdout.count("(struct drgn_test_list_entry){"), 3)
        self.assertIn("container_of(", cmd.drgn_option.stdout)
        self.assertIn("for object in pointer[:3]", cmd.drgn_option.stdout)
        self.assertIdentical(
            cmd.drgn_option.globals["object"], self.prog["drgn_test_list_entries"][2]
        )

    @skip_unless_have_test_kmod
    def test_count_with_offset_and_member(self):
        address = self.prog["drgn_test_list_entries"][0].value.address_
        offset = offsetof(self.prog.type("struct drgn_test_list_entry"), "value")
        cmd = self.check_crash_command(
            f"struct drgn_test_list_entry.value {hex(address)} -l {offset} -c 3"
        )
        self.assertEqual(cmd.stdout.count("(int)"), 3)
        self.assertIn(f"- {offset}", cmd.drgn_option.stdout)
        self.assertIn("for object in pointer[:3]", cmd.drgn_option.stdout)
        self.assertIn("    value = object.value", cmd.drgn_option.stdout)
        self.assertIdentical(
            cmd.drgn_option.globals["object"], self.prog["drgn_test_list_entries"][2]
        )
        self.assertIdentical(
            cmd.drgn_option.globals["value"],
            self.prog["drgn_test_list_entries"][2].value,
        )

    @skip_unless_have_test_kmod
    def test_count_with_container_of_and_member(self):
        address = self.prog["drgn_test_list_entries"][0].value.address_
        cmd = self.check_crash_command(
            f"struct drgn_test_list_entry.value {hex(address)} -l drgn_test_list_entry.value -c 3"
        )
        self.assertEqual(cmd.stdout.count("(int)"), 3)
        self.assertIn("container_of(", cmd.drgn_option.stdout)
        self.assertIn("for object in pointer[:3]", cmd.drgn_option.stdout)
        self.assertIn("    value = object.value", cmd.drgn_option.stdout)
        self.assertIdentical(
            cmd.drgn_option.globals["object"], self.prog["drgn_test_list_entries"][2]
        )
        self.assertIdentical(
            cmd.drgn_option.globals["value"],
            self.prog["drgn_test_list_entries"][2].value,
        )

    @skip_unless_have_test_kmod
    def test_cpuspec(self):
        cmd = self.check_crash_command(
            "struct drgn_test_percpu_struct drgn_test_percpu_structs:a"
        )
        cpus = sorted(possible_cpus())
        matches = re.findall(
            r"^\[([0-9]+)\]: [0-9a-f]+\n\(struct drgn_test_percpu_struct\)\{",
            cmd.stdout,
            flags=re.MULTILINE,
        )
        self.assertEqual([int(match) for match in matches], cpus)
        self.assertIn("per_cpu(", cmd.drgn_option.stdout)
        self.assertEqual(cmd.drgn_option.globals["object"].cpu, max(cpus))

    @skip_unless_have_test_kmod
    def test_cpuspec_with_member(self):
        cmd = self.check_crash_command(
            "struct drgn_test_percpu_struct.cpu drgn_test_percpu_structs:a"
        )
        cpus = sorted(possible_cpus())
        matches = re.findall(r"cpu = \([^)]*\)([0-9]+)", cmd.stdout, flags=re.MULTILINE)
        self.assertEqual([int(match) for match in matches], cpus)
        self.assertIn("per_cpu(", cmd.drgn_option.stdout)
        self.assertEqual(cmd.drgn_option.globals["object"].cpu, max(cpus))
        self.assertEqual(cmd.drgn_option.globals["cpu"], max(cpus))

    @skip_unless_have_test_kmod
    def test_cpuspec_with_count(self):
        cmd = self.check_crash_command(
            "struct drgn_test_percpu_struct drgn_test_percpu_arrays:a 3"
        )
        cpus = sorted(possible_cpus())
        matches = re.findall(
            r"(cpu|i) = \([^)]*\)([0-9]+)", cmd.stdout, flags=re.MULTILINE
        )
        expected = []
        for cpu in cpus:
            for i in range(3):
                expected.append(("cpu", str(cpu)))
                expected.append(("i", str(i)))
        self.assertEqual(matches, expected)
        self.assertEqual(cmd.drgn_option.globals["object"].cpu, max(cpus))
        self.assertEqual(cmd.drgn_option.globals["object"].i, 2)

    @skip_unless_have_test_kmod
    def test_cpuspec_with_count_and_members(self):
        cmd = self.check_crash_command(
            "struct drgn_test_percpu_struct.cpu,i drgn_test_percpu_arrays:a 3"
        )
        cpus = sorted(possible_cpus())
        matches = re.findall(
            r"^(cpu|i) = \([^)]*\)([0-9]+)", cmd.stdout, flags=re.MULTILINE
        )
        expected = []
        for cpu in cpus:
            for i in range(3):
                expected.append(("cpu", str(cpu)))
                expected.append(("i", str(i)))
        self.assertEqual(matches, expected)
        self.assertEqual(cmd.drgn_option.globals["object"].cpu, max(cpus))
        self.assertEqual(cmd.drgn_option.globals["object"].i, 2)
        self.assertEqual(cmd.drgn_option.globals["cpu"], max(cpus))
        self.assertEqual(cmd.drgn_option.globals["i"], 2)

    @skip_unless_have_test_kmod
    def test_radix(self):
        self.addCleanup(self.prog.config.pop, "crash_radix", None)

        self.run_crash_command("set radix 16")
        cmd = self.run_crash_command(
            "struct drgn_test_list_entry drgn_test_singular_list_entry"
        )
        self.assertRegex(cmd.stdout, r"value = \([^)]+\)0x0")

        cmd = self.run_crash_command(
            "struct drgn_test_list_entry drgn_test_singular_list_entry -d"
        )
        self.assertRegex(cmd.stdout, r"value = \([^)]+\)0\b")

        self.run_crash_command("set radix 10")
        cmd = self.run_crash_command(
            "struct drgn_test_list_entry drgn_test_singular_list_entry"
        )
        self.assertRegex(cmd.stdout, r"value = \([^)]+\)0\b")

        cmd = self.run_crash_command(
            "struct drgn_test_list_entry drgn_test_singular_list_entry -x"
        )
        self.assertRegex(cmd.stdout, r"value = \([^)]+\)0x0")

    def test_type_with_count(self):
        self.assertRaisesRegex(
            CommandError,
            "requires address",
            self.run_crash_command,
            "struct list_head -c 1",
        )

    def test_type_with_offset(self):
        self.assertRaisesRegex(
            CommandError,
            "requires address",
            self.run_crash_command,
            "struct list_head -l 0",
        )

    def test_invalid_structure_name(self):
        self.assertRaisesRegex(
            ValueError,
            "invalid type name",
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


class TestUnion(CrashCommandTestCase):
    @skip_unless_have_test_kmod
    def test_type(self):
        cmd = self.check_crash_command("union drgn_test_union")
        self.assertIn("union drgn_test_union {", cmd.stdout)
        self.assertRegex(cmd.stdout, "(?m)^SIZE: [0-9]+$")
        self.assertEqual(
            cmd.drgn_option.globals["type"].type_name(), "union drgn_test_union"
        )
        self.assertIsInstance(cmd.drgn_option.globals["size"], int)

    @skip_unless_have_test_kmod
    def test_typedef(self):
        cmd = self.check_crash_command("union drgn_test_anonymous_union")
        self.assertIn("} drgn_test_anonymous_union", cmd.stdout)
        self.assertIn('prog.type("drgn_test_anonymous_union")', cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["type"].type_name(), "drgn_test_anonymous_union"
        )

    def test_struct(self):
        self.assertRaises(LookupError, self.run_crash_command, "union task_struct")

    def test_anonymous_struct(self):
        self.assertRaises(LookupError, self.run_crash_command, "union atomic_t")


class TestAsterisk(CrashCommandTestCase):
    def test_struct(self):
        cmd = self.check_crash_command("*list_head")
        self.assertIn("struct list_head {", cmd.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["type"].type_name(), "struct list_head"
        )

    def test_struct_with_space(self):
        cmd = self.check_crash_command("* list_head")
        self.assertIn("struct list_head {", cmd.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["type"].type_name(), "struct list_head"
        )

    @skip_unless_have_test_kmod
    def test_union(self):
        cmd = self.check_crash_command("*drgn_test_union")
        self.assertIn("union drgn_test_union {", cmd.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["type"].type_name(), "union drgn_test_union"
        )

    def test_struct_typedef(self):
        cmd = self.check_crash_command("*atomic_t")
        self.assertIn("} atomic_t", cmd.stdout)
        self.assertIn('prog.type("atomic_t")', cmd.drgn_option.stdout)
        self.assertEqual(cmd.drgn_option.globals["type"].type_name(), "atomic_t")

    @skip_unless_have_test_kmod
    def test_union_typedef(self):
        cmd = self.check_crash_command("*drgn_test_anonymous_union")
        self.assertIn("} drgn_test_anonymous_union", cmd.stdout)
        self.assertIn('prog.type("drgn_test_anonymous_union")', cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["type"].type_name(), "drgn_test_anonymous_union"
        )

    def test_not_found(self):
        self.assertRaises(
            LookupError, self.run_crash_command, "*drgn_test_non_existent"
        )


class TestImplicit(CrashCommandTestCase):
    def test_struct(self):
        cmd = self.check_crash_command("list_head")
        self.assertIn("struct list_head {", cmd.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["type"].type_name(), "struct list_head"
        )

    @skip_unless_have_test_kmod
    def test_union(self):
        cmd = self.check_crash_command("drgn_test_union")
        self.assertIn("union drgn_test_union {", cmd.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["type"].type_name(), "union drgn_test_union"
        )

    def test_struct_typedef(self):
        cmd = self.check_crash_command("atomic_t")
        self.assertIn("} atomic_t", cmd.stdout)
        self.assertIn('prog.type("atomic_t")', cmd.drgn_option.stdout)
        self.assertEqual(cmd.drgn_option.globals["type"].type_name(), "atomic_t")

    @skip_unless_have_test_kmod
    def test_union_typedef(self):
        cmd = self.check_crash_command("drgn_test_anonymous_union")
        self.assertIn("} drgn_test_anonymous_union", cmd.stdout)
        self.assertIn('prog.type("drgn_test_anonymous_union")', cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["type"].type_name(), "drgn_test_anonymous_union"
        )

    def test_member(self):
        cmd = self.check_crash_command("task_struct.pid init_task")
        self.assertRegex(cmd.stdout, r"pid = \([^)]*\)0")
        self.assertIn(".pid", cmd.drgn_option.stdout)
        self.assertIdentical(cmd.drgn_option.globals["object"], self.prog["init_task"])
        self.assertEqual(cmd.drgn_option.globals["pid"], 0)

    def test_not_found(self):
        self.assertRaises(
            CommandNotFoundError, self.run_crash_command, "drgn_test_non_existent"
        )


class TestTask(CrashCommandTestCase):
    def test_no_args(self):
        self.run_crash_command("set -p")

        cmd = self.check_crash_command("task")
        self.assertIn(f"PID: {os.getpid()}", cmd.stdout)
        self.assertIn("(struct task_struct){", cmd.stdout)
        self.assertIn("(struct thread_info){", cmd.stdout)

        task = find_task(self.prog, os.getpid())
        self.assertEqual(cmd.drgn_option.globals["task"], task)
        self.assertIn("pid", cmd.drgn_option.globals)
        self.assertIn("cpu", cmd.drgn_option.globals)
        self.assertIn("command", cmd.drgn_option.globals)
        self.assertEqual(cmd.drgn_option.globals["thread_info"], task_thread_info(task))

    def test_pids(self):
        cmd = self.check_crash_command("task 1 2")
        foreach_cmd = self.check_crash_command("foreach 1 2 task", mode="capture")

        for c in (cmd, foreach_cmd):
            self.assertIn("PID: 1", c.stdout)
            self.assertIn("PID: 2", c.stdout)
            self.assertIn("(struct task_struct){", c.stdout)
            self.assertIn("(struct thread_info){", c.stdout)

        task = find_task(self.prog, 2)
        self.assertEqual(cmd.drgn_option.globals["task"], task)
        self.assertIn("pid", cmd.drgn_option.globals)
        self.assertIn("cpu", cmd.drgn_option.globals)
        self.assertIn("command", cmd.drgn_option.globals)
        self.assertEqual(cmd.drgn_option.globals["thread_info"], task_thread_info(task))

        self.assertEqual(cmd.drgn_option.stdout, foreach_cmd.drgn_option.stdout)

    def test_members(self):
        cmd = self.check_crash_command("task 1 -R on_rq,prio")
        foreach_cmd = self.check_crash_command(
            "foreach 1 task -R on_rq,prio", mode="capture"
        )

        for c in (cmd, foreach_cmd):
            self.assertNotIn("(struct task_struct){", c.stdout)
            self.assertNotIn("(struct thread_info){", c.stdout)
            self.assertIn("on_rq =", c.stdout)
            self.assertIn("prio =", c.stdout)

        task = find_task(self.prog, 1)
        self.assertEqual(cmd.drgn_option.globals["task"], task)
        self.assertIn("pid", cmd.drgn_option.globals)
        self.assertIn("cpu", cmd.drgn_option.globals)
        self.assertIn("command", cmd.drgn_option.globals)
        self.assertIsInstance(cmd.drgn_option.globals["on_rq"], Object)
        self.assertIsInstance(cmd.drgn_option.globals["prio"], Object)
        self.assertNotIn("thread_info", cmd.drgn_option.globals)

        self.assertEqual(cmd.drgn_option.stdout, foreach_cmd.drgn_option.stdout)

    def test_members_without_R(self):
        cmd = self.check_crash_command("task 1 prio")
        self.assertNotIn("(struct task_struct){", cmd.stdout)
        self.assertNotIn("(struct thread_info){", cmd.stdout)
        self.assertIn("prio =", cmd.stdout)

        task = find_task(self.prog, 1)
        self.assertEqual(cmd.drgn_option.globals["task"], task)
        self.assertIn("pid", cmd.drgn_option.globals)
        self.assertIn("cpu", cmd.drgn_option.globals)
        self.assertIn("command", cmd.drgn_option.globals)
        self.assertIsInstance(cmd.drgn_option.globals["prio"], Object)
        self.assertNotIn("thread_info", cmd.drgn_option.globals)

    def test_members_with_and_without_R(self):
        cmd = self.check_crash_command("task -R on_rq 1 prio")
        self.assertNotIn("(struct task_struct){", cmd.stdout)
        self.assertNotIn("(struct thread_info){", cmd.stdout)
        self.assertIn("on_rq =", cmd.stdout)
        self.assertIn("prio =", cmd.stdout)

        task = find_task(self.prog, 1)
        self.assertEqual(cmd.drgn_option.globals["task"], task)
        self.assertIn("pid", cmd.drgn_option.globals)
        self.assertIn("cpu", cmd.drgn_option.globals)
        self.assertIn("command", cmd.drgn_option.globals)
        self.assertIsInstance(cmd.drgn_option.globals["on_rq"], Object)
        self.assertIsInstance(cmd.drgn_option.globals["prio"], Object)
        self.assertNotIn("thread_info", cmd.drgn_option.globals)
