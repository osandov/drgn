# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import re

from drgn import Object, offsetof
from drgn.commands import CommandArgumentError
from drgn.commands._builtin.crash._collections import _find_tree_type
from drgn.helpers.linux.rbtree import (
    rbtree_inorder_for_each,
    rbtree_inorder_for_each_entry,
    rbtree_preorder_for_each,
    rbtree_preorder_for_each_entry,
)
from tests import TestCase
from tests.linux_kernel import skip_unless_have_test_kmod
from tests.linux_kernel.crash_commands import CrashCommandTestCase


class TestFindTreeType(TestCase):
    def test_full(self):
        self.assertEqual(_find_tree_type("rbtree"), "rbtree")
        self.assertEqual(_find_tree_type("radix"), "radix")
        self.assertEqual(_find_tree_type("xarray"), "xarray")
        self.assertEqual(_find_tree_type("maple"), "maple")

    def test_abbreviated(self):
        for expected, abbreviations in (
            ("rbtree", ("rb", "rbt", "rbtr", "rbtre")),
            ("radix", ("ra", "rad", "radi")),
            ("xarray", ("x", "xa", "xar", "xarr", "xarra")),
            ("maple", ("m", "ma", "map", "mapl")),
        ):
            for abbreviation in abbreviations:
                with self.subTest(abbreviation=abbreviation):
                    self.assertEqual(_find_tree_type(abbreviation), expected)

    def test_ambiguous(self):
        self.assertRaises(CommandArgumentError, _find_tree_type, "r")

    def test_unknown(self):
        self.assertRaises(CommandArgumentError, _find_tree_type, "z")


@skip_unless_have_test_kmod
class TestTree(CrashCommandTestCase):
    def test_rbtree(self):
        cmd = self.check_crash_command("tree drgn_test_rb_root")
        self.assertEqual(
            cmd.stdout,
            "".join(
                [
                    f"{node.value_():x}\n"
                    for node in rbtree_preorder_for_each(
                        self.prog["drgn_test_rb_root"].address_of_()
                    )
                ]
            ),
        )
        self.assertIn("root = prog[", cmd.drgn_option.stdout)
        self.assertIn("rbtree_preorder_for_each(", cmd.drgn_option.stdout)
        self.assertNotIn("rbtree_inorder_for_each", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["root"],
            self.prog["drgn_test_rb_root"].address_of_(),
        )
        self.assertEqual(
            cmd.drgn_option.globals["node"].type_.type_name(), "struct rb_node *"
        )

        with self.subTest("explicit type"):
            explicit_cmd = self.check_crash_command("tree -t rbtree drgn_test_rb_root")
            self.assertEqual(explicit_cmd.stdout, cmd.stdout)
            self.assertEqual(explicit_cmd.drgn_option.stdout, cmd.drgn_option.stdout)

    def test_rbtree_linear(self):
        cmd = self.check_crash_command("tree -l drgn_test_rb_root")
        self.assertEqual(
            cmd.stdout,
            "".join(
                [
                    f"{node.value_():x}\n"
                    for node in rbtree_inorder_for_each(
                        self.prog["drgn_test_rb_root"].address_of_()
                    )
                ]
            ),
        )
        self.assertIn("root = prog[", cmd.drgn_option.stdout)
        self.assertIn("rbtree_inorder_for_each(", cmd.drgn_option.stdout)
        self.assertNotIn("rbtree_preorder_for_each", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["root"],
            self.prog["drgn_test_rb_root"].address_of_(),
        )
        self.assertEqual(
            cmd.drgn_option.globals["node"].type_.type_name(), "struct rb_node *"
        )

    def test_rbtree_node_member(self):
        cmd = self.check_crash_command(
            "tree -o drgn_test_rb_entry.node drgn_test_rb_root"
        )
        self.assertEqual(
            cmd.stdout,
            "".join(
                [
                    f"{entry.value_():x}\n"
                    for entry in rbtree_preorder_for_each_entry(
                        "struct drgn_test_rb_entry",
                        self.prog["drgn_test_rb_root"].address_of_(),
                        "node",
                    )
                ]
            ),
        )
        self.assertIn("rbtree_preorder_for_each_entry(", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["entry"].type_.type_name(),
            "struct drgn_test_rb_entry *",
        )

    def test_rbtree_node_member_linear(self):
        cmd = self.check_crash_command(
            "tree -l -o drgn_test_rb_entry.node drgn_test_rb_root"
        )
        self.assertEqual(
            cmd.stdout,
            "".join(
                [
                    f"{entry.value_():x}\n"
                    for entry in rbtree_inorder_for_each_entry(
                        "struct drgn_test_rb_entry",
                        self.prog["drgn_test_rb_root"].address_of_(),
                        "node",
                    )
                ]
            ),
        )
        self.assertIn("rbtree_inorder_for_each_entry(", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["entry"].type_.type_name(),
            "struct drgn_test_rb_entry *",
        )

    def test_rbtree_node_offset(self):
        offset = offsetof(self.prog.type("struct drgn_test_rb_entry"), "node")
        cmd = self.check_crash_command(f"tree -o {offset} drgn_test_rb_root")
        self.assertEqual(
            cmd.stdout,
            "".join(
                [
                    f"{entry.value_():x}\n"
                    for entry in rbtree_preorder_for_each_entry(
                        "struct drgn_test_rb_entry",
                        self.prog["drgn_test_rb_root"].address_of_(),
                        "node",
                    )
                ]
            ),
        )
        self.assertIn("rbtree_preorder_for_each(", cmd.drgn_option.stdout)
        self.assertIn(f"- {offset}", cmd.drgn_option.stdout)
        self.assertEqual(cmd.drgn_option.globals["entry"].type_.type_name(), "void *")
        self.assertEqual(
            cmd.drgn_option.globals["node"].value_(),
            cmd.drgn_option.globals["entry"].value_() + offset,
        )

    def test_rbtree_entry_type(self):
        cmd = self.check_crash_command("tree -s drgn_test_rb_entry drgn_test_rb_root")
        for node in rbtree_preorder_for_each(
            self.prog["drgn_test_rb_root"].address_of_()
        ):
            self.assertRegex(cmd.stdout, rf"(?m)^{node.value_():x}$")
        self.assertIn("(struct drgn_test_rb_entry){", cmd.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["entry"].type_.type_name(),
            "struct drgn_test_rb_entry *",
        )

    def test_rbtree_entry_type_and_node_member(self):
        cmd = self.check_crash_command(
            "tree -l -s drgn_test_rb_entry -o drgn_test_rb_entry.node drgn_test_rb_root"
        )
        self.assertEqual(
            re.findall(r"\.value = \(int\)[0-9]+", cmd.stdout),
            [f".value = (int){i}" for i in range(4)],
        )
        self.assertIn("(struct drgn_test_rb_entry){", cmd.stdout)
        self.assertIn("rbtree_inorder_for_each_entry(", cmd.drgn_option.stdout)
        self.assertNotIn("cast(", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["entry"].type_.type_name(),
            "struct drgn_test_rb_entry *",
        )
        self.assertEqual(cmd.drgn_option.globals["entry"].value, 3)

    def test_rbtree_entry_type_and_node_offset(self):
        offset = offsetof(self.prog.type("struct drgn_test_rb_entry"), "node")
        cmd = self.check_crash_command(
            f"tree -l -s drgn_test_rb_entry -o {offset} drgn_test_rb_root"
        )
        self.assertEqual(
            re.findall(r"\.value = \(int\)[0-9]+", cmd.stdout),
            [f".value = (int){i}" for i in range(4)],
        )
        self.assertIn("(struct drgn_test_rb_entry){", cmd.stdout)
        self.assertIn(f"- {offset}", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["entry"].type_.type_name(),
            "struct drgn_test_rb_entry *",
        )
        self.assertEqual(cmd.drgn_option.globals["entry"].value, 3)

    def test_rbtree_members(self):
        cmd = self.check_crash_command(
            "tree -l -s drgn_test_rb_entry.value -o drgn_test_rb_entry.node drgn_test_rb_root"
        )
        self.assertEqual(
            re.findall(r"\bvalue = \(int\)[0-9]+", cmd.stdout),
            [f"value = (int){i}" for i in range(4)],
        )
        self.assertEqual(
            cmd.drgn_option.globals["entry"].type_.type_name(),
            "struct drgn_test_rb_entry *",
        )
        self.assertIdentical(
            cmd.drgn_option.globals["value"].read_(), Object(self.prog, "int", 3)
        )

    def test_rbtree_wrong_entry_type(self):
        cmd = self.check_crash_command(
            "tree -l -s list_head -o drgn_test_rb_entry.node drgn_test_rb_root"
        )
        self.assertIn("(struct list_head){", cmd.stdout)
        self.assertIn("rbtree_inorder_for_each_entry(", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["entry"].type_.type_name(), "struct list_head *"
        )

    def test_rbtree_start_address(self):
        address = self.prog["drgn_test_rb_root"].address_
        cmd = self.check_crash_command(f"tree {hex(address)}")
        self.assertEqual(
            cmd.stdout,
            "".join(
                [
                    f"{node.value_():x}\n"
                    for node in rbtree_preorder_for_each(
                        self.prog["drgn_test_rb_root"].address_of_()
                    )
                ]
            ),
        )
        self.assertIn("Object(", cmd.drgn_option.stdout)

    def test_rbtree_root_member(self):
        cmd = self.check_crash_command(
            "tree -l -s drgn_test_rb_entry.value -o drgn_test_rb_entry.node -r drgn_test_rbtree_container_struct.root drgn_test_rbtree_container"
        )
        self.assertEqual(
            re.findall(r"\bvalue = \(int\)[0-9]+", cmd.stdout),
            [f"value = (int){i}" for i in range(2)],
        )
        self.assertIn("root = prog[", cmd.drgn_option.stdout)
        self.assertIn("].root", cmd.drgn_option.stdout)
        self.assertIdentical(
            cmd.drgn_option.globals["root"],
            self.prog["drgn_test_rbtree_container"].root.address_of_(),
        )
        self.assertIdentical(
            cmd.drgn_option.globals["value"],
            self.prog["drgn_test_rbtree_container"].entries[1].value,
        )

    def test_rbtree_root_offset(self):
        offset = offsetof(
            self.prog.type("struct drgn_test_rbtree_container_struct"), "root"
        )
        cmd = self.check_crash_command(
            f"tree -l -s drgn_test_rb_entry.value -o drgn_test_rb_entry.node -r {offset} drgn_test_rbtree_container"
        )
        self.assertEqual(
            re.findall(r"\bvalue = \(int\)[0-9]+", cmd.stdout),
            [f"value = (int){i}" for i in range(2)],
        )
        self.assertIn(f"+ {offset}", cmd.drgn_option.stdout)
        self.assertIdentical(
            cmd.drgn_option.globals["root"],
            self.prog["drgn_test_rbtree_container"].root.address_of_(),
        )
        self.assertIdentical(
            cmd.drgn_option.globals["value"],
            self.prog["drgn_test_rbtree_container"].entries[1].value,
        )

    def test_rbtree_root_member_start_address(self):
        address = self.prog["drgn_test_rbtree_container"].address_
        cmd = self.check_crash_command(
            f"tree -l -s drgn_test_rb_entry.value -o drgn_test_rb_entry.node -r drgn_test_rbtree_container_struct.root {hex(address)}"
        )
        self.assertEqual(
            re.findall(r"\bvalue = \(int\)[0-9]+", cmd.stdout),
            [f"value = (int){i}" for i in range(2)],
        )
        self.assertIn("Object(", cmd.drgn_option.stdout)
        self.assertIn("+= offsetof(", cmd.drgn_option.stdout)
        self.assertIdentical(
            cmd.drgn_option.globals["root"],
            self.prog["drgn_test_rbtree_container"].root.address_of_(),
        )
        self.assertIdentical(
            cmd.drgn_option.globals["value"],
            self.prog["drgn_test_rbtree_container"].entries[1].value,
        )

    def test_rbtree_root_offset_start_address(self):
        address = self.prog["drgn_test_rbtree_container"].address_
        offset = offsetof(
            self.prog.type("struct drgn_test_rbtree_container_struct"), "root"
        )
        cmd = self.check_crash_command(
            f"tree -l -s drgn_test_rb_entry.value -o drgn_test_rb_entry.node -r {offset} {hex(address)}"
        )
        self.assertEqual(
            re.findall(r"\bvalue = \(int\)[0-9]+", cmd.stdout),
            [f"value = (int){i}" for i in range(2)],
        )
        self.assertIn(f"+ {offset}", cmd.drgn_option.stdout)
        self.assertIdentical(
            cmd.drgn_option.globals["root"],
            self.prog["drgn_test_rbtree_container"].root.address_of_(),
        )
        self.assertIdentical(
            cmd.drgn_option.globals["value"],
            self.prog["drgn_test_rbtree_container"].entries[1].value,
        )

    def test_radix(self):
        cmd = self.check_crash_command("tree -t radix drgn_test_radix_tree_sparse")
        self.assertEqual(
            cmd.stdout,
            """\
1234
5678
9abc
""",
        )
        self.assertIn("root = prog[", cmd.drgn_option.stdout)
        self.assertIn("radix_tree_for_each(", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["root"],
            self.prog["drgn_test_radix_tree_sparse"].address_of_(),
        )
        self.assertEqual(cmd.drgn_option.globals["index"], 0xFFFFFFFF)
        self.assertIdentical(
            cmd.drgn_option.globals["entry"].read_(),
            Object(self.prog, "void *", 0x9ABC),
        )

    def skip_unless_have_xarray(self):
        if not self.prog["drgn_test_have_xarray"]:
            self.skipTest("kernel does not have XArray")

    def test_xarray(self):
        self.skip_unless_have_xarray()
        cmd = self.check_crash_command("tree -t xarray drgn_test_xarray_sparse")
        self.assertEqual(
            cmd.stdout,
            """\
1234
5678
9abc
""",
        )
        self.assertIn("root = prog[", cmd.drgn_option.stdout)
        self.assertIn("xa_for_each(", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["root"],
            self.prog["drgn_test_xarray_sparse"].address_of_(),
        )
        self.assertEqual(cmd.drgn_option.globals["index"], 0xFFFFFFFF)
        self.assertIdentical(
            cmd.drgn_option.globals["entry"].read_(),
            Object(self.prog, "void *", 0x9ABC),
        )

    def test_xarray_entry_type(self):
        self.skip_unless_have_xarray()
        cmd = self.check_crash_command(
            "tree -t xarray -s drgn_test_xarray_entry drgn_test_xarray_pointers"
        )
        self.assertEqual(cmd.stdout.count("(struct drgn_test_xarray_entry){"), 4)
        self.assertEqual(cmd.drgn_option.globals["index"], 3)
        self.assertIdentical(
            cmd.drgn_option.globals["entry"].read_(),
            self.prog["drgn_test_xarray_entries"][3].address_of_(),
        )

    def test_xarray_members(self):
        self.skip_unless_have_xarray()
        cmd = self.check_crash_command(
            "tree -t xarray -s drgn_test_xarray_entry.value drgn_test_xarray_pointers"
        )
        self.assertEqual(
            re.findall(r"\bvalue = \(int\)[0-9]+", cmd.stdout),
            [f"value = (int){i}" for i in range(4)],
        )
        self.assertIdentical(
            cmd.drgn_option.globals["entry"].read_(),
            self.prog["drgn_test_xarray_entries"][3].address_of_(),
        )
        self.assertIdentical(
            cmd.drgn_option.globals["value"].read_(), Object(self.prog, "int", 3)
        )

    def test_maple(self):
        if not self.prog["drgn_test_have_maple_tree"]:
            self.skipTest("kernel does not have maple tree")
        cmd = self.check_crash_command(
            "tree -t maple drgn_test_maple_tree_sparse_ranges"
        )
        self.assertEqual(
            cmd.stdout,
            """\
b0ba000
b0ba001
b0ba002
b0ba003
b0ba004
""",
        )
        self.assertIn("root = prog[", cmd.drgn_option.stdout)
        self.assertIn("mt_for_each(", cmd.drgn_option.stdout)
        self.assertEqual(
            cmd.drgn_option.globals["root"],
            self.prog["drgn_test_maple_tree_sparse_ranges"].address_of_(),
        )
        self.assertEqual(cmd.drgn_option.globals["first_index"], 81)
        self.assertEqual(cmd.drgn_option.globals["last_index"], 100)
        self.assertIdentical(
            cmd.drgn_option.globals["entry"].read_(),
            Object(self.prog, "void *", 0xB0BA004),
        )

    def test_wrong_type(self):
        cmd = self.run_crash_command("tree drgn_test_radix_tree_sparse --drgn")
        print(cmd.stdout)
        self.assertIn("prog.symbol", cmd.stdout)
        self.assertIn("root = Object", cmd.stdout)
