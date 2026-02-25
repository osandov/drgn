# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import errno
import os
from unittest import SkipTest

from tests.linux_kernel.bpf import (
    BPF_LD_MAP_FD,
    BPF_MAP_TYPE_HASH,
    BPF_PROG_TYPE_KPROBE,
    BPF_PROG_TYPE_SOCKET_FILTER,
    BPF_REG_0,
    bpf_map_create,
    bpf_map_get_info_by_fd,
    bpf_prog_get_info_by_fd,
    bpf_prog_ids,
    bpf_prog_load,
)
from tests.linux_kernel.crash_commands import CrashCommandTestCase
from tests.linux_kernel.helpers.test_bpf import BpfTestCase


class TestBpf(CrashCommandTestCase, BpfTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # This command isn't supported before Linux kernel commits dc4bb0e23561
        # ("bpf: Introduce bpf_prog ID") and f3f1c054c288 ("bpf: Introduce bpf_map
        # ID") (in v4.13).
        try:
            next(bpf_prog_ids())
        except StopIteration:
            # Kernel supports BPF IDs but no programs exist yet
            pass
        except OSError as e:
            if e.errno != errno.EINVAL:
                raise
            raise SkipTest("This kernel version doesn't support BPF object IDs")

    def test_bpf(self):
        with contextlib.ExitStack() as exit_stack:
            map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, 8, 8, 8)
            exit_stack.callback(os.close, map_fd)

            prog1_fd = bpf_prog_load(BPF_PROG_TYPE_KPROBE, self.INSNS, b"GPL")
            exit_stack.callback(os.close, prog1_fd)

            prog2_insns = BPF_LD_MAP_FD(BPF_REG_0, map_fd) + self.INSNS
            prog2_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog2_insns, b"GPL")
            exit_stack.callback(os.close, prog2_fd)

            map_id = bpf_map_get_info_by_fd(map_fd).id
            prog1_id = bpf_prog_get_info_by_fd(prog1_fd).id
            prog2_info = bpf_prog_get_info_by_fd(prog2_fd)
            prog2_id = prog2_info.id
            prog2_tag = "".join(f"{b:02x}" for b in prog2_info.tag)

            cmd = self.check_crash_command("bpf")

            self.assertIn("BPF_PROG_TYPE", cmd.stdout)
            self.assertRegex(
                cmd.stdout,
                rf"(?sm)BPF_PROG.*^\s*{prog1_id}\s+.*KPROBE\s+[0-9a-f]{{16}}\s*$",
            )
            self.assertRegex(
                cmd.stdout,
                rf"(?sm)BPF_PROG.*^\s*{prog2_id}\s+.*SOCKET_FILTER\s+.*{prog2_tag}\s+{map_id}$",
            )
            self.assertIn("BPF_MAP_TYPE", cmd.stdout)
            self.assertRegex(
                cmd.stdout,
                rf"(?sm)BPF_MAP.*^\s*{map_id}\s+.*HASH\s+",
            )

    def test_bpf_program_by_id(self):
        with contextlib.ExitStack() as exit_stack:
            prog_fd = bpf_prog_load(BPF_PROG_TYPE_KPROBE, self.INSNS, b"GPL")
            exit_stack.callback(os.close, prog_fd)

            prog_info = bpf_prog_get_info_by_fd(prog_fd)
            prog_id = prog_info.id
            prog_tag = "".join(f"{b:02x}" for b in prog_info.tag)

            cmd = self.check_crash_command(f"bpf -p {prog_id}")

            self.assertRegex(
                cmd.stdout,
                rf"(?sm)ID\s+.*BPF_PROG_TYPE.*^\s*{prog_id}\s+.*KPROBE\s+.*{prog_tag}\s*$",
            )

            self.assertRegex(
                cmd.stdout,
                r"(?sm)^\s*XLATED:\s*\d+\s+JITED:\s*\d+\s+MEMLOCK:\s*\d+",
            )

            self.assertRegex(
                cmd.stdout,
                r"(?sm)^\s*LOAD_TIME:\s*((\w+\s+){3}\d{2}:\d{2}:\d{2}\s+\d{4}|\(unknown\))",
            )

            self.assertRegex(
                cmd.stdout,
                r"(?sm)^\s*GPL_COMPATIBLE:\s*(yes|no)\s+NAME:\s*(\(unused\)|\(unknown\)|\S+)\s+UID:\s*\d+",
            )

    def test_bpf_program_by_id_invalid(self):
        self.assertRaises(
            Exception,
            self.check_crash_command,
            "bpf -p 1a",
        )
        self.assertRaises(
            Exception,
            self.check_crash_command,
            "bpf -p 1$^7",
        )

    def test_bpf_map_by_id(self):
        with contextlib.ExitStack() as exit_stack:
            map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, 4, 8, 256)
            exit_stack.callback(os.close, map_fd)

            map_info = bpf_map_get_info_by_fd(map_fd)
            map_id = map_info.id

            cmd = self.check_crash_command(f"bpf -m {map_id}")

            self.assertIn("BPF_MAP_TYPE", cmd.stdout)

            self.assertRegex(
                cmd.stdout,
                rf"(?sm)ID\s+.*BPF_MAP.*^\s*{map_id}\s+.*HASH\s+",
            )

            self.assertRegex(
                cmd.stdout,
                r"(?sm)^\s*KEY_SIZE:\s*4\s+VALUE_SIZE:\s*8\s+MAX_ENTRIES:\s*256",
            )

            self.assertRegex(
                cmd.stdout,
                r"(?sm)NAME:\s*(\(unused\)|\(unknown\)|\"[^\"]*\")\s+UID:\s*(\d+|\(unknown\)|\(unused\))",
            )

    def test_bpf_map_by_id_with_program(self):
        with contextlib.ExitStack() as exit_stack:
            map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, 8, 8, 16)
            exit_stack.callback(os.close, map_fd)

            prog_insns = BPF_LD_MAP_FD(BPF_REG_0, map_fd) + self.INSNS
            prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog_insns, b"GPL")
            exit_stack.callback(os.close, prog_fd)

            map_info = bpf_map_get_info_by_fd(map_fd)
            map_id = map_info.id

            cmd = self.check_crash_command(f"bpf -m {map_id}")

            self.assertIn(f"{map_id}", cmd.stdout)
            self.assertIn("HASH", cmd.stdout)
            self.assertIn("KEY_SIZE:", cmd.stdout)
            self.assertIn("VALUE_SIZE:", cmd.stdout)
            self.assertIn("MAX_ENTRIES:", cmd.stdout)

    def test_bpf_map_by_id_invalid(self):
        self.assertRaises(
            Exception,
            self.check_crash_command,
            "bpf -m abc",
        )

        self.assertRaises(
            Exception,
            self.check_crash_command,
            "bpf -m 1$^7",
        )

    def test_bpf_command_shows_maps(self):
        with contextlib.ExitStack() as exit_stack:
            map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, 8, 8, 8)
            exit_stack.callback(os.close, map_fd)

            map_id = bpf_map_get_info_by_fd(map_fd).id

            cmd = self.check_crash_command("bpf")

            self.assertIn("BPF_MAP", cmd.stdout)

            self.assertRegex(
                cmd.stdout,
                rf"(?sm)^\s*{map_id}\s+.*HASH\s+",
            )
