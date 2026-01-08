# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import ctypes
import gzip
import mmap
import os
from pathlib import Path
import re
import unittest

from _drgn_util.platform import NORMALIZED_MACHINE_NAME
from drgn import Object, Symbol
from tests.linux_kernel import (
    IOCB_CMD_PREAD,
    IOCB_CMD_PWRITE,
    io_destroy,
    io_setup,
    io_submit,
    iocb,
    possible_cpus,
    skip_unless_have_test_kmod,
)
from tests.linux_kernel.crash_commands import CrashCommandTestCase
from tests.linux_kernel.helpers.test_irq import proc_irq_smp_affinity_list


class TestSys(CrashCommandTestCase):
    def test_sys(self):
        cmd = self.check_crash_command("sys")
        for field in (
            "KERNEL",
            "DUMPFILE",
            "CPUS",
            "DATE",
            "UPTIME",
            "LOAD AVERAGE",
            "TASKS",
            "NODENAME",
            "RELEASE",
            "VERSION",
            "MACHINE",
            "MEMORY",
        ):
            self.assertRegex(cmd.stdout, rf"(?m)^\s*{field}:")

        for variable in (
            "kernel",
            "taints",
            "dumpfile",
            "cpus",
            "offline_cpus",
            "timestamp",
            "uptime_",
            "load_average",
            "num_tasks",
            "nodename",
            "release",
            "version",
            "machine",
            "memory",
        ):
            self.assertIn(variable, cmd.drgn_option.globals)

    def test_sys_config(self):
        try:
            with gzip.open("/proc/config.gz", "rt") as f:
                expected = f.read()
        except FileNotFoundError:
            self.skipTest("kernel not built with CONFIG_IKCONFIG_PROC")

        cmd = self.check_crash_command("sys config")
        self.assertEqual(cmd.stdout, expected)
        self.assertIn("kconfig", cmd.drgn_option.globals)


class TestDev(CrashCommandTestCase):
    def test_no_args(self):
        cmd = self.check_crash_command("dev")
        with open("/proc/devices", "r") as f:
            for line in f:
                if line.isspace() or line in (
                    "Character devices:\n",
                    "Block devices:\n",
                ):
                    continue
                match = re.fullmatch(r"\s*([0-9]+)\s+(.*)\n", line)
                self.assertRegex(
                    cmd.stdout, rf"(?m)^\s*{match.group(1)}\s+{match.group(2)}"
                )

        for variable in ("cdev", "operations", "disk"):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)
        self.assertIn("major", cmd.drgn_option.globals)

    def test_ioports(self):
        cmd = self.check_crash_command("dev -i")
        lines = iter(cmd.stdout.splitlines())
        # Skip the header and root resource.
        next(lines)
        next(lines)
        with open("/proc/ioports", "r") as f:
            for output_line, file_line in zip(lines, f):
                output_match = re.fullmatch(
                    r"\s*[0-9a-f]+\s+([0-9a-f]+)-([0-9a-f]+)\s+(.*)", output_line
                )
                file_match = re.fullmatch(
                    r"\s*([0-9a-f]+)-([0-9a-f]+)\s*:\s*(.*)\n", file_line
                )
                self.assertEqual(
                    (
                        int(output_match.group(1), 16),
                        int(output_match.group(2), 16),
                        output_match.group(3),
                    ),
                    (
                        int(file_match.group(1), 16),
                        int(file_match.group(2), 16),
                        file_match.group(3),
                    ),
                )

        for variable in ("resource", "start", "end", "name"):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)

    def test_pci(self):
        cmd = self.check_crash_command("dev -p")
        for path in Path("/sys/bus/pci/devices").iterdir():
            self.assertIn(path.name, cmd.stdout)

        self.assertIsInstance(cmd.drgn_option.globals["root_bus"], Object)
        self.assertIsInstance(cmd.drgn_option.globals["busname"], str)
        # Everything else is a local variable in a recursive function.

    @skip_unless_have_test_kmod
    def test_disks(self):
        cmd_d_while_idle = self.check_crash_command("dev -d", mode="capture")
        cmd_D_while_idle = self.check_crash_command("dev -D", mode="capture")

        with contextlib.ExitStack() as exit_stack:
            fd = os.open("/dev/drgntestb0", os.O_RDWR | os.O_DIRECT)
            exit_stack.callback(os.close, fd)

            major = os.major(os.fstat(fd).st_rdev)

            map = exit_stack.enter_context(
                mmap.mmap(-1, 2 * mmap.PAGESIZE, mmap.MAP_PRIVATE)
            )

            iocbs = (iocb * 2)()
            iocbs[0].aio_lio_opcode = IOCB_CMD_PWRITE
            iocbs[0].aio_fildes = fd
            iocbs[0].aio_buf = ctypes.addressof(ctypes.c_char.from_buffer(map))
            iocbs[0].aio_nbytes = mmap.PAGESIZE
            iocbs[0].aio_offset = mmap.PAGESIZE

            iocbs[1].aio_lio_opcode = IOCB_CMD_PREAD
            iocbs[1].aio_fildes = fd
            iocbs[1].aio_buf = ctypes.addressof(
                ctypes.c_char.from_buffer(map, mmap.PAGESIZE)
            )
            iocbs[1].aio_nbytes = mmap.PAGESIZE
            iocbs[1].aio_offset = 3 * mmap.PAGESIZE

            ctx_id = io_setup(len(iocbs))
            exit_stack.callback(io_destroy, ctx_id)

            truant = Path("/sys/block/drgntestb0/truant")
            truant.write_text("1\n")
            exit_stack.callback(truant.write_text, "0\n")

            io_submit(ctx_id, iocbs)

            cmd_d_while_busy = self.check_crash_command("dev -d")
            cmd_D_while_busy = self.check_crash_command("dev -D", mode="capture")

        self.assertIn("drgntestb0", cmd_d_while_idle.stdout)
        self.assertNotIn("drgntestb0", cmd_D_while_idle.stdout)
        for cmd in (cmd_d_while_busy, cmd_D_while_busy):
            self.assertRegex(
                cmd.stdout,
                rf"(?m)^\s*{major}\s+[0-9a-f]+\s+drgntestb0\s+[0-9a-f]+\s+2\s+1\s+1\s*$",
            )

        for cmd in (cmd_d_while_idle, cmd_D_while_idle, cmd_D_while_busy):
            self.assertEqual(
                cmd.drgn_option.stdout, cmd_d_while_busy.drgn_option.stdout
            )

        cmd = cmd_d_while_busy
        for variable in ("disk", "major", "queue"):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)
        self.assertIsInstance(cmd.drgn_option.globals["name"], bytes)
        for variable in ("read", "write", "total"):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], int)


def nr_irqs():
    with open("/proc/stat", "r") as f:
        for line in f:
            if line.startswith("intr "):
                return len(line.split()) - 2


def nr_softirqs():
    with open("/proc/stat", "r") as f:
        for line in f:
            if line.startswith("softirq "):
                return len(line.split()) - 2


class TestIrq(CrashCommandTestCase):
    def _test_irq_common(self, cmd):
        for path in Path("/sys/kernel/irq").iterdir():
            expected = (path / "actions").read_text().rstrip("\n")
            if expected:
                irq = int(path.name)
                break
        else:
            self.skipTest("IRQ with action not found")

        action = expected.partition(",")[0]
        self.assertRegex(cmd.stdout, rf'(?m)^\s*{irq}.*"{re.escape(action)}"')

        self.assertIn("for_each_irq_desc()", cmd.drgn_option.stdout)
        self.assertIsInstance(cmd.drgn_option.globals["irq"], int)
        for variable in ("irq_desc", "action", "name"):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)

    def test_irq(self):
        cmd = self.check_crash_command("irq")

        irqs = [int(x) for x in re.findall(r"^\s*([0-9]+)", cmd.stdout, flags=re.M)]
        self.assertEqual(irqs, list(range(nr_irqs())))

        self._test_irq_common(cmd)

    def test_used(self):
        cmd = self.check_crash_command("irq -u")

        irqs = [int(x) for x in re.findall(r"^\s*([0-9]+)", cmd.stdout, flags=re.M)]
        expected = [int(path.name) for path in Path("/sys/kernel/irq").iterdir()]
        expected.sort()
        self.assertEqual(irqs, expected)

        self._test_irq_common(cmd)

    def test_number(self):
        numbers = []
        for path in Path("/sys/kernel/irq").iterdir():
            numbers.append(int(path.name))
            if len(numbers) >= 2:
                break
        numbers.reverse()

        cmd = self.check_crash_command(f"irq {' '.join([str(x) for x in numbers])}")

        irqs = [int(x) for x in re.findall(r"^\s*([0-9]+)", cmd.stdout, flags=re.M)]
        self.assertEqual(irqs, numbers)

        self.assertIn("irq_to_desc(", cmd.drgn_option.stdout)
        self.assertIsInstance(cmd.drgn_option.globals["irq"], int)
        # Omit "name" since the IRQs we chose may not have any actions with
        # names.
        for variable in ("irq_desc", "action"):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)

    def test_invalid_number(self):
        number = nr_irqs()
        # The drgn code would fault on a NULL irq_desc, so just compile it.
        cmd = self.check_crash_command(f"irq {number}", mode="compile")
        self.assertEqual(cmd.stdout, f"irq: invalid IRQ number: {number}\n")

    @unittest.skipUnless(NORMALIZED_MACHINE_NAME == "x86_64", "machine is not x86_64")
    def test_idt(self):
        cmd = self.check_crash_command("irq -d")

        vecs = [int(x) for x in re.findall(r"^\s*\[([0-9]+)\]", cmd.stdout, flags=re.M)]
        self.assertEqual(vecs, list(range(256)))

        self.assertRegex(cmd.stdout, r"(?m)^\s*\[3\] .*int3")

        self.assertIsInstance(cmd.drgn_option.globals["vec"], int)
        for variable in ("gate", "func"):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)
        self.assertIsInstance(cmd.drgn_option.globals["sym"], Symbol)

    def test_softirqs(self):
        cmd = self.check_crash_command("irq -b")

        vecs = [int(x) for x in re.findall(r"^\s*\[([0-9]+)\]", cmd.stdout, flags=re.M)]
        self.assertEqual(vecs, list(range(nr_softirqs())))

        self.assertRegex(cmd.stdout, r"(?m)^\s*\[[0-9]+\] .*<\w+\>\s*$")

        self.assertIsInstance(cmd.drgn_option.globals["vec"], int)
        self.assertIsInstance(cmd.drgn_option.globals["action"], Object)
        self.assertIsInstance(cmd.drgn_option.globals["sym"], Symbol)

    def test_affinity(self):
        cmd = self.check_crash_command("irq -a")

        proc_path = Path("/proc/irq")
        expected = [
            (
                int(path.name),
                proc_irq_smp_affinity_list(proc_path / path.name).rstrip("\n"),
            )
            for path in Path("/sys/kernel/irq").iterdir()
            if (path / "actions").read_text().rstrip("\n")
        ]
        expected.sort()
        actual = [
            (int(irq), affinity)
            for irq, affinity in re.findall(
                r"^\s*([0-9]+)\s+\S+\s+(\S+)", cmd.stdout, flags=re.M
            )
        ]
        self.assertEqual(actual, expected)

        self.assertIsInstance(cmd.drgn_option.globals["irq"], int)
        for variable in ("irq_desc", "affinity"):
            with self.subTest(variable=variable):
                self.assertIsInstance(cmd.drgn_option.globals[variable], Object)
        self.assertIsInstance(cmd.drgn_option.globals["names"], list)
        self.assertIsInstance(cmd.drgn_option.globals["affinity_list"], str)

    def test_stats(self):
        cmd = self.check_crash_command("irq -s")

        expected = [
            int(path.name)
            for path in Path("/sys/kernel/irq").iterdir()
            if (path / "actions").read_text().rstrip("\n")
        ]
        expected.sort()
        num_possible_cpus = len(possible_cpus())
        actual = [
            int(irq)
            for irq in re.findall(
                rf"^\s*([0-9]+):(?:\s+[0-9]+){{{num_possible_cpus}}}",
                cmd.stdout,
                flags=re.M,
            )
        ]
        self.assertEqual(actual, expected)

        self.assertIsInstance(cmd.drgn_option.globals["irq"], int)
        self.assertIsInstance(cmd.drgn_option.globals["irq_desc"], Object)
        self.assertIsInstance(cmd.drgn_option.globals["names"], list)
        self.assertIn("chip_name", cmd.drgn_option.globals)
        self.assertIsInstance(cmd.drgn_option.globals["count"], int)

    def test_stats_cpu(self):
        cpu = max(possible_cpus())
        cmd = self.check_crash_command(f"irq -s -c {cpu}")

        expected = [
            int(path.name)
            for path in Path("/sys/kernel/irq").iterdir()
            if (path / "actions").read_text().rstrip("\n")
        ]
        expected.sort()
        actual = [
            int(irq)
            for irq in re.findall(r"^\s*([0-9]+):\s+[0-9]+", cmd.stdout, flags=re.M)
        ]
        self.assertEqual(actual, expected)

        self.assertEqual(cmd.drgn_option.globals["cpu"], cpu)
        self.assertIsInstance(cmd.drgn_option.globals["irq"], int)
        self.assertIsInstance(cmd.drgn_option.globals["irq_desc"], Object)
        self.assertIsInstance(cmd.drgn_option.globals["names"], list)
        self.assertIn("chip_name", cmd.drgn_option.globals)
        self.assertIsInstance(cmd.drgn_option.globals["count"], int)


class TestLog(CrashCommandTestCase):
    def test_no_args(self):
        cmd = self.check_crash_command("log")

        self.assertRegex(cmd.stdout, r"^\[\s*[0-9]+\.[0-9]+\] .")

        self.assertIn("get_dmesg()", cmd.drgn_option.stdout)
        self.assertIsInstance(cmd.drgn_option.globals["dmesg"], bytes)

    def test_t(self):
        cmd = self.check_crash_command("log -t")

        self.assertRegex(cmd.stdout, r"^[^[]")

        self.assertIn("get_dmesg(timestamps=False)", cmd.drgn_option.stdout)
        self.assertIsInstance(cmd.drgn_option.globals["dmesg"], bytes)

    def test_T(self):
        cmd = self.check_crash_command("log -T")

        self.assertRegex(cmd.stdout, r"^\[[A-Z]")

        self.assertIn('get_dmesg(timestamps="human")', cmd.drgn_option.stdout)
        self.assertIsInstance(cmd.drgn_option.globals["dmesg"], bytes)
