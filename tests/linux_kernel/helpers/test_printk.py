# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import errno
import os
import re

from drgn.helpers.linux.printk import (
    PrintkRecord,
    for_each_dmesg_stack_trace,
    get_printk_records,
)
from tests.linux_kernel import LinuxKernelTestCase


def unescape_text(s):
    return re.sub(
        rb"\\x([0-9A-Fa-f]{2})", lambda match: bytes([int(match.group(1), 16)]), s
    )


def get_kmsg_records():
    result = []
    with open("/dev/kmsg", "rb") as f:
        fd = f.fileno()
        os.set_blocking(fd, False)
        while True:
            try:
                record = os.read(fd, 4096)
            except OSError as e:
                if e.errno == errno.EAGAIN:
                    break
                else:
                    raise
            prefix, _, escaped = record.partition(b";")
            fields = prefix.split(b",")
            syslog = int(fields[0])
            escaped_lines = escaped.splitlines()
            context = {}
            for escaped_line in escaped_lines[1:]:
                assert escaped_line.startswith(b" ")
                key, value = escaped_line[1:].split(b"=", 1)
                context[unescape_text(key)] = unescape_text(value)
            result.append(
                PrintkRecord(
                    text=unescape_text(escaped_lines[0]),
                    facility=syslog >> 3,
                    level=syslog & 7,
                    seq=int(fields[1]),
                    timestamp=int(fields[2]) * 1000,
                    caller_tid=None,
                    caller_cpu=None,
                    continuation=b"c" in fields[3],
                    context=context,
                )
            )
    return result


class TestPrintk(LinuxKernelTestCase):
    def test_get_printk_records(self):
        self.assertEqual(
            get_kmsg_records(),
            [
                record._replace(
                    # Round timestamp down since /dev/kmsg only has microsecond
                    # granularity.
                    timestamp=record.timestamp // 1000 * 1000,
                    # Remove caller ID since it's only available from /dev/kmsg
                    # when the kernel is compiled with CONFIG_PRINTK_CALLER.
                    caller_tid=None,
                    caller_cpu=None,
                )
                for record in get_printk_records(self.prog)
            ],
        )

    def test_for_each_dmesg_stack_trace(self):
        with open("/proc/sysrq-trigger", "wb") as f:
            f.write(b"l")

        traces = list(for_each_dmesg_stack_trace(self.prog))

        for trace in traces:
            # write_sysrq_trigger() has been so named since the initial import
            # of Linux source into git, commit 1da177e4c3f41
            # ("Linux-2.6.12-rc2").
            if any(frame.name == "write_sysrq_trigger" for frame in trace.stack_trace):
                break
        else:
            self.fail("Did not find test stack trace in kernel log")
