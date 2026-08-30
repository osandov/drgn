# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import errno
import os
import re

from drgn import Object, TypeMember
from drgn.helpers.linux.printk import PrintkRecord, get_printk_records
from tests import MockObject, MockProgramTestCase
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


class TestPrintkLockless(MockProgramTestCase):
    DATA_ADDRESS = 0x1000
    DESC_ADDRESS = 0x2000
    INFO_ADDRESS = 0x3000
    DATA_RING_SIZE = 256
    ULONG_SIZE = 8

    def setUp(self):
        super().setUp()

        ulong_type = self.prog.int_type("unsigned long", self.ULONG_SIZE, False)
        long_type = self.prog.int_type("long", self.ULONG_SIZE, True)
        u64_type = self.prog.int_type("unsigned long long", 8, False)
        u32_type = self.prog.int_type("unsigned int", 4, False)
        u16_type = self.prog.int_type("unsigned short", 2, False)
        u8_type = self.prog.int_type("unsigned char", 1, False)
        char_type = self.prog.int_type("char", 1, True)
        self.types.append(ulong_type)

        atomic_long_type = self.prog.struct_type(
            "atomic_long_t",
            self.ULONG_SIZE,
            (TypeMember(long_type, "counter", 0),),
        )
        lpos_type = self.prog.struct_type(
            "prb_data_blk_lpos",
            2 * self.ULONG_SIZE,
            (
                TypeMember(ulong_type, "begin", 0),
                TypeMember(ulong_type, "next", 8 * self.ULONG_SIZE),
            ),
        )
        self.desc_type = self.prog.struct_type(
            "prb_desc",
            3 * self.ULONG_SIZE,
            (
                TypeMember(atomic_long_type, "state_var", 0),
                TypeMember(lpos_type, "text_blk_lpos", 8 * self.ULONG_SIZE),
            ),
        )
        dev_info_type = self.prog.struct_type(
            "dev_printk_info",
            64,
            (
                TypeMember(self.prog.array_type(char_type, 16), "subsystem", 0),
                TypeMember(self.prog.array_type(char_type, 48), "device", 128),
            ),
        )
        self.info_type = self.prog.struct_type(
            "printk_info",
            88,
            (
                TypeMember(u64_type, "seq", 0),
                TypeMember(u64_type, "ts_nsec", 64),
                TypeMember(u16_type, "text_len", 128),
                TypeMember(u8_type, "facility", 144),
                TypeMember(Object(self.prog, u8_type, bit_field_size=5), "flags", 152),
                TypeMember(Object(self.prog, u8_type, bit_field_size=3), "level", 157),
                TypeMember(u32_type, "caller_id", 160),
                TypeMember(dev_info_type, "dev_info", 192),
            ),
        )
        desc_ring_type = self.prog.struct_type(
            "prb_desc_ring",
            6 * self.ULONG_SIZE,
            (
                TypeMember(u32_type, "count_bits", 0),
                TypeMember(
                    self.prog.pointer_type(self.desc_type),
                    "descs",
                    8 * self.ULONG_SIZE,
                ),
                TypeMember(
                    self.prog.pointer_type(self.info_type),
                    "infos",
                    16 * self.ULONG_SIZE,
                ),
                TypeMember(atomic_long_type, "head_id", 24 * self.ULONG_SIZE),
                TypeMember(atomic_long_type, "tail_id", 32 * self.ULONG_SIZE),
                TypeMember(
                    atomic_long_type, "last_finalized_seq", 40 * self.ULONG_SIZE
                ),
            ),
        )
        data_ring_type = self.prog.struct_type(
            "prb_data_ring",
            4 * self.ULONG_SIZE,
            (
                TypeMember(u32_type, "size_bits", 0),
                TypeMember(
                    self.prog.pointer_type(char_type), "data", 8 * self.ULONG_SIZE
                ),
                TypeMember(atomic_long_type, "head_lpos", 16 * self.ULONG_SIZE),
                TypeMember(atomic_long_type, "tail_lpos", 24 * self.ULONG_SIZE),
            ),
        )
        self.prb_type = self.prog.struct_type(
            "printk_ringbuffer",
            11 * self.ULONG_SIZE,
            (
                TypeMember(desc_ring_type, "desc_ring", 0),
                TypeMember(data_ring_type, "text_data_ring", 48 * self.ULONG_SIZE),
                TypeMember(atomic_long_type, "fail", 80 * self.ULONG_SIZE),
            ),
        )
        self.objects.extend(
            (
                MockObject("LOG_CONT", u8_type, value=8),
                MockObject("desc_committed", u8_type, value=1),
                MockObject("desc_finalized", u8_type, value=2),
            )
        )

    def _get_records(
        self, lpos_begin, lpos_next, text=b"hello world", *, text_offset=None
    ):
        data = bytearray(self.DATA_RING_SIZE)
        if text_offset is None:
            text_offset = (lpos_begin & (self.DATA_RING_SIZE - 1)) + self.ULONG_SIZE
        data[text_offset : text_offset + len(text)] = text
        self.add_memory_segment(bytes(data), virt_addr=self.DATA_ADDRESS)
        desc = Object(
            self.prog,
            self.desc_type,
            value={
                "state_var": {"counter": 1 << 62},  # desc_committed, id = 0
                "text_blk_lpos": {"begin": lpos_begin, "next": lpos_next},
            },
        )
        info = Object(
            self.prog,
            self.info_type,
            value={
                "seq": 0,
                "ts_nsec": 456,
                "text_len": len(text),
                "facility": 1,  # LOG_USER
                "flags": 0,
                "level": 6,
                "caller_id": 123,
                "dev_info": {"subsystem": b"", "device": b""},
            },
        )
        self.add_memory_segment(desc.to_bytes_(), virt_addr=self.DESC_ADDRESS)
        self.add_memory_segment(info.to_bytes_(), virt_addr=self.INFO_ADDRESS)
        self.objects.append(
            MockObject(
                "prb",
                self.prb_type,
                value={
                    "desc_ring": {
                        "head_id": {"counter": 0},
                        "tail_id": {"counter": 0},
                        "count_bits": 0,
                        "descs": self.DESC_ADDRESS,
                        "infos": self.INFO_ADDRESS,
                    },
                    "text_data_ring": {
                        "size_bits": 8,
                        "data": self.DATA_ADDRESS,
                    },
                },
            )
        )
        return get_printk_records(self.prog)

    def _record(self, text=b"hello world"):
        return PrintkRecord(
            text=text,
            facility=1,  # LOG_USER
            level=6,
            seq=0,
            timestamp=456,
            caller_tid=123,
            caller_cpu=None,
            continuation=False,
            context={},
        )

    def test_regular(self):
        self.assertEqual(self._get_records(16, 40), [self._record()])

    def test_ends_at_boundary(self):
        self.assertEqual(self._get_records(232, 256), [self._record()])

    def test_wrapped(self):
        self.assertEqual(
            self._get_records(248, 280, text_offset=self.ULONG_SIZE),
            [self._record()],
        )

    def test_failed(self):
        self.assertEqual(self._get_records(1, 1, b""), [])

    def test_invalid_data_less(self):
        self.assertEqual(self._get_records(1, 3, b""), [])

    def test_empty(self):
        self.assertEqual(self._get_records(3, 3, b""), [self._record(b"")])


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
