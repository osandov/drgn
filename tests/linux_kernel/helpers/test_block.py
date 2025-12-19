# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import ctypes
import mmap
import os
import os.path
from pathlib import Path

from drgn import Object
from drgn.helpers.linux.block import (
    bdev_partno,
    blk_mq_rq_from_pdu,
    blk_rq_bytes,
    blk_rq_pos,
    disk_devt,
    disk_name,
    for_each_disk,
    for_each_partition,
    nr_blockdev_pages,
    op_is_write,
    part_devt,
    part_name,
    req_op,
    rq_data_dir,
)
from drgn.helpers.linux.device import MAJOR, MINOR
from tests.linux_kernel import (
    IOCB_CMD_PWRITE,
    LinuxKernelTestCase,
    io_destroy,
    io_setup,
    io_submit,
    iocb,
    meminfo_field_in_pages,
    skip_unless_have_test_kmod,
)


class TestBlock(LinuxKernelTestCase):
    def test_disk_devt(self):
        for disk in for_each_disk(self.prog):
            path = os.path.join(b"/sys/block", disk_name(disk), b"dev")
            with open(path, "r") as f:
                expected = f.read().strip()
            devt = disk_devt(disk).value_()
            self.assertEqual(f"{MAJOR(devt)}:{MINOR(devt)}", expected)

    def test_for_each_disk(self):
        self.assertEqual(
            {disk_name(disk).decode() for disk in for_each_disk(self.prog)},
            set(os.listdir("/sys/block")),
        )

    def test_part_devt(self):
        for part in for_each_partition(self.prog):
            path = os.path.join(b"/sys/class/block", part_name(part), b"dev")
            with open(path, "r") as f:
                expected = f.read().strip()
            devt = part_devt(part).value_()
            self.assertEqual(f"{MAJOR(devt)}:{MINOR(devt)}", expected)

    def test_for_each_partition(self):
        self.assertEqual(
            {part_name(part).decode() for part in for_each_partition(self.prog)},
            set(os.listdir("/sys/class/block")),
        )

    def test_bdev_partno(self):
        for part in for_each_partition(self.prog):
            try:
                with open(
                    os.path.join(b"/sys/class/block", part_name(part), b"partition"),
                    "r",
                ) as f:
                    partition = int(f.read())
            except FileNotFoundError:
                partition = 0
            if part.type_.type.tag == "hd_struct":
                self.skipTest("can't get bdev easily on old kernels")
            self.assertIdentical(bdev_partno(part), Object(self.prog, "u8", partition))

    def test_nr_blockdev_pages(self):
        self.assertAlmostEqual(
            nr_blockdev_pages(self.prog),
            meminfo_field_in_pages("Buffers"),
            delta=1024 * 1024 * 1024,
        )

    @skip_unless_have_test_kmod
    def test_rq_helpers(self):
        with contextlib.ExitStack() as exit_stack:
            fd = os.open("/dev/drgntestb0", os.O_RDWR | os.O_DIRECT)
            exit_stack.callback(os.close, fd)

            map = exit_stack.enter_context(
                mmap.mmap(-1, mmap.PAGESIZE, mmap.MAP_PRIVATE)
            )

            iocbs = (iocb * 1)()
            iocbs[0].aio_lio_opcode = IOCB_CMD_PWRITE
            iocbs[0].aio_fildes = fd
            iocbs[0].aio_buf = ctypes.addressof(ctypes.c_char.from_buffer(map))
            iocbs[0].aio_nbytes = mmap.PAGESIZE
            iocbs[0].aio_offset = 6 * mmap.PAGESIZE

            ctx_id = io_setup(len(iocbs))
            exit_stack.callback(io_destroy, ctx_id)

            truant = Path("/sys/block/drgntestb0/truant")
            truant.write_text("1\n")
            exit_stack.callback(truant.write_text, "0\n")

            io_submit(ctx_id, iocbs)

            rq = blk_mq_rq_from_pdu(
                self.prog["drgn_test_blkdevs"][0].loafing_requests.next
            )
            self.assertEqual(req_op(rq), self.prog["REQ_OP_WRITE"])
            self.assertEqual(rq_data_dir(rq), 1)
            self.assertEqual(blk_rq_pos(rq), (6 * mmap.PAGESIZE) >> 9)
            self.assertEqual(blk_rq_bytes(rq), mmap.PAGESIZE)

    def test_op_is_write(self):
        self.assertFalse(op_is_write(self.prog["REQ_OP_READ"]))
        self.assertTrue(op_is_write(self.prog["REQ_OP_WRITE"]))
        self.assertTrue(op_is_write(self.prog["REQ_OP_DISCARD"]))
