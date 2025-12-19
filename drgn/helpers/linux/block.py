# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Block Layer
-----------

The ``drgn.helpers.linux.block`` module provides helpers for working with the
Linux block layer, including disks (``struct gendisk``) and partitions.

Since Linux v5.11, partitions are represented by ``struct block_device``.
Before that, they were represented by ``struct hd_struct``.
"""

from typing import Callable, Iterator, Literal, Optional, Tuple

from drgn import Object, ObjectNotFoundError, Program, cast, container_of
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.device import MAJOR, MINOR, MKDEV, class_for_each_device
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.sbitmap import sbitmap_for_each_set
from drgn.helpers.linux.xarray import xa_for_each

__all__ = (
    "bdev_partno",
    "blk_mq_rq_from_pdu",
    "blk_mq_rq_to_pdu",
    "blk_rq_bytes",
    "blk_rq_pos",
    "disk_devt",
    "disk_name",
    "for_each_disk",
    "for_each_partition",
    "nr_blockdev_pages",
    "op_is_write",
    "part_devt",
    "part_name",
    "print_disks",
    "print_partitions",
    "req_op",
    "request_queue_busy_iter",
    "rq_data_dir",
)


def disk_devt(disk: Object) -> Object:
    """
    Get a disk's device number.

    :param disk: ``struct gendisk *``
    :return: ``dev_t``
    """
    return Object(disk.prog_, "dev_t", MKDEV(disk.major, disk.first_minor))


def disk_name(disk: Object) -> bytes:
    """
    Get the name of a disk (e.g., ``sda``).

    :param disk: ``struct gendisk *``
    """
    return disk.disk_name.string_()


def _bdev_partno_flags(bdev: Object) -> Object:
    return cast("u8", bdev.__bd_flags.counter)


def _bdev_partno_old(bdev: Object) -> Object:
    return bdev.bd_partno.read_()


def bdev_partno(bdev: Object) -> Object:
    """
    Get the partition number of a block device.

    :param bdev: ``struct block_device *``
    :return: ``u8``
    """
    try:
        impl = bdev.prog_.cache["bdev_partno"]
    except KeyError:
        # Since Linux kernel commit 1116b9fa15c0 ("bdev: infrastructure for
        # flags") (in v6.10), partno is part of the atomic_t __bd_flags member.
        # Before that, it's its own member.
        bdev.prog_.cache["bdev_partno"] = impl = (
            _bdev_partno_flags
            if bdev.prog_.type("struct block_device").has_member("__bd_flags")
            else _bdev_partno_old
        )
    return impl(bdev)


@takes_program_or_default
def for_each_disk(prog: Program) -> Iterator[Object]:
    """
    Iterate over all disks in the system.

    :return: Iterator of ``struct gendisk *`` objects.
    """
    # Before Linux kernel commit 0d02129e76ed ("block: merge struct
    # block_device and struct hd_struct") (in v5.11), partition devices are in
    # struct hd_struct::__dev. After that commit, they are in struct
    # block_device::bd_device. We start by assuming that the kernel has this
    # commit and fall back to the old path if that fails.
    have_bd_device = True
    for device in class_for_each_device(prog["block_class"].address_of_()):
        if have_bd_device:
            try:
                bdev = container_of(device, "struct block_device", "bd_device")
            except LookupError:
                have_bd_device = False
            else:
                if not bdev_partno(bdev):
                    yield bdev.bd_disk
                continue
        part = container_of(device, "struct hd_struct", "__dev")
        if part.partno == 0:
            yield container_of(part, "struct gendisk", "part0")


@takes_program_or_default
def print_disks(prog: Program) -> None:
    """Print all of the disks in the system."""
    for disk in for_each_disk(prog):
        major = disk.major.value_()
        minor = disk.first_minor.value_()
        name = escape_ascii_string(disk_name(disk), escape_backslash=True)
        print(f"{major}:{minor} {name} ({disk.type_.type_name()})0x{disk.value_():x}")


def part_devt(part: Object) -> Object:
    """
    Get a partition's device number.

    :param part: ``struct block_device *`` or ``struct hd_struct *`` depending
        on the kernel version.
    :return: ``dev_t``
    """
    try:
        return part.bd_dev
    except AttributeError:
        return part.__dev.devt


def part_name(part: Object) -> bytes:
    """
    Get the name of a partition (e.g., ``sda1``).

    :param part: ``struct block_device *`` or ``struct hd_struct *`` depending
        on the kernel version.
    """
    try:
        bd_device = part.bd_device
    except AttributeError:
        return part.__dev.kobj.name.string_()
    return bd_device.kobj.name.string_()


@takes_program_or_default
def for_each_partition(prog: Program) -> Iterator[Object]:
    """
    Iterate over all partitions in the system.

    :return: Iterator of ``struct block_device *`` or ``struct hd_struct *``
        objects depending on the kernel version.
    """
    # See the comment in for_each_disk().
    have_bd_device = True
    for device in class_for_each_device(prog["block_class"].address_of_()):
        if have_bd_device:
            try:
                yield container_of(device, "struct block_device", "bd_device")
                continue
            except LookupError:
                have_bd_device = False
        yield container_of(device, "struct hd_struct", "__dev")


@takes_program_or_default
def print_partitions(prog: Program) -> None:
    """Print all of the partitions in the system."""
    for part in for_each_partition(prog):
        devt = part_devt(part).value_()
        name = escape_ascii_string(part_name(part), escape_backslash=True)
        print(
            f"{MAJOR(devt)}:{MINOR(devt)} {name} ({part.type_.type_name()})0x{part.value_():x}"
        )


@takes_program_or_default
def nr_blockdev_pages(prog: Program) -> int:
    """Get the number of memory pages used for block device buffers."""
    return sum(
        inode.i_mapping.nrpages.value_()
        for inode in list_for_each_entry(
            "struct inode",
            prog["blockdev_superblock"].s_inodes.address_of_(),
            "i_sb_list",
        )
    )


def _req_op_impls(
    prog: Program,
) -> Tuple[Callable[[Object], Object], Callable[[Object], bool]]:
    # Since Linux kernel commit ef295ecf090d ("block: better op and flags
    # encoding") (in v4.10), the request operation is the least significant
    # byte of cmd_flags. Before that, it is the most significant 3 bits. We
    # detect this by the presence of enum rq_flag_bits, which was renamed to
    # enum req_flag_bits in that commit.
    #
    # The next commit in that series, 87374179c535 ("block: add a proper block
    # layer data direction encoding"), also changed the operation numbers so
    # that odd numbers are considered writes and even reads. Before that,
    # anything other than REQ_OP_READ (0) was considered a write.
    try:
        prog.type("enum rq_flag_bits")
    except LookupError:
        # The above commit renamed enum req_op to enum req_opf. Commit
        # ff07a02e9e8e ("treewide: Rename enum req_opf into enum req_op") (in
        # v6.0) renamed it back.
        try:
            type = prog.type("enum req_op")
        except LookupError:
            type = prog.type("enum req_opf")

        def req_op(rq: Object) -> Object:
            return cast(type, rq.cmd_flags & 0xFF)

        def op_is_write(op: Object) -> bool:
            return bool(op.value_() & 1)

    else:
        type = prog.type("enum req_op")

        def req_op(rq: Object) -> Object:
            return cast(type, rq.cmd_flags >> 61)

        def op_is_write(op: Object) -> bool:
            return bool(op)

    prog.cache["req_op"] = req_op
    prog.cache["op_is_write"] = op_is_write
    return req_op, op_is_write


def req_op(rq: Object) -> Object:
    """
    Get the operation of a block request.

    >>> req_op(rq)
    (enum req_op)REQ_OP_WRITE

    :param rq: ``struct request *``
    :return: ``enum req_op`` (or ``enum req_opf`` between Linux 4.10 and Linux
        6.0)
    """
    try:
        impl = rq.prog_.cache["req_op"]
    except KeyError:
        impl = _req_op_impls(rq.prog_)[0]
    return impl(rq)


def op_is_write(op: Object) -> bool:
    """
    Return whether a block request operation is a "write"/"data out" operation.

    >>> op_is_write(prog["REQ_OP_READ"])
    False
    >>> op_is_write(prog["REQ_OP_WRITE"])
    True
    >>> op_is_write(prog["REQ_OP_DISCARD"])
    True

    :param op: ``enum req_op`` (or ``enum req_opf`` between Linux 4.10 and
        Linux 6.0)
    """
    try:
        impl = op.prog_.cache["op_is_write"]
    except KeyError:
        impl = _req_op_impls(op.prog_)[1]
    return impl(op)


def rq_data_dir(rq: Object) -> int:
    """
    Return 1 if a block request is a "write"/"data out" operation and 0
    otherwise.

    :param rq: ``struct request *``
    """
    return int(op_is_write(req_op(rq)))


def blk_rq_pos(rq: Object) -> Object:
    """
    Get the current sector of a block request.

    :param rq: ``struct request *``
    :return: ``sector_t``
    """
    return rq.member_("__sector")


def blk_rq_bytes(rq: Object) -> Object:
    """
    Get the number of bytes left in a block request.

    :param rq: ``struct request *``
    :return: ``unsigned int``
    """
    return rq.member_("__data_len")


def blk_mq_rq_to_pdu(rq: Object) -> Object:
    """
    Get the driver command data for a block request.

    :param rq: ``struct request *``
    :return: ``void *``
    """
    return cast("void *", rq + 1)


def blk_mq_rq_from_pdu(pdu: Object) -> Object:
    """
    Get a block request from its driver command data.

    :param pdu: ``void *``
    :return: ``struct request *``
    """
    return cast("struct request *", pdu) - 1


def _queue_for_each_hw_ctx(q: Object) -> Iterator[Object]:
    try:
        queue_hw_ctx = q.queue_hw_ctx
    except AttributeError:
        pass
    else:
        yield from queue_hw_ctx[: q.nr_hw_queues]
        return

    # Between Linux kernel commits 4e5cc99e1e48 ("blk-mq: manage hctx map via
    # xarray") (in v5.18) and d0c98769ee7d ("blk-mq: use array manage hctx map
    # instead of xarray") (in v6.19), hardware contexts are in an xarray.
    hctx_type = q.prog_.type("struct blk_mq_hw_ctx *")
    for _, entry in xa_for_each(q.hctx_table.address_of_()):
        yield cast(hctx_type, entry)


def _blk_mq_tags_for_each(
    tags: Object, rqs: Object, pred: Optional[Callable[[Object, int], bool]]
) -> Iterator[Object]:
    nr_reserved_tags = tags.nr_reserved_tags.value_()
    if nr_reserved_tags:
        for bit in sbitmap_for_each_set(tags.breserved_tags.sb.address_of_()):
            bit += nr_reserved_tags
            rq = rqs[bit].read_()
            if pred is None or pred(rq, bit):
                yield rq

    for bit in sbitmap_for_each_set(tags.bitmap_tags.sb.address_of_()):
        rq = rqs[bit].read_()
        if pred is None or pred(rq, bit):
            yield rq


def request_queue_busy_iter(
    q: Object, tags: Optional[Literal["driver", "sched"]] = None
) -> Iterator[Object]:
    """
    Iterate over all busy requests on a block request queue.

    .. note::

        This does not support the legacy block layer, which was removed in
        Linux 5.0.

    :param q: ``struct request_queue *``
    :param tags: If ``"driver"``, iterate over requests with an allocated
        driver tag. If ``"sched"``, iterate over requests with an allocated
        scheduler tag. Defaults to ``"driver"`` if the I/O scheduler is
        ``none`` and ``"sched"`` otherwise.

        Typically, a scheduler tag is allocated when a request is first
        submitted, then a driver tag is allocated later when the I/O scheduler
        dispatches the request. Both are freed when the request completes. If
        the I/O scheduler is ``none``, then no scheduler tags are allocated.

        Therefore, the default includes all submitted requests regardless of
        the I/O scheduler. (For flush operations, ``"sched"`` will include the
        original request but not the dedicated flush request; see
        :linux:`block/blk-flush.c`.)
    :return: Iterator of ``struct request *`` objects.
    """
    q = q.read_()
    tag_set = q.tag_set.read_()
    if not tag_set:
        # bio-based drivers don't have tags/requests.
        return
    # BLK_MQ_F_TAG_HCTX_SHARED was added in Linux kernel commit 32bc15afed04
    # ("blk-mq: Facilitate a shared sbitmap per tagset") (in v5.10).
    try:
        shared_tags = bool(tag_set.flags & q.prog_["BLK_MQ_F_TAG_HCTX_SHARED"])
    except ObjectNotFoundError:
        shared_tags = False

    if tags != "driver":
        if q.elevator:
            if shared_tags:
                # Since Linux kernel commit e155b0c238b2 ("blk-mq: Use shared
                # tags for shared sbitmap support") (in v5.16), all hctxs with
                # shared tags use the same ->sched_tags.
                try:
                    sched_tags = q.sched_shared_tags.read_()
                except AttributeError:
                    pass
                else:
                    yield from _blk_mq_tags_for_each(
                        sched_tags, sched_tags.static_rqs.read_(), None
                    )
                    return

                # Between that commit and d97e594c5166 ("blk-mq: Use request
                # queue-wide tags for tagset-wide sbitmap") (in v5.14), every
                # hctx with shared tags has its own ->sched_tags but they share
                # the same sbitmaps. Before that, every hctx with shared tags
                # has its own ->sched_tags and sbitmaps. The following works
                # for both cases.
                for hctx in _queue_for_each_hw_ctx(q):
                    sched_tags = hctx.sched_tags.read_()
                    yield from _blk_mq_tags_for_each(
                        sched_tags,
                        sched_tags.static_rqs.read_(),
                        lambda rq, tag: bool(rq.ref.refs.counter),
                    )
                return

            for hctx in _queue_for_each_hw_ctx(q):
                sched_tags = hctx.sched_tags.read_()
                yield from _blk_mq_tags_for_each(
                    sched_tags, sched_tags.static_rqs.read_(), None
                )
            return
        elif tags is not None:
            return

    # Since Linux kernel commit e155b0c238b2 ("blk-mq: Use shared tags for
    # shared sbitmap support") (in v5.16), every hctx with shared tags has its
    # own ->tags but they share the same sbitmaps.
    if shared_tags and hasattr(tag_set, "__bitmap_tags"):
        for hctx in _queue_for_each_hw_ctx(q):
            t = hctx.tags.read_()
            yield from _blk_mq_tags_for_each(
                t,
                t.rqs.read_(),
                lambda rq, tag: bool(rq)
                and rq.tag.value_() == tag
                and rq.mq_hctx == hctx,
            )
        return

    for t in tag_set.tags[: 1 if shared_tags else tag_set.nr_hw_queues]:
        t = t.read_()
        yield from _blk_mq_tags_for_each(
            t,
            t.rqs.read_(),
            lambda rq, tag: bool(rq) and rq.tag.value_() == tag and rq.q == q,
        )
