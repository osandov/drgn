# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Log Buffer
----------

The ``drgn.helpers.linux.dmesg`` module provides helpers for reading the Linux
kernel log buffer.
"""

from typing import Dict, List, NamedTuple

from drgn import Object, Program, cast, sizeof

__all__ = (
    "get_dmesg",
    "get_printk_records",
)


class PrintkRecord(NamedTuple):
    """Kernel log record."""

    text: bytes
    """Message text."""
    facility: int
    """:manpage:`syslog(3)` facility."""
    level: int
    """Log level."""
    seq: int
    """Sequence number."""
    timestamp: int
    """Timestamp in nanoseconds."""
    continuation: bool
    """Whether this record is a continuation of a previous record."""
    context: Dict[bytes, bytes]
    """
    Additional metadata for the message.

    See the |/dev/kmsg documentation|_ for an explanation of the keys and
    values.

    .. |/dev/kmsg documentation| replace:: ``/dev/kmsg`` documentation
    .. _/dev/kmsg documentation: https://www.kernel.org/doc/Documentation/ABI/testing/dev-kmsg
    """


def _get_printk_records_lockless(prog: Program, prb: Object) -> List[PrintkRecord]:
    ulong_size = sizeof(prog.type("unsigned long"))
    DESC_SV_BITS = ulong_size * 8
    DESC_FLAGS_SHIFT = DESC_SV_BITS - 2
    DESC_FLAGS_MASK = 3 << DESC_FLAGS_SHIFT
    DESC_ID_MASK = DESC_FLAGS_MASK ^ ((1 << DESC_SV_BITS) - 1)

    LOG_CONT = prog["LOG_CONT"].value_()
    desc_committed = prog["desc_committed"].value_()
    desc_finalized = prog["desc_finalized"].value_()

    def record_committed(current_id: int, state_var: int) -> bool:
        state_desc_id = state_var & DESC_ID_MASK
        state = 3 & (state_var >> DESC_FLAGS_SHIFT)
        return (current_id == state_desc_id) and (
            state == desc_committed or state == desc_finalized
        )

    desc_ring = prb.desc_ring
    desc_ring_count = 1 << desc_ring.count_bits.value_()
    text_data_ring = prb.text_data_ring
    text_data_ring_mask = (1 << text_data_ring.size_bits) - 1

    result = []

    def add_record(current_id: int) -> None:
        idx = current_id % desc_ring_count
        desc = desc_ring.descs[idx]
        if not record_committed(current_id, desc.state_var.counter.value_()):
            return

        lpos_begin = desc.text_blk_lpos.begin & text_data_ring_mask
        lpos_next = desc.text_blk_lpos.next & text_data_ring_mask
        lpos_begin += ulong_size

        if lpos_begin == lpos_next:
            # Data-less record.
            return
        if lpos_begin > lpos_next:
            # Data wrapped.
            lpos_begin -= lpos_begin
        info = desc_ring.infos[idx]
        text_len = info.text_len
        if lpos_next - lpos_begin < text_len:
            # Truncated record.
            text_len = lpos_next - lpos_begin

        context = {}
        subsystem = info.dev_info.subsystem.string_()
        device = info.dev_info.device.string_()
        if subsystem:
            context[b"SUBSYSTEM"] = subsystem
        if device:
            context[b"DEVICE"] = device

        result.append(
            PrintkRecord(
                text=prog.read(text_data_ring.data + lpos_begin, text_len),
                facility=info.facility.value_(),
                level=info.level.value_(),
                seq=info.seq.value_(),
                timestamp=info.ts_nsec.value_(),
                continuation=bool(info.flags.value_() & LOG_CONT),
                context=context,
            )
        )

    head_id = desc_ring.head_id.counter.value_()
    current_id = desc_ring.tail_id.counter.value_()
    while current_id != head_id:
        add_record(current_id)
        current_id = (current_id + 1) & DESC_ID_MASK
    add_record(current_id)
    return result


def _get_printk_records_structured(prog: Program) -> List[PrintkRecord]:
    printk_logp_type = prog.type("struct printk_log *")
    LOG_CONT = prog["LOG_CONT"].value_()

    result = []
    current_idx = prog["log_first_idx"]
    next_idx = prog["log_next_idx"]
    seq = prog["log_first_seq"].value_()
    while current_idx != next_idx:
        log = cast(printk_logp_type, prog["log_buf"] + current_idx)
        text_len = log.text_len.value_()
        dict_len = log.dict_len.value_()
        text_dict = prog.read(log + 1, text_len + dict_len)
        context = {}
        if dict_len:
            for elmt in text_dict[text_len:].split(b"\0"):
                key, value = elmt.split(b"=", 1)
                context[key] = value
        result.append(
            PrintkRecord(
                text=text_dict[:text_len],
                facility=log.facility.value_(),
                level=log.level.value_(),
                seq=seq,
                timestamp=log.ts_nsec.value_(),
                continuation=bool(log.flags.value_() & LOG_CONT),
                context=context,
            )
        )
        log_len = log.len.read_()
        if log_len:
            current_idx += log_len
        else:
            # Zero means the buffer wrapped around.
            current_idx -= current_idx
        seq += 1
    return result


def get_printk_records(prog: Program) -> List[PrintkRecord]:
    """Get a list of records in the kernel log buffer."""
    # Linux kernel commit 896fbe20b4e2 ("printk: use the lockless ringbuffer")
    # changed the ring buffer structure completely.
    try:
        prb = prog["prb"]
    except KeyError:
        return _get_printk_records_structured(prog)
    else:
        return _get_printk_records_lockless(prog, prb)


def get_dmesg(prog: Program) -> bytes:
    """
    Get the contents of the kernel log buffer formatted like
    :manpage:`dmesg(1)`.

    The format of each line is:

    .. code-block::

        [   timestamp] message

    Use :func:`get_printk_records()` directly to format the log buffer
    differently.
    """
    lines = [
        b"[% 5d.%06d] %s"
        % (
            record.timestamp // 1000000000,
            record.timestamp % 1000000000 // 1000,
            record.text,
        )
        for record in get_printk_records(prog)
    ]
    lines.append(b"")  # So we get a trailing newline.
    return b"\n".join(lines)
