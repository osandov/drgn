# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Log Buffer
----------

The ``drgn.helpers.linux.printk`` module provides helpers for reading the Linux
kernel log buffer.
"""

from typing import Dict, List, NamedTuple, Optional, Tuple

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
    caller_tid: Optional[int]
    """
    Thread ID of thread that logged this record, if available.

    This is available if the message was logged from task context and if the
    kernel saves the ``printk()`` caller ID.

    As of Linux 5.10, the kernel always saves the caller ID. From Linux 5.1
    through 5.9, it is saved only if the kernel was compiled with
    ``CONFIG_PRINTK_CALLER``. Before that, it is never saved.
    """
    caller_cpu: Optional[int]
    """
    Processor ID of CPU that logged this record, if available.

    This is available only if the message was logged when not in task context
    (e.g., in an interrupt handler) and if the kernel saves the ``printk()``
    caller ID.

    See :attr:`caller_tid` for when the kernel saves the caller ID.
    """
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


def _caller_id(caller_id: int) -> Tuple[Optional[int], Optional[int]]:
    if caller_id & 0x80000000:
        return None, caller_id & ~0x80000000
    else:
        return caller_id, None


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
    descs = desc_ring.descs.read_()
    infos = desc_ring.infos.read_()
    desc_ring_mask = (1 << desc_ring.count_bits.value_()) - 1
    text_data_ring = prb.text_data_ring
    text_data_ring_data = text_data_ring.data.read_()
    text_data_ring_mask = (1 << text_data_ring.size_bits) - 1

    result = []

    def add_record(current_id: int) -> None:
        idx = current_id & desc_ring_mask
        desc = descs[idx].read_()
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
        info = infos[idx].read_()
        text_len = info.text_len
        if lpos_next - lpos_begin < text_len:
            # Truncated record.
            text_len = lpos_next - lpos_begin

        caller_tid, caller_cpu = _caller_id(info.caller_id.value_())

        context = {}
        subsystem = info.dev_info.subsystem.string_()
        device = info.dev_info.device.string_()
        if subsystem:
            context[b"SUBSYSTEM"] = subsystem
        if device:
            context[b"DEVICE"] = device

        result.append(
            PrintkRecord(
                text=prog.read(text_data_ring_data + lpos_begin, text_len),
                facility=info.facility.value_(),
                level=info.level.value_(),
                seq=info.seq.value_(),
                timestamp=info.ts_nsec.value_(),
                caller_tid=caller_tid,
                caller_cpu=caller_cpu,
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
    have_caller_id = printk_logp_type.type.has_member("caller_id")
    LOG_CONT = prog["LOG_CONT"].value_()

    result = []
    log_buf = prog["log_buf"].read_()
    current_idx = prog["log_first_idx"].read_()
    next_idx = prog["log_next_idx"].read_()
    seq = prog["log_first_seq"].value_()
    while current_idx != next_idx:
        logp = cast(printk_logp_type, log_buf + current_idx)
        log = logp[0].read_()
        text_len = log.text_len.value_()
        dict_len = log.dict_len.value_()
        text_dict = prog.read(logp + 1, text_len + dict_len)

        if have_caller_id:
            caller_tid, caller_cpu = _caller_id(log.caller_id.value_())
        else:
            caller_tid = caller_cpu = None

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
                caller_tid=caller_tid,
                caller_cpu=caller_cpu,
                continuation=bool(log.flags.value_() & LOG_CONT),
                context=context,
            )
        )
        log_len = log.len.read_()
        if log_len:
            current_idx += log_len
        else:
            # Zero means the buffer wrapped around.
            if current_idx < next_idx:
                # Avoid getting into an infinite loop if the buffer is
                # corrupted.
                break
            current_idx -= current_idx
        seq += 1
    return result


def get_printk_records(prog: Program) -> List[PrintkRecord]:
    """Get a list of records in the kernel log buffer."""
    # Linux kernel commit 896fbe20b4e2 ("printk: use the lockless ringbuffer")
    # (in v5.10) changed the ring buffer structure completely.
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

    If you need to format the log buffer differently, use
    :func:`get_printk_records()` and format it yourself.
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
