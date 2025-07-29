# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Log Buffer
----------

The ``drgn.helpers.linux.printk`` module provides helpers for reading the Linux
kernel log buffer.
"""

import operator
import re
import sys
from typing import (
    TYPE_CHECKING,
    Dict,
    Iterator,
    List,
    Literal,
    NamedTuple,
    Optional,
    Tuple,
    Union,
)

if TYPE_CHECKING:
    from _typeshed import SupportsWrite

from datetime import datetime

from drgn import Object, Program, StackTrace, cast, sizeof
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.timekeeping import ktime_get_coarse_ns, ktime_get_coarse_real_ns

__all__ = (
    "for_each_dmesg_stack_trace",
    "get_dmesg",
    "get_printk_records",
    "print_dmesg",
    "stack_trace_from_text",
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
    try:
        printk_logp_type = prog.type("struct printk_log *")
    except LookupError:
        # Before Linux kernel commit 62e32ac3505a ("printk: rename struct log
        # to struct printk_log") (in v3.11), records were "struct log" instead
        # of "struct printk_log". RHEL 7 kernel still uses old naming.
        printk_logp_type = prog.type("struct log *")

    have_caller_id = printk_logp_type.type.has_member("caller_id")
    LOG_CONT = prog["LOG_CONT"].value_()

    result = []
    # Between Linux kernel commits cbd357008604 ("bpf: verifier (add ability to
    # receive verification log)") (in v3.18) and e7bf8249e8f1 ("bpf:
    # encapsulate verifier log state into a structure") (in v4.15),
    # kernel/bpf/verifier.c also contains a variable named log_buf.
    log_buf = prog.object("log_buf", filename="printk.c").read_()
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


@takes_program_or_default
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


def _format_record_default(record: PrintkRecord) -> bytes:
    return b"[% 5d.%06d] %s" % (
        record.timestamp // 1000000000,
        record.timestamp % 1000000000 // 1000,
        record.text,
    )


@takes_program_or_default
def get_dmesg(
    prog: Program, *, timestamps: Union[bool, Literal["human"]] = True
) -> bytes:
    """
    Get the contents of the kernel log buffer formatted like
    :manpage:`dmesg(1)`.

    If you just want to print the log buffer, use :func:`print_dmesg()`.

    The format of each line is:

    .. code-block::

        [   timestamp] message

    If you need to format the log buffer differently, use
    :func:`get_printk_records()` and format it yourself.

    :param timestamps: How to format timestamps. If ``True``, timestamps are
        formatted in decimal seconds. If ``False``, timestamps are omitted. If
        ``"human"``, timestamps are formatted as human-readable dates and
        times, which are only correct for messages printed since the last
        suspend/resume.
    """
    if timestamps == "human":
        boot_time_s = (
            ktime_get_coarse_real_ns(prog).value_() - ktime_get_coarse_ns(prog).value_()
        )

        def format(record: PrintkRecord) -> bytes:
            return b"[%s] %s" % (
                datetime.fromtimestamp((boot_time_s + record.timestamp) // 1000000000)
                .astimezone()
                .strftime("%a %b %e %T %Z %Y")
                .encode(),
                record.text,
            )

    else:
        assert isinstance(timestamps, bool)
        if timestamps:
            format = _format_record_default
        else:
            format = operator.attrgetter("text")  # type: ignore[assignment]

    lines = [format(record) for record in get_printk_records(prog)]
    lines.append(b"")  # So we get a trailing newline.
    return b"\n".join(lines)


@takes_program_or_default
def print_dmesg(
    prog: Program,
    *,
    timestamps: Union[bool, Literal["human"]] = True,
    file: "Optional[SupportsWrite[str]]" = None,
) -> None:
    """
    Print the contents of the kernel log buffer.

    >>> print_dmesg()
    [    0.000000] Linux version 6.8.0-vmtest28.1default (drgn@drgn) (x86_64-linux-gcc (GCC) 12.2.0, GNU ld (GNU Binutils) 2.39) #1 SMP PREEMPT_DYNAMIC Mon Mar 11 06:38:45 UTC 2024
    [    0.000000] Command line: rootfstype=9p rootflags=trans=virtio,cache=loose,msize=1048576 ro console=ttyS0,115200 panic=-1 crashkernel=256M init=/tmp/drgn-vmtest-rudzppeo/init
    [    0.000000] BIOS-provided physical RAM map:
    ...

    :param timestamps: How to format timestamps. See :func:`get_dmesg()`.
    :param file: File to print to. Defaults to :data:`sys.stdout`.
    """
    (sys.stdout if file is None else file).write(
        get_dmesg(prog, timestamps=timestamps).decode(errors="replace")
    )


@takes_program_or_default
def stack_trace_from_text(prog: Program, log: str) -> StackTrace:
    """
    Return a drgn stack trace from a text form

    Search the given text for all occurrences of the pattern
    ``symbol+0x1a/0x40`` (a symbol name with an offset and size). Look up the
    symbols and convert this sequence into a drgn stack trace. The resulting
    stack trace can leverage drgn's understanding of the debug info, and thus it
    can include information not present in the original text: filenames, line
    numbers, and even extra stack frames for inline functions.

    :param log: the text of the stack trace
    :returns: an equivalent drgn stack trace
    """
    pcs = []
    for match in re.finditer(
        r"(\? )?([a-zA-Z_][a-zA-Z0-9_.]*)\+(0x[0-9a-f]+)/0x[0-9a-f]+", log
    ):
        # Some symbols have a "?" before them, these are text addresses found on
        # the stack which are not part of the reliable stack trace. We could try
        # to tweak the regex with a negative lookbehind assertion to avoid them,
        # but it turns out to be easier to just match and ignore them.
        if match.group(1) == "? ":
            continue
        symbol_name = match.group(2)
        offset = int(match.group(3), 16)
        pcs.append(prog.symbol(symbol_name).address + offset)
    return prog.stack_trace_from_pcs(pcs)


class PrintkStackTrace(NamedTuple):
    """A stack trace and metadata logged to the kernel log."""

    timestamp: int
    """Timestamp in nanoseconds"""

    stack_trace: StackTrace
    """The trace, reperesented with a drgn stack trace object."""

    cpu: Optional[int]
    """The CPU of the stack trace, if it was found in the log."""

    pid: Optional[int]
    """The PID of the stack trace, if it was found in the log."""


@takes_program_or_default
def for_each_dmesg_stack_trace(
    prog: Program, records: Optional[List[PrintkRecord]] = None
) -> Iterator[PrintkStackTrace]:
    """
    Yield stack traces from the kernel log, or the provided log records

    This searches the kernel log, or provided records, for stack traces. Stack
    traces are printed by architecture-specific code, whose format can vary.
    Further, stack traces are printed in many situations (panics, warnings,
    etc), and the format of the metadata placed around them can vary as well.
    As a result, this process is best-effort, and could even fail. It is only
    tested on x86_64 at this time.

    :param records: a list of printk records to search. If not provided, we'll
      use the full list from get_printk_records()
    :returns: an iterator of printk stack trace records
    """
    if records is None:
        records = get_printk_records(prog)

    cpu_pid_re = re.compile(rb"(cpu|pid):\s*(\d+)", re.I)
    i = 0
    while i < len(records):
        record = records[i]
        if b"Call Trace:" not in record.text:
            i += 1
            continue

        # Collect the records composing the stack trace.
        this_trace = []
        j = i + 1
        while j < len(records) and records[j].text[0] == ord(b" "):
            this_trace.append(records[j].text)
            j += 1

        trace_text = b"".join(this_trace).decode("utf-8", errors="replace")
        trace = stack_trace_from_text(prog, trace_text)

        # Search the previous log records for the first record containing "CPU:"
        # and/or "PID", which is within 1ms of the Call Trace record.
        NUM_SEARCH = 20
        cpu = pid = None
        for k in range(i - 1, max(i - 1 - NUM_SEARCH, 0), -1):
            if (record.timestamp - records[k].timestamp) > 1000000:
                break

            for match in cpu_pid_re.finditer(records[k].text):
                if match.group(1).lower() == b"cpu":
                    cpu = int(match.group(2))
                else:
                    pid = int(match.group(2))
            if cpu is not None or pid is not None:
                break
        yield PrintkStackTrace(record.timestamp, trace, cpu, pid)
        i = j
