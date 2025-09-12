# Copyright (c) 2026 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Stack
-----

The ``drgn.helpers.linux.stack`` module contains helpers for working with Linux
kernel stacks. These helpers can provide additional information specific to the
kernel.
"""
from dataclasses import dataclass
import enum
from itertools import chain
import operator
from typing import Iterator, List, Sequence, Tuple, Union

from drgn import (
    Architecture,
    IntegerLike,
    Object,
    ObjectNotFoundError,
    Program,
    StackFrame,
    StackTrace,
    TypeKind,
    sizeof,
)
from drgn.cli import display_str
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.percpu import per_cpu
from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.sched import task_cpu

__all__ = (
    "StackKind",
    "StackSegment",
    "LinuxKernelStack",
    "kernel_stack_trace",
)


class StackKind(enum.Enum):
    """A ``StackKind`` represents a kind of context associated with a stack."""

    USER = 1
    """Stack frames associated with userspace"""

    TASK = 2
    """Stack frames associated with the kernel's thread stack"""

    IRQ = 3
    """Stack frames associated with IRQ handlers"""

    SOFTIRQ = 4
    """Stack frames associated with softirqs"""

    NMI = 5
    """Stack frames associated with NMI handlers (arch-specific)"""

    EXCEPTION = 6
    """Stack frames associated with other exceptions (arch-specific)"""

    UNKNOWN = 7
    """Stack frames which could not be categorized"""


@dataclass(frozen=True)
class StackSegment:
    """A subset of a stack trace associated with a context."""

    kind: StackKind
    """The kind of stack associated with this segment"""

    frames: Sequence[StackFrame]
    """Stack frames that are part of the segment"""

    def __iter__(self) -> Iterator[StackFrame]:
        return iter(self.frames)

    def __len__(self) -> int:
        return len(self.frames)

    def __getitem__(self, key: int) -> StackFrame:
        return self.frames[key]


@display_str
@dataclass(frozen=True)
class LinuxKernelStack:
    """
    A stack trace broken into segments associated with execution contexts.

    Stack traces for kernel programs may span many execution contexts, each one
    interrupting the previous one. For instance, a user task may be interrupted
    by the kernel handling its system call, which could in turn be interrupted
    by a hardware interrupt. A ``LinuxKernelStack`` groups the frames of a stack
    trace into :class:`StackSegments<StackSegment>`, each of which is associated
    with a :class:`StackKind`. It may also be iterated and indexed like a normal
    :class:`~drgn.StackTrace`.
    """

    prog: Program
    """The program associated with the stack trace"""

    segments: Sequence[StackSegment]
    """Segments of the stack trace"""

    def __str__(self) -> str:
        lines = []
        i = -1
        for seg in self.segments:
            for i, frame in enumerate(seg.frames, i + 1):
                source_info = ""
                try:
                    source_info = " (%s:%d:%d)" % frame.source()
                except LookupError:
                    pass
                lines.append(f"#{i:<2d} {frame.name}{source_info}")
            lines.append(f"  --- end {seg.kind.name} stack ---")
        return "\n".join(lines)

    def __iter__(self) -> Iterator[StackFrame]:
        return chain.from_iterable(map(iter, self.segments))

    def __len__(self) -> int:
        return sum(len(seg.frames) for seg in self.segments)

    def __getitem__(self, index: int) -> StackFrame:
        if index < 0:
            index += len(self)
        if index < 0:
            raise IndexError("index out of range")
        start = 0
        for segment in self.segments:
            if start <= index < start + len(segment.frames):
                return segment.frames[index - start]
            start += len(segment.frames)
        raise IndexError("index out of range")


def _real_frames(trace: StackTrace) -> Iterator[List[StackFrame]]:
    # Yield all inline frames associated with their "physical" stack frame in a
    # single list. This simplifies iteration later.
    current = []
    for frame in trace:
        current.append(frame)
        if not frame.is_inline:
            yield current
            current = []
    if current:
        yield current


def _x86_64_exception_stacks(
    prog: Program, cpu: int
) -> List[Tuple[int, int, StackKind]]:
    try:
        # The cpu_entry_area was introduced in ece614dcfd964 ("x86/mm/fixmap:
        # Generalize the GDT fixmap mechanism, introduce struct
        # cpu_entry_area"), and later in the same series, the field
        # "exception_stacks" was introduced. This was all part of the KPTI
        # (Kernel Page Table Isolation) effort, which removes most of the
        # kernel's memory mappings from userspace page tables. This was merged
        # in v4.15 and backported to v4.14.9 stable.
        #
        # Prior to this, the per-CPU variable `exception_stacks` was an array of
        # stacks for different exception modes, and it was used directly for
        # exception stacks. But since KPTI results in this memory being
        # unmapped, the cpu_entry_area was created in "fixmap" memory which *is*
        # part of the minimal userspace page tables. The `exception_stacks`
        # variable still exists and contains the backing memory for these
        # mappings. But the stack pointers we observe use the addresses for the
        # cpu_entry_area, so the exception_stacks variable isn't helpful for
        # categorizing stacks once KPTI is present.
        #
        # So, when we see the cpu_entry_area type, we can assume that the KPTI
        # patches are present, and we should use it to find exception stacks.
        # Prior to that, we can just rely on exception_stacks.
        cea_tp = prog.type("struct cpu_entry_area")
    except LookupError:
        estacks = per_cpu(prog["exception_stacks"], cpu)
        base = estacks.address_of_().value_()
        return [(base, base + sizeof(estacks), StackKind.EXCEPTION)]

    _CEA_START = 0xFFFFFE0000000000 + prog["PAGE_SIZE"].value_()
    try:
        # Since v6.2 97e3d26b5e5f3 ("x86/mm: Randomize per-cpu entry area")
        # the CPU entry area has randomized offsets.
        cea_offset = int(per_cpu(prog["_cea_offset"], cpu))
    except ObjectNotFoundError:
        # Prior, it was a plain CPU index.
        cea_offset = cpu
    assert cea_tp.size is not None
    cea_start = _CEA_START + cea_offset * cea_tp.size

    stacks = []

    # Try to determine the NMI stack range and put it into the first slot, so we
    # can be more precise.
    try:
        # Since v5.1, in commit 019b17b3ffe48 ("x86/exceptions: Add structs for
        # exception stacks"), the exception stacks are stored in structs, and we
        # can easily identify the NMI stack (and even specific exception stacks,
        # if we cared to do so).
        cea = Object(prog, cea_tp, address=cea_start)
        estacks = cea.estacks
        nmi_stack = estacks.NMI_stack
        nmi_start = int(nmi_stack.address_of_())
        stacks.append((nmi_start, nmi_start + sizeof(nmi_stack), StackKind.NMI))

    except AttributeError:
        # Prior to that, there's a big array containing each stack in the
        # cpu_entry_area. Without hard-coding it, we can't really determine the
        # NMI stack, so don't bother. Just lump it in with the rest of the
        # exception stacks.
        pass

    # The CPU entry area for the CPU contains all other exception stacks.
    stacks.append((cea_start, cea_start + cea_tp.size, StackKind.EXCEPTION))
    return stacks


def _x86_64_stack_ranges(task: Object, cpu: int) -> List[Tuple[int, int, StackKind]]:
    prog = task.prog_

    stacks = _x86_64_exception_stacks(prog, cpu)

    try:
        # Since v6.15, the hardirq stack pointer is its own percpu global.
        # Commit c6a0918072eaa ("x86/irq: Move irq stacks to percpu hot
        # section") put it there.
        #
        # Strangely, prior to commit d7b6d709a76a4 ("x86/percpu: Move irq_stack
        # variables next to current_task") from v6.2, the hardirq_stack_ptr
        # variable was also a percpu global. So this suffices for that case as
        # well.
        hardirq_top = int(per_cpu(prog["hardirq_stack_ptr"], cpu))
    except ObjectNotFoundError:
        try:
            # As said above, between 6.2 and 6.12, it was found in pcpu_hot.
            hardirq_top = int(per_cpu(prog["pcpu_hot"], cpu).hardirq_stack_ptr)
        except ObjectNotFoundError:
            # And prior to v5.2 (commit 758a2e3122284 ("x86/irq/64: Rename
            # irq_stack_ptr to hardirq_stack_ptr")) it was just irq_stack_ptr:
            hardirq_top = int(per_cpu(prog["irq_stack_ptr"], cpu))

    # x86_64 defines IRQ_STACK_SIZE the same way as THREAD_SIZE
    irq_stack_size = prog["THREAD_SIZE"].value_()
    stacks.append((hardirq_top - irq_stack_size, hardirq_top, StackKind.IRQ))

    # On x86_64, userspace memory addresses always have the MSB cleared. The
    # actual userspace address range is smaller. However, don't include the zero
    # page in this, as it's not a valid stack pointer.
    stacks.append((int(prog["PAGE_SIZE"]), (1 << 63), StackKind.USER))

    return stacks


def _aarch64_stack_ranges(task: Object, cpu: int) -> List[Tuple[int, int, StackKind]]:
    prog = task.prog_
    irq_stack_ptr = per_cpu(prog["irq_stack_ptr"], cpu).value_()
    # aarch64 defines IRQ_STACK_SIZE as THREAD_SIZE
    thread_size = prog["THREAD_SIZE"].value_()
    return [
        (irq_stack_ptr, irq_stack_ptr + thread_size, StackKind.IRQ),
    ]


def _aarch64_classify(_: Object, __: int, frames: List[StackFrame]) -> StackKind:
    # aarch64 supports memory tagging, where the upper byte of a user memory
    # address can be set to a tag. The canonical address is formed by
    # sign-extending bit 55 into bits 56-63. In our case, we just want to test
    # it to determine whether the address is userspace or kernel.
    try:
        if not frames[0].sp & (1 << 55):
            return StackKind.USER
    except LookupError:
        pass
    return StackKind.UNKNOWN


def _arm_stack_ranges(task: Object, cpu: int) -> List[Tuple[int, int, StackKind]]:
    prog = task.prog_
    # ARM can have different user/kernel splits: 1/3, 2/2, and 3/1. While _stext
    # is not directly at that split, it's very close, and we can just mask off
    # the top two bits to get what the actual split is without any offset.
    kernel_offset = prog.symbol("_stext").address & 0xC0000000
    ranges = [
        (prog["PAGE_SIZE"].value_(), kernel_offset, StackKind.USER),
    ]
    try:
        irq_stack_ptr = per_cpu(prog["irq_stack_ptr"], cpu).value_()
        # arm allocates IRQ stacks at THREAD_SIZE
        thread_size = prog["THREAD_SIZE"].value_()
        ranges.append((irq_stack_ptr, irq_stack_ptr + thread_size, StackKind.IRQ))
    except ObjectNotFoundError:
        # IRQ stacks were implemented for arm in d4664b6c987f8 ("ARM: implement
        # IRQ stacks"), starting with v5.18. Prior to that, IRQs were taken on
        # the kernel thread stack.
        pass
    return ranges


def _s390x_stack_ranges(task: Object, cpu: int) -> List[Tuple[int, int, StackKind]]:
    prog = task.prog_

    # Lowcore is a CPU control block which contains, among other thengs, the
    # stack pointers each CPU is configured to use. The stacks pointers are
    # stored with an offset so that they are ready to use by the CPU. But they
    # leave enough room to store a pt_regs and a linkage stack frame at the top.
    lowcore = prog["lowcore_ptr"][cpu]
    thread_size = prog["THREAD_SIZE"].value_()
    stack_init_offset = (
        thread_size
        - sizeof(prog.type("struct stack_frame"))
        - sizeof(prog.type("struct pt_regs"))
    )

    irq = lowcore.async_stack.value_() - stack_init_offset
    restart = lowcore.restart_stack.value_() - stack_init_offset
    ranges = [
        (irq, irq + thread_size, StackKind.IRQ),
        # The remaining arch-specific stacks don't have a better categorization
        # other than "exception"
        (restart, restart + thread_size, StackKind.EXCEPTION),
    ]

    try:
        mcck = lowcore.mcck_stack.value_() - stack_init_offset
        ranges.append((mcck, mcck + thread_size, StackKind.EXCEPTION))
    except AttributeError:
        # mcck_stack is introduced in v5.12 with commit b61b1595124a1 ("s390:
        # add stack for machine check handler").
        pass

    try:
        nodat = lowcore.nodat_stack.value_() - stack_init_offset
    except AttributeError:
        # nodat_stack was panic_stack prior to v4.20, commit ce3dc447493ff
        # ("s390: add support for virtually mapped kernel stacks").
        nodat = lowcore.panic_stack.value_() - stack_init_offset
    ranges.append((nodat, nodat + thread_size, StackKind.EXCEPTION))

    return ranges


def _s390x_classify(_: Object, __: int, frames: List[StackFrame]) -> StackKind:
    # drgn's registers contain the "program status word" which includes the
    # pstate bit, which is set when running in userspace.
    regs = frames[0].registers()
    PSW_MASK_PSTATE = 0x0001000000000000
    pswm = regs.get("pswm")
    if pswm is not None and pswm & PSW_MASK_PSTATE:
        return StackKind.USER
    else:
        return StackKind.UNKNOWN


def _ppc64_stack_ranges(task: Object, cpu: int) -> List[Tuple[int, int, StackKind]]:
    prog = task.prog_
    thread_size = prog["THREAD_SIZE"].value_()

    # These point to the beginning of the stack region
    hardirq = prog["hardirq_ctx"][cpu].value_()
    softirq = prog["softirq_ctx"][cpu].value_()
    ranges = [
        (hardirq, hardirq + thread_size, StackKind.IRQ),
        (softirq, softirq + thread_size, StackKind.SOFTIRQ),
    ]

    try:
        # The PACA (Processor Auxiliary Control Area) defines stack pointers.
        # These are defined differently for "Book 3E" (embedded) and "Book 3S"
        # (server) processors. Drgn tests against Book 3S, so that's what we
        # mainly support.
        paca = prog["paca_ptrs"][cpu]
        if not paca:
            return ranges
    except ObjectNotFoundError:
        # Prior to commit d2e60075a3d44 ("powerpc/64: Use array of paca pointers
        # and allocate pacas individually") in v4.17, this was a struct array,
        # rather than array of pointers to structs.
        paca = prog["paca"][cpu]

    for name in ("emercency_sp", "nmi_emergency_sp", "mc_emergency_sp"):
        sp = int(getattr(paca, name, 0))
        if sp:
            ranges.append((sp - thread_size, sp, StackKind.EXCEPTION))

    return ranges


def _classify_segment(task: Object, cpu: int, frames: List[StackFrame]) -> StackSegment:
    prog = task.prog_
    kind = StackKind.UNKNOWN
    try:
        sp = frames[0].sp
    except LookupError:
        return StackSegment(kind, frames)

    # Architecture-independent: the task stack
    ranges = [
        (
            int(task.stack),
            int(task.stack) + prog["THREAD_SIZE"].value_(),
            StackKind.TASK,
        ),
    ]
    arch = prog.platform.arch if prog.platform else None
    if arch == Architecture.X86_64:
        ranges.extend(_x86_64_stack_ranges(task, cpu))
    elif arch == Architecture.AARCH64:
        ranges.extend(_aarch64_stack_ranges(task, cpu))
    elif arch == Architecture.ARM:
        ranges.extend(_arm_stack_ranges(task, cpu))
    elif arch == Architecture.PPC64:
        ranges.extend(_ppc64_stack_ranges(task, cpu))
    elif arch == Architecture.S390X:
        ranges.extend(_s390x_stack_ranges(task, cpu))

    for start, stop, range_kind in ranges:
        if start <= sp < stop:
            kind = range_kind
            break
    else:
        if arch == Architecture.S390X:
            kind = _s390x_classify(task, cpu, frames)
        elif arch == Architecture.AARCH64:
            kind = _aarch64_classify(task, cpu, frames)

    return StackSegment(kind, frames)


@takes_program_or_default
def kernel_stack_trace(
    prog: Program, task_arg: Union[Object, IntegerLike]
) -> LinuxKernelStack:
    """
    Create a stack trace and return a categorized :class:`LinuxKernelStack`.

    This function creates a stack trace, breaks it into segments, and
    categorizes each segment. The process is best-effort. Not all stack kinds
    can be segmented or recognized, as the process is architecture and version
    specific.

    :param task: a PID or ``struct task_struct *`` to unwind
    :returns: a separated, annotated stack
    """
    if isinstance(task_arg, Object):
        underlying_type = task_arg.type_
        while underlying_type.kind == TypeKind.TYPEDEF:
            underlying_type = underlying_type.type
        if underlying_type.kind == TypeKind.INT:
            pid = operator.index(task_arg)
            task = find_task(prog, pid)
        elif underlying_type.kind == TypeKind.POINTER:
            task = task_arg
        else:
            raise TypeError("expected struct task_struct *, or int (pid)")
    else:
        pid = operator.index(task_arg)
        task = find_task(prog, pid)

    cpu = task_cpu(task)
    trace = task.prog_.stack_trace(task)
    segments: List[StackSegment] = []
    current: List[StackFrame] = []

    for frame_list in _real_frames(trace):
        frame = frame_list[-1]

        if current and frame.interrupted:
            segments.append(_classify_segment(task, cpu, current))
            current = []

        current.extend(frame_list)

    if current:
        segments.append(_classify_segment(task, cpu, current))

    return LinuxKernelStack(task.prog_, segments)
