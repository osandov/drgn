# Copyright (c) Meta Platforms, Inc. and affiliates.
# Copyright (c) 2023, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Interrupts
----------

The ``drgn.helpers.linux.irq`` module provides helpers for working with IRQs
and interrupt descriptors.
"""

from typing import Iterator, List, Optional, Tuple

from drgn import IntegerLike, Object, ObjectNotFoundError, Program, cast
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.cpumask import cpumask_of
from drgn.helpers.linux.mapletree import mt_for_each, mtree_load
from drgn.helpers.linux.percpu import per_cpu
from drgn.helpers.linux.radixtree import radix_tree_for_each, radix_tree_lookup

__all__ = (
    "for_each_irq_desc",
    "gate_desc_func",
    "irq_desc_action_names",
    "irq_desc_affinity_mask",
    "irq_desc_chip_name",
    "irq_desc_kstat_cpu",
    "irq_to_desc",
)


@takes_program_or_default
def irq_to_desc(prog: Program, irq: IntegerLike) -> Object:
    """
    Get the interrupt descriptor for an IRQ number.

    :param irq: IRQ number.
    :return: ``struct irq_desc *`` (``NULL`` if not found)
    """
    # Since Linux kernel commit 721255b9826b ("genirq: Use a maple tree for
    # interrupt descriptor management") (in v6.5), interrupt descriptors are in
    # a maple tree.
    try:
        sparse_irqs = prog["sparse_irqs"]
    except ObjectNotFoundError:
        pass
    else:
        return cast("struct irq_desc *", mtree_load(sparse_irqs.address_of_(), irq))

    # Before that, they are in a radix tree.
    return cast(
        "struct irq_desc *",
        radix_tree_lookup(prog["irq_desc_tree"].address_of_(), irq),
    )


@takes_program_or_default
def for_each_irq_desc(prog: Program) -> Iterator[Tuple[int, Object]]:
    """
    Iterate over all allocated interrupt descriptors.

    :return: Iterator of (IRQ number, ``struct irq_desc *`` object) tuples.
    """
    irq_desc_type = prog.type("struct irq_desc *")

    # Since Linux kernel commit 721255b9826b ("genirq: Use a maple tree for
    # interrupt descriptor management") (in v6.5), interrupt descriptors are in
    # a maple tree.
    try:
        sparse_irqs = prog["sparse_irqs"]
    except ObjectNotFoundError:
        pass
    else:
        for irq, _, entry in mt_for_each(sparse_irqs.address_of_()):
            yield irq, cast(irq_desc_type, entry)
        return

    # Before that, they are in a radix tree.
    for irq, entry in radix_tree_for_each(prog["irq_desc_tree"].address_of_()):
        yield irq, cast(irq_desc_type, entry)


def irq_desc_affinity_mask(desc: Object) -> Object:
    """
    Get the CPU affinity mask for an interrupt descriptor.

    :param desc: ``struct irq_desc *``
    :return: ``struct cpumask *``
    """
    # Since Linux kernel commit aa0813581b8d ("genirq: Provide an IRQ affinity
    # mask in non-SMP configs") (in v6.0), struct irq_common_data::affinity
    # doesn't exist on !SMP. Before that, it exists on !SMP but is
    # uninitialized. So, we need to check for !SMP first.
    if "nr_cpu_ids" not in desc.prog_:
        return cpumask_of(desc.prog_, 0)

    try:
        # affinity is a cpumask_var_t, which is a pointer if
        # CONFIG_CPUMASK_OFFSTACK=y and an array otherwise. The `+ 0` converts
        # it to a pointer in the array case and is a no-op in the pointer case.
        return desc.irq_common_data.affinity + 0
    except AttributeError:
        # Before Linux kernel commit 9df872faa7e1 ("genirq: Move field
        # 'affinity' from irq_data into irq_common_data") (in v4.3), the
        # affinity member is in struct irq_data instead of struct
        # irq_common_data.
        return desc.irq_data.affinity + 0


def irq_desc_action_names(desc: Object) -> List[bytes]:
    """
    Get a list of the names of actions set on an interrupt descriptor.

    Actions without names (e.g., ``chained_action``) are skipped.

    >>> irq_desc_action_names(irq_to_desc(27))
    [b'i2c_designware.0', b'idma64.0']

    :param desc: ``struct irq_desc *``
    """
    action = desc.action.read_()
    names = []
    while action:
        name = action.name.read_()
        if name:
            names.append(name.string_())
        action = action.next.read_()
    return names


def irq_desc_chip_name(desc: Object) -> Optional[bytes]:
    """
    Get the name of the controller chip that manages an interrupt descriptor.

    :param desc: ``struct irq_desc *``
    :return: Chip name, or ``None`` if the chip or name is not set.
    """
    chip = desc.irq_data.chip.read_()
    if chip:
        name = chip.name.read_()
        if name:
            return name.string_()
    return None


def irq_desc_kstat_cpu(desc: Object, cpu: IntegerLike) -> int:
    """
    Get the number of times that an interrupt has fired on a given CPU.

    :param desc: ``struct irq_desc *``
    :param cpu: CPU number.
    """
    kstat_irqs = desc.kstat_irqs.read_()
    if not kstat_irqs:
        return 0
    # Since Linux kernel commit 86d2a2f51fba ("genirq: Convert kstat_irqs to a
    # struct") (in v6.10), kstat_irqs is a structure with the actual counter in
    # a member. Before that, kstat_irqs was the counter itself.
    try:
        cnt = kstat_irqs.cnt
    except AttributeError:
        cnt = kstat_irqs[0]
    return per_cpu(cnt, cpu).value_()


def gate_desc_func(gate: Object) -> Object:
    """
    Get the IDT entry function for a gate on x86.

    >>> gate_desc_func(prog["idt_table"][3])
    (void *)asm_exc_int3+0x0 = 0xffffffff91001240

    :param gate: ``gate_desc`` or ``gate_desc *``
    :return: ``void *``
    """
    return Object(
        gate.prog_,
        "void *",
        (gate.offset_high.value_() << 32)
        | (gate.offset_middle.value_() << 16)
        | gate.offset_low.value_(),
    )
