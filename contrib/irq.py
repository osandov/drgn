#!/usr/bin/env drgn
# Copyright (c) 2023, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

""" Script to dump irq stats using drgn"""

from typing import Iterator
from typing import Tuple

from drgn import NULL
from drgn import Object
from drgn import Program
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.cpumask import for_each_present_cpu
from drgn.helpers.linux.cpumask import cpumask_to_cpulist
from drgn.helpers.linux.mapletree import mtree_load
from drgn.helpers.linux.mapletree import mt_for_each
from drgn.helpers.linux.percpu import per_cpu_ptr
from drgn.helpers.linux.radixtree import radix_tree_for_each
from drgn.helpers.linux.radixtree import radix_tree_lookup


def _sparse_irq_supported(prog: Program) -> Tuple[bool, str]:
    try:
        # Since Linux kernel commit 721255b9826b ("genirq: Use a maple
        # tree for interrupt descriptor management") (in v6.5), sparse
        # irq descriptors are stored in a maple tree.
        _ = prog["sparse_irqs"]
        return True, "maple"
    except KeyError:
        # Before that, they are in radix tree.
        try:
            _ = prog["irq_desc_tree"]
            return True, "radix"
        except KeyError:
            return False, None


def _kstat_irqs_cpu(prog: Program, irq: int, cpu: int) -> int:
    desc = irq_to_desc(prog, irq)
    if not desc:
        return 0

    addr = per_cpu_ptr(desc.kstat_irqs, cpu)
    return Object(prog, "int", address=addr).value_()


def irq_in_use(prog: Program, irq: int) -> bool:
    """
    Check if a given irq number is in use or not.
    An irq number is considered to be in use by the kernel, if the kernel
    has allocated a irq descriptor for it. The irq may not yet have any
    registered irq handlers.

    :param prog: drgn program
    :param irq: irq number

    :return: True if irq is in use, False otherwise
    """
    desc = irq_to_desc(prog, irq)
    # An irq number is in use if irq_desc object has been allocated for it
    return bool(desc)


def irq_has_action(prog: Program, irq: int) -> bool:
    """
    Check if a given irq has handler(s) registered or not.

    :param prog: drgn program
    :param irq: irq number

    :return: True if irq has registered handler(s), False otherwise
    """

    desc = irq_to_desc(prog, irq)
    return bool(desc and desc.action)


def for_each_irq(prog: Program) -> Iterator[int]:
    """
    Iterate through all allocated irq numbers.

    :param prog: drgn program

    :return: Iterator of irq numbers
    """
    _, tree_type = _sparse_irq_supported(prog)

    if tree_type == "radix":
        irq_desc_tree = prog["irq_desc_tree"].address_of_()
        for irq, _ in radix_tree_for_each(irq_desc_tree):
            yield irq
    elif tree_type == "maple":
        irq_desc_tree = prog["sparse_irqs"].address_of_()
        for irq, _, _ in mt_for_each(irq_desc_tree):
            yield irq
    else:
        count = len(prog["irq_desc"])
        for irq_num in range(count):
            yield irq_num


def for_each_irq_desc(prog: Program) -> Iterator[Object]:
    """
    Iterate through all allocated irq descriptors.

    :param prog: drgn program

    :return: Iterator of ``struct irq_desc *`` objects.
    """
    _, tree_type = _sparse_irq_supported(prog)
    if tree_type == "radix":
        irq_desc_tree = prog["irq_desc_tree"].address_of_()
        for _, addr in radix_tree_for_each(irq_desc_tree):
            irq_desc = Object(prog, "struct irq_desc", address=addr).address_of_()
            yield irq_desc
    elif tree_type == "maple":
        irq_desc_tree = prog["sparse_irqs"].address_of_()
        for _, _, addr in mt_for_each(irq_desc_tree):
            irq_desc = Object(prog, "struct irq_desc", address=addr).address_of_()
            yield irq_desc
    else:
        count = len(prog["irq_desc"])
        for irq_num in range(count):
            yield (prog["irq_desc"][irq_num]).address_of_()


def irq_name_to_desc(prog: Program, name: str) -> Object:
    """
    Get ``struct irq_desc *`` for irq handler of given name

    :param prog: drgn program
    :param name: name of irq handler

    :return: ``struct irq_desc *`` object if irq descriptor is found.
             NULL otherwise
    """
    for desc in for_each_irq_desc(prog):
        if desc.action and desc.action.name == name:
            return desc

    return NULL(prog, "void *")


def irq_to_desc(prog: Program, irq: int) -> Object:
    """
    Get ``struct irq_desc *`` for given irq number

    :param prog: drgn program
    :param irq: irq number

    :return: ``struct irq_desc *`` object if irq descriptor is found.
             NULL otherwise
    """
    _, tree_type = _sparse_irq_supported(prog)

    if tree_type:
        if tree_type == "radix":
            addr = radix_tree_lookup(prog["irq_desc_tree"].address_of_(), irq)
        else:
            addr = mtree_load(prog["sparse_irqs"].address_of_(), irq)

        if addr:
            return Object(prog, "struct irq_desc", address=addr).address_of_()
        else:
            return NULL(prog, "void *")
    else:
        return (prog["irq_desc"][irq]).address_of_()


def get_irq_affinity(prog: Program, irq: int) -> Object:
    """
    Get ``struct cpumask`` for given irq's cpu affinity

    :param prog: drgn program
    :param irq: irq number

    :return: ``struct cpumask`` object if irq descriptor is found.
             NULL otherwise
    """

    if not irq_in_use(prog, irq):
        print("IRQ not in use so affinity data is not reliable")

    irq_desc = irq_to_desc(prog, irq)

    # if CONFIG_CPUMASK_OFFSTACK is enabled then affinity is an array
    # of cpumask objects otherwise it is pointer to a cpumask object
    if hasattr(irq_desc, "irq_common_data"):
        try:
            _ = len(irq_desc.irq_common_data.affinity)
            addr = irq_desc.irq_common_data.affinity.address_
        except TypeError:
            addr = irq_desc.irq_common_data.affinity.value_()
    elif hasattr(irq_desc, "irq_data"):
        try:
            _ = len(irq_desc.irq_data.affinity)
            addr = irq_desc.irq_data.affinity.address_
        except TypeError:
            addr = irq_desc.irq_data.affinity.value_()
    else:
        return None

    return Object(prog, "struct cpumask", address=addr)


def get_irq_affinity_list(prog: Program, irq: int) -> Object:
    """
    Get affinity of a given cpu.

    :param prog: drgn program
    :param irq: irq number

    :return: range of cpus to which irq is affined to
    """

    affinity = get_irq_affinity(prog, irq)
    if affinity is not None:
        return cpumask_to_cpulist(affinity)
    else:
        return None


def show_irq_num_stats(prog: Program, irq: int) -> None:
    """
    Show stats for a given irq number

    :param prog: drgn program
    :param irq: irq number

    :return: None
    """

    if not irq_in_use(prog, irq):
        print(f"irq: {irq} is not in use")
        return

    if not irq_has_action(prog, irq):
        print(f"irq: {irq} has no handlers registered")
        return
    print_header = True
    total_count = 0
    for cpu in for_each_present_cpu(prog):
        kstat_irqs = _kstat_irqs_cpu(prog, irq, cpu)
        if not kstat_irqs:
            continue
        desc = irq_to_desc(prog, irq)
        name = escape_ascii_string(
            desc.action.name.string_(), escape_backslash=True
        )
        if print_header:
            print(
                f"irq: {irq} name: {name} ({desc.type_.type_name()})0x{desc.value_():x}"
            )
            print_header = False

        total_count += kstat_irqs
        print(f"    CPU: {cpu}  \t count: {kstat_irqs}")

    print(f"    Total: {total_count}")


def show_irq_name_stats(prog: Program, irq_name: str) -> None:
    """
    Show irq stats for irqs whose handler have specified name or
    for irqs whose handler names begin with specified string.

    :param prog: drgn program
    :param irq_name: name or beginning of name of irq handler

    :return: None
    """

    found = False
    for irq in for_each_irq(prog):
        if irq_in_use(prog, irq) and irq_has_action(prog, irq):
            desc = irq_to_desc(prog, irq)
            name = escape_ascii_string(
                desc.action.name.string_(), escape_backslash=True
            )
            if name.startswith(irq_name):
                found = True
                show_irq_num_stats(prog, irq)

    if not found:
        print(
            f"Found no irq with name: {irq_name} or with name starting with: {irq_name}"
        )


def show_irq_stats(prog: Program) -> None:
    """
    Show stats for all irqs.
    :param prog: drgn program

    :return: None
    """
    for irq in for_each_irq(prog):
        if irq_in_use(prog, irq) and irq_has_action(prog, irq):
            show_irq_num_stats(prog, irq)


def show_cpu_irq_num_stats(prog: Program, cpu: int, irq: int) -> None:
    """
    Show irq stats of a cpu for a given irq number

    :param prog: drgn program
    :param cpu: cpu index
    :param irq: irq number

    :return: None
    """

    if not irq_in_use(prog, irq):
        print(f"irq: {irq} is not in use")
        return

    if not irq_has_action(prog, irq):
        print(f"irq: {irq} has no handlers registered")
        return

    print(f"IRQ stats for cpu: {cpu}")
    desc = irq_to_desc(prog, irq)
    name = escape_ascii_string(
        desc.action.name.string_(), escape_backslash=True
    )
    kstat_irqs = _kstat_irqs_cpu(prog, irq, cpu)
    print(
        f"    irq: {irq} name: {name} ({desc.type_.type_name()})0x{desc.value_():x} count: {kstat_irqs}"
    )


def show_cpu_irq_name_stats(prog: Program, cpu: int, irq_name: str) -> None:
    """
    Show irq stats of a cpu for irqs whose handler have specified name or
    for irqs whose handler names begin with specified string.

    :param prog: drgn program
    :param cpu: cpu index
    :param irq_name: name or beginning of name of irq handler

    :return: None
    """

    found = False
    total_irqs_on_cpu = 0
    print(f"IRQ stats for cpu: {cpu}")
    for irq in for_each_irq(prog):
        if irq_in_use(prog, irq) and irq_has_action(prog, irq):
            desc = irq_to_desc(prog, irq)
            name = escape_ascii_string(
                desc.action.name.string_(), escape_backslash=True
            )
            if name.startswith(irq_name):
                found = True
                kstat_irqs = _kstat_irqs_cpu(prog, irq, cpu)
                if not kstat_irqs:
                    continue
                total_irqs_on_cpu += kstat_irqs
                print(
                    f"    irq: {irq} name: {name} ({desc.type_.type_name()})0x{desc.value_():x} count: {kstat_irqs}"
                )

    if not found:
        print(
            f"Found no irq with name: {irq_name} or with name starting with: {irq_name}"
        )
    else:
        print(f"Total: {total_irqs_on_cpu}")


def show_cpu_irq_stats(prog: Program, cpu: int) -> None:
    """
    Show irq stats for specified cpu.

    :param prog: drgn program
    :param cpu: cpu index

    :return: None
    """
    total_irqs_on_cpu = 0
    print(f"IRQ stats for cpu: {cpu}")
    for irq in for_each_irq(prog):
        if irq_in_use(prog, irq) and irq_has_action(prog, irq):
            kstat_irqs = _kstat_irqs_cpu(prog, irq, cpu)
            if not kstat_irqs:
                continue

            desc = irq_to_desc(prog, irq)
            name = escape_ascii_string(
                desc.action.name.string_(), escape_backslash=True
            )
            print(
                f"    irq: {irq} name: {name} ({desc.type_.type_name()})0x{desc.value_():x} count: {kstat_irqs}"
            )
            total_irqs_on_cpu += kstat_irqs

    print(f"Total: {total_irqs_on_cpu}")


def show_each_cpu_irq_stats(prog: Program) -> None:
    """
    Show irq stats for each cpu.

    :param prog: drgn program

    :return: None
    """
    for cpu in for_each_present_cpu(prog):
        show_cpu_irq_stats(prog, cpu)
        print("\n")


def print_irq_affinity(prog: Program, irq: int) -> None:
    """
    Print cpu affinity of specified irq.

    :param prog: drgn program
    :param irq: irq number

    :return: None
    """

    if not irq_in_use(prog, irq):
        print(f"irq: {irq} is not in use")
        return

    if not irq_has_action(prog, irq):
        print(f"irq: {irq} has no handlers registered")
        return

    desc = irq_to_desc(prog, irq)
    name = escape_ascii_string(
        desc.action.name.string_(), escape_backslash=True
    )
    affinity = get_irq_affinity_list(prog, irq)
    print(f"irq: {irq} name: {name} affinity: {affinity}")


def print_irqs_affinities(prog: Program) -> None:
    """
    Print cpu affinities for all irqs in use.

    :param prog: drgn program

    :return: None
    """
    for irq in for_each_irq(prog):
        if irq_in_use(prog, irq) and irq_has_action(prog, irq):
            print_irq_affinity(prog, irq)


def print_all_irqs(prog: Program) -> None:
    """
    Print number, name, ``struct irq_desc *`` and ``struct irqaction *`` for all irqs in use.

    :param prog: drgn program

    :return: None
    """
    for irq in for_each_irq(prog):
        if irq_in_use(prog, irq) and irq_has_action(prog, irq):
            desc = irq_to_desc(prog, irq)
            name = escape_ascii_string(
                desc.action.name.string_(), escape_backslash=True
            )
            print(
                f"irq: {irq} name: {name} ({desc.type_.type_name()})0x{desc.value_():x}  ({desc.action.type_.type_name()})0x{desc.action.value_():x}"
            )


print("###################################################")
print("List of IRQs")
print("###################################################")
print_all_irqs(prog)
print("\n")

print("###################################################")
print("IRQ affinities")
print("###################################################")
print_irqs_affinities(prog)
print("\n")

print("###################################################")
print("IRQ stats")
print("###################################################")
show_irq_stats(prog)
print("\n")

print("###################################################")
print("cpuwise IRQ stats")
print("###################################################")
show_each_cpu_irq_stats(prog)
print("\n")
