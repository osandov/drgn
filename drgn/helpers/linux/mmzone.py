# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Memory Zones
------------

The ``drgn.helpers.linux.mmzone`` module provides helpers for working with
memory zones and `SPARSEMEM <https://docs.kernel.org/mm/memory-model.html>`_.
"""

import operator
from typing import Iterator, Mapping, Tuple

from drgn import NULL, IntegerLike, Object, ObjectNotFoundError, Program, TypeKind
from drgn.helpers.common.format import decode_flags
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.nodemask import for_each_online_node

__all__ = (
    "NODE_DATA",
    "decode_section_flags",
    "early_section",
    "early_section_nr",
    "for_each_online_pgdat",
    "for_each_present_section",
    "nr_to_section",
    "online_section",
    "online_section_nr",
    "pfn_to_section",
    "pfn_to_section_nr",
    "present_section",
    "present_section_nr",
    "section_decode_mem_map",
    "section_mem_map_addr",
    "section_nr_to_pfn",
    "valid_section",
    "valid_section_nr",
)


@takes_program_or_default
def NODE_DATA(prog: Program, nid: IntegerLike) -> Object:
    """
    Get the NUMA node memory layout data of a given NUMA node.

    :param nid: NUMA node ID.
    :return: ``struct pglist_data *``
    """
    try:
        return prog["node_data"][nid]
    except ObjectNotFoundError:
        # CONFIG_NUMA=n
        return prog["contig_page_data"].address_of_()


@takes_program_or_default
def for_each_online_pgdat(prog: Program) -> Iterator[Object]:
    """
    Get the NUMA node memory layout data of each online NUMA node.

    :return: Iterator of ``struct pglist_data *`` objects
    """
    for nid in for_each_online_node(prog):
        yield NODE_DATA(prog, nid)


@takes_program_or_default
def nr_to_section(prog: Program, nr: IntegerLike) -> Object:
    """
    Get the SPARSEMEM section with the given number.

    :param nr: ``unsigned long``
    :return: ``struct mem_section *`` (``NULL`` if not found)
    """
    nr = operator.index(nr)
    SECTIONS_PER_ROOT = prog["SECTIONS_PER_ROOT"].value_()
    root = nr // SECTIONS_PER_ROOT

    if root >= prog["NR_SECTION_ROOTS"].value_():
        return NULL(prog, "struct mem_section *")

    mem_section = prog["mem_section"]
    unaliased_type = mem_section.type_.unaliased()
    if unaliased_type.kind == TypeKind.POINTER:
        mem_section = mem_section.read_()
        if not mem_section:
            return NULL(prog, unaliased_type.type)

    mem_section_root = mem_section[root]
    if mem_section_root.type_.unaliased_kind() == TypeKind.POINTER:
        mem_section_root = mem_section_root.read_()
        if not mem_section_root:
            return mem_section_root

    return mem_section_root + (nr & (SECTIONS_PER_ROOT - 1))


@takes_program_or_default
def pfn_to_section_nr(prog: Program, pfn: IntegerLike) -> Object:
    """
    Get the SPARSEMEM section number containing the given page frame number
    (PFN).

    :param pfn: ``unsigned long``
    :return: ``unsigned long``
    """
    return Object(prog, "unsigned long", pfn) >> (
        prog["SECTION_SIZE_BITS"] - prog["PAGE_SHIFT"]
    )


@takes_program_or_default
def section_nr_to_pfn(prog: Program, nr: IntegerLike) -> Object:
    """
    Get the first page frame number (PFN) in the given SPARSEMEM section
    number.

    :param nr: ``unsigned long``
    :return: ``unsigned long``
    """
    return Object(prog, "unsigned long", nr) << (
        prog["SECTION_SIZE_BITS"] - prog["PAGE_SHIFT"]
    )


@takes_program_or_default
def pfn_to_section(prog: Program, pfn: IntegerLike) -> Object:
    """
    Get the SPARSEMEM section containing the given page frame number (PFN).

    :param pfn: ``unsigned long``
    :return: ``struct mem_section *``
    """
    return nr_to_section(pfn_to_section_nr(prog, pfn))


def _section_flags(prog: Program) -> Mapping[str, int]:
    try:
        return prog.cache["section_flags"]
    except KeyError:
        pass

    # Since Linux kernel commit ed7802dd48f7 ("mm: memory_hotplug: enumerate
    # all supported section flags") (in v6.0), the section flags are an
    # anonymous enum. Before that, they were macros.
    try:
        flags_type = prog["SECTION_MARKED_PRESENT_BIT"].type_
    except ObjectNotFoundError:
        flags = {
            # These haven't changed since they were introduced in Linux kernel
            # commit 29751f6991e8 ("[PATCH] sparsemem hotplug base") (in
            # v2.6.13).
            "SECTION_MARKED_PRESENT": 0x1,
            "SECTION_HAS_MEM_MAP": 0x2,
            # Strictly speaking, the remaining flags didn't exit in older
            # kernel versions, but the bits won't be set before they were
            # introduced anyways.
            # Introduced in Linux kernel commit 2d070eab2e82 ("mm: consider
            # zone which is not fully populated to have holes") (in v4.13).
            "SECTION_IS_ONLINE": 0x4,
            # Introduced in Linux kernel commit 326e1b8f83a4 ("mm/sparsemem:
            # introduce a SECTION_IS_EARLY flag") (in v5.3).
            "SECTION_IS_EARLY": 0x8,
            # Introduced in Linux kernel commit 1f90a3477df3 ("mm: teach
            # pfn_to_online_page() about ZONE_DEVICE section collisions") (in
            # v5.12).
            "SECTION_TAINT_ZONE_DEVICE": 0x10,
            "SECTION_MAP_MASK": 0xFFFFFFFFFFFFFFE0,
        }
    else:
        flags = {}
        for enumerator in flags_type.enumerators:  # type: ignore[union-attr]
            name = enumerator.name
            if name == "SECTION_MAP_LAST_BIT":
                flags["SECTION_MAP_MASK"] = (
                    (1 << enumerator.value) - 1
                ) ^ 0xFFFFFFFFFFFFFFFF
            elif name.endswith("_BIT"):
                flags[name[: -len("_BIT")]] = 1 << enumerator.value

    prog.cache["section_flags"] = flags
    return flags


def section_mem_map_addr(section: Object) -> Object:
    """
    Get the SPARSEMEM memory map for the given section.

    This is encoded such that ``mem_map[pfn]`` is the ``struct page`` for the
    given page frame number (PFN).

    :param section: ``struct mem_section *``
    :return: ``struct page *``
    """
    prog = section.prog_
    return Object(
        prog,
        "struct page *",
        section.section_mem_map.value_() & _section_flags(prog)["SECTION_MAP_MASK"],
    )


def section_decode_mem_map(section: Object, nr: IntegerLike) -> Object:
    """
    Get the decoded address of the SPARSEMEM memory map for the given section.

    This is the address such that ``mem_map[0]`` is the ``struct page`` for the
    first page in the section.

    :param section: ``struct mem_section *``
    :param nr: Section number.
    :return: ``struct page *``
    """
    return section_mem_map_addr(section) + section_nr_to_pfn(section.prog_, nr)


def present_section(section: Object) -> bool:
    """
    Return whether a SPARSEMEM section is present.

    :param section: ``struct mem_section *``
    """
    section = section.read_()
    if not section:
        return False
    return bool(
        section.section_mem_map.value_()
        & _section_flags(section.prog_)["SECTION_MARKED_PRESENT"]
    )


@takes_program_or_default
def present_section_nr(prog: Program, nr: IntegerLike) -> bool:
    """
    Return whether the SPARSEMEM section with the given number is present.

    :param nr: ``unsigned long``
    """
    return present_section(nr_to_section(prog, nr))


def valid_section(section: Object) -> bool:
    """
    Return whether a SPARSEMEM section is valid, i.e., has a ``mem_map``.

    :param section: ``struct mem_section *``
    """
    section = section.read_()
    if not section:
        return False
    return bool(
        section.section_mem_map.value_()
        & _section_flags(section.prog_)["SECTION_HAS_MEM_MAP"]
    )


@takes_program_or_default
def valid_section_nr(prog: Program, nr: IntegerLike) -> bool:
    """
    Return whether the SPARSEMEM section with the given number is valid, i.e.,
    has a ``mem_map``.

    :param nr: ``unsigned long``
    """
    return valid_section(nr_to_section(prog, nr))


def online_section(section: Object) -> bool:
    """
    Return whether a SPARSEMEM section is online.

    This is only valid since Linux kernel 4.13.

    :param section: ``struct mem_section *``
    """
    section = section.read_()
    if not section:
        return False
    return bool(
        section.section_mem_map.value_()
        & _section_flags(section.prog_)["SECTION_IS_ONLINE"]
    )


@takes_program_or_default
def online_section_nr(prog: Program, nr: IntegerLike) -> bool:
    """
    Return whether the SPARSEMEM section with the given number is online.

    This is only valid since Linux kernel 4.13.

    :param nr: ``unsigned long``
    """
    return online_section(nr_to_section(prog, nr))


def early_section(section: Object) -> bool:
    """
    Return whether a SPARSEMEM section was created during early memory
    initialization.

    This is only valid since Linux kernel 5.3.

    :param section: ``struct mem_section *``
    """
    section = section.read_()
    if not section:
        return False
    return bool(
        section.section_mem_map.value_()
        & _section_flags(section.prog_)["SECTION_IS_EARLY"]
    )


@takes_program_or_default
def early_section_nr(prog: Program, nr: IntegerLike) -> bool:
    """
    Return whether the SPARSEMEM section with the given number was created
    during early memory initialization.

    This is only valid since Linux kernel 5.3.

    :param nr: ``unsigned long``
    """
    return early_section(nr_to_section(prog, nr))


def decode_section_flags(section: Object) -> str:
    """
    Get a human-readable representation of the flags set on a SPARSEMEM section.

    >>> decode_section_flags(section)
    'SECTION_MARKED_PRESENT|SECTION_HAS_MEM_MAP|SECTION_IS_ONLINE|SECTION_IS_EARLY'

    :param section: ``struct mem_section *``
    """
    flags = _section_flags(section.prog_)
    return decode_flags(
        section.section_mem_map.value_() & ~flags["SECTION_MAP_MASK"],
        flags.items(),
        False,
    )


def _highest_present_section_nr(prog: Program) -> int:
    try:
        return prog["__highest_present_section_nr"].value_()
    except ObjectNotFoundError:
        pass
    # Before Linux kernel commit c4e1be9ec113 ("mm, sparsemem: break out of
    # loops early") (in v4.13), __highest_present_section_nr didn't exist, so
    # we have to loop all the way up to NR_MEM_SECTIONS.
    # NR_MEM_SECTIONS = 1 << SECTIONS_SHIFT
    # SECTIONS_SHIFT = MAX_PHYSMEM_BITS - SECTION_SIZE_BITS
    return 1 << (prog["MAX_PHYSMEM_BITS"] - prog["SECTION_SIZE_BITS"]).value_()


@takes_program_or_default
def for_each_present_section(prog: Program) -> Iterator[Tuple[int, Object]]:
    """
    Iterate over each present SPARSEMEM section.

    :return: Iterator of (section number, ``struct mem_section *`` object)
        tuples.
    """
    SECTIONS_PER_ROOT = prog["SECTIONS_PER_ROOT"].value_()
    SECTION_MARKED_PRESENT = _section_flags(prog)["SECTION_MARKED_PRESENT"]

    highest_present_section_nr = _highest_present_section_nr(prog)
    nr_roots = highest_present_section_nr // SECTIONS_PER_ROOT + 1

    mem_section = prog["mem_section"]
    unaliased_type = mem_section.type_.unaliased()
    if unaliased_type.kind == TypeKind.POINTER:
        mem_section = mem_section.read_()
        if not mem_section:
            return

    root_kind = unaliased_type.type.unaliased_kind()

    nr = 0
    for root_nr, root in enumerate(mem_section[:nr_roots]):
        if root_kind == TypeKind.POINTER:
            root = root.read_()
            if not root:
                nr += SECTIONS_PER_ROOT
                continue

        if root_nr == nr_roots - 1:
            nr_sections = highest_present_section_nr % SECTIONS_PER_ROOT + 1
        else:
            nr_sections = SECTIONS_PER_ROOT
        for section in root[:nr_sections]:
            # Open-coded present_section() to avoid some overhead.
            if section.section_mem_map.value_() & SECTION_MARKED_PRESENT:
                yield nr, section.address_of_()
            nr += 1
