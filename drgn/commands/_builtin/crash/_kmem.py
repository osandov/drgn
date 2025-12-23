# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""kmem command."""

import argparse
import functools
import operator
import sys
from typing import (
    AbstractSet,
    Any,
    Callable,
    Iterable,
    List,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
)

from drgn import (
    NULL,
    FaultError,
    Object,
    Program,
    ProgramFlags,
    RelocatableModule,
    TypeKind,
    cast,
    sizeof,
)
from drgn.commands import (
    CommandArgumentError,
    _repr_black,
    argument,
    drgn_argument,
    mutually_exclusive_group,
)
from drgn.commands._builtin.crash._sys import _print_sys
from drgn.commands.crash import (
    CrashDrgnCodeBuilder,
    _parse_members,
    _sanitize_member_name,
    crash_command,
)
from drgn.helpers import ValidationError
from drgn.helpers.common.format import (
    CellFormat,
    RowOptions,
    _print_table_row,
    double_quote_ascii_string,
    escape_ascii_string,
    number_in_binary_units,
    print_table,
)
from drgn.helpers.common.memory import IdentifiedSymbol, identify_address_all
from drgn.helpers.common.type import typeof_member
from drgn.helpers.linux.block import nr_blockdev_pages
from drgn.helpers.linux.common import (
    IdentifiedPage,
    IdentifiedSlabObject,
    IdentifiedTaskStack,
    IdentifiedTaskStruct,
    IdentifiedVmap,
)
from drgn.helpers.linux.cpumask import for_each_possible_cpu
from drgn.helpers.linux.device import dev_name
from drgn.helpers.linux.hugetlb import (
    for_each_hstate,
    huge_page_size,
    hugetlb_total_usage,
)
from drgn.helpers.linux.list import (
    validate_list_count_nodes,
    validate_list_for_each_entry,
)
from drgn.helpers.linux.mm import (
    PFN_PHYS,
    decode_memory_block_state,
    decode_page_flags_value,
    follow_pfn,
    for_each_memory_block,
    for_each_page,
    for_each_valid_pfn_and_page,
    for_each_vmap_area,
    memory_block_size_bytes,
    page_flags,
    page_index,
    page_to_pfn,
    page_to_virt,
    pfn_to_page,
    totalram_pages,
    vm_commit_limit,
    vm_memory_committed,
)
from drgn.helpers.linux.mmzone import (
    NODE_DATA,
    decode_section_flags,
    for_each_online_pgdat,
    for_each_present_section,
    high_wmark_pages,
    low_wmark_pages,
    min_wmark_pages,
    section_decode_mem_map,
    section_mem_map_addr,
    section_nr_to_pfn,
)
from drgn.helpers.linux.nodemask import for_each_online_node
from drgn.helpers.linux.percpu import per_cpu_ptr
from drgn.helpers.linux.slab import (
    find_slab_cache,
    for_each_slab_cache,
    slab_cache_order,
    slab_cache_usage,
    slab_total_usage,
)
from drgn.helpers.linux.swap import swap_total_usage, total_swapcache_pages
from drgn.helpers.linux.vmstat import (
    global_node_page_state,
    global_numa_event_state,
    global_vm_event_state,
    global_zone_page_state,
    nr_free_pages,
    zone_page_state,
)


def _kmem_free(prog: Program, drgn_arg: bool, show_pages: bool = False) -> None:
    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import("drgn.helpers.linux.mm", "PFN_PHYS", "pfn_to_page")
        code.add_from_import("drgn.helpers.linux.mmzone", "for_each_online_pgdat")
        code.add_from_import(
            "drgn.helpers.linux.vmstat", "nr_free_pages", "zone_page_state"
        )
        with code.begin_block(
            """\
actual_free_pages = 0
for pgdat in for_each_online_pgdat():
    for zone in pgdat.node_zones:
        name = zone.name
        size = zone.spanned_pages
        if size == 0:
            continue
        free = zone_page_state(zone, prog["NR_FREE_PAGES"])
        start_pfn = zone.zone_start_pfn.read_()
        mem_map = pfn_to_page(start_pfn)
        start_paddr = PFN_PHYS(start_pfn)

        for order, free_area in enumerate(zone.free_area):
            block_size = prog["PAGE_SIZE"] << order
            for migrate_type, free_list in enumerate(free_area.free_list):
"""
        ), code.begin_retry_loop_if_live(100):
            if show_pages:
                code.add_from_import(
                    "drgn.helpers.linux.list", "validate_list_for_each_entry"
                )
                code.append(
                    """\
num_blocks = 0
for page in validate_list_for_each_entry(
    "struct page", free_list.address_of_(), "lru"
):
    num_blocks += 1
"""
                )
            else:
                code.add_from_import(
                    "drgn.helpers.linux.list", "validate_list_count_nodes"
                )
                code.append(
                    "num_blocks = validate_list_count_nodes(free_list.address_of_())\n"
                )
        code.append(
            """\
                num_pages = num_blocks << order
                actual_free_pages += num_pages

expected_free_pages = nr_free_pages()
"""
        )
        code.print()
        return

    migrate_types = {
        enumerator.value: enumerator.name[len("MIGRATE_") :]
        # enum migratetype was anonymous until Linux kernel commit a6ffdc07847e
        # ("mm: use is_migrate_highatomic() to simplify the code") (in v4.12).
        for enumerator in prog["MIGRATE_UNMOVABLE"].type_.enumerators  # type: ignore[union-attr]
        if enumerator.name.startswith("MIGRATE_")
    }

    pgdats = list(for_each_online_pgdat(prog))
    if len(pgdats) > 1:
        node_header: Sequence[Any] = (CellFormat("NODE", ">"),)
    else:
        node_header = ()

    free_list_header = [
        CellFormat("ORDER", "^"),
        CellFormat("SIZE", ">"),
        "MIGRATE",
        CellFormat("FREE_LIST", "^"),
    ]
    if not show_pages:
        free_list_header.append(CellFormat("BLOCKS", ">"))
        free_list_header.append(CellFormat("PAGES", ">"))

    rows: List[Sequence[Any]] = []
    first = True
    total_free_pages = 0
    for pgdat in pgdats:
        for i, zone in enumerate(pgdat.node_zones):
            if len(pgdats) > 1:
                node_row: Sequence[Any] = (pgdat.node_id.value_(),)
            else:
                node_row = ()
            size = zone.spanned_pages.value_()

            if first:
                first = False
            else:
                rows.append(())
            rows.append(
                RowOptions(
                    (
                        *node_header,
                        CellFormat("ZONE", "^"),
                        "NAME",
                        CellFormat("SIZE", ">"),
                        CellFormat("FREE", ">"),
                        CellFormat("MEM_MAP", "^"),
                        "START_PADDR",
                        "START_PFN",
                    ),
                    group=1,
                )
            )

            if size == 0:
                free = 0
                mem_map_cell = start_paddr_cell = start_pfn_cell = CellFormat(0, "^")
            else:
                free = zone_page_state(zone, prog["NR_FREE_PAGES"])
                start_pfn = zone.zone_start_pfn.read_()
                mem_map_cell = CellFormat(pfn_to_page(start_pfn).value_(), "^x")
                start_paddr_cell = CellFormat(PFN_PHYS(start_pfn).value_(), "^x")
                start_pfn_cell = CellFormat(start_pfn.value_(), "^")
            rows.append(
                RowOptions(
                    (
                        *node_row,
                        CellFormat(i, "^"),
                        escape_ascii_string(zone.name.string_(), escape_backslash=True),
                        size,
                        free,
                        mem_map_cell,
                        start_paddr_cell,
                        start_pfn_cell,
                    ),
                    group=1,
                )
            )

            if size == 0:
                continue

            if not show_pages:
                rows.append(free_list_header)
            for order, free_area in enumerate(zone.free_area):
                size = (prog["PAGE_SIZE"].value_() << order) // 1024
                size_cell = CellFormat(f"{size}k", ">")
                for migrate_type, free_list in enumerate(free_area.free_list):
                    num_blocks: Any = "[CORRUPTED]"
                    num_pages: Any = ""
                    # Walking free lists is racy. Retry a limited number of
                    # times on live kernels.
                    for _ in range(10):
                        try:
                            if show_pages:
                                pages = list(
                                    validate_list_for_each_entry(
                                        "struct page", free_list.address_of_(), "lru"
                                    )
                                )
                                num_blocks = len(pages)
                            else:
                                num_blocks = validate_list_count_nodes(
                                    free_list.address_of_()
                                )
                        except (FaultError, ValidationError):
                            if not (prog.flags & ProgramFlags.IS_LIVE):
                                break
                        else:
                            num_pages = num_blocks << order
                            total_free_pages += num_pages
                            break
                    if show_pages:
                        rows.append(free_list_header)
                    row = [
                        CellFormat(order, "^"),
                        size_cell,
                        migrate_types[migrate_type],
                        CellFormat(free_list.address_, "^x"),
                    ]
                    if not show_pages:
                        row.append(num_blocks)
                        row.append(num_pages)
                    rows.append(row)

                    if show_pages:
                        for page in pages:
                            rows.append(
                                RowOptions((CellFormat(page.value_(), "x"),), group=2)
                            )
    print_table(rows)

    free_pages = nr_free_pages(prog)
    if free_pages == total_free_pages:
        verified = "verified"
    else:
        verified = f"found {total_free_pages}"
    print(f"\nnr_free_pages: {free_pages}  ({verified})")


def _kmem_info(prog: Program, drgn_arg: bool) -> None:
    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import("drgn.helpers.linux.block", "nr_blockdev_pages")
        code.add_from_import("drgn.helpers.linux.hugetlb", "hugetlb_total_usage")
        code.add_from_import(
            "drgn.helpers.linux.mm",
            "totalram_pages",
            "vm_commit_limit",
            "vm_memory_committed",
        )
        code.add_from_import("drgn.helpers.linux.slab", "slab_total_usage")
        code.add_from_import(
            "drgn.helpers.linux.vmstat", "global_node_page_state", "nr_free_pages"
        )
        code.add_from_import(
            "drgn.helpers.linux.swap", "swap_total_usage", "total_swapcache_pages"
        )
        code.append(
            """\
total_mem = totalram_pages()
free = nr_free_pages()
used = total_mem - free
buffers = nr_blockdev_pages()
cached = (
    global_node_page_state(prog["NR_FILE_PAGES"]) - total_swapcache_pages() - buffers
)
slab_usage = slab_total_usage()

hugetlb_usage = hugetlb_total_usage()

swap_usage = swap_total_usage()

commit_limit = vm_commit_limit()
committed = vm_memory_committed()
"""
        )
        code.print()
        return

    rows: List[Sequence[Any]] = [
        (
            "",
            CellFormat("PAGES", ">"),
            CellFormat("TOTAL", ">"),
            CellFormat("PERCENTAGE", "^"),
        )
    ]

    page_size = prog["PAGE_SIZE"].value_()

    def binary_units_cell(n: int) -> CellFormat:
        return CellFormat(
            "0" if n == 0 else number_in_binary_units(n * page_size) + "B", ">"
        )

    total_mem = totalram_pages(prog)
    rows.append(
        (
            CellFormat("TOTAL MEM", ">"),
            total_mem,
            binary_units_cell(total_mem),
            CellFormat("----", "^"),
        )
    )

    free = nr_free_pages(prog)
    buffers = nr_blockdev_pages(prog)
    cached = (
        global_node_page_state(prog["NR_FILE_PAGES"])
        - total_swapcache_pages(prog)
        - buffers
    )

    for label, pages in (
        ("FREE", free),
        ("USED", total_mem - free),
        ("BUFFERS", buffers),
        ("CACHED", cached),
        ("SLAB", slab_total_usage(prog).total_pages),
    ):
        rows.append(
            (
                CellFormat(label, ">"),
                pages,
                binary_units_cell(pages),
                CellFormat(f"{pages / total_mem:.0%} of TOTAL MEM", ">"),
            ),
        )

    rows.append(())

    hugetlb_usage = hugetlb_total_usage(prog)
    rows.append(
        (
            CellFormat("TOTAL HUGE", ">"),
            hugetlb_usage.pages,
            binary_units_cell(hugetlb_usage.pages),
            CellFormat("----", "^"),
        )
    )
    rows.append(
        (
            CellFormat("HUGE FREE", ">"),
            hugetlb_usage.free_pages,
            binary_units_cell(hugetlb_usage.free_pages),
            CellFormat(
                f"{hugetlb_usage.free_pages / hugetlb_usage.pages if hugetlb_usage.pages else 0:.0%} of TOTAL HUGE",
                ">",
            ),
        )
    )

    rows.append(())

    swap_usage = swap_total_usage(prog)
    rows.append(
        (
            CellFormat("TOTAL SWAP", ">"),
            swap_usage.pages,
            binary_units_cell(swap_usage.pages),
            CellFormat("----", "^"),
        )
    )
    for label, pages in (
        ("SWAP USED", swap_usage.used_pages),
        ("SWAP FREE", swap_usage.free_pages),
    ):
        rows.append(
            (
                CellFormat(label, ">"),
                pages,
                binary_units_cell(pages),
                CellFormat(
                    f"{pages / swap_usage.pages if swap_usage.pages else 0:.0%} of TOTAL SWAP",
                    ">",
                ),
            )
        )

    rows.append(())

    commit_limit = vm_commit_limit(prog)
    committed = vm_memory_committed(prog)
    rows.append(
        (
            CellFormat("COMMIT LIMIT", ">"),
            commit_limit,
            binary_units_cell(commit_limit),
            CellFormat("----", "^"),
        )
    )
    rows.append(
        (
            CellFormat("COMMITTED", ">"),
            committed,
            binary_units_cell(committed),
            CellFormat(
                f"{committed / commit_limit:.0%} of TOTAL LIMIT",
                ">",
            ),
        )
    )

    print_table(rows)


def _kmem_vmalloc(
    prog: Program, drgn_arg: bool, *, identified: Optional[IdentifiedVmap] = None
) -> None:
    if drgn_arg:
        sys.stdout.write(
            """\
from drgn.helpers.linux.mm import for_each_vmap_area


for va in for_each_vmap_area():
    vm = va.vm
    start = va.va_start
    end = va.va_end
    size = end - start
"""
        )
        return

    rows: List[Sequence[Any]] = [
        (
            CellFormat("VMAP_AREA", "^"),
            CellFormat("VM_STRUCT", "^"),
            CellFormat("ADDRESS RANGE", "^"),
            CellFormat("SIZE", ">"),
        )
    ]
    if identified is None:

        def areas() -> Iterable[Tuple[Object, Object]]:
            for va in for_each_vmap_area(prog):
                yield va, va.vm.read_()

    else:

        def areas() -> Iterable[Tuple[Object, Object]]:
            yield identified.vmap_area, identified.vm_struct

    for va, vm in areas():
        start = va.va_start.value_()
        end = va.va_end.value_()
        rows.append(
            (
                CellFormat(va.value_(), "^x"),
                CellFormat(vm.value_(), "^x"),
                CellFormat(f"{start:x} - {end:x}", "^"),
                end - start,
            )
        )

    print_table(rows)


def _kmem_vmstat(prog: Program, drgn_arg: bool) -> None:
    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import(
            "drgn.helpers.linux.vmstat",
            "global_node_page_state",
            "global_numa_event_state",
            "global_vm_event_state",
            "global_zone_page_state",
        )
        code.append(
            """\
for name, item in prog.type("enum zone_stat_item").enumerators:
    if name == "NR_VM_ZONE_STAT_ITEMS":
        continue
    value = global_zone_page_state(item)

for name, item in prog.type("enum node_stat_item").enumerators:
    if name == "NR_VM_NODE_STAT_ITEMS":
        continue
    value = global_node_page_state(item)


# This depends on CONFIG_NUMA and was added in v4.14.
try:
    numa_stat_item_type = prog.type("enum numa_stat_item")
except LookupError:
    pass
else:
    for name, item in numa_stat_item_type.enumerators:
        # This was renamed in v5.14.
        if name == "NR_VM_NUMA_EVENT_ITEMS" or name == "NR_VM_NUMA_STAT_ITEMS":
            continue
        value = global_numa_event_state(item)

# This depends on CONFIG_VM_EVENT_COUNTERS.
if "vm_event_states" in prog:
    for name, item in prog.type("enum vm_event_item").enumerators:
        if name == "NR_VM_EVENT_ITEMS":
            continue
        value = global_vm_event_state(item)
"""
        )
        code.print()
        return

    rows: List[Sequence[Any]] = []
    rows.append(RowOptions(("VM_ZONE_STAT:",), group=1))
    for name, item in prog.type("enum zone_stat_item").enumerators:  # type: ignore[union-attr]
        if name == "NR_VM_ZONE_STAT_ITEMS":
            continue
        rows.append(
            (
                CellFormat("  " + name, ">"),
                CellFormat(global_zone_page_state(prog, item), "<"),
            )
        )

    rows.append(())
    rows.append(RowOptions(("VM_NODE_STAT:",), group=1))
    for name, item in prog.type("enum node_stat_item").enumerators:  # type: ignore[union-attr]
        if name == "NR_VM_NODE_STAT_ITEMS":
            continue
        rows.append(
            (
                CellFormat("  " + name, ">"),
                CellFormat(global_node_page_state(prog, item), "<"),
            )
        )

    try:
        numa_stat_item_type = prog.type("enum numa_stat_item")
    except LookupError:
        pass
    else:
        rows.append(())
        if "vm_numa_event" in prog:
            rows.append(RowOptions(("VM_NUMA_EVENT:",), group=1))
            nr_numa_items = "NR_VM_NUMA_EVENT_ITEMS"
        else:
            rows.append(RowOptions(("VM_NUMA_STAT:",), group=1))
            nr_numa_items = "NR_VM_NUMA_STAT_ITEMS"
        if nr_numa_items is not None:
            for name, item in numa_stat_item_type.enumerators:  # type: ignore[union-attr]
                if name == nr_numa_items:
                    continue
                rows.append(
                    (
                        CellFormat("  " + name, ">"),
                        CellFormat(global_numa_event_state(prog, item), "<"),
                    )
                )

    if "vm_event_states" in prog:
        rows.append(())
        rows.append(RowOptions(("VM_EVENT_STATES:",), group=1))
        for name, item in prog.type("enum vm_event_item").enumerators:  # type: ignore[union-attr]
            if name == "NR_VM_EVENT_ITEMS":
                continue
            rows.append(
                (
                    CellFormat("  " + name, ">"),
                    CellFormat(global_vm_event_state(prog, item), "<"),
                )
            )

    print_table(rows, sep=": ")


def _kmem_nodes(prog: Program, drgn_arg: bool) -> None:
    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import("drgn.helpers.linux.device", "dev_name")
        code.add_from_import(
            "drgn.helpers.linux.mm",
            "PFN_PHYS",
            "decode_memory_block_state",
            "for_each_memory_block",
            "memory_block_size_bytes",
            "pfn_to_page",
        )
        code.add_from_import(
            "drgn.helpers.linux.mmzone",
            "NODE_DATA",
            "decode_section_flags",
            "for_each_online_node",
            "for_each_present_section",
            "section_decode_mem_map",
            "section_mem_map_addr",
            "section_nr_to_pfn",
        )

        code.append(
            """\
for node in for_each_online_node():
    pgdat = NODE_DATA(node)
    size = pgdat.node_spanned_pages
    start_pfn = pgdat.node_start_pfn
    mem_map = pfn_to_page(start_pfn)
    start_paddr = PFN_PHYS(start_pfn)

    for zone in pgdat.node_zones:
        zone_name = zone.name
        zone_size = zone.spanned_pages
        if zone_size == 0:
            continue
        zone_start_pfn = zone.zone_start_pfn.read_()
        zone_mem_map = pfn_to_page(zone_start_pfn)
        zone_start_paddr = PFN_PHYS(zone_start_pfn)


if "mem_section" in prog:  # Check for CONFIG_SPARSEMEM.
    for nr, section in for_each_present_section():
        coded_mem_map = section_mem_map_addr(section)
        mem_map = section_decode_mem_map(section, nr)
        state = decode_section_flags(section)
        pfn = section_nr_to_pfn(nr)


if "memory_subsys" in prog:  # Check for CONFIG_MEMORY_HOTPLUG.
    block_size = memory_block_size_bytes()
    for mem in for_each_memory_block():
        name = dev_name(mem.dev.address_of_())
        start_section_no = mem.start_section_nr
        physical_start = PFN_PHYS(section_nr_to_pfn(start_section_no))
        physical_end = physical_start + block_size
        node = getattr(mem, "nid", None)  # Only available since Linux 4.17.
        state = decode_memory_block_state(mem)
"""
        )
        code.print()
        return

    rows: List[Sequence[Any]] = []
    for nid in for_each_online_node(prog):
        if rows:
            rows.append(RowOptions((), group=3))
            rows.append(RowOptions(("-" * 72,), group=3))
            rows.append(RowOptions((), group=3))

        rows.append(
            (
                CellFormat("NODE", "^"),
                CellFormat("SIZE", "^"),
                CellFormat("PGLIST_DATA", "^"),
                # Crash includes BOOTMEM_DATA, which was removed entirely in
                # Linux kernel commit 355c45affca7 ("mm: remove bootmem
                # allocator implementation.") (in v4.20) and removed from most
                # mainstream architectures years before that. We don't bother.
                CellFormat("NODE_ZONES", "^"),
            )
        )
        pgdat = NODE_DATA(prog, nid)
        prefix: Sequence[Any] = (
            CellFormat(nid, "^"),
            CellFormat(pgdat.node_spanned_pages.value_(), "^"),
            CellFormat(pgdat.value_(), "^x"),
        )
        zone_rows = [
            (),
            RowOptions(
                (
                    CellFormat("ZONE", "^"),
                    "NAME",
                    CellFormat("SIZE", ">"),
                    CellFormat("MEM_MAP", "^"),
                    CellFormat("START_PADDR", ">"),
                    CellFormat("START_PFN", ">"),
                ),
                group=2,
            ),
        ]
        for i, zone in enumerate(pgdat.node_zones):
            rows.append((*prefix, CellFormat(zone.address_, "^x")))
            prefix = ("", "", "")

            zone_size = zone.spanned_pages.value_()
            if zone_size == 0:
                zone_mem_map_cell: Any = 0
                zone_start_paddr_cell: Any = 0
                zone_start_pfn_cell: Any = 0
            else:
                zone_start_pfn = zone.zone_start_pfn.read_()
                zone_mem_map_cell = CellFormat(
                    pfn_to_page(zone_start_pfn).value_(), "x"
                )
                zone_start_paddr_cell = CellFormat(
                    PFN_PHYS(zone_start_pfn).value_(), "x"
                )
                zone_start_pfn_cell = zone_start_pfn.value_()
            zone_rows.append(
                RowOptions(
                    (
                        CellFormat(i, "^"),
                        escape_ascii_string(zone.name.string_(), escape_backslash=True),
                        zone_size,
                        zone_mem_map_cell,
                        zone_start_paddr_cell,
                        zone_start_pfn_cell,
                    ),
                    group=2,
                )
            )

        rows.append(
            RowOptions(
                (
                    CellFormat("MEM_MAP", "^"),
                    CellFormat("START_PADDR", "^"),
                    CellFormat("START_PFN", "^"),
                ),
                group=1,
            )
        )
        node_start_pfn = pgdat.node_start_pfn.read_()
        rows.append(
            RowOptions(
                (
                    CellFormat(pfn_to_page(node_start_pfn).value_(), "^x"),
                    CellFormat(PFN_PHYS(node_start_pfn).value_(), "^x"),
                    CellFormat(node_start_pfn.value_(), "^"),
                ),
                group=1,
            )
        )
        rows.extend(zone_rows)

    print_table(rows)
    rows.clear()

    if "mem_section" in prog:
        print()
        print("-" * 72)
        print()

        rows.append(
            (
                CellFormat("NR", ">"),
                CellFormat("SECTION", "^"),
                CellFormat("CODED_MEM_MAP", "^"),
                CellFormat("MEM_MAP", "^"),
                "STATE",
                "PFN",
            )
        )
        for nr, section in for_each_present_section(prog):
            rows.append(
                (
                    nr,
                    CellFormat(section.value_(), "^x"),
                    CellFormat(section_mem_map_addr(section).value_(), "^x"),
                    CellFormat(section_decode_mem_map(section, nr).value_(), "^x"),
                    "".join(
                        [
                            {
                                "SECTION_MARKED_PRESENT": "P",
                                "SECTION_HAS_MEM_MAP": "M",
                                "SECTION_IS_ONLINE": "O",
                                "SECTION_IS_EARLY": "E",
                                "SECTION_TAINT_ZONE_DEVICE": "D",
                            }.get(flag, "")
                            for flag in decode_section_flags(section).split("|")
                        ]
                    ),
                    CellFormat(section_nr_to_pfn(prog, nr).value_(), "<"),
                )
            )
        print_table(rows)
        rows.clear()

    if "memory_subsys" in prog:
        print()
        print("-" * 72)
        print()

        block_size = memory_block_size_bytes(prog)

        # struct memory_block::nid was added in Linux kernel commit
        # d0dc12e86b31 ("mm/memory_hotplug: optimize memory hotplug") (in
        # v4.17).
        if prog.type("struct memory_block").has_member("nid"):
            node_heading: Sequence[Any] = (CellFormat("NODE", "^"),)
        else:
            node_heading = ()

        rows.append(
            (
                # Crash uses the heading MEM_BLOCK, which can easily be confused
                # with struct memblock, an entirely different type.
                CellFormat("MEMORY_BLOCK", "^"),
                "NAME",
                CellFormat("PHYSICAL RANGE", "^"),
                *node_heading,
                "STATE",
                "START_SECTION_NO",
            )
        )
        paddr_width = len(hex(PFN_PHYS(prog["max_pfn"]))) - 2
        for mem in for_each_memory_block(prog):
            start_section_nr = mem.start_section_nr.read_()
            physical_start = PFN_PHYS(section_nr_to_pfn(start_section_nr))
            physical_end = physical_start + block_size - 1

            if node_heading:
                node_cell: Sequence[Any] = (CellFormat(mem.nid.value_(), "^"),)
            else:
                node_cell = ()

            state = decode_memory_block_state(mem)
            if state.startswith("MEM_"):
                state = state[len("MEM_") :]

            rows.append(
                (
                    CellFormat(mem.value_(), "^x"),
                    escape_ascii_string(
                        dev_name(mem.dev.address_of_()), escape_backslash=True
                    ),
                    CellFormat(
                        f"{physical_start.value_():{paddr_width}x}"
                        f" - {physical_end.value_():{paddr_width}x}",
                        "^",
                    ),
                    *node_cell,
                    state,
                    CellFormat(start_section_nr.value_(), "<"),
                ),
            )
        print_table(rows)


def _kmem_zones(prog: Program, drgn_arg: bool) -> None:
    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import(
            "drgn.helpers.linux.mmzone",
            "for_each_online_pgdat",
            "high_wmark_pages",
            "low_wmark_pages",
            "min_wmark_pages",
        )
        code.add_from_import("drgn.helpers.linux.vmstat", "zone_page_state")
        code.append(
            """\
for pgdat in for_each_online_pgdat():
    node = pgdat.node_id
    for zone in pgdat.node_zones:
        zone = zone.address_of_()
        name = zone.name
        size = zone.spanned_pages
        if size == 0:
            continue

        present = zone.present_pages
        min_watermark = min_wmark_pages(zone)
        low_watermark = low_wmark_pages(zone)
        high_watermark = high_wmark_pages(zone)

        for stat_name, stat_item in prog.type("enum zone_stat_item").enumerators:
            if stat_name == "NR_VM_ZONE_STAT_ITEMS":
                continue
            stat_value = zone_page_state(zone, stat_item)
"""
        )
        code.print()
        return

    separator = ""
    for pgdat in for_each_online_pgdat(prog):
        nid = pgdat.node_id.value_()
        for i, zone in enumerate(pgdat.node_zones):
            # Separate with one newline after an unpopulated zone, two after
            # populated.
            sys.stdout.write(separator)

            zone = zone.address_of_()
            print(
                f"NODE: {nid}  ZONE: {i}  ADDR: {zone.value_():x}  NAME: {double_quote_ascii_string(zone.name.string_())}"
            )

            size = zone.spanned_pages.value_()
            if not size:
                print("  [unpopulated]")
                separator = "\n"
                continue

            present = zone.present_pages.value_()
            if present < size:
                present_column = f"  PRESENT: {present}"
            else:
                present_column = ""

            minw = min_wmark_pages(zone)
            loww = low_wmark_pages(zone)
            highw = high_wmark_pages(zone)

            print(
                f"  SIZE: {size}{present_column}  MIN/LOW/HIGH: {minw}/{loww}/{highw}\n  VM_STAT:"
            )

            rows: List[Sequence[Any]] = []
            for name, item in prog.type("enum zone_stat_item").enumerators:  # type: ignore[union-attr]
                if name == "NR_VM_ZONE_STAT_ITEMS":
                    continue
                rows.append(
                    (
                        CellFormat("  " + name, ">"),
                        CellFormat(zone_page_state(zone, item), "<"),
                    )
                )
            print_table(rows)
            separator = "\n\n"


def _kmem_per_cpu_offset(prog: Program, drgn_arg: bool) -> None:
    if drgn_arg:
        sys.stdout.write(
            """\
from drgn import NULL
from drgn.helpers.linux.cpumask import for_each_possible_cpu
from drgn.helpers.linux.percpu import per_cpu_ptr


for cpu in for_each_possible_cpu():
    offset = per_cpu_ptr(NULL(prog, "void *"), cpu)
"""
        )
        return

    print("PER-CPU OFFSET VALUES:")
    nullptr = NULL(prog, "void *")
    for cpu in for_each_possible_cpu(prog):
        cpu_field = f"CPU {cpu}"
        print(f"{cpu_field:>7}: {per_cpu_ptr(nullptr, cpu).value_():x}")


def _kmem_hstate(prog: Program, drgn_arg: bool) -> None:
    if drgn_arg:
        sys.stdout.write(
            """\
from drgn.helpers.linux.hugetlb import for_each_hstate, huge_page_size


for hstate in for_each_hstate(prog):
    size = huge_page_size(hstate)
    free = hstate.free_huge_pages
    total = hstate.nr_huge_pages
    name = hstate.name
"""
        )
        return

    rows: List[Sequence[Any]] = [
        (
            CellFormat("HSTATE", "^"),
            CellFormat("SIZE", ">"),
            CellFormat("FREE", ">"),
            CellFormat("TOTAL", ">"),
            "NAME",
        )
    ]
    for hstate in for_each_hstate(prog):
        rows.append(
            (
                CellFormat(hstate.value_(), "^x"),
                CellFormat(number_in_binary_units(huge_page_size(hstate)) + "B", ">"),
                hstate.free_huge_pages.value_(),
                hstate.nr_huge_pages.value_(),
                escape_ascii_string(hstate.name.string_(), escape_backslash=True),
            )
        )

    print_table(rows)


def _page_flags_and_decoded_flags(page: Object) -> str:
    flags = page_flags(page).read_()
    decoded_flags = decode_page_flags_value(flags).replace("|", ",").replace("PG_", "")
    return f"{flags.value_():x} {decoded_flags}"


def _page_flags_member(page: Object) -> str:
    flags = page_flags(page)
    return f"{flags.value_():0{sizeof(flags) * 2}x}"


def _page_list_head_member(member: str, page: Object) -> str:
    node = page[0].subobject_(member)
    next = node.next
    prev = node.prev
    return f"{next.value_():0{sizeof(next) * 2}x},{prev.value_():0{sizeof(prev) * 2}x}"


def _page_callback_head_member(member: str, page: Object) -> str:
    head = page[0].subobject_(member)
    next = head.next
    func = head.func
    return f"{next.value_():0{sizeof(next) * 2}x},{func.value_():0{sizeof(func) * 2}x}"


def _page_decimal_member(member: str, page: Object) -> str:
    return str(page[0].subobject_(member).value_())


def _page_hex_member(member: str, page: Object) -> str:
    object = page[0].subobject_(member)
    return f"{object.value_():0{sizeof(object) * 2}x}"


_T = TypeVar("_T")


def _print_pages_default_members(
    prog: Program,
    iterable: Iterable[_T],
    *,
    get_page: Callable[[_T], Object],
    get_physical: Optional[Callable[[_T], int]] = None,
    get_mapping: Optional[Callable[[_T], int]] = None,
    get_index: Optional[Callable[[_T], int]] = None,
) -> None:
    address_size = prog.address_size()
    PAGE_SHIFT = prog["PAGE_SHIFT"].value_()

    # print_table() requires having all rows available ahead of time. With a
    # row per page, this would take too much time and memory. Instead, we
    # compute the column widths and print each row manually.
    widths = [
        address_size * 2,
        len(hex(prog["max_pfn"].value_() << PAGE_SHIFT)) - 2,
        address_size * 2,
        12,
        3,
        5,
    ]

    first = True
    for item in iterable:
        if first:
            _print_table_row(
                (
                    CellFormat("PAGE", "^"),
                    CellFormat("PHYSICAL", ">"),
                    CellFormat("MAPPING", "^"),
                    CellFormat("INDEX", ">"),
                    CellFormat("CNT", ">"),
                    "FLAGS",
                ),
                widths=widths,
            )
            first = False

        page = get_page(item)
        _print_table_row(
            (
                f"{page.value_():0{address_size * 2}x}",
                CellFormat(
                    (
                        page_to_pfn(page).value_() << PAGE_SHIFT
                        if get_physical is None
                        else get_physical(item)
                    ),
                    "x",
                ),
                CellFormat(
                    page.mapping.value_() if get_mapping is None else get_mapping(item),
                    "x",
                ),
                CellFormat(
                    page_index(page).value_() if get_index is None else get_index(item),
                    "x",
                ),
                CellFormat(page._refcount.counter.value_(), "x"),
                _page_flags_and_decoded_flags(page),
            ),
            widths=widths,
        )


def _print_pages_members(
    prog: Program,
    members: str,
    pages: Iterable[Object],
) -> None:
    address_size = prog.address_size()
    header: List[Any] = [CellFormat("PAGE", "^")]
    widths = [address_size * 2]
    getters: List[Callable[[Object], Any]] = [
        lambda page: f"{page.value_():0{address_size * 2}x}"
    ]

    struct_page = prog.type("struct page")
    integer_base = prog.config.get("crash_radix", 10)
    for member in _parse_members(members):
        header.append(member)

        if member == "flags":
            widths.append(address_size * 2)
            getters.append(_page_flags_member)
            continue

        member_type = typeof_member(struct_page, member)
        member_type_kind = member_type.unaliased_kind()
        member_type_name = member_type.type_name()
        if member_type_name == "struct list_head":
            widths.append(max(address_size * 4 + 1, len(member)))
            getters.append(functools.partial(_page_list_head_member, member))
        elif member_type_name == "struct callback_head":
            widths.append(max(address_size * 4 + 1, len(member)))
            getters.append(functools.partial(_page_callback_head_member, member))
        elif member_type_name == "atomic_t" or member_type_name == "atomic_long_t":
            widths.append(max(12, len(member)))
            getters.append(functools.partial(_page_decimal_member, member + ".counter"))
        elif (
            member_type_kind == TypeKind.INT and integer_base == 16
        ) or member_type_kind == TypeKind.POINTER:
            widths.append(max(sizeof(member_type) * 2, len(member)))
            getters.append(functools.partial(_page_hex_member, member))
        elif member_type_kind == TypeKind.INT:
            widths.append(max(12, len(member)))
            getters.append(functools.partial(_page_decimal_member, member))
        else:
            raise NotImplementedError(
                f"formatting {member_type_name!r} not implemented"
            )

    _print_table_row(header, widths=widths)
    for page in pages:
        _print_table_row([getter(page) for getter in getters], widths=widths)


def _kmem_pages(
    prog: Program,
    drgn_arg: bool,
    *,
    members: Optional[str] = None,
    identified: Optional[IdentifiedPage] = None,
) -> None:
    if members is None:
        if drgn_arg:
            code = CrashDrgnCodeBuilder(prog)
            code.add_from_import(
                "drgn.helpers.linux.mm",
                "PFN_PHYS",
                "decode_page_flags_value",
                "for_each_valid_pfn_and_page",
                "page_flags",
                "page_index",
            )
            code.append(
                """\
for pfn, page in for_each_valid_pfn_and_page():
    physical = PFN_PHYS(pfn)
    mapping = page.mapping
    index = page_index(page)
    cnt = page._refcount.counter
    flags = page_flags(page)
    decoded_flags = decode_page_flags_value(flags)
"""
            )
            return code.print()

        PAGE_SHIFT = prog["PAGE_SHIFT"].value_()
        _print_pages_default_members(
            prog,
            (
                for_each_valid_pfn_and_page(prog)
                if identified is None
                else ((identified.pfn, identified.page),)
            ),
            get_page=operator.itemgetter(1),
            get_physical=lambda item: item[0] << PAGE_SHIFT,
        )
    else:
        if drgn_arg:
            code = CrashDrgnCodeBuilder(prog)
            code.add_from_import("drgn.helpers.linux.mm", "for_each_page")
            code.append("for page in for_each_page():\n")
            for member in _parse_members(members):
                if member == "flags":
                    code.add_from_import("drgn.helpers.linux.mm", "page_flags")
                    code.append("    flags = page_flags(page)\n")
                else:
                    code.append(
                        f"    {_sanitize_member_name(member)} = " f"page.{member}\n"
                    )
            return code.print()

        _print_pages_members(
            prog,
            members,
            for_each_page(prog) if identified is None else (identified.page,),
        )


def _kmem_slab(
    prog: Program,
    drgn_arg: bool,
    *,
    ignore: AbstractSet[bytes],
    names: Optional[Sequence[str]] = None,
    identified: Optional[IdentifiedSlabObject] = None,
) -> None:
    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import(
            "drgn.helpers.linux.slab", "slab_cache_pages_per_slab", "slab_cache_usage"
        )

        if len(ignore) > 1:
            code.append("ignore = {")
            code.append(", ".join([repr(name) for name in sorted(ignore)]))
            code.append("}\n\n")

        if names:
            code.add_from_import("drgn.helpers.linux.slab", "find_slab_cache")
            # If we're only matching one name, use an if statement instead of a
            # loop. However, ignore is handled with a continue statement, so
            # always use a loop if there are names to ignore.
            if len(names) == 1 and not ignore:
                code.append(
                    f"""\
cache = find_slab_cache({_repr_black(names[0])})
if cache:
"""
                )
            else:
                code.append("for search_name in (\n")
                for search_name in names:
                    code.append(f"    {_repr_black(search_name)},\n")
                code.append(
                    """):
    cache = find_slab_cache(search_name)
    if not cache:
        continue
"""
                )
        else:
            code.add_from_import("drgn.helpers.linux.slab", "for_each_slab_cache")
            code.append("for cache in for_each_slab_cache():\n")

        code.append("    name = cache.name\n")

        if ignore:
            if len(ignore) == 1:
                code.append(f"    if name.string_() == {next(iter(ignore))!r}:\n")
            else:
                code.append("    if name.string_() in ignore:\n")
            code.append("        continue\n")

        code.append(
            """\
    objsize = cache.object_size
    try:
        usage = slab_cache_usage(cache)
    except ValueError:
        # SLUB without SLUB_DEBUG and SLOB do not support slab_cache_usage().
        pass
    else:
        allocated = usage.active_objs
        total = usage.num_objs
        slabs = usage.num_slabs
    try:
        ssize = prog["PAGE_SIZE"] * slab_cache_pages_per_slab(cache)
    except ValueError:
        # SLOB does not support slab_cache_pages_per_slab().
        pass
"""
        )
        code.print()
        return

    rows: List[Sequence[Any]] = [
        (
            "CACHE",
            CellFormat("OBJSIZE", ">"),
            CellFormat("ALLOCATED", ">"),
            CellFormat("TOTAL", ">"),
            CellFormat("SLABS", ">"),
            CellFormat("SSIZE", ">"),
            "NAME",
        )
    ]

    if identified is not None:
        caches: Iterable[Object] = (identified.slab_object_info.slab_cache,)
    elif names is None:
        caches = for_each_slab_cache(prog)
    else:
        caches = [cache for name in names if (cache := find_slab_cache(prog, name))]

    for cache in caches:
        name = cache.name.string_()
        if name in ignore:
            rows.append(
                (
                    CellFormat(cache.value_(), "<x"),
                    "[IGNORED]",
                    "",
                    "",
                    "",
                    "",
                    escape_ascii_string(cache.name.string_(), escape_backslash=True),
                )
            )
        else:
            objsize = cache.object_size.value_()
            try:
                order = slab_cache_order(cache)
            except ValueError:
                # SLOB doesn't support slab_cache_order() or
                # slab_cache_usage().
                allocated: Any = "[UNKNOWN]"
                total: Any = ""
                slabs: Any = ""
                ssize: Any = ""
            else:
                ssize = CellFormat(
                    f"{(prog['PAGE_SIZE'].value_() << order) // 1024}k", ">"
                )
                # SLUB without SLUB_DEBUG supports slab_cache_order() but not
                # slab_cache_usage().
                try:
                    usage = slab_cache_usage(cache)
                except ValueError:
                    allocated = "[UNKNOWN]"
                    total = ""
                    slabs = ""
                except (FaultError, ValidationError):
                    allocated = "[CORRUPTED]"
                    total = ""
                    slabs = ""
                else:
                    allocated = usage.active_objs
                    total = usage.num_objs
                    slabs = usage.num_slabs
            rows.append(
                (
                    CellFormat(cache.value_(), "<x"),
                    objsize,
                    allocated,
                    total,
                    slabs,
                    ssize,
                    escape_ascii_string(cache.name.string_(), escape_backslash=True),
                )
            )

            if identified is not None:
                rows.append(
                    RowOptions(
                        (
                            "",
                            "SLAB",
                            "MEMORY",
                        ),
                        group=1,
                    )
                )
                slab = identified.slab_object_info.slab
                slab_memory = page_to_virt(cast("struct page *", slab))
                rows.append(
                    RowOptions(
                        (
                            "",
                            f"{slab.value_():x}",
                            f"{slab_memory.value_():x}",
                        ),
                        group=1,
                    )
                )

                rows.append(
                    RowOptions(
                        (
                            "",
                            "FREE / [ALLOCATED]",
                        ),
                        group=2,
                    )
                )
                object_address = f"{identified.slab_object_info.address:x}"
                if identified.slab_object_info.allocated:
                    object_address = f"[{object_address}]"
                rows.append(
                    RowOptions(
                        (
                            "",
                            object_address,
                        ),
                        group=2,
                    )
                )
    print_table(rows)


def _kmem_page_flags(prog: Program, drgn_arg: bool, flags: Optional[int]) -> None:
    if drgn_arg:
        if flags is None:
            sys.stdout.write(
                """\
for name, bit in prog.type("enum pageflags").enumerators:
    if name == "__NR_PAGEFLAGS":
        continue
    value = 1 << bit
"""
            )
        else:
            sys.stdout.write(
                f"""\
from drgn.helpers.linux.mm import decode_page_flags_value


flags = decode_page_flags_value(0x{flags:x})
"""
            )
        return

    if flags is None:
        prefix = ""
    else:
        print(f"FLAGS: {flags:x}")
        prefix = "  "
    rows: List[Sequence[Any]] = [
        (prefix + "PAGE-FLAG", CellFormat("BIT", ">"), "VALUE")
    ]
    width = len(hex((1 << prog["__NR_PAGEFLAGS"].value_()) - 1)) - 2
    for name, bit in prog.type("enum pageflags").enumerators:  # type: ignore[union-attr]
        if name == "__NR_PAGEFLAGS":
            continue
        value = 1 << bit
        if flags is None or flags & value:
            rows.append((prefix + name, bit, f"{value:0{width}x}"))
    print_table(rows)


_IDENTIFY_MODES = {
    None,
    # Crash supposedly supports -f, too, but I've never been able to get it to
    # work, so we ignore it for now.
    "free",
    "pages",
    "slab",
    "vmalloc",
}


def _kmem_identify(
    prog: Program,
    drgn_arg: bool,
    addresses: List[int],
    mode: Optional[str],
    *,
    page_members: Optional[str],
    ignore_slab_caches: AbstractSet[bytes],
    slab_cache_names: bool,
) -> None:
    if mode not in _IDENTIFY_MODES:
        raise CommandArgumentError(f"address not allowed with {mode}")

    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import("drgn.helpers.common.memory", "identify_address")
        if len(addresses) == 1:
            code.append(f"address = {hex(addresses[0])}\n")
        else:
            code.append("for address in (")
            code.append(", ".join([hex(address) for address in addresses]))
            code.append("):\n    ")
        code.append("identified = identify_address(address)\n")
        code.print()
        return

    first = True

    def print_divider() -> None:
        nonlocal first
        if first:
            first = False
        else:
            print()

    for address in addresses:
        all_identified = identify_address_all(prog, address)
        if all_identified is None:
            all_identified = ()

        found_vmap = False
        found_page = False
        found_slab = False
        for identified in all_identified:
            if isinstance(identified, IdentifiedSymbol):
                if mode is None:
                    offset = address - identified.symbol.address
                    offset_str = f"+{offset}" if offset else ""

                    module_str = ""
                    try:
                        module = prog.module(address)
                    except LookupError:
                        pass
                    else:
                        if isinstance(module, RelocatableModule):
                            module_str = f" [{module.name}]"

                    print_divider()
                    print(
                        f"{address:x} (?) {identified.symbol.name}{offset_str}{module_str}"
                    )
            elif isinstance(identified, (IdentifiedTaskStruct, IdentifiedTaskStack)):
                if mode is None:
                    print_divider()
                    _print_sys(prog, system_fields=False, context=identified.task)
            elif isinstance(identified, IdentifiedVmap):
                found_vmap = True
                if mode is None or mode == "vmalloc":
                    print_divider()
                    _kmem_vmalloc(prog, False, identified=identified)
            elif isinstance(identified, IdentifiedPage):
                found_page = True
                if mode is None or mode == "pages":
                    print_divider()
                    _kmem_pages(
                        prog, False, members=page_members, identified=identified
                    )
            elif isinstance(identified, IdentifiedSlabObject):
                found_slab = True
                if mode is None or mode == "slab":
                    print_divider()
                    if slab_cache_names:
                        print(
                            f"kmem: ignoring pre-selected slab caches for address: {address:x}"
                        )
                    if identified.slab_object_info.address:
                        _kmem_slab(
                            prog,
                            False,
                            ignore=ignore_slab_caches,
                            identified=identified,
                        )
                    else:
                        print(f"kmem: address is from SLOB: {address:x}")

        if not found_vmap and mode == "vmalloc":
            print_divider()
            # Crash fails with a bad memory access instead.
            print(f"kmem: address is not allocated in vmalloc subsystem: {address:x}")

        if not found_page and (mode is None or mode == "pages"):
            try:
                pfn = follow_pfn(prog["init_mm"].address_of_(), address)
            except (FaultError, NotImplementedError):
                pass
            else:
                print_divider()
                _kmem_pages(
                    prog,
                    False,
                    members=page_members,
                    identified=IdentifiedPage(address, pfn_to_page(pfn), pfn.value_()),
                )

        if mode == "slab" and not found_slab:
            print_divider()
            print(f"kmem: address is not allocated in slab subsystem: {address:x}")


@crash_command(
    description="kernel memory",
    long_description="""
    Display information about various parts of the memory management subsystem.
    """,
    arguments=(
        mutually_exclusive_group(
            argument(
                "-f",
                dest="mode",
                action="store_const",
                const="free",
                help="display and verify page allocator free lists",
            ),
            argument(
                "-F",
                dest="mode",
                action="store_const",
                const="free_pages",
                help="like -f, but also display each page on the free lists",
            ),
            argument(
                "-i",
                dest="mode",
                action="store_const",
                const="info",
                help="display general memory usage information",
            ),
            argument(
                "-v",
                dest="mode",
                action="store_const",
                const="vmalloc",
                help="display memory regions allocated with vmalloc()/vmap()",
            ),
            argument(
                "-V",
                dest="mode",
                action="store_const",
                const="vmstat",
                help="display zone, node, NUMA, and VM event statistics",
            ),
            argument(
                "-n",
                dest="mode",
                action="store_const",
                const="nodes",
                help="display NUMA nodes, SPARSEMEM sections, and memory blocks",
            ),
            argument(
                "-z",
                dest="mode",
                action="store_const",
                const="zones",
                help="display per-zone memory statistics",
            ),
            argument(
                "-o",
                dest="mode",
                action="store_const",
                const="per_cpu_offset",
                help="""
                display each CPU's per-CPU offset (the value added to convert a
                per-CPU symbol to a virtual address)
                """,
            ),
            argument(
                "-h",
                dest="mode",
                action="store_const",
                const="hstate",
                help="display HugeTLB state",
            ),
            argument(
                "-p",
                dest="mode",
                action="store_const",
                const="pages",
                help="""
                display every valid struct page, including its physical
                address, mapping, index, refcount, and flags
                """,
            ),
            argument(
                "-m",
                dest="page_members",
                help="""
                display the given comma-separated members of every valid struct page
                """,
            ),
            argument(
                "-s",
                dest="mode",
                action="store_const",
                const="slab",
                help="display an overview of slab caches",
            ),
            argument(
                "-g",
                dest="page_flags",
                metavar="FLAGS",
                type="hexadecimal",
                nargs="?",
                default=argparse.SUPPRESS,
                help="""
                display the flags set on a hexadecimal page flags value, or
                display all of the possible flags if no value is given
                """,
            ),
        ),
        argument(
            "-I",
            dest="ignore_slab_caches",
            metavar="NAME[,NAME...]",
            help="""
            when used with -s, comma-separated list of names of slab caches to
            ignore
            """,
        ),
        argument(
            "name",
            nargs="*",
            help="""
            when used with -s, only display the slab caches with the given names
            """,
        ),
        argument(
            "address",
            nargs="*",
            help="""
            addresses to identify as symbols, tasks, task stacks, vmalloc
            allocations, pages, and/or slab objects. Can be combined with -v,
            -p, -m, or -s to limit the search to their respective types
            """,
        ),
        drgn_argument,
    ),
)
def _crash_cmd_kmem(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    # argparse greedily assigns all of the positional arguments to name.
    # Separate the addresses.
    posargs = args.name
    args.name = []
    assert not args.address
    for posarg in posargs:
        try:
            args.address.append(int(posarg, 16))
        except ValueError:
            args.name.append(posarg)

    if args.page_members is not None:
        args.mode = "pages"
    elif hasattr(args, "page_flags"):
        args.mode = "page_flags"

    if args.ignore_slab_caches is None:
        ignore_slab_caches: AbstractSet[bytes] = frozenset()
    else:
        if args.mode != "slab":
            raise CommandArgumentError("-I can only be used with -s")
        ignore_slab_caches = {
            name.encode() for name in args.ignore_slab_caches.split(",")
        }

    if args.name:
        if args.mode != "slab":
            raise CommandArgumentError("name can only be used with -s")
        slab_cache_names: Optional[List[str]] = args.name
    else:
        slab_cache_names = None

    if args.address:
        _kmem_identify(
            prog,
            args.drgn,
            args.address,
            args.mode,
            page_members=args.page_members,
            ignore_slab_caches=ignore_slab_caches,
            slab_cache_names=bool(slab_cache_names),
        )
    elif args.mode == "free":
        return _kmem_free(prog, args.drgn)
    elif args.mode == "free_pages":
        return _kmem_free(prog, args.drgn, show_pages=True)
    elif args.mode == "info":
        return _kmem_info(prog, args.drgn)
    elif args.mode == "vmalloc":
        return _kmem_vmalloc(prog, args.drgn)
    elif args.mode == "vmstat":
        return _kmem_vmstat(prog, args.drgn)
    elif args.mode == "nodes":
        return _kmem_nodes(prog, args.drgn)
    elif args.mode == "zones":
        return _kmem_zones(prog, args.drgn)
    elif args.mode == "per_cpu_offset":
        return _kmem_per_cpu_offset(prog, args.drgn)
    elif args.mode == "hstate":
        return _kmem_hstate(prog, args.drgn)
    elif args.mode == "pages":
        return _kmem_pages(prog, args.drgn, members=args.page_members)
    elif args.mode == "slab":
        return _kmem_slab(
            prog, args.drgn, ignore=ignore_slab_caches, names=slab_cache_names
        )
    elif args.mode == "page_flags":
        return _kmem_page_flags(prog, args.drgn, args.page_flags)
    else:
        raise CommandArgumentError("address or option is required")
