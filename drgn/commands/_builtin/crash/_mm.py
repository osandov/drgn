# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Memory management-related crash commands."""

import argparse
import sys
from typing import AbstractSet, Any, List, Optional, Sequence

from drgn import NULL, FaultError, Program, ProgramFlags
from drgn.commands import (
    CommandArgumentError,
    _repr_black,
    argument,
    drgn_argument,
    mutually_exclusive_group,
)
from drgn.commands.crash import CrashDrgnCodeBuilder, crash_command
from drgn.helpers.common.format import (
    CellFormat,
    escape_ascii_string,
    number_in_binary_units,
    print_table,
)
from drgn.helpers.linux.cpumask import for_each_possible_cpu
from drgn.helpers.linux.hugetlb import (
    for_each_hstate,
    huge_page_size,
    hugetlb_total_usage,
)
from drgn.helpers.linux.mm import (
    for_each_vmap_area,
    global_node_page_state,
    nr_blockdev_pages,
    nr_free_pages,
    totalram_pages,
    vm_commit_limit,
    vm_memory_committed,
)
from drgn.helpers.linux.percpu import per_cpu_ptr
from drgn.helpers.linux.slab import (
    SlabCorruptionError,
    find_slab_cache,
    for_each_slab_cache,
    slab_cache_order,
    slab_cache_usage,
    slab_total_usage,
)
from drgn.helpers.linux.swap import (
    for_each_swap_info,
    swap_file_path,
    swap_is_file,
    swap_total_usage,
    swap_usage_in_pages,
    total_swapcache_pages,
)


@crash_command(
    description="bytes to page",
    long_description="Convert byte numbers (usually physical addresses) to page numbers.",
    arguments=(
        argument(
            "address",
            type="hexadecimal",
            nargs="+",
            help="hexadecimal byte number/physical address",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_btop(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import("drgn.helpers.linux.mm", "PHYS_PFN")

        if len(args.address) == 1:
            code.append(f"phys_addr = {hex(args.address[0])}\n")
        else:
            code.append("for phys_addr in ")
            for i, address in enumerate(args.address):
                if i > 0:
                    code.append(", ")
                code.append(hex(address))
            code.append(":\n    ")

        code.append("pfn = PHYS_PFN(phys_addr)\n")
        code.print()
        return

    PAGE_SHIFT = prog["PAGE_SHIFT"].value_()
    for address in args.address:
        print(f"{address:x}: {address >> PAGE_SHIFT:x}")


@crash_command(
    description="page to bytes",
    long_description="Convert page frame numbers to byte numbers (physical addresses).",
    arguments=(
        argument(
            "pfn", type="decimal_or_hexadecimal", nargs="+", help="page frame number"
        ),
        drgn_argument,
    ),
)
def _crash_cmd_ptob(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import("drgn.helpers.linux.mm", "PFN_PHYS")

        if len(args.pfn) == 1:
            code.append(f"pfn = {hex(args.pfn[0])}\n")
        else:
            code.append("for pfn in ")
            for i, pfn in enumerate(args.pfn):
                if i > 0:
                    code.append(", ")
                code.append(hex(pfn))
            code.append(":\n    ")

        code.append("phys_addr = PFN_PHYS(pfn)\n")
        code.print()
        return

    PAGE_SHIFT = prog["PAGE_SHIFT"].value_()
    for pfn in args.pfn:
        print(f"{pfn:x}: {pfn << PAGE_SHIFT:x}")


def _kmem_info(
    prog: Program,
    drgn_arg: bool,
) -> None:
    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import("drgn.helpers.linux.hugetlb", "hugetlb_total_usage")
        code.add_from_import(
            "drgn.helpers.linux.mm",
            "global_node_page_state",
            "nr_blockdev_pages",
            "nr_free_pages",
            "totalram_pages",
            "vm_commit_limit",
            "vm_memory_committed",
        )
        code.add_from_import("drgn.helpers.linux.slab", "slab_total_usage")
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
    prog: Program,
    drgn_arg: bool,
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
    for va in for_each_vmap_area(prog):
        start = va.va_start.value_()
        end = va.va_end.value_()
        rows.append(
            (
                CellFormat(va.value_(), "^x"),
                CellFormat(va.vm.value_(), "^x"),
                CellFormat(f"{start:x} - {end:x}", "^"),
                end - start,
            )
        )

    print_table(rows)


def _kmem_per_cpu_offset(
    prog: Program,
    drgn_arg: bool,
) -> None:
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


def _kmem_hstate(
    prog: Program,
    drgn_arg: bool,
) -> None:
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


def _kmem_slab(
    prog: Program,
    drgn_arg: bool,
    *,
    ignore: AbstractSet[bytes],
    names: Optional[List[str]],
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
    usage = slab_cache_usage(cache)
    allocated = usage.active_objs
    total = usage.num_objs
    slabs = usage.num_slabs
    ssize = prog["PAGE_SIZE"] * slab_cache_pages_per_slab(cache)
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

    if names is None:
        caches = for_each_slab_cache(prog)
    else:
        caches = iter(
            [cache for name in names if (cache := find_slab_cache(prog, name))]
        )

    for cache in caches:
        name = cache.name.string_()
        if name in ignore:
            objsize: Any = "[IGNORED]"
            allocated: Any = ""
            total: Any = ""
            slabs: Any = ""
            ssize_cell: Any = ""
        else:
            objsize = cache.object_size.value_()
            allocated = "[CORRUPTED]"
            total = slabs = ""
            # Walking slab lists is racy. Retry a limited number of times on
            # live kernels.
            for i in range(10):
                try:
                    usage = slab_cache_usage(cache)
                except (FaultError, SlabCorruptionError):
                    if not (prog.flags & ProgramFlags.IS_LIVE):
                        break
                else:
                    allocated = usage.active_objs
                    total = usage.num_objs
                    slabs = usage.num_slabs
                    break
            ssize = prog["PAGE_SIZE"].value_() << slab_cache_order(cache)
            ssize_cell = CellFormat(f"{ssize // 1024}k", ">")
        rows.append(
            (
                CellFormat(cache.value_(), "<x"),
                objsize,
                allocated,
                total,
                slabs,
                ssize_cell,
                escape_ascii_string(cache.name.string_(), escape_backslash=True),
            )
        )
    print_table(rows)


@crash_command(
    description="kernel memory",
    long_description="""
    Display information about various parts of the memory management subsystem.
    """,
    arguments=(
        mutually_exclusive_group(
            argument(
                "-i",
                dest="info",
                action="store_true",
                help="display general memory usage information",
            ),
            argument(
                "-v",
                dest="vmalloc",
                action="store_true",
                help="display memory regions allocated with vmalloc()/vmap()",
            ),
            argument(
                "-o",
                dest="per_cpu_offset",
                action="store_true",
                help="""
                display each CPU's per-CPU offset (the value added to convert a
                per-CPU symbol to a virtual address)
                """,
            ),
            argument(
                "-h",
                dest="hstate",
                action="store_true",
                help="display HugeTLB state",
            ),
            argument(
                "-s",
                dest="slab",
                action="store_true",
                help="display an overview of slab caches",
            ),
            required=True,
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
        drgn_argument,
    ),
)
def _crash_cmd_kmem(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if args.ignore_slab_caches is None:
        ignore_slab_caches: AbstractSet[bytes] = frozenset()
    else:
        if not args.slab:
            raise CommandArgumentError("-I can only be used with -s")
        ignore_slab_caches = {
            name.encode() for name in args.ignore_slab_caches.split(",")
        }

    if args.name:
        if not args.slab:
            raise CommandArgumentError("name can only be used with -s")
        slab_cache_names: Optional[List[str]] = args.name
    else:
        slab_cache_names = None

    if args.info:
        return _kmem_info(prog, args.drgn)
    if args.vmalloc:
        return _kmem_vmalloc(prog, args.drgn)
    if args.per_cpu_offset:
        return _kmem_per_cpu_offset(prog, args.drgn)
    if args.hstate:
        return _kmem_hstate(prog, args.drgn)
    if args.slab:
        return _kmem_slab(
            prog, args.drgn, ignore=ignore_slab_caches, names=slab_cache_names
        )


@crash_command(
    description="list swap devices",
    arguments=(drgn_argument,),
)
def _crash_cmd_swap(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import(
            "drgn.helpers.linux.swap",
            "for_each_swap_info",
            "swap_file_path",
            "swap_is_file",
            "swap_usage_in_pages",
        )
        code.append(
            """\
for si in for_each_swap_info():
    is_file = swap_is_file(si)
    pages = si.pages
    used_pages = swap_usage_in_pages(si)
    priority = si.prio
    path = swap_file_path(si)
"""
        )
        code.print()
        return

    rows: List[Sequence[Any]] = [
        (
            "SWAP_INFO_STRUCT",
            CellFormat("TYPE", "^"),
            CellFormat("SIZE", "^"),
            CellFormat("USED", "^"),
            CellFormat("PCT", ">"),
            CellFormat("PRI", ">"),
            "FILENAME",
        ),
    ]
    for si in for_each_swap_info(prog):
        size = (si.pages * prog["PAGE_SIZE"]).value_()
        used = swap_usage_in_pages(si) * prog["PAGE_SIZE"].value_()
        rows.append(
            (
                CellFormat(si.value_(), "x"),
                CellFormat(
                    "FILE" if swap_is_file(si) else "PARTITION",
                    "^",
                ),
                CellFormat(f"{size // 1024}k", "^"),
                CellFormat(f"{used // 1024}k", "^"),
                CellFormat(used / size, ".0%"),
                si.prio.value_(),
                escape_ascii_string(swap_file_path(si)),
            ),
        )
    print_table(rows)
