#!/usr/bin/env drgn
# Copyright (c) 2026, Kylin Software, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Traverse all pages in the system and categorize them by type.

This drgn script iterates through all physical pages in the system and
categorizes them into different types:
- anon: anonymous pages (non-compound)
- file: file-backed pages (non-compound)
- anon_thp: anonymous THP (Transparent Huge Pages, order >= 9)
- file_thp: file-backed THP (order >= 9)
- thp: other THP pages (no mapping)
- hugepage: HugeTLB pages (page_type == PGTY_hugetlb)
- slab: slab allocator pages
- reserved: reserved pages (kernel memory, firmware, etc.)
- compound_small: small compound pages (order 1-8, not THP)
- other: other pages (no mapping, non-compound)

Supports both live system analysis and vmcore dump analysis.

Usage:
    Live system:
        drgn -s /path/to/vmlinux follow_gloable_page.py
    
    Vmcore dump:
        drgn -c vmcore -s vmlinux follow_gloable_page.py
"""

from collections import defaultdict
from drgn import FaultError
from drgn.helpers.linux.mm import (
    for_each_page,
    PageSlab,
    PageReserved,
    PageCompound,
    PageTail,
    compound_head,
    compound_nr,
    compound_order,
)

DESC = """
Global Page Statistics Analyzer
================================
This tool traverses all pages in the system and categorizes them by type.
Categories: anon, file, anon_thp, file_thp, thp, hugepage, slab, reserved, compound_small, other
"""

def is_hugetlb_page(page):
    """
    Check if a page is a HugeTLB page by checking page_type.

    Returns True if page is HugeTLB, False otherwise.
    """
    if page is None:
        return False
    try:
        if PageCompound(page):
            try:
                head = compound_head(page)
                page_type_val = head.page_type.value_()
                # PGTY_hugetlb = 0xf4
                if ((page_type_val >> 24) & 0xff) == 0xf4:
                    return True
            except Exception:
                pass
    except Exception:
        pass
    return False


def is_thp_page(page):
    """
    Check if a page is a THP (Transparent Huge Page) by checking order.

    THP is defined as: compound page with order >= HPAGE_PMD_ORDER (typically 9 on x86_64).
    This matches the kernel's folio_test_pmd_mappable() logic.

    Returns True if page is THP, False otherwise.
    """
    if page is None:
        return False
    try:
        if PageCompound(page):
            try:
                head = compound_head(page)
                # Get the order of the compound page
                order = compound_order(head).value_()
                # HPAGE_PMD_ORDER is typically 9 on x86_64 (2MB / 4KB = 512 pages)
                # THP is defined as order >= HPAGE_PMD_ORDER
                HPAGE_PMD_ORDER = 9  # x86_64 default
                if order >= HPAGE_PMD_ORDER:
                    return True
            except Exception:
                pass
    except Exception:
        pass
    return False


def format_memory_size(page_count, page_size):
    """
    Format memory size from page count to human-readable format (GB, MB, KB, B).

    :param page_count: Number of pages
    :param page_size: Size of each page in bytes
    :return: Formatted string with appropriate unit
    """
    total_bytes = page_count * page_size

    if total_bytes >= 1024 * 1024 * 1024:  # GB
        return f"{total_bytes / (1024 * 1024 * 1024):>10.2f} GB"
    elif total_bytes >= 1024 * 1024:  # MB
        return f"{total_bytes / (1024 * 1024):>10.2f} MB"
    elif total_bytes >= 1024:  # KB
        return f"{total_bytes / 1024:>10.2f} KB"
    else:  # B
        return f"{total_bytes:>10} B"


def categorize_page(page):
    """
    Categorize a page into one of the predefined types.

    Returns: (category, page_count) where:
    - category: string (anon, file, hugepage, slab, reserved, other)
    - page_count: number of pages (1 for normal pages, compound_nr for compound pages)
    - Returns (None, 0) for tail pages (should be skipped)
    """
    try:
        # Check if it's a reserved page (kernel memory, firmware, etc.)
        if PageReserved(page):
            return ("reserved", 1)

        # Check if it's part of a compound page
        if PageCompound(page):
            # Skip tail pages - they will be counted via head page
            if PageTail(page):
                return (None, 0)  # Signal to skip this page

            # This is a head page - get the compound page count
            nr_pages = compound_nr(page).value_()

            # Check if it's a HugeTLB page (check head page)
            if is_hugetlb_page(page):
                return ("hugepage", nr_pages)

            # Check if it's a slab page (check head page for compound pages)
            if PageSlab(page):
                return ("slab", nr_pages)

            # Check if it's a THP page (order >= HPAGE_PMD_ORDER)
            if is_thp_page(page):
                # THP: check mapping to determine anon vs file
                mapping = page.mapping.value_()
                if mapping != 0:
                    PAGE_MAPPING_ANON = 1
                    if mapping & PAGE_MAPPING_ANON:
                        return ("anon_thp", nr_pages)
                    else:
                        return ("file_thp", nr_pages)
                else:
                    return ("thp", nr_pages)

            # Check mapping to determine anon vs file (check head page)
            mapping = page.mapping.value_()
            if mapping != 0:
                PAGE_MAPPING_ANON = 1
                if mapping & PAGE_MAPPING_ANON:
                    return ("anon", nr_pages)
                else:
                    return ("file", nr_pages)

            # Other compound pages (smaller than THP, e.g., order 1-8)
            return ("compound_small", nr_pages)

        # For non-compound pages, check if it's a slab page
        if PageSlab(page):
            return ("slab", 1)

        # Check if it's a HugeTLB page (check head page)
        if is_hugetlb_page(page):
            return ("hugepage", 1)

        # For non-compound pages, check mapping to determine anon vs file
        mapping = page.mapping.value_()

        # Check if mapping is not NULL
        if mapping != 0:
            # Check PAGE_MAPPING_ANON flag (bit 0)
            PAGE_MAPPING_ANON = 1
            if mapping & PAGE_MAPPING_ANON:
                return ("anon", 1)
            else:
                return ("file", 1)
        else:
            # No mapping - categorize as other
            return ("other", 1)

    except FaultError:
        return ("error", 1)
    except Exception:
        return ("error", 1)

def main():
    print(DESC)
    print("Analyzing pages... This may take a while.\n")

    # Statistics
    stats = defaultdict(int)
    error_count = 0
    total_pages = 0
    skipped_tail_pages = 0

    # Page size information
    try:
        PAGE_SIZE = prog["PAGE_SIZE"].value_()
        PAGE_SHIFT = prog["PAGE_SHIFT"].value_()
        print(f"System page size: {PAGE_SIZE} bytes (2^{PAGE_SHIFT})")
        print(f"Total memory zones: checking all valid pages\n")
    except Exception as e:
        print(f"Warning: Could not get page size info: {e}\n")
        PAGE_SIZE = 4096

    # Traverse all pages
    try:
        for page in for_each_page():
            total_pages += 1
            category, page_count = categorize_page(page)

            # Skip tail pages (returns None)
            if category is None:
                skipped_tail_pages += 1
                continue

            if category == "error":
                error_count += 1
            else:
                stats[category] += page_count

            # Progress indicator
            if total_pages % 100000 == 0:
                print(f"Processed {total_pages} pages...", end="\r")

    except KeyboardInterrupt:
        print(f"\n\nInterrupted at {total_pages} pages")
    except Exception as e:
        print(f"\n\nError during traversal: {e}")
        import traceback
        traceback.print_exc()

    # Print statistics
    print("\n" + "=" * 90)
    print("PAGE STATISTICS SUMMARY")
    print("=" * 90)
    print(f"\nTotal pages processed: {total_pages:,}")
    print(f"Total memory: {format_memory_size(total_pages, PAGE_SIZE).strip()}")
    print(f"Tail pages skipped: {skipped_tail_pages:,} (counted via head pages)")

    if error_count > 0:
        print(f"Pages with errors: {error_count:,}")

    print(f"\n{'Category':<40} {'Pages':>12} {'Memory Size':>15} {'Percentage':>12}")
    print("-" * 90)

    # Sort by count (descending)
    sorted_stats = sorted(stats.items(), key=lambda x: x[1], reverse=True)

    for category, count in sorted_stats:
        percentage = (count / total_pages * 100) if total_pages > 0 else 0
        memory_size = format_memory_size(count, PAGE_SIZE)
        print(f"{category:<40} {count:>12,} {memory_size} {percentage:>11.2f}%")

    # Add total summary at the end
    print("-" * 90)
    print(f"{'TOTAL':<40} {total_pages:>12,} {format_memory_size(total_pages, PAGE_SIZE)} {100.0:>11.2f}%")

    print("\n" + "=" * 90)
    print("Analysis complete.")
    print("=" * 90)


if __name__ == "__main__":
    main()
