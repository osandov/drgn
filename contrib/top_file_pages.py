#!/usr/bin/env drgn
# Copyright (C) 2026 Kylin Software, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later
# Iterate all pages, group by inode, output top N
import argparse
import os
from collections import Counter
from typing import Any

from drgn import FaultError, Object
from drgn.helpers.linux.fs import inode_path
from drgn.helpers.linux.rbtree import rbtree_inorder_for_each_entry
from drgn.helpers.linux.mm import (
    PageCompound,
    PageSlab,
    PageTail,
    compound_nr,
    for_each_page,
)

# Mapping low tag bits (anon, KSM, and on pre-v6.17 kernels movable
# pages): a tagged mapping is never a struct address_space. This equals
# PAGE_MAPPING_FLAGS/FOLIO_MAPPING_FLAGS (0x3) on every kernel version;
# real address_space pointers always have the low bits clear.
# See include/linux/page-flags.h.
PAGE_MAPPING_FLAGS = 0x3


def _sb_id(sb: Any) -> str:
    try:
        return os.fsdecode(sb.s_id.string_())
    except (FaultError, AttributeError, UnicodeDecodeError):
        try:
            return str(sb.s_id.value_())
        except (FaultError, AttributeError):
            return hex(sb.value_())


def _get_inode_users(inode: Object) -> "list[tuple[int, str]]":
    """Return deduplicated list of (pid, comm) for processes mapping this inode."""
    users: dict[int, str] = {}
    try:
        mapping = inode.i_mapping
        for vma in rbtree_inorder_for_each_entry(
            "struct vm_area_struct",
            mapping.i_mmap.rb_root,
            "shared.rb",
        ):
            try:
                task = vma.vm_mm.owner
                if not task.value_():
                    continue
                pid = int(task.pid.value_())
                comm = task.comm.string_().decode(errors="replace")
                users.setdefault(pid, comm)
            except (FaultError, AttributeError):
                pass
    except (FaultError, AttributeError):
        pass
    return [(pid, users[pid]) for pid in sorted(users)]


def _collect_page_owners() -> "tuple[Counter, dict[tuple, Object]]":
    """Walk all pages and group file-backed pages by owner.

    Returns (counts, sample_obj): counts maps each ("inode", inode_addr)
    or ("mapping", mapping_addr) key to its page count, and sample_obj
    holds one inode Object per "inode" key for display-field resolution.
    """
    counts: Counter = Counter()
    sample_obj: dict[tuple, Object] = {}

    for page in for_each_page():
        # Skip compound tail pages — their mapping is meaningless
        if PageTail(page):
            continue

        try:
            # One read of the whole struct page; the field checks below
            # are buffer slices instead of separate memory round-trips
            pg = page[0].read_()
        except FaultError:
            continue

        # Slab pages: mapping holds SLUB internal data, not file-backed
        if PageSlab(pg):
            continue

        mapping_val = pg.mapping.value_()
        if not mapping_val or (mapping_val & PAGE_MAPPING_FLAGS):
            continue

        # Count compound head by compound_nr, base page as 1
        nr = compound_nr(page).value_() if PageCompound(pg) else 1

        try:
            inode = pg.mapping.host
            inode_addr = int(inode.value_())
        except (AttributeError, FaultError):
            # mapping.host unreadable — group by mapping address
            counts[("mapping", mapping_val)] += nr
            continue

        # inode_addr uniquely identifies a live inode; display fields
        # (i_ino, i_sb) are resolved per top-N entry at print time
        key = ("inode", inode_addr)
        counts[key] += nr
        sample_obj.setdefault(key, inode)

    return counts, sample_obj


def _print_top_owners(
    counts: Counter, sample_obj: "dict[tuple, Object]", limit: int
) -> None:
    """Print the top-N page owners with paths and mapping processes."""
    print(f"Top {limit} page owners:")
    for i, (key, cnt) in enumerate(counts.most_common(limit), 1):
        if key[0] == "inode":
            inode_obj = sample_obj[key]
            inode_addr = key[1]

            path = ""
            try:
                p = inode_path(inode_obj)
                if p is not None:
                    path = os.fsdecode(p)
            except (AttributeError, FaultError):
                pass

            try:
                ino = int(inode_obj.i_ino.value_())
            except (AttributeError, FaultError):
                ino = None

            try:
                sbid = _sb_id(inode_obj.i_sb)
            except (AttributeError, FaultError):
                sbid = "<sb?>"

            if path:
                path_str = path
            elif ino is not None:
                path_str = f"sb={sbid} ino={ino}"
            else:
                path_str = f"sb={sbid} inode={hex(inode_addr)}"
            entry_prefix = f"{i:2}. {cnt:8} pages  "
            print(f"{entry_prefix}{path_str}  inode_addr={hex(inode_addr)}")

            # Sub-lines align with the path column of the entry above
            users = _get_inode_users(inode_obj)
            indent = " " * len(entry_prefix)
            if users:
                user_strs = [f"{pid}({comm})" for pid, comm in users]
                print(f"{indent}Used by ({len(users)}): {', '.join(user_strs)}")
            else:
                print(f"{indent}Used by: (none, reclaimable)")
        else:
            _, addr = key
            print(f"{i:2}. {cnt:8} pages  mapping@{hex(addr)}")


def top_file_pages(limit: int = 10) -> None:
    counts, sample_obj = _collect_page_owners()
    _print_top_owners(counts, sample_obj, limit)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Group pages by inode, output top N",
    )
    parser.add_argument(
        "N",
        nargs="?",
        type=int,
        default=10,
        help="number of entries to show (default 10)",
    )
    top_file_pages(parser.parse_args().N)
