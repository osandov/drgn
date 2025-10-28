#!/usr/bin/env drgn
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Search kernel memory for a byte string. This only works if the kernel was built
with CONFIG_PROC_KCORE=y.
"""

import argparse
import sys

from drgn import FaultError, Object
from drgn.helpers.common.memory import identify_address
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.mm import for_each_vmap_area, virt_to_page


def virt_to_vmap_address(prog, addr):
    page = virt_to_page(addr)
    for va in for_each_vmap_area(prog):
        vm = va.vm.read_()
        if vm:
            for i, va_page in enumerate(
                Object(
                    prog, prog.array_type(page.type_, vm.nr_pages), address=vm.pages
                ).read_()
            ):
                if va_page == page:
                    return (
                        va.va_start.value_()
                        + (i << prog["PAGE_SHIFT"])
                        + (addr & (prog["PAGE_SIZE"].value_() - 1))
                    )
    return None


def search_memory(prog, needle):
    KCORE_RAM = prog["KCORE_RAM"]
    CHUNK_SIZE = 1024 * 1024
    PAGE_SIZE = prog["PAGE_SIZE"].value_()
    for kc in list_for_each_entry(
        "struct kcore_list", prog["kclist_head"].address_of_(), "list"
    ):
        if kc.type != KCORE_RAM:
            continue
        addr = kc.addr.value_()
        end = addr + kc.size.value_()
        while addr < end:
            try:
                buf = prog.read(addr, min(CHUNK_SIZE, end - addr))
            except FaultError:
                # We start with a large chunk size to reduce the overhead of
                # reading memory. However, if we're reading from a core dump,
                # reading with a large chunk size may fault on excluded pages.
                if CHUNK_SIZE > PAGE_SIZE:
                    # We faulted with a large chunk size. Fall back to
                    # page-by-page and retry.
                    CHUNK_SIZE = PAGE_SIZE
                else:
                    # We're already reading page-by-page. Skip this page.
                    addr += CHUNK_SIZE
                continue

            i = 0
            while i < len(buf):
                i = buf.find(needle, i)
                if i < 0:
                    break

                vmap_address = virt_to_vmap_address(prog, addr + i)
                if vmap_address is not None:
                    identity = identify_address(prog, vmap_address)
                else:
                    identity = identify_address(prog, addr + i)

                if identity is None:
                    print(hex(addr + i))
                else:
                    print(hex(addr + i), identity)
                i += 1

            addr += CHUNK_SIZE


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Search kernel memory for a byte string"
    )
    parser.add_argument(
        "bytes",
        nargs="?",
        help="hexadecimal bytes to read; if omitted, read byte string from stdin",
    )
    args = parser.parse_args()
    if args.bytes is None:
        needle = sys.stdin.buffer.read()
    else:
        needle = bytes.fromhex(args.bytes)
    search_memory(prog, needle)
