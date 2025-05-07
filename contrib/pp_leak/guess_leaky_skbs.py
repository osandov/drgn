#!/usr/bin/env drgn

# Copyright (c) 2025 NVIDIA Corporation & Affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

help="""
Takes in a virtual address from a page or a `struct page *` and tries to find
a SKB that references this page either in the linear part or in skb_frag_info.

Endianess is handled by the script.

This only works if the kernel was built with CONFIG_PROC_KCORE=y. The
script is based on search_kernel_memory.py
"""

import argparse
import math
import sys
from drgn import (
        Object,
        PlatformFlags,
        FaultError,
        Object,
        offsetof,
        sizeof,
)
from drgn.helpers.common.memory import (
        identify_address,
)
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.mm import (
        for_each_vmap_area,
        virt_to_page,
        page_to_virt,
)
from drgn.helpers.linux.net import (
    skb_shinfo,
)


byteorder = "little" if prog.platform.flags & PlatformFlags.IS_LITTLE_ENDIAN else "big"
PAGE_SIZE = prog["PAGE_SIZE"].value_()
PAGE_SHIFT = prog["PAGE_SHIFT"].value_()


def get_opts():
    parser = argparse.ArgumentParser(description=help)
    parser.add_argument(
        "bytes",
        nargs="?",
        help="hexadecimal bytes to read. By default they represent a "
             "virtual address.",
    )
    parser.add_argument(
        "--as-frag", default=False, action="store_true",
        help="Interpret address as being skb_shinfo(skb).frag.netmem.")
    parser.add_argument(
        "--virt", default=False, action="store_true",
        help="Given address is a virtual addresss in a page.")
    parser.add_argument(
        "--show-skb", default=False, action="store_true",
        help="Show matched SKB.")
    parser.add_argument(
        "--verbose", default=False, action="store_true",
        help="Print partial matches.")

    return parser.parse_args()


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

    for kc in list_for_each_entry(
        "struct kcore_list", prog["kclist_head"].address_of_(), "list"
    ):
        if kc.type != KCORE_RAM:
            continue
        start = kc.addr.value_()
        end = start + kc.size.value_()
        for addr in range(start, end, CHUNK_SIZE):
            buf = prog.read(addr, min(CHUNK_SIZE, end - addr))
            i = 0
            while i < len(buf):
                i = buf.find(needle, i)
                if i < 0:
                    break

                yield addr + i
                i += 8


def search_page_reference(page):
    """
    Search kernel memory for references to the given page contents
    (virtual addresses within the PAGE_SIZE range).

    Does page conversion.
    """

    val = page_to_virt(page).value_()

    skip_bytes = math.ceil(PAGE_SHIFT / 8)
    ptr_size = 8

    val_endian = val.to_bytes(ptr_size, byteorder)
    if byteorder == "little":
        big_needle = val_endian[skip_bytes:ptr_size - skip_bytes]
    else:
        big_needle = val_endian[0:ptr_size - skip_bytes]

    small_needle = val >> PAGE_SHIFT

    # Search for first 6 bytes:
    for addr in search_memory(prog, big_needle):

        if byteorder == "little":
            # Adjust address to skipped bytes:
            addr = addr - skip_bytes

        mem_bytes = prog.read(addr, ptr_size)
        mem_val = int.from_bytes(mem_bytes, byteorder)

        if mem_val >> PAGE_SHIFT == small_needle:
            yield (addr, mem_val)


def search_raw(value):
    """
    Search kernel memory for value respectinv the value pointer.
    """

    ptr_size = 8
    needle = value.to_bytes(ptr_size, byteorder)

    for addr in search_memory(prog, needle):
        mem_bytes = prog.read(addr, ptr_size)
        mem_val = int.from_bytes(mem_bytes, byteorder)
        yield (addr, mem_val)


def guess_skb_is_legit(skb) -> bool:
    """
    Guess if there is a legit SKB at the given address.
    """

    # 2 consecutive pointers that point to the same page indicate that
    # this could be skb.head and skb.data.
    if virt_to_page(skb.head).value_() != virt_to_page(skb.data).value_():
        return False

    if skb.end.value_() > PAGE_SIZE or skb.tail.value_() > PAGE_SIZE:
        return False

    # Many checks could be added here ...
    return True


def search_skb_with_page_as_linear(page, verbose=False):
    """
    Search SKB for given page.
    """
    for addr, val in search_page_reference(page):

        if verbose:
            print(f"Found reference at {hex(addr)}: value {hex(val)}. {identify_address(prog, addr)}")

        skb_addr = addr - offsetof(prog.type("struct sk_buff"), "head")
        skb = Object(prog, "struct sk_buff", address=skb_addr)
        if guess_skb_is_legit(skb):
            yield skb


def search_skb_with_page_as_shinfo_frag(page_ptr, verbose):

    for addr, _ in search_raw(page_ptr):

        if verbose:
            print(f"Found raw value at addr {hex(addr)}. {identify_address(prog, addr)}")

        page = virt_to_page(addr)
        for skb in search_skb_with_page_as_linear(page):

            # For shinfo, a match happens for
            shinfo = skb_shinfo(skb)
            shinfo_start = shinfo.value_()
            shinfo_end = shinfo.value_() + sizeof(prog.type("struct skb_shared_info"))
            if shinfo_start <= addr and addr < shinfo_end:
                yield skb


opts = get_opts()

# Drop hex prefix.
if opts.bytes.startswith("0x"):
    opts.bytes = opts.bytes[2:]

value = int.from_bytes(bytes.fromhex(opts.bytes))

if opts.as_frag:
    for skb in search_skb_with_page_as_shinfo_frag(value, opts.verbose):
        print(f"Possible skb match at address {hex(skb.address_of_())}")
        if opts.show_skb:
            print(skb)

else:
    if opts.virt:
        try:
            page = virt_to_page(value)
        except FaultError:
            print("Given address doesn't seem to be a virtual address or it can't be converted to a page.")
            sys.exit(1)
    else:
        page = Object(prog, "struct page", address=value).address_of_()

    for skb in search_skb_with_page_as_linear(page, opts.verbose):
        print(f"Possible skb match at address {hex(skb.address_of_())}")
        if opts.show_skb:
            print(skb)

