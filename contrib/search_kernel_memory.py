#!/usr/bin/env drgn
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Search kernel memory for a byte string. This only works if the kernel was built
with CONFIG_PROC_KCORE=y.
"""

import argparse
import sys

from drgn.helpers.common.memory import identify_address
from drgn.helpers.linux.list import list_for_each_entry


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
                identity = identify_address(prog, addr + i)
                if identity is None:
                    print(hex(addr + i))
                else:
                    print(hex(addr + i), identity)
                i += 1


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
