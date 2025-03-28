#!/usr/bin/env drgn

# Copyright (c) 2025 NVIDIA Corporation & Affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

help="""
Detect leaked page_pool pages by scanning through all the pages.

Has options for peeking into the page memory and showing the struct page.
"""


import argparse
from drgn import FaultError
from drgn.helpers.common.memory import (
        print_annotated_memory
)
from drgn.helpers.linux.mm import (
    for_each_page,
    page_to_virt
)
from drgn.helpers.linux.net import is_pp_page


def get_opts():
    parser = argparse.ArgumentParser(description=help)
    parser.add_argument(
        "-l", "--peek", default=100, type=int, help="Peek into page given amount of bytes.")
    parser.add_argument(
        "-s", "--show", default=False, action="store_true", help="Show page struct.")

    args = parser.parse_args()
    return args


opt = get_opts()

for page in for_each_page():
        try:
            if is_pp_page(page) and page.pp.user.detach_time > 0:
                if opt.show:
                    print(page)
                else:
                    print(f"Leaked page: {hex(page)}")
                if opt.peek > 0:
                    print("Page content: ")
                    print_annotated_memory(page_to_virt(page), opt.peek)
        except FaultError:
            continue

