#!/usr/bin/env drgn

# Copyright (c) 2025 NVIDIA Corporation & Affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

help="""
Detect leaked page_pool pages by scanning TCP sockets for SKBs from the
receive queue that are using such leaked pages.

It is a good idea to filter out by interface to reduce the run time
of the script.
"""


import sys
import argparse

from drgn import (
    Object,
    FaultError,
)
from drgn.helpers.linux import (
    hlist_nulls_empty,
    sk_nulls_for_each,
)
from drgn.helpers.linux.mm import virt_to_page
from drgn.helpers.linux.net import (
    netdev_get_by_name,
    skb_shinfo,
    is_pp_page
)


def get_opts():
    parser = argparse.ArgumentParser(description=help)
    parser.add_argument(
        "-i", "--interface", default=None, type=str, help="Filter by interface name.")

    args = parser.parse_args()
    return args


opts = get_opts()
ifindex = -1
if opts.interface:
    netdev = netdev_get_by_name(opts.interface)
    if netdev.value_() == 0:
        print(f"Netdev interface '{opts.interface}' not found.")
        sys.exit(1)

    ifindex = netdev.ifindex

tcp_hashinfo = prog.object("tcp_hashinfo")

for i in range(tcp_hashinfo.ehash_mask + 1):
    head = tcp_hashinfo.ehash[i].chain
    if hlist_nulls_empty(head):
        continue

    for sk in sk_nulls_for_each(head):

        # Filter by interface:
        if ifindex > 0 and sk.sk_rx_dst_ifindex.value_() != ifindex:
            continue

        first_skb = sk.sk_receive_queue.next
        skb = first_skb
        while skb != None:

            try:
                # Check linear part of skb:
                page = virt_to_page(skb.data)
                if is_pp_page(page) and page.pp.user.detach_time:
                    print(f"Found leaked page {hex(page)} in linear part of  skb: {hex(skb.address_of_())}. sk: {hex(sk)}")

                # Check fragments:
                shinfo = skb_shinfo(skb)
                for i in range(0, shinfo.nr_frags):
                    frag = shinfo.frags[i]
                    page = Object(prog, "struct page", address=frag.netmem)
                    if is_pp_page(page) and page.pp.user.detach_time:
                        print(f"Found leaked page {hex(page.address_of_())} in skb frag {i} of skb: {hex(skb.address_of_())}")

            except FaultError:
                continue

            # Move to next skb:
            skb = skb.next
            if skb == first_skb:
                break
