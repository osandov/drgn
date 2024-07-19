#!/usr/bin/env drgn
# Copyright (c) Canonical Ltd.
# SPDX-License-Identifier: LGPL-2.1-or-later

""" Script to dump slabinfo status using drgn"""

from typing import Iterator, Optional

from drgn import Object
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.list import list_for_each_entry, list_for_each_entry_reverse
from drgn.helpers.linux.slab import for_each_slab_cache

MAX_PARTIAL_TO_SCAN = 10000
OO_SHIFT = 16
OO_MASK = (1 << OO_SHIFT) - 1


def for_each_kmem_cache_node(slab_cache: Object) -> Iterator[Object]:
    """
    Iterate over all kmem_cache_node of specific slab cache.

    :return: Iterator of ``struct kmem_cache_node *`` objects.
    """
    for nid in range(0, prog["nr_node_ids"].value_()):
        yield slab_cache.node[nid]


def count_partial_free_approx(kmem_cache_node: Object) -> Optional[Object]:
    x = Object(prog, "unsigned long", 0)
    n = kmem_cache_node
    if n.nr_partial <= MAX_PARTIAL_TO_SCAN:
        for slab in list_for_each_entry(
            "struct slab", n.partial.address_of_(), "slab_list"
        ):
            x += slab.objects - slab.inuse
    else:
        scanned = 0
        for slab in list_for_each_entry(
            "struct slab", n.partial.address_of_(), "slab_list"
        ):
            x += slab.objects - slab.inuse
            scanned += 1
            if scanned == MAX_PARTIAL_TO_SCAN / 2:
                break
        for slab in list_for_each_entry_reverse(
            "struct slab", n.partial.address_of_(), "slab_list"
        ):
            x += slab.objects - slab.inuse
            scanned += 1
            if scanned == MAX_PARTIAL_TO_SCAN / 2:
                break
        x = x * n.nr_partial / scanned
        x = min(x, n.total_objects)
    return x


def oo_objects(kmem_cache_order_objects: Object) -> Optional[Object]:
    return kmem_cache_order_objects.x & OO_MASK


def oo_order(kmem_cache_order_objects: Object) -> Optional[Object]:
    return kmem_cache_order_objects.x >> OO_SHIFT


print(
    f"{'struct kmem_cache *':^20} | {'name':^20} | {'active_objs':^12} | {'num_objs':^12} | {'objsize':^8} | {'objperslab':^11} | {'pageperslab':^13}"
)
print(
    f"{'':-^20} | {'':-^20} | {'':-^12} | {'':-^12} | {'':-^8} | {'':-^11} | {'':-^13}"
)

for s in for_each_slab_cache(prog):
    nr_slabs = 0
    nr_objs = 0
    nr_free = 0
    for node in for_each_kmem_cache_node(s):
        nr_slabs += node.nr_slabs.counter.value_()
        nr_objs += node.total_objects.counter.value_()
        nr_free += count_partial_free_approx(node).value_()
    active_objs = nr_objs - nr_free
    num_objs = nr_objs
    active_slab = nr_slabs
    num_slabs = nr_slabs
    objects_per_slab = oo_objects(s.oo).value_()
    cache_order = oo_order(s.oo).value_()
    name = escape_ascii_string(s.name.string_(), escape_backslash=True)

    print(
        f"0x{s.value_():<18x} | {name:20.19s} | {active_objs:12} | {num_objs:12} | {s.size.value_():8} | {objects_per_slab:11} | {1<<cache_order:13}"
    )
