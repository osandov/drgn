# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
BPF
---

The ``drgn.helpers.linux.bpf`` module provides helpers for working with BPF
interface in :linux:`include/linux/bpf.h`, :linux:`include/linux/bpf-cgroup.h`,
etc.
"""


import itertools
from typing import Iterator

from drgn import IntegerLike, Object, Program, cast, offsetof, sizeof
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.idr import idr_find, idr_for_each
from drgn.helpers.linux.list import hlist_for_each_entry, list_for_each_entry

__all__ = (
    "bpf_btf_for_each",
    "bpf_link_for_each",
    "bpf_map_for_each",
    "bpf_prog_for_each",
    "cgroup_bpf_prog_for_each",
    "cgroup_bpf_prog_for_each_effective",
    "bpf_prog_used_maps",
    "bpf_prog_by_id",
    "bpf_map_by_id",
    "bpf_map_memory_usage",
)


@takes_program_or_default
def bpf_btf_for_each(prog: Program) -> Iterator[Object]:
    """
    Iterate over all BTF objects.

    This is only supported since Linux v4.18.

    :return: Iterator of ``struct btf *`` objects.
    """
    type = prog.type("struct btf *")
    # BTF was introduced in Linux kernel commit 69b693f0aefa ("bpf: btf:
    # Introduce BPF Type Format (BTF)") (in v4.18). btf_idr was added in a
    # later commit in v4.18, 78958fca7ead ("bpf: btf: Introduce BTF ID").
    for nr, entry in idr_for_each(prog["btf_idr"]):
        yield cast(type, entry)


@takes_program_or_default
def bpf_link_for_each(prog: Program) -> Iterator[Object]:
    """
    Iterate over all BPF links.

    This is only supported since Linux v5.8.

    :return: Iterator of ``struct bpf_link *`` objects.
    """
    type = prog.type("struct bpf_link *")
    # link_idr didn't exist before Linux kernel commit a3b80e107894 ("bpf:
    # Allocate ID for bpf_link") (in v5.8). struct bpf_link didn't exist at all
    # before Linux kernel commit 70ed506c3bbc ("bpf: Introduce pinnable
    # bpf_link abstraction") (in v5.7), and we don't support Linux v5.7
    # anyways.
    for nr, entry in idr_for_each(prog["link_idr"]):
        yield cast(type, entry)


@takes_program_or_default
def bpf_map_for_each(prog: Program) -> Iterator[Object]:
    """
    Iterate over all BPF maps.

    This is only supported since Linux v4.13.

    :return: Iterator of ``struct bpf_map *`` objects.
    """
    type = prog.type("struct bpf_map *")
    # map_idr didn't exist before Linux kernel commit f3f1c054c288 ("bpf:
    # Introduce bpf_map ID") (in v4.13).
    for nr, entry in idr_for_each(prog["map_idr"]):
        yield cast(type, entry)


@takes_program_or_default
def bpf_prog_for_each(prog: Program) -> Iterator[Object]:
    """
    Iterate over all BPF programs.

    This is only supported since Linux v4.13.

    :return: Iterator of ``struct bpf_prog *`` objects.
    """
    type = prog.type("struct bpf_prog *")
    # prog_idr didn't exist before Linux kernel commit dc4bb0e23561 ("bpf:
    # Introduce bpf_prog ID") (in v4.13).
    for nr, entry in idr_for_each(prog["prog_idr"]):
        yield cast(type, entry)


def cgroup_bpf_prog_for_each(
    cgrp: Object, bpf_attach_type: IntegerLike
) -> Iterator[Object]:
    """
    Iterate over all cgroup BPF programs of the given attach type attached to
    the given cgroup.

    :param cgrp: ``struct cgroup *``
    :param bpf_attach_type: ``enum cgroup_bpf_attach_type`` (``enum
        bpf_attach_type`` before Linux 5.15)
    :return: Iterator of ``struct bpf_prog *`` objects.
    """
    # Before Linux kernel commit 3007098494be ("cgroup: add support for eBPF
    # programs") (in v4.10), struct cgroup::bpf didn't exist because cgroup BPF
    # programs didn't exist.
    try:
        cgrp_bpf = cgrp.bpf
    except AttributeError:
        return
    # Since Linux kernel commit 324bda9e6c5a ("bpf: multi program support for
    # cgroup+bpf") (in v4.15), the attached programs are stored in an array of
    # lists, struct cgroup_bpf::progs. Before that, only one program of each
    # attach type could be attached to a cgroup, so the attached programs are
    # stored in an array of struct bpf_prog *, struct cgroup_bpf::prog.
    try:
        progs = cgrp_bpf.progs
    except AttributeError:
        # If the kernel was not configured with CONFIG_CGROUP_BPF, then struct
        # cgroup_bpf is an empty structure.
        try:
            prog = cgrp_bpf.prog[bpf_attach_type]
        except AttributeError:
            return
        if prog:
            yield prog
    else:
        # Since Linux kernel commit 00442143a2ab ("bpf: convert
        # cgroup_bpf.progs to hlist") (in v6.0-rc1), the list of programs is an
        # hlist_head. Before that, it was a list_head.
        list = progs[bpf_attach_type].address_of_()
        if hasattr(list, "first"):
            iterator = hlist_for_each_entry
        else:
            iterator = list_for_each_entry
        for pl in iterator("struct bpf_prog_list", list, "node"):
            yield pl.prog


def cgroup_bpf_prog_for_each_effective(
    cgrp: Object, bpf_attach_type: IntegerLike
) -> Iterator[Object]:
    """
    Iterate over all effective cgroup BPF programs of the given attach type for
    the given cgroup.

    :param cgrp: ``struct cgroup *``
    :param bpf_attach_type: ``enum bpf_attach_type``
    :return: Iterator of ``struct bpf_prog *`` objects.
    """
    # Before Linux kernel commit 3007098494be ("cgroup: add support for eBPF
    # programs") (in v4.10), struct cgroup::bpf didn't exist because cgroup BPF
    # programs didn't exist. Since then, if the kernel was not configured with
    # CONFIG_CGROUP_BPF, then struct cgroup_bpf is an empty structure.
    try:
        effective = cgrp.bpf.effective[bpf_attach_type]
    except AttributeError:
        return
    # Since Linux kernel commit 324bda9e6c5a ("bpf: multi program support for
    # cgroup+bpf") (in v4.15), struct cgroup_bpf::effective is an array of
    # struct bpf_prog_array. Before that, only one program of each attach type
    # could be effective for a cgroup, so struct cgroup_bpf::effective is an
    # array of struct bpf_prog *.
    try:
        effective_items = effective.items
    except AttributeError:
        if effective:
            yield effective
    else:
        for i in itertools.count():
            prog = effective_items[i].prog.read_()
            if not prog:
                break
            yield prog


def bpf_prog_used_maps(bpf_prog: Object) -> Iterator[Object]:
    """
    Yield maps used by a BPF program.

    :param bpf_prog: ``struct bpf_prog *``
    :return: Iterator of ``struct bpf_map *`` objects.
    """
    aux = bpf_prog.aux.read_()
    return iter(aux.used_maps[: aux.used_map_cnt])


@takes_program_or_default
def bpf_prog_by_id(prog: Program, id: IntegerLike) -> Object:
    """
    Get a BPF program by ID.

    This is only supported since Linux v4.13.

    :param prog: Program object
    :param id: BPF program ID
    :return: ``struct bpf_prog *`` object, or a null pointer if not found
    """
    return cast("struct bpf_prog *", idr_find(prog["prog_idr"].address_of_(), id))


@takes_program_or_default
def bpf_map_by_id(prog: Program, id: IntegerLike) -> Object:
    """
    Get a BPF map by ID.

    This is only supported since Linux v4.13.

    :param prog: Program object
    :param id: BPF map ID
    :return: ``struct bpf_map *`` object, or a null pointer if not found
    """
    return cast("struct bpf_map *", idr_find(prog["map_idr"].address_of_(), id))


def bpf_map_memory_usage(bpf_map: Object) -> int:
    """
    Get the memory usage of a BPF map in bytes.

    :param bpf_map: ``struct bpf_map *`` object
    :return: Memory usage in bytes
    """
    prog = bpf_map.prog_
    PAGE_SIZE = prog["PAGE_SIZE"].value_()

    # Linux 5.3 to 5.10: bpf_map.memory.pages
    # Commit 3539b96e041c ("bpf: group memory related fields in struct
    # bpf_map_memory") (in v5.3) moved the pages field into struct bpf_map_memory.
    # This was removed in v5.11 by commit 80ee81e0403c ("bpf: Eliminate
    # rlimit-based memory accounting infra for bpf maps").
    try:
        memory_pages = bpf_map.memory.pages.value_()
        return memory_pages * PAGE_SIZE
    except AttributeError:
        pass

    # Linux 4.10 to 5.2: bpf_map.pages
    # Commit aaac3ba95e4c ("bpf: charge user for creation of BPF maps and
    # programs") (in v4.10) added the pages field directly to struct bpf_map.
    # This was moved into struct bpf_map_memory in v5.3.
    try:
        pages = bpf_map.pages.value_()
        return pages * PAGE_SIZE
    except AttributeError:
        pass

    # Special case for RINGBUF maps (Linux 5.8+)
    # Commit 457f44363a88 ("bpf: Implement BPF ring buffer and verifier support
    # for it") (in v5.8) added BPF_MAP_TYPE_RINGBUF.
    try:
        map_type_val = bpf_map.map_type.value_()
        BPF_MAP_TYPE_RINGBUF = 0x1B
        if map_type_val == BPF_MAP_TYPE_RINGBUF:
            memlock = _ringbuf_map_mem_usage(prog, bpf_map, PAGE_SIZE)
            if memlock and memlock > 0:
                return memlock
    except Exception:
        pass

    # Fallback: calculate based on key_size, value_size, max_entries.
    # Formula: round_up(max_entries * round_up(key_size + value_size, 8), PAGE_SIZE)
    try:
        key_size = bpf_map.key_size.value_()
        value_size = bpf_map.value_size.value_()
        max_entries = bpf_map.max_entries.value_()
        calculated_size = _bpf_map_memory_size(
            bpf_map, key_size, value_size, max_entries, PAGE_SIZE
        )
        if calculated_size > 0:
            return calculated_size
    except Exception:
        pass

    raise ValueError("could not determine memory usage for BPF map")


def _ringbuf_map_mem_usage(prog: Program, bpf_map: Object, page_size: int) -> int:
    # Calculate memory usage for a BPF ringbuf map.
    # Replicates the logic from kernel/bpf/ringbuf.c:ringbuf_map_mem_usage().
    # Returns 0 on error.

    try:
        bpf_ringbuf_map_type = prog.type("struct bpf_ringbuf_map")
        if bpf_ringbuf_map_type.size is None:
            return 0
        usage = bpf_ringbuf_map_type.size

        map_offset = offsetof(bpf_ringbuf_map_type, "map")

        bpf_ringbuf_map_addr = bpf_map.value_() - map_offset

        rb_offset = offsetof(bpf_ringbuf_map_type, "rb")

        rb_addr = bpf_ringbuf_map_addr + rb_offset
        rb_ptr = prog.read_u64(rb_addr)

        bpf_ringbuf_type = prog.type("struct bpf_ringbuf")
        nr_pages_offset = offsetof(bpf_ringbuf_type, "nr_pages")

        nr_pages = prog.read_u64(rb_ptr + nr_pages_offset)

        page_shift = page_size.bit_length() - 1
        usage += nr_pages << page_shift

        consumer_pos_offset = offsetof(bpf_ringbuf_type, "consumer_pos")
        nr_meta_pages = (consumer_pos_offset >> page_shift) + 2

        max_entries = bpf_map.max_entries.value_()
        nr_data_pages = max_entries >> page_shift

        ptr_size = sizeof(prog.type("void *"))
        usage += (nr_meta_pages + 2 * nr_data_pages) * ptr_size

        return usage

    except Exception:
        return 0


def _bpf_map_memory_size(
    bpf_map: Object, key_size: int, value_size: int, max_entries: int, page_size: int
) -> int:
    # Estimate memory usage of a BPF map from its key/value sizes and entry
    # count.

    from drgn.helpers.linux.cpumask import num_possible_cpus

    def is_percpu_map(map_type: int) -> bool:
        # See include/uapi/linux/bpf.h
        BPF_MAP_TYPE_PERCPU_HASH = 5
        BPF_MAP_TYPE_PERCPU_ARRAY = 6
        BPF_MAP_TYPE_LRU_PERCPU_HASH = 10
        BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21
        return map_type in (
            BPF_MAP_TYPE_PERCPU_HASH,
            BPF_MAP_TYPE_PERCPU_ARRAY,
            BPF_MAP_TYPE_LRU_PERCPU_HASH,
            BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
        )

    def is_fd_map(map_type: int) -> bool:
        # See include/uapi/linux/bpf.h
        BPF_MAP_TYPE_PROG_ARRAY = 3
        BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4
        BPF_MAP_TYPE_CGROUP_ARRAY = 8
        BPF_MAP_TYPE_ARRAY_OF_MAPS = 12
        BPF_MAP_TYPE_HASH_OF_MAPS = 13
        return map_type in (
            BPF_MAP_TYPE_PROG_ARRAY,
            BPF_MAP_TYPE_PERF_EVENT_ARRAY,
            BPF_MAP_TYPE_CGROUP_ARRAY,
            BPF_MAP_TYPE_ARRAY_OF_MAPS,
            BPF_MAP_TYPE_HASH_OF_MAPS,
        )

    map_type_val = bpf_map.map_type.value_()

    if is_percpu_map(map_type_val):
        try:
            cpus_possible = num_possible_cpus(bpf_map.prog_)
            valsize = ((value_size + 7) // 8) * 8 * cpus_possible
        except Exception:
            return 0
    elif is_fd_map(map_type_val):
        valsize = 4
    else:
        valsize = value_size

    size = ((key_size + valsize + 7) // 8) * 8

    return ((max_entries * size + page_size - 1) // page_size) * page_size
