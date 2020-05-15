# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

"""
BPF
---

The ``drgn.helpers.linux.bpf`` module provides helpers for working with BPF
interface in :linux:`include/linux/bpf.h`, :linux:`include/linux/bpf-cgroup.h`,
etc.
"""


import itertools

from drgn import cast
from drgn.helpers.linux.idr import idr_for_each
from drgn.helpers.linux.list import list_for_each_entry


__all__ = (
    "bpf_map_for_each",
    "bpf_prog_for_each",
    "cgroup_bpf_prog_for_each",
    "cgroup_bpf_prog_for_each_effective",
)


def bpf_map_for_each(prog):
    """
    .. c:function:: bpf_map_for_each(prog)

    Iterate over all bpf maps.

    :return: Iterator of ``struct bpf_map *`` objects.
    """
    for nr, entry in idr_for_each(prog["map_idr"]):
        yield cast("struct bpf_map *", entry)


def bpf_prog_for_each(prog):
    """
    .. c:function:: bpf_prog_for_each(prog)

    Iterate over all bpf programs.

    :return: Iterator of ``struct bpf_prog *`` objects.
    """
    for nr, entry in idr_for_each(prog["prog_idr"]):
        yield cast("struct bpf_prog *", entry)


def cgroup_bpf_prog_for_each(cgrp, bpf_attach_type):
    """
    .. c:function:: cgroup_bpf_prog_for_each(struct cgroup *cgrp, int bpf_attach_type)

    Iterate over all cgroup bpf programs of the given attach type attached to
    the given cgroup.

    :return: Iterator of ``struct bpf_prog *`` objects.
    """
    progs_head = cgrp.bpf.progs[bpf_attach_type]
    for pl in list_for_each_entry(
        "struct bpf_prog_list", progs_head.address_of_(), "node"
    ):
        yield pl.prog


def cgroup_bpf_prog_for_each_effective(cgrp, bpf_attach_type):
    """
    .. c:function:: cgroup_bpf_prog_for_each(struct cgroup *cgrp, int bpf_attach_type)

    Iterate over all effective cgroup bpf programs of the given attach type for
    the given cgroup.

    :return: Iterator of ``struct bpf_prog *`` objects.
    """
    prog_array_items = cgrp.bpf.effective[bpf_attach_type].items
    for i in itertools.count():
        prog = prog_array_items[i].prog.read_()
        if not prog:
            break
        yield prog
