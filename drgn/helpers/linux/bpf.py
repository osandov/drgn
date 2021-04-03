# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
BPF
---

The ``drgn.helpers.linux.bpf`` module provides helpers for working with BPF
interface in :linux:`include/linux/bpf.h`, :linux:`include/linux/bpf-cgroup.h`,
etc.
"""


import itertools
from typing import Iterator

from drgn import IntegerLike, Object, Program, cast
from drgn.helpers.linux.idr import idr_for_each
from drgn.helpers.linux.list import list_for_each_entry

__all__ = (
    "bpf_map_for_each",
    "bpf_prog_for_each",
    "cgroup_bpf_prog_for_each",
    "cgroup_bpf_prog_for_each_effective",
)


def bpf_map_for_each(prog: Program) -> Iterator[Object]:
    """
    Iterate over all BPF maps.

    :return: Iterator of ``struct bpf_map *`` objects.
    """
    for nr, entry in idr_for_each(prog["map_idr"]):
        yield cast("struct bpf_map *", entry)


def bpf_prog_for_each(prog: Program) -> Iterator[Object]:
    """
    Iterate over all BPF programs.

    :return: Iterator of ``struct bpf_prog *`` objects.
    """
    for nr, entry in idr_for_each(prog["prog_idr"]):
        yield cast("struct bpf_prog *", entry)


def cgroup_bpf_prog_for_each(
    cgrp: Object, bpf_attach_type: IntegerLike
) -> Iterator[Object]:
    """
    Iterate over all cgroup BPF programs of the given attach type attached to
    the given cgroup.

    :param cgrp: ``struct cgroup *``
    :param bpf_attach_type: ``enum bpf_attach_type``
    :return: Iterator of ``struct bpf_prog *`` objects.
    """
    progs_head = cgrp.bpf.progs[bpf_attach_type]
    for pl in list_for_each_entry(
        "struct bpf_prog_list", progs_head.address_of_(), "node"
    ):
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
    prog_array_items = cgrp.bpf.effective[bpf_attach_type].items
    for i in itertools.count():
        prog = prog_array_items[i].prog.read_()
        if not prog:
            break
        yield prog
