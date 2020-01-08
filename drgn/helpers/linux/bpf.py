# SPDX-License-Identifier: GPL-3.0+

"""
BPF
---

The ``drgn.helpers.linux.bpf`` module provides helpers for working with BPF
interface in :linux:`include/linux/bpf.h`, :linux:`include/linux/bpf-cgroup.h`,
etc.
"""


import itertools

from drgn.helpers import enum_type_to_class
from drgn.helpers.linux.list import list_for_each_entry


__all__ = [
    "cgroup_bpf_prog_for_each",
    "cgroup_bpf_prog_for_each_effective",
]


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
