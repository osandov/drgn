#!/usr/bin/env drgn
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""List the paths of all descendants of a cgroup v2"""

import argparse
from contextlib import contextmanager
import os
import sys
from collections import Counter

from drgn import cast
from drgn.helpers.common.type import enum_type_to_class
from drgn.helpers.linux import (
    cgroup_bpf_prog_for_each,
    cgroup_path,
    css_for_each_descendant_pre,
    fget,
    find_task,
)

# Since Linux kernel commit 6fc88c354f3a ("bpf: Migrate cgroup_bpf to internal
# cgroup_bpf_attach_type enum") (in v5.15), the attach type is the
# cgroup-specific enum cgroup_bpf_attach_type. Before that, it was the generic
# enum bpf_attach_type.
try:
    enum_cgroup_bpf_attach_type = prog.type("enum cgroup_bpf_attach_type")
except LookupError:
    CgroupBpfAttachType = enum_type_to_class(
        prog.type("enum bpf_attach_type"),
        "CgroupBpfAttachType",
        exclude=("__MAX_BPF_ATTACH_TYPE",),
    )
else:
    CgroupBpfAttachType = enum_type_to_class(
        enum_cgroup_bpf_attach_type,
        "CgroupBpfAttachType",
        exclude=("CGROUP_BPF_ATTACH_TYPE_INVALID", "MAX_CGROUP_BPF_ATTACH_TYPE",),
    )

CgroupSubsysId = enum_type_to_class(
    prog.type("enum cgroup_subsys_id"),
    "CgroupSubsysId",
    exclude=("CGROUP_SUBSYS_COUNT",),
)

@contextmanager
def open_dir(*args, **kwds):
    # Built-in open() context manager can't deal with directories.
    fd = os.open(*args, **kwds)
    try:
        yield fd
    finally:
        os.close(fd)


def print_cgroup_bpf_progs(cgrp):
    cgroup_printed = False
    for attach_type in CgroupBpfAttachType:
        attach_flags = cgrp.bpf.flags[attach_type.value].value_()
        for prog in cgroup_bpf_prog_for_each(cgrp, attach_type.value):
            prog_id = prog.aux.id.value_()
            prog_name = prog.aux.name.string_().decode()
            if not cgroup_printed:
                print(cgroup_path(cgrp).decode())
                cgroup_printed = True
            print(
                "    {:<8} {:<30} {:<15} {:<15}".format(
                    prog_id, attach_type.name, attach_flags, prog_name
                )
            )


def get_cgroup(path):
    task = find_task(prog, os.getpid())
    try:
        with open_dir(path, os.O_RDONLY) as fd:
            file_ = fget(task, fd)
            kn = cast("struct kernfs_node *", file_.f_path.dentry.d_inode.i_private)
            return cast("struct cgroup *", kn.priv)
    except FileNotFoundError as e:
        raise argparse.ArgumentTypeError(e)


def cmd_tree(cgroup):
    css = cgroup.self.address_of_()

    for pos in css_for_each_descendant_pre(css):
        if not pos.flags & prog["CSS_ONLINE"]:
            continue
        print(cgroup_path(pos.cgroup).decode())


def cmd_bpf(cgroup):
    css = cgroup.self.address_of_()

    for pos in css_for_each_descendant_pre(css):
        if not pos.flags & prog["CSS_ONLINE"]:
            continue
        print_cgroup_bpf_progs(pos.cgroup)


def cmd_stat(cgroup):
    stat = Counter()
    stat_dying = Counter()

    for ssid in CgroupSubsysId:
        css = cgroup.subsys[ssid.value]
        # XXX if subsys of offlined or cgroup rmdir'd under our hands we won't see its subtree
        if not css:
            continue
        for pos in css_for_each_descendant_pre(css):
            stat[ssid] +=1
            if not pos.flags & prog["CSS_ONLINE"]:
                stat_dying[ssid] += 1

    for ssid in CgroupSubsysId:
        if stat[ssid.value] == 0:
            continue
        print("nr_{:<30} {:>4}".format(
            ssid.name,
            stat[ssid.value]
            )
        )
    for ssid in CgroupSubsysId:
        if stat_dying[ssid.value] == 0:
            continue
        print("nr_dying_{:<24} {:>4}".format(
            ssid.name,
            stat_dying[ssid.value]
            )
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["tree", "bpf", "stat"])
    parser.add_argument("cgroups", help="Cgroups", nargs="*", type=get_cgroup)
    args = parser.parse_args()

    if len(args.cgroups) == 0:
        args.cgroups.append(prog["cgrp_dfl_root"].cgrp)

    for cg in args.cgroups:
        if len(args.cgroups) > 1:
            print(cg.kn.name.string_())
        locals()["cmd_" + args.command](cg)

