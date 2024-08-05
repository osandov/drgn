#!/usr/bin/env drgn
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""List the paths of all descendants of a cgroup v2"""

import argparse
from contextlib import contextmanager
import os
import sys

from drgn import cast
from drgn.helpers.common.type import enum_type_to_class
from drgn.helpers.linux import (
    cgroup_bpf_prog_for_each,
    cgroup_path,
    css_for_each_descendant_pre,
    fget,
    find_task,
)

BpfAttachType = enum_type_to_class(
    prog.type("enum bpf_attach_type"),
    "BpfAttachType",
    exclude=("__MAX_BPF_ATTACH_TYPE",),
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
    for attach_type in BpfAttachType:
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["tree", "bpf"])
    parser.add_argument("cgroups", help="Cgroups", nargs="*", type=get_cgroup)
    args = parser.parse_args()

    if len(args.cgroups) == 0:
        args.cgroups.append(prog["cgrp_dfl_root"].cgrp)

    for cg in args.cgroups:
        if len(args.cgroups) > 1:
            print(cg.kn.name.string_())
        locals()["cmd_" + args.command](cg)

