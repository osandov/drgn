"""List the paths of all descendants of a cgroup v2"""

import os
import sys

from contextlib import contextmanager

from drgn import cast
from drgn.helpers.linux import (
    cgroup_path,
    css_for_each_descendant_pre,
    fget,
    find_task,
)


@contextmanager
def open_dir(*args, **kwds):
    # Built-in open() context manager can't deal with directories.
    fd = os.open(*args, **kwds)
    try:
        yield fd
    finally:
        os.close(fd)


def get_cgroup():
    if len(sys.argv) == 1:
        return prog["cgrp_dfl_root"].cgrp
    task = find_task(prog, os.getpid())
    with open_dir(sys.argv[1], os.O_RDONLY) as fd:
        file_ = fget(task, fd)
        kn = cast("struct kernfs_node *", file_.f_path.dentry.d_inode.i_private)
        return cast("struct cgroup *", kn.priv)


css = get_cgroup().self.address_of_()

for pos in css_for_each_descendant_pre(css):
    print(cgroup_path(pos.cgroup).decode())
