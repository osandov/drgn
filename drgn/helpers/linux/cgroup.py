# SPDX-License-Identifier: GPL-3.0+

"""
Cgroup
------

The ``drgn.helpers.linux.cgroup`` module provides helpers for working with the
cgroup interface in :linux:`include/linux/cgroup.h`. Only cgroup v2 is
supported.
"""


from drgn import NULL, cast, container_of
from drgn.helpers.linux.kernfs import kernfs_name, kernfs_path

__all__ = [
    "cgroup_name",
    "cgroup_parent",
    "cgroup_path",
    "sock_cgroup_ptr",
]


def sock_cgroup_ptr(skcd):
    """
    .. c:function:: struct cgroup *sock_cgroup_ptr(struct sock_cgroup_data *skcd)

    Get the cgroup for a socket from the given ``struct sock_cgroup_data *``
    (usually from ``struct sock::sk_cgrp_data``).
    """
    return cast("struct cgroup *", skcd.val)


def cgroup_parent(cgrp):
    """
    .. c:function:: struct cgroup *cgroup_parent(struct cgroup *cgrp)

    Return the parent cgroup of the given cgroup if it exists, ``NULL``
    otherwise.
    """
    parent_css = cgrp.self.parent
    if parent_css:
        return container_of(parent_css, "struct cgroup", "self")
    return NULL(cgrp.prog_, "struct cgroup *")


def cgroup_name(cgrp):
    """
    .. c:function:: char *cgroup_name(struct cgroup *cgrp)

    Get the name of the given cgroup.

    :rtype: bytes
    """
    return kernfs_name(cgrp.kn)


def cgroup_path(cgrp):
    """
    .. c:function:: char *cgroup_path(struct cgroup *cgrp)

    Get the full path of the given cgroup.

    :rtype: bytes
    """
    return kernfs_path(cgrp.kn)
