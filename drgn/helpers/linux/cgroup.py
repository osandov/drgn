# Copyright (c) Facebook, Inc. and its affiliates.
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
from drgn.helpers.linux.list import list_for_each_entry

__all__ = (
    "cgroup_name",
    "cgroup_parent",
    "cgroup_path",
    "css_for_each_child",
    "css_for_each_descendant_pre",
    "css_next_child",
    "css_next_descendant_pre",
    "sock_cgroup_ptr",
)


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


def css_next_child(pos, parent):
    """
    .. c:function:: struct cgroup_subsys_state *css_next_child(struct cgroup_subsys_state *pos, struct cgroup_subsys_state *parent)

    Get the next child (or ``NULL`` if there is none) of the given parent
    starting from the given position (``NULL`` to initiate traversal).
    """
    if not pos:
        next_ = container_of(
            parent.children.next, "struct cgroup_subsys_state", "sibling"
        )
    elif not (pos.flags & pos.prog_["CSS_RELEASED"]):
        next_ = container_of(pos.sibling.next, "struct cgroup_subsys_state", "sibling")
    else:
        serial_nr = pos.serial_nr.value_()  # Read once and cache.
        for next_ in list_for_each_entry(
            "struct cgroup_subsys_state", parent.children.address_of_(), "sibling"
        ):
            if next_.serial_nr > serial_nr:
                break

    if next_.sibling.address_of_() != parent.children.address_of_():
        return next_
    return NULL(next_.prog_, "struct cgroup_subsys_state *")


def css_next_descendant_pre(pos, root):
    """
    .. c:function:: struct cgroup_subsys_state *css_next_descendant_pre(struct cgroup_subsys_state *pos, struct cgroup_subsys_state *root)

    Get the next pre-order descendant (or ``NULL`` if there is none) of the
    given css root starting from the given position (``NULL`` to initiate
    traversal).
    """
    # If first iteration, visit root.
    if not pos:
        return root

    # Visit the first child if exists.
    null = NULL(pos.prog_, "struct cgroup_subsys_state *")
    next_ = css_next_child(null, pos)
    if next_:
        return next_

    # No child, visit my or the closest ancestor's next sibling.
    while pos != root:
        next_ = css_next_child(pos, pos.parent)
        if next_:
            return next_
        pos = pos.parent

    return NULL(root.prog_, "struct cgroup_subsys_state *")


def _css_for_each_impl(next_fn, css):
    pos = NULL(css.prog_, "struct cgroup_subsys_state *")
    while True:
        pos = next_fn(pos, css)
        if not pos:
            break
        if pos.flags & pos.prog_["CSS_ONLINE"]:
            yield pos


def css_for_each_child(css):
    """
    .. c:function:: css_for_each_child(struct cgroup_subsys_state *css)

    Iterate through children of the given css.

    :return: Iterator of ``struct cgroup_subsys_state *`` objects.
    """
    return _css_for_each_impl(css_next_child, css)


def css_for_each_descendant_pre(css):
    """
    .. c:function:: css_for_each_descendant_pre(struct cgroup_subsys_state *css)

    Iterate through the given css's descendants in pre-order.

    :return: Iterator of ``struct cgroup_subsys_state *`` objects.
    """
    return _css_for_each_impl(css_next_descendant_pre, css)
