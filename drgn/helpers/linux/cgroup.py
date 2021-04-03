# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Cgroup
------

The ``drgn.helpers.linux.cgroup`` module provides helpers for working with the
cgroup interface in :linux:`include/linux/cgroup.h`. Only cgroup v2 is
supported.
"""

from typing import Callable, Iterator

from drgn import NULL, Object, cast, container_of
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


def sock_cgroup_ptr(skcd: Object) -> Object:
    """
    Get the cgroup for a socket from the given ``struct sock_cgroup_data *``
    (usually from ``struct sock::sk_cgrp_data``).

    :param skcd: ``struct sock_cgroup_data *``
    :return: ``struct cgroup *``
    """
    return cast("struct cgroup *", skcd.val)


def cgroup_parent(cgrp: Object) -> Object:
    """
    Return the parent cgroup of the given cgroup if it exists, ``NULL``
    otherwise.

    :param cgrp: ``struct cgroup *``
    :return: ``struct cgroup *``
    """
    parent_css = cgrp.self.parent
    if parent_css:
        return container_of(parent_css, "struct cgroup", "self")
    return NULL(cgrp.prog_, "struct cgroup *")


def cgroup_name(cgrp: Object) -> bytes:
    """
    Get the name of the given cgroup.

    :param cgrp: ``struct cgroup *``
    """
    return kernfs_name(cgrp.kn)


def cgroup_path(cgrp: Object) -> bytes:
    """
    Get the full path of the given cgroup.

    :param cgrp: ``struct cgroup *``
    """
    return kernfs_path(cgrp.kn)


def css_next_child(pos: Object, parent: Object) -> Object:
    """
    Get the next child (or ``NULL`` if there is none) of the given parent
    starting from the given position (``NULL`` to initiate traversal).

    :param pos: ``struct cgroup_subsys_state *``
    :param parent: ``struct cgroup_subsys_state *``
    :return: ``struct cgroup_subsys_state *``
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


def css_next_descendant_pre(pos: Object, root: Object) -> Object:
    """
    Get the next pre-order descendant (or ``NULL`` if there is none) of the
    given css root starting from the given position (``NULL`` to initiate
    traversal).

    :param pos: ``struct cgroup_subsys_state *``
    :param root: ``struct cgroup_subsys_state *``
    :return: ``struct cgroup_subsys_state *``
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


def _css_for_each_impl(
    next_fn: Callable[[Object, Object], Object], css: Object
) -> Iterator[Object]:
    pos = NULL(css.prog_, "struct cgroup_subsys_state *")
    while True:
        pos = next_fn(pos, css)
        if not pos:
            break
        if pos.flags & pos.prog_["CSS_ONLINE"]:
            yield pos


def css_for_each_child(css: Object) -> Iterator[Object]:
    """
    Iterate through children of the given css.

    :param css: ``struct cgroup_subsys_state *``
    :return: Iterator of ``struct cgroup_subsys_state *`` objects.
    """
    return _css_for_each_impl(css_next_child, css)


def css_for_each_descendant_pre(css: Object) -> Iterator[Object]:
    """
    Iterate through the given css's descendants in pre-order.

    :param css: ``struct cgroup_subsys_state *``
    :return: Iterator of ``struct cgroup_subsys_state *`` objects.
    """
    return _css_for_each_impl(css_next_descendant_pre, css)
