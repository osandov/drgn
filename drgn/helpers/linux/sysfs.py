# (C) Copyright IBM Corp. 2026
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Sysfs
-----

The ``drgn.helpers.linux.sysfs`` module provides helpers for working with
the sysfs interface built on top of kernfs.
"""

from typing import List, Optional

from drgn import NULL, Object, Program, cast, container_of
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.kernfs import (
    _kernfs_node_type,
    kernfs_children,
    kernfs_parent,
    kernfs_walk,
)

__all__ = (
    "sysfs_lookup_node",
    "sysfs_lookup_kobject",
    "sysfs_lookup",
    "sysfs_listdir",
)


@takes_program_or_default
def sysfs_lookup_node(prog: Program, path: str) -> Object:
    """
    Look up a ``struct kernfs_node *`` for a given sysfs path.

    The path may be provided either relative to ``/sys`` (e.g.,
    ``devices/system/cpu``) or as an absolute path beginning with
    ``/sys``.

    If the path is empty or refers to ``/sys`` itself, this returns
    the sysfs root node.

    :param path: Sysfs path (absolute or relative to ``/sys``)
    :return: ``struct kernfs_node *`` or ``NULL``
    """
    root_kn = prog["sysfs_root_kn"]

    if path.startswith("/"):
        path = path.lstrip("/")
        if path == "sys":
            path = ""
        elif path.startswith("sys/"):
            path = path[4:].lstrip("/")
        else:
            return NULL(prog, "struct kernfs_node *")

    return kernfs_walk(root_kn, path)


@takes_program_or_default
def sysfs_lookup_kobject(prog: Program, path: str) -> Optional[Object]:
    """
    Look up the ``struct kobject *`` corresponding to a sysfs path.

    If the path refers to a directory, this returns ``kn->priv``.
    If the path refers to a file (attribute), this returns the
    parent kobject (i.e., the parent node’s ``priv``)

    :param path: Sysfs path (absolute or relative to ``/sys``)
    :return: ``struct kobject *`` or ``NULL``
    """
    kn = sysfs_lookup_node(prog, path)
    if not kn:
        return NULL(prog, "struct kobject *")

    if _kernfs_node_type(kn, "KERNFS_DIR"):
        return cast("struct kobject *", kn.priv)

    parent = kernfs_parent(kn)
    if not parent:
        return NULL(prog, "struct kobject *")

    return cast("struct kobject *", parent.priv)


@takes_program_or_default
def sysfs_lookup(prog: Program, path: str) -> Optional[Object]:
    """
    Look up the object represented by a sysfs path.

    Resolve the ``struct kobject`` corresponding to a sysfs entry and,
    when possible, return the kernel structure which contains that
    kobject.

    Note: This may return more specific types for other cases in the future.

    Depending on the kobject type, this helper may return:

    - ``struct device *``
    - ``struct class *``
    - ``struct bus_type *``
    - ``struct device_driver *``
    - ``struct module_kobject *``

    If the kobject type does not correspond to a known container
    structure, the function returns the ``struct kobject *``.

    :param path: Sysfs path (absolute or relative to ``/sys``)
    :return: Corresponding container structure pointer or
        ``struct kobject *`` or ``NULL``
    """
    kobj = sysfs_lookup_kobject(prog, path)
    if not kobj:
        return NULL(prog, "struct kobject *")

    # device
    try:
        device_ktype = prog["device_ktype"].address_of_()
    except KeyError:
        pass
    else:
        if kobj.ktype == device_ktype:
            return container_of(kobj, "struct device", "kobj")

    # module
    try:
        module_ktype = prog["module_ktype"].address_of_()
    except KeyError:
        pass
    else:
        if kobj.ktype == module_ktype:
            return container_of(kobj, "struct module_kobject", "kobj")

    # driver
    try:
        driver_ktype = prog["driver_ktype"].address_of_()
    except KeyError:
        pass
    else:
        if kobj.ktype == driver_ktype:
            drv_priv = container_of(kobj, "struct driver_private", "kobj")
            return drv_priv.driver

    # class
    try:
        class_ktype = prog["class_ktype"].address_of_()
    except KeyError:
        pass
    else:
        if kobj.ktype == class_ktype:
            kset = container_of(kobj, "struct kset", "kobj")
            subsys = container_of(kset, "struct subsys_private", "subsys")
            return getattr(subsys, "class")

    # bus
    try:
        bus_ktype = prog["bus_ktype"].address_of_()
    except KeyError:
        pass
    else:
        if kobj.ktype == bus_ktype:
            kset = container_of(kobj, "struct kset", "kobj")
            subsys = container_of(kset, "struct subsys_private", "subsys")
            return subsys.bus

    return kobj


@takes_program_or_default
def sysfs_listdir(prog: Program, path: str) -> List[bytes]:
    """
    List the children of a sysfs directory.

    :param path: Sysfs directory path (absolute or relative to ``/sys``)
    :return: List of child entry names
    :raises ValueError: If path is not found or not a directory
    """
    kn = sysfs_lookup_node(prog, path)
    if not kn:
        raise ValueError(f"{path}: not found")

    return [child.name.string_() for child in kernfs_children(kn)]
