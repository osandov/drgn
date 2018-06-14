# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""
Linux kernel filesystem helpers

This module provides helpers for working with the Linux virtual filesystem
(VFS) layer, including mounts, dentries, and inodes.
"""

from drgn.helpers.kernel.list import hlist_for_each_entry, list_for_each_entry
from drgn.program import Program
from drgn.util import escape_string
import os

__all__ = [
    'd_path',
    'dentry_path',
    'inode_path',
    'inode_paths',
    'for_each_mount',
    'print_mounts',
]


def d_path(path_or_vfsmnt, dentry=None):
    """
    char *d_path(struct path *)
    char *d_path(struct vfsmount *, struct dentry *)

    Return the full path of a dentry given a struct path or a mount and a
    dentry.
    """
    type_name = str(path_or_vfsmnt.type_.type_name())
    if type_name == 'struct path' or type_name == 'struct path *':
        vfsmnt = path_or_vfsmnt.mnt
        dentry = path_or_vfsmnt.dentry.read_once_()
    else:
        vfsmnt = path_or_vfsmnt
        dentry = dentry.read_once_()
    mnt = vfsmnt.container_of_('struct mount', 'mnt')

    components = []
    while True:
        while True:
            d_parent = dentry.d_parent.read_once_()
            if dentry == d_parent:
                break
            components.append(dentry.d_name.name.string_())
            components.append(b'/')
            dentry = d_parent
        mnt_parent = mnt.mnt_parent.read_once_()
        if mnt == mnt_parent:
            break
        dentry = mnt.mnt_mountpoint
        mnt = mnt_parent
    if components:
        return b''.join(reversed(components))
    else:
        return b'/'


def dentry_path(dentry):
    """
    char *dentry_path(struct dentry *)

    Return the path of a dentry from the root of its filesystem.
    """
    components = []
    while True:
        d_parent = dentry.d_parent.read_once_()
        if dentry == d_parent:
            break
        components.append(dentry.d_name.name.string_())
        components.append(b'/')
        dentry = d_parent
    if components:
        return b''.join(reversed(components))
    else:
        return b'/'


def inode_path(inode):
    """
    char *inode_path(struct inode *)

    Return any path of an inode from the root of its filesystem.
    """
    return dentry_path(inode.i_dentry.first.container_of_('struct dentry', 'd_u.d_alias'))


def inode_paths(inode):
    """
    inode_paths(struct inode *)

    Return an iterator over all of the paths of an inode from the root of its
    filesystem.
    """
    return (
        dentry_path(dentry) for dentry in
        hlist_for_each_entry('struct dentry', inode.i_dentry.address_of_(), 'd_u.d_alias')
    )


def for_each_mount(prog_or_ns, src=None, dst=None, fstype=None):
    """
    for_each_mount(struct mnt_namespace *, char *src, char *dst, char *fstype)

    Return an iterator over all of the mounts in a given namespace. If given a
    Program object instead, the initial mount namespace is used. The returned
    mounts can be filtered by source, destination, or filesystem type, all of
    which are encoded using os.fsencode().

    The generated values are (source, destination, filesystem type, struct
    mount *) tuples. The source, destination, and filesystem type are returned
    as bytes.
    """
    if isinstance(prog_or_ns, Program):
        ns = prog_or_ns['init_task'].nsproxy.mnt_ns
    else:
        ns = prog_or_ns
    if src is not None:
        src = os.fsencode(src)
    if dst is not None:
        dst = os.fsencode(dst)
    if fstype:
        fstype = os.fsencode(fstype)
    for mnt in list_for_each_entry('struct mount', ns.list.address_of_(),
                                   'mnt_list'):
        mnt_src = mnt.mnt_devname.string_()
        if src is not None and mnt_src != src:
            continue
        mnt_dst = d_path(mnt.mnt.address_of_(), mnt.mnt.mnt_root)
        if dst is not None and mnt_dst != dst:
            continue
        sb = mnt.mnt.mnt_sb.read_once_()
        mnt_fstype = sb.s_type.name.string_()
        subtype = sb.s_subtype.read_once_()
        if subtype:
            subtype = subtype.string_()
            if subtype:
                mnt_fstype += b'.' + subtype
        if fstype is not None and mnt_fstype != fstype:
            continue
        yield mnt_src, mnt_dst, mnt_fstype, mnt


def print_mounts(prog_or_ns, src=None, dst=None, fstype=None):
    """
    print_mounts(struct mnt_namespace *, char *src, char *dst, char *fstype)

    Print the mount table of a given namespace. The arguments are the same as
    for_each_mount(). The output format is similar to /proc/mounts but prints
    the value of each struct mount *.
    """
    for mnt_src, mnt_dst, mnt_fstype, mnt in for_each_mount(prog_or_ns, src,
                                                            dst, fstype):
        mnt_src = escape_string(mnt_src, escape_backslash=True)
        mnt_dst = escape_string(mnt_dst, escape_backslash=True)
        mnt_fstype = escape_string(mnt_fstype, escape_backslash=True)
        print(f'{mnt_src} {mnt_dst} {mnt_fstype} ({mnt.type_.type_name()})0x{mnt.value_():x}')
