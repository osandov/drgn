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

__all__ = [
    'd_path',
    'dentry_path',
    'inode_path',
    'inode_paths',
    'mounts',
    'print_mounts',
]


def d_path(path_or_mnt, dentry=None):
    """
    char *d_path(struct path *)
    char *d_path(struct vfsmount *, struct dentry *)

    Return the full path of a dentry given a struct path or a mount and a
    dentry.
    """
    type_name = str(path_or_mnt.type_.type_name())
    if type_name == 'struct path' or type_name == 'struct path *':
        mnt = path_or_mnt.mnt.read_once_()
        dentry = path_or_mnt.dentry.read_once_()
    else:
        mnt = path_or_mnt.read_once_()
        dentry = dentry.read_once_()

    components = []
    while True:
        while True:
            d_parent = dentry.d_parent.read_once_()
            if dentry == d_parent:
                break
            components.append(dentry.d_name.name.string_())
            components.append(b'/')
            dentry = d_parent
        dentry = mnt.mnt_mountpoint
        mnt_parent = mnt.mnt_parent.read_once_()
        if mnt == mnt_parent:
            break
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


def mounts(prog_or_ns):
    """
    mounts()
    mounts(struct mnt_namespace *)

    Return an iterator over all of the mounts in a given namespace. If given a
    Program object instead, the initial mount namespace is used. The generated
    values are (source, destination, filesystem type, struct mount *) tuples.
    """
    if isinstance(prog_or_ns, Program):
        ns = prog_or_ns['init_task'].nsproxy.mnt_ns
    else:
        ns = prog_or_ns
    for mnt in list_for_each_entry('struct mount', ns.list.address_of_(),
                                   'mnt_list'):
        src = mnt.mnt_devname.string_()
        dst = d_path(mnt, mnt.mnt.mnt_root)
        sb = mnt.mnt.mnt_sb.read_once_()
        fstype = sb.s_type.name.string_()
        subtype = sb.s_subtype.read_once_()
        if subtype:
            subtype = subtype.string_()
            if subtype:
                fstype += b'.' + subtype
        yield src, dst, fstype, mnt


def print_mounts(prog_or_ns):
    """
    print_mounts()
    print_mounts(struct mnt_namespace *)

    Print the mount table of a given namespace. See mounts() for the behavior
    of the prog_or_ns argument. The format is similar to /proc/mounts but
    prints the value of each struct mount *.
    """
    for src, dst, fstype, mnt in mounts(prog_or_ns):
        src = escape_string(src, escape_backslash=True)
        dst = escape_string(dst, escape_backslash=True)
        fstype = escape_string(fstype, escape_backslash=True)
        print(f'{src} {dst} {fstype} ({mnt.type_.type_name()})0x{mnt.value_():x}')
