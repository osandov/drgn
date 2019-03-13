# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""
Linux kernel filesystem helpers

This module provides helpers for working with the Linux virtual filesystem
(VFS) layer, including mounts, dentries, and inodes.
"""

import os

from drgn import container_of, Program
from drgn.internal.util import escape_string
from drgn.helpers.kernel.list import hlist_for_each_entry, list_for_each_entry

__all__ = [
    'd_path',
    'dentry_path',
    'inode_path',
    'inode_paths',
    'for_each_mount',
    'print_mounts',
    'fget',
    'for_each_file',
    'print_files',
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
        dentry = path_or_vfsmnt.dentry.read_()
    else:
        vfsmnt = path_or_vfsmnt
        dentry = dentry.read_()
    mnt = container_of(vfsmnt, 'struct mount', 'mnt')

    d_op = dentry.d_op.read_()
    if d_op and d_op.d_dname:
        return None

    components = []
    while True:
        while True:
            d_parent = dentry.d_parent.read_()
            if dentry == d_parent:
                break
            components.append(dentry.d_name.name.string_())
            components.append(b'/')
            dentry = d_parent
        mnt_parent = mnt.mnt_parent.read_()
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
        d_parent = dentry.d_parent.read_()
        if dentry == d_parent:
            break
        components.append(dentry.d_name.name.string_())
        dentry = d_parent
    return b'/'.join(reversed(components))


def inode_path(inode):
    """
    char *inode_path(struct inode *)

    Return any path of an inode from the root of its filesystem.
    """
    return dentry_path(container_of(inode.i_dentry.first, 'struct dentry',
                                    'd_u.d_alias'))


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
        sb = mnt.mnt.mnt_sb.read_()
        mnt_fstype = sb.s_type.name.string_()
        subtype = sb.s_subtype.read_()
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


def fget(task, fd):
    """
    struct file *fget(struct task_struct *, int fd)

    Return the kernel file descriptor (struct file *) of the fd of a given
    task.
    """
    return task.files.fdt.fd[fd]


def for_each_file(task):
    """
    for_each_file(struct task_struct *)

    Return an iterator over all of the files open in a given task. The
    generated values are (fd, path, struct file *) tuples. The path is returned
    as bytes.
    """
    fdt = task.files.fdt.read_()
    bits_per_long = 8 * fdt.open_fds.type_.type.sizeof()
    for i in range((fdt.max_fds.value_() + bits_per_long - 1) // bits_per_long):
        word = fdt.open_fds[i].value_()
        for j in range(bits_per_long):
            if word & (1 << j):
                fd = i * bits_per_long + j
                file = fdt.fd[fd].read_()
                yield fd, d_path(file.f_path), file


def print_files(task):
    """
    print_files(struct task_struct *)

    Print the open files of a given task.
    """
    for fd, path, file in for_each_file(task):
        if path is None:
            path = file.f_inode.i_sb.s_type.name.string_()
        path = escape_string(path, escape_backslash=True)
        print(f'{fd} {path} ({file.type_.type_name()})0x{file.value_():x}')
