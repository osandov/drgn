# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Virtual Filesystem Layer
------------------------

The ``drgn.helpers.linux.fs`` module provides helpers for working with the
Linux virtual filesystem (VFS) layer, including mounts, dentries, and inodes.
"""

import os
from typing import Iterator, Optional, Tuple, Union, overload

from drgn import IntegerLike, Object, Path, Program, container_of, sizeof
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.common.prog import takes_object_or_program_or_default
from drgn.helpers.linux.list import (
    hlist_empty,
    hlist_for_each_entry,
    list_for_each_entry,
)
from drgn.helpers.linux.rbtree import rbtree_inorder_for_each_entry

__all__ = (
    "path_lookup",
    "d_path",
    "dentry_path",
    "inode_path",
    "inode_paths",
    "mount_src",
    "mount_dst",
    "mount_fstype",
    "for_each_mount",
    "print_mounts",
    "fget",
    "for_each_file",
    "print_files",
)


def _follow_mount(mnt: Object, dentry: Object) -> Tuple[Object, Object]:
    # DCACHE_MOUNTED is a macro, so we can't easily get the value. But, it
    # hasn't changed since v2.6.38, so let's hardcode it for now.
    DCACHE_MOUNTED = 0x10000
    while dentry.d_flags & DCACHE_MOUNTED:
        for mounted in list_for_each_entry(
            "struct mount", mnt.mnt_mounts.address_of_(), "mnt_child"
        ):
            if mounted.mnt_mountpoint == dentry:
                mnt = mounted
                dentry = mounted.mnt.mnt_root.read_()
                break
        else:
            break
    return mnt, dentry


def _follow_dotdot(
    mnt: Object, dentry: Object, root_mnt: Object, root_dentry: Object
) -> Tuple[Object, Object]:
    while dentry != root_dentry or mnt != root_mnt:
        d_parent = dentry.d_parent.read_()
        if dentry != d_parent:
            dentry = d_parent
            break
        mnt_parent = mnt.mnt_parent.read_()
        if mnt == mnt_parent:
            break
        dentry = mnt.mnt_mountpoint
        mnt = mnt_parent
    return _follow_mount(mnt, dentry)


@takes_object_or_program_or_default
def path_lookup(
    prog: Program,
    root: Optional[Object],
    path: Path,
    *,
    allow_negative: bool = False,
) -> Object:
    """
    Look up the given path name.

    :param root: ``struct path *`` to use as the root directory. Defaults to
        the initial root filesystem if given a :class:`~drgn.Program` or
        :ref:`omitted <default-program>`.
    :param path: Path to lookup.
    :param allow_negative: Whether to allow returning a negative dentry (i.e.,
        a dentry for a non-existent path).
    :return: ``struct path``
    :raises Exception: if the dentry is negative and ``allow_negative`` is
        ``False``, or if the path is not present in the dcache. The latter does
        not necessarily mean that the path does not exist; it may be uncached.
        On a live system, you can make the kernel cache the path by accessing
        it (e.g., with :func:`open()` or :func:`os.stat()`):

    >>> path_lookup('/usr/include/stdlib.h')
    ...
    Exception: could not find '/usr/include/stdlib.h' in dcache
    >>> open('/usr/include/stdlib.h').close()
    >>> path_lookup('/usr/include/stdlib.h')
    (struct path){
            .mnt = (struct vfsmount *)0xffff8b70413cdca0,
            .dentry = (struct dentry *)0xffff8b702ac2c480,
    }
    """
    if root is None:
        root = prog["init_task"].fs.root
    mnt = root_mnt = container_of(root.mnt.read_(), "struct mount", "mnt")
    dentry = root_dentry = root.dentry.read_()
    components = os.fsencode(path).split(b"/")
    for i, component in enumerate(components):
        if component == b"" or component == b".":
            continue
        elif component == b"..":
            mnt, dentry = _follow_dotdot(mnt, dentry, root_mnt, root_dentry)
        else:
            # Since Linux kernel commit da549bdd15c2 ("dentry: switch the lists
            # of children to hlist") (in v6.8), the children are in an hlist.
            # Before that, they're in a list with different field names.
            try:
                children = hlist_for_each_entry(
                    "struct dentry", dentry.d_children.address_of_(), "d_sib"
                )
            except AttributeError:
                children = list_for_each_entry(
                    "struct dentry", dentry.d_subdirs.address_of_(), "d_child"
                )
            for child in children:
                if child.d_name.name.string_() == component:
                    dentry = child
                    break
            else:
                failed_path = os.fsdecode(b"/".join(components[: i + 1]))
                raise Exception(f"could not find {failed_path!r} in dcache")
            mnt, dentry = _follow_mount(mnt, dentry)
    if not allow_negative and not dentry.d_inode:
        failed_path = os.fsdecode(b"/".join(components))
        raise Exception(f"{failed_path!r} dentry is negative")
    return Object(
        prog,
        "struct path",
        value={"mnt": mnt.mnt.address_of_(), "dentry": dentry},
    )


@overload
def d_path(path: Object) -> bytes:
    """
    Return the full path of a dentry given a ``struct path``.

    :param path: ``struct path`` or ``struct path *``
    """
    ...


@overload
def d_path(vfsmnt: Object, dentry: Object) -> bytes:
    """
    Return the full path of a dentry given a mount and dentry.

    :param vfsmnt: ``struct vfsmount *``
    :param dentry: ``struct dentry *``
    """
    ...


def d_path(  # type: ignore  # Need positional-only arguments.
    path_or_vfsmnt: Object, dentry: Optional[Object] = None
) -> bytes:
    if dentry is None:
        vfsmnt = path_or_vfsmnt.mnt
        dentry = path_or_vfsmnt.dentry.read_()
    else:
        vfsmnt = path_or_vfsmnt
        dentry = dentry.read_()
    mnt = container_of(vfsmnt, "struct mount", "mnt")

    d_op = dentry.d_op.read_()
    if d_op and d_op.d_dname:
        return b"[" + dentry.d_inode.i_sb.s_type.name.string_() + b"]"

    components = []
    while True:
        if dentry == mnt.mnt.mnt_root:
            mnt_parent = mnt.mnt_parent.read_()
            if mnt == mnt_parent:
                break
            dentry = mnt.mnt_mountpoint.read_()
            mnt = mnt_parent
            continue
        d_parent = dentry.d_parent.read_()
        if dentry == d_parent:
            break
        components.append(dentry.d_name.name.string_())
        components.append(b"/")
        dentry = d_parent
    if components:
        return b"".join(reversed(components))
    else:
        return b"/"


def dentry_path(dentry: Object) -> bytes:
    """
    Return the path of a dentry from the root of its filesystem.

    :param dentry: ``struct dentry *``
    """
    components = []
    while True:
        d_parent = dentry.d_parent.read_()
        if dentry == d_parent:
            break
        components.append(dentry.d_name.name.string_())
        dentry = d_parent
    return b"/".join(reversed(components))


def inode_path(inode: Object) -> Optional[bytes]:
    """
    Return any path of an inode from the root of its filesystem.

    :param inode: ``struct inode *``
    :return: Path, or ``None`` if the inode has no aliases.
    """
    if hlist_empty(inode.i_dentry):
        return None
    return dentry_path(
        container_of(inode.i_dentry.first, "struct dentry", "d_u.d_alias")
    )


def inode_paths(inode: Object) -> Iterator[bytes]:
    """
    Return an iterator over all of the paths of an inode from the root of its
    filesystem.

    :param inode: ``struct inode *``
    """
    return (
        dentry_path(dentry)
        for dentry in hlist_for_each_entry(
            "struct dentry", inode.i_dentry.address_of_(), "d_u.d_alias"
        )
    )


def mount_src(mnt: Object) -> bytes:
    """
    Get the source device name for a mount.

    :param mnt: ``struct mount *``
    """
    return mnt.mnt_devname.string_()


def mount_dst(mnt: Object) -> bytes:
    """
    Get the path of a mount point.

    :param mnt: ``struct mount *``
    """
    return d_path(mnt.mnt.address_of_(), mnt.mnt.mnt_root)


def mount_fstype(mnt: Object) -> bytes:
    """
    Get the filesystem type of a mount.

    :param mnt: ``struct mount *``
    """
    sb = mnt.mnt.mnt_sb.read_()
    fstype = sb.s_type.name.string_()
    subtype_obj = sb.s_subtype.read_()
    if subtype_obj:
        subtype = subtype_obj.string_()
        if subtype:
            fstype += b"." + subtype
    return fstype


@takes_object_or_program_or_default
def for_each_mount(
    prog: Program,
    ns: Optional[Object],
    *,
    src: Optional[Path] = None,
    dst: Optional[Path] = None,
    fstype: Optional[Union[str, bytes]] = None,
) -> Iterator[Object]:
    """
    Iterate over all of the mounts in a given namespace.

    :param ns: ``struct mnt_namespace *``. Defaults to the initial mount
        namespace if given a :class:`~drgn.Program` or :ref:`omitted
        <default-program>`.
    :param src: Only include mounts with this source device name.
    :param dst: Only include mounts with this destination path.
    :param fstype: Only include mounts with this filesystem type.
    :return: Iterator of ``struct mount *`` objects.
    """
    if ns is None:
        ns = prog["init_task"].nsproxy.mnt_ns
    if src is not None:
        src = os.fsencode(src)
    if dst is not None:
        dst = os.fsencode(dst)
    if fstype:
        fstype = os.fsencode(fstype)
    # Since Linux kernel commit 2eea9ce4310d ("mounts: keep list of mounts in
    # an rbtree") (in v6.8), the mounts in a namespace are in a red-black tree.
    # Before that, they're in a list.
    # The old case is first here because before that commit, struct mount also
    # had a different member named "mounts".
    try:
        mounts = list_for_each_entry("struct mount", ns.list.address_of_(), "mnt_list")
    except AttributeError:
        mounts = rbtree_inorder_for_each_entry(
            "struct mount", ns.mounts.address_of_(), "mnt_node"
        )
    for mnt in mounts:
        if (
            (src is None or mount_src(mnt) == src)
            and (dst is None or mount_dst(mnt) == dst)
            and (fstype is None or mount_fstype(mnt) == fstype)
        ):
            yield mnt


@takes_object_or_program_or_default
def print_mounts(
    prog: Program,
    ns: Optional[Object],
    *,
    src: Optional[Path] = None,
    dst: Optional[Path] = None,
    fstype: Optional[Union[str, bytes]] = None,
) -> None:
    """
    Print the mount table of a given namespace. The arguments are the same as
    :func:`for_each_mount()`. The output format is similar to ``/proc/mounts``
    but prints the value of each ``struct mount *``.
    """
    for mnt in for_each_mount(
        prog if ns is None else ns,  # type: ignore  # python/mypy#12056
        src=src,
        dst=dst,
        fstype=fstype,
    ):
        mnt_src = escape_ascii_string(mount_src(mnt), escape_backslash=True)
        mnt_dst = escape_ascii_string(mount_dst(mnt), escape_backslash=True)
        mnt_fstype = escape_ascii_string(mount_fstype(mnt), escape_backslash=True)
        print(
            f"{mnt_src} {mnt_dst} {mnt_fstype} ({mnt.type_.type_name()})0x{mnt.value_():x}"
        )


def fget(task: Object, fd: IntegerLike) -> Object:
    """
    Return the kernel file descriptor of the fd of a given task.

    :param task: ``struct task_struct *``
    :param fd: File descriptor.
    :return: ``struct file *``
    """
    return task.files.fdt.fd[fd]


def for_each_file(task: Object) -> Iterator[Tuple[int, Object]]:
    """
    Iterate over all of the files open in a given task.

    :param task: ``struct task_struct *``
    :return: Iterator of (fd, ``struct file *``) tuples.
    """
    files = task.files.read_()
    if not files:
        return
    fdt = files.fdt.read_()
    bits_per_long = 8 * sizeof(fdt.open_fds.type_.type)
    for i in range((fdt.max_fds.value_() + bits_per_long - 1) // bits_per_long):
        word = fdt.open_fds[i].value_()
        for j in range(bits_per_long):
            if word & (1 << j):
                fd = i * bits_per_long + j
                file = fdt.fd[fd].read_()
                yield fd, file


def print_files(task: Object) -> None:
    """
    Print the open files of a given task.

    :param task: ``struct task_struct *``
    """
    for fd, file in for_each_file(task):
        path = d_path(file.f_path)
        escaped_path = escape_ascii_string(path, escape_backslash=True)
        print(f"{fd} {escaped_path} ({file.type_.type_name()})0x{file.value_():x}")
