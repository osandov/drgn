# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Virtual Filesystem Layer
------------------------

The ``drgn.helpers.linux.fs`` module provides helpers for working with the
Linux virtual filesystem (VFS) layer, including mounts, dentries, and inodes.
"""

import operator
import os
from typing import Iterator, Optional, Tuple, Union, overload

from drgn import (
    IntegerLike,
    Object,
    Path,
    Program,
    TypeKind,
    cast,
    container_of,
    sizeof,
)
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.common.prog import takes_object_or_program_or_default
from drgn.helpers.linux.list import (
    hlist_empty,
    hlist_for_each_entry,
    list_for_each_entry,
)
from drgn.helpers.linux.rbtree import rbtree_inorder_for_each_entry
from drgn.helpers.linux.xarray import xa_for_each, xa_is_value

__all__ = (
    "address_space_for_each_page",
    "d_path",
    "decode_file_type",
    "dentry_path",
    "fget",
    "for_each_file",
    "for_each_mount",
    "inode_for_each_page",
    "inode_path",
    "inode_paths",
    "mount_dst",
    "mount_fstype",
    "mount_src",
    "path_lookup",
    "print_files",
    "print_mounts",
    "super_block_for_each_mount",
)


def _follow_mount(mnt: Object, dentry: Object) -> Tuple[Object, Object]:
    prog = dentry.prog_
    try:
        DCACHE_MOUNTED = prog.cache["DCACHE_MOUNTED"]
    except KeyError:
        tokens = prog["UTS_RELEASE"].string_().split(b".", 2)
        major, minor = int(tokens[0]), int(tokens[1])
        # Linux kernel commit 9748cb2dc393 ("VFS: repack DENTRY_ flags.") (in
        # v6.15) changed the value of DCACHE_MOUNTED. Unfortunately, it's a
        # macro, so we have to hardcode it based on a version check until it's
        # converted to an enum.
        if (major, minor) >= (6, 15):
            DCACHE_MOUNTED = 1 << 15
        else:
            DCACHE_MOUNTED = 1 << 16
        prog.cache["DCACHE_MOUNTED"] = DCACHE_MOUNTED

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

S_IFMT      = 0o170000
S_IFLNK     = 0o120000
def is_inode_symlink(
    inode: Object) -> bool:
    return (inode.i_mode & S_IFMT) == S_IFLNK

XFS_IFINLINE            = 0x01
XFS_DINODE_FMT_LOCAL    = 0x01
def xfs_get_link(
    inode: Object) -> bytes:
    xfs_inode = container_of(inode, "struct xfs_inode", "i_vnode")
    ifork = xfs_inode.i_df
    # xfs_ifork_t has different members in different versions.
    if hasattr(ifork, "if_format") and ifork.if_format == XFS_DINODE_FMT_LOCAL:
        return xfs_inode.i_df.if_u1.if_data.string_()
    elif hasattr(ifork, "if_flags") and ifork.if_flags == XFS_IFINLINE:
        return xfs_inode.i_df.if_u1.if_data.string_()

    # doesn't support long symbol path yet as the path is not stored in inode.
    return b""

# caller makes sure this is a symbol link inode
def get_link(
    inode: Object) -> bytes:
    if inode.i_link:
        return inode.i_link

    if inode.i_sb.s_type.name.string_() == b"xfs":
        return xfs_get_link(inode)

    return b""

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
            if dentry.d_inode and is_inode_symlink(dentry.d_inode):
                s = get_link(dentry.d_inode)
                if not s:
                    raise Exception(f"could not get link from inode")

                # full symbol link target path
                if s[0:1] == b'/':
                    link_target = s
                else:
                    solved_path = b"/" + b"/".join(components[0:i+1])
                    link_target = solved_path + "/" + s
                link_target = link_target + b"/" + b"/".join(components[i+1:])
                return path_lookup(prog_or_root, link_target, allow_negative)
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


@overload
def d_path(dentry: Object) -> bytes:
    """
    Return the full path of a dentry.

    Since a mount is not provided, this arbitrarily selects a mount to determine
    the path.

    :param dentry: ``struct dentry *``
    """
    ...


def d_path(  # type: ignore  # Need positional-only arguments.
    arg1: Object, arg2: Optional[Object] = None
) -> bytes:
    if arg2 is None:
        try:
            mnt = container_of(arg1.mnt, "struct mount", "mnt")
            dentry = arg1.dentry.read_()
        except AttributeError:
            # Select an arbitrary mount from this dentry's super block. We
            # choose the first non-internal mount. Internal mounts exist for
            # kernel filesystems (e.g. debugfs) and they are mounted at "/".
            # Paths from these mounts aren't usable in userspace and they're
            # confusing. If there's no other option, we will use the first
            # internal mount we encountered.
            #
            # The MNT_INTERNAL flag is defined as a macro in the kernel source.
            # Introduced in 2.6.34 and has not been modified since.
            MNT_INTERNAL = 0x4000
            internal_mnt = None
            dentry = arg1
            for mnt in super_block_for_each_mount(dentry.d_sb):
                if mnt.mnt.mnt_flags & MNT_INTERNAL:
                    internal_mnt = internal_mnt or mnt
                    continue
                break
            else:
                if internal_mnt is not None:
                    mnt = internal_mnt
                else:
                    raise ValueError("Could not find a mount for this dentry")
    else:
        mnt = container_of(arg1, "struct mount", "mnt")
        dentry = arg2.read_()

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


def inode_for_each_page(inode: Object) -> Iterator[Tuple[int, Object]]:
    """
    Iterate over all cached pages and their indices in an inode.

    >>> for index, page in inode_for_each_page(inode):
    ...     print(index, hex(page))
    ...
    0 0xffffcfde4d0b6b00
    1 0xffffcfde4d0bda40
    3 0xffffcfde4d0b8b80

    :param inode: ``struct inode *``
    :return: Iterator of (index, ``struct page *`` object) tuples.
    """
    return address_space_for_each_page(inode.i_mapping.read_())


def address_space_for_each_page(mapping: Object) -> Iterator[Tuple[int, Object]]:
    """
    Iterate over all cached pages and their indices in an inode address space.

    :param mapping: ``struct address_space *``
    :return: Iterator of (index, ``struct page *`` object) tuples.
    """
    try:
        i_pages = mapping.i_pages
    except AttributeError:
        # i_pages was renamed from page_tree in Linux kernel commit
        # b93b016313b3 ("page cache: use xa_lock") (in v4.17).
        i_pages = mapping.page_tree
    page_type = mapping.prog_.type("struct page *")
    for index, entry in xa_for_each(i_pages.address_of_()):
        if not xa_is_value(entry):  # Skip shadow entries.
            yield index, cast(page_type, entry)


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
            mnt.mnt.mnt_sb  # skip cursors (v5.8 - v6.8)
            and (src is None or mount_src(mnt) == src)
            and (dst is None or mount_dst(mnt) == dst)
            and (fstype is None or mount_fstype(mnt) == fstype)
        ):
            yield mnt


def super_block_for_each_mount(sb: Object) -> Iterator[Object]:
    """
    Iterate over every mount of a super block.

    :param sb: ``struct super_block *``.
    :return: Iterator of ``struct mount *`` objects.
    """
    # Since Linux kernel commit 09a1b33c080f ("preparations to taking
    # MNT_WRITE_HOLD out of ->mnt_flags") (in v6.18), mounts for a super_block
    # are on an open-coded singly-linked list. Before that, they are on a
    # list_head.
    s_mounts = sb.s_mounts
    if s_mounts.type_.unaliased_kind() == TypeKind.POINTER:
        mount = s_mounts.read_()
        while mount:
            yield mount
            mount = mount.mnt_next_for_sb.read_()
    else:
        yield from list_for_each_entry(
            "struct mount", s_mounts.address_of_(), "mnt_instance"
        )


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
        prog if ns is None else ns,
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


# From include/uapi/linux/stat.h in the Linux kernel source code.
_S_IFMT = 0o170000
_S_IFMT_TO_STR = {
    0o140000: "SOCK",
    0o120000: "LNK",
    0o100000: "REG",
    0o060000: "BLK",
    0o040000: "DIR",
    0o020000: "CHR",
    0o010000: "FIFO",
}


def decode_file_type(mode: IntegerLike) -> str:
    """
    Convert a file mode to a human-readable file type string.

    :param mode: File mode (e.g., ``struct inode::i_mode`` or
        :attr:`os.stat_result.st_mode`).
    :return: File type as a string (e.g., "REG", "DIR", "CHR", etc.), or a raw
        octal value if unknown.
    """
    fmt = operator.index(mode) & _S_IFMT
    try:
        return _S_IFMT_TO_STR[fmt]
    except KeyError:
        return f"{fmt:06o}"
