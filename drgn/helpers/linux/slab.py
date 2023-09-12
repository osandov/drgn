# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Slab Allocator
--------------

The ``drgn.helpers.linux.slab`` module provides helpers for working with the
Linux slab allocator.

.. warning::

    Beware of slab merging when using these helpers. See
    :func:`slab_cache_is_merged()
    <drgn.helpers.linux.slab.slab_cache_is_merged>`.
"""

import operator
from os import fsdecode
from typing import Callable, Dict, Iterator, Optional, Set, Tuple, Union, overload

from drgn import (
    NULL,
    FaultError,
    IntegerLike,
    Object,
    Program,
    Type,
    cast,
    container_of,
    sizeof,
)
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.mm import (
    PageSlab,
    compound_head,
    for_each_page,
    page_to_virt,
    pfn_to_virt,
    virt_to_page,
)
from drgn.helpers.linux.percpu import per_cpu_ptr
from drgn.helpers.linux.rbtree import rbtree_inorder_for_each_entry

__all__ = (
    "find_containing_slab_cache",
    "find_slab_cache",
    "for_each_slab_cache",
    "get_slab_cache_aliases",
    "print_slab_caches",
    "slab_cache_for_each_allocated_object",
    "slab_cache_is_merged",
    "slab_object_info",
)


# Get the type containing slab information.
#
# Linux kernel commit d122019bf061cccc4583eb9ad40bf58c2fe517be ("mm: Split slab
# into its own type") (in v5.17) moved slab information from struct page to
# struct slab. The former can be casted to the latter.
def _get_slab_type(prog: Program) -> Type:
    try:
        return prog.type("struct slab *")
    except LookupError:
        return prog.type("struct page *")


def slab_cache_is_merged(slab_cache: Object) -> bool:
    """
    Return whether a slab cache has been merged with any other slab caches.

    Unless configured otherwise, the kernel may merge slab caches of similar
    sizes together. See the `SLUB users guide
    <https://docs.kernel.org/vm/slub.html#slab-merging>`_ and
    ``slab_merge``/``slab_nomerge`` in the `kernel parameters documentation
    <https://www.kernel.org/doc/Documentation/admin-guide/kernel-parameters.txt>`_.

    This can cause confusion, as only the name of the first cache will be
    found, and objects of different types will be mixed in the same slab cache.

    For example, suppose that we have two types, ``struct foo`` and ``struct
    bar``, which have the same size but are otherwise unrelated. If the kernel
    creates a slab cache named ``foo`` for ``struct foo``, then another slab
    cache named ``bar`` for ``struct bar``, then slab cache ``foo`` will be
    reused instead of creating another cache for ``bar``. So the following will
    fail::

        find_slab_cache(prog, "bar")

    And the following will also return ``struct bar *`` objects errantly casted to
    ``struct foo *``::

        slab_cache_for_each_allocated_object(
            find_slab_cache(prog, "foo"), "struct foo"
        )

    Unfortunately, these issues are difficult to work around generally, so one
    must be prepared to handle them on a case-by-case basis (e.g., by looking
    up the slab cache by its variable name and by checking that members of the
    structure make sense for the expected type).

    :param slab_cache: ``struct kmem_cache *``
    """
    return slab_cache.refcount > 1


def get_slab_cache_aliases(prog: Program) -> Dict[str, str]:
    """
    Return a dict mapping slab cache name to the cache it was merged with.

    The SLAB and SLUB subsystems can merge caches with similar settings and
    object sizes, as described in the documentation of
    :func:`slab_cache_is_merged()`. In some cases, the information about which
    caches were merged is lost, but in other cases, we can reconstruct the info.
    This function reconstructs the mapping, but requires that the kernel is
    configured with ``CONFIG_SLUB`` and ``CONFIG_SYSFS``.

    The returned dict maps from original cache name, to merged cache name. You
    can use this mapping to discover the correct cache to lookup via
    :func:`find_slab_cache()`. The dict contains an entry only for caches which
    were merged into a cache of a different name.

    >>> cache_to_merged = get_slab_cache_aliases(prog)
    >>> cache_to_merged["dnotify_struct"]
    'avc_xperms_data'
    >>> "avc_xperms_data" in cache_to_merged
    False
    >>> find_slab_cache(prog, "dnotify_struct") is None
    True
    >>> find_slab_cache(prog, "avc_xperms_data") is None
    False

    :warning: This function will only work on kernels which are built with
      ``CONFIG_SLUB`` and ``CONFIG_SYSFS`` enabled.

    :param prog: Program to search
    :returns: Mapping of slab cache name to final merged name
    :raises LookupError: If the helper fails because the debugged kernel
      doesn't have the required configuration
    """
    try:
        slab_kset = prog["slab_kset"]
    except KeyError:
        raise LookupError(
            "Couldn't find SLUB sysfs information: get_slab_cache_aliases() "
            "requires CONFIG_SLUB and CONFIG_SYSFS enabled in the debugged "
            "kernel."
        ) from None
    link_flag = prog.constant("KERNFS_LINK")
    name_map = {}
    for child in rbtree_inorder_for_each_entry(
        "struct kernfs_node",
        slab_kset.kobj.sd.dir.children.address_of_(),
        "rb",
    ):
        if child.flags & link_flag:
            cache = container_of(
                cast("struct kobject *", child.symlink.target_kn.priv),
                "struct kmem_cache",
                "kobj",
            )
            original_name = fsdecode(child.name.string_())
            target_name = fsdecode(cache.name.string_())
            if original_name != target_name:
                name_map[original_name] = target_name
    return name_map


def for_each_slab_cache(prog: Program) -> Iterator[Object]:
    """
    Iterate over all slab caches.

    :return: Iterator of ``struct kmem_cache *`` objects.
    """
    return list_for_each_entry(
        "struct kmem_cache", prog["slab_caches"].address_of_(), "list"
    )


def find_slab_cache(prog: Program, name: Union[str, bytes]) -> Optional[Object]:
    """
    Return the slab cache with the given name.

    :param name: Slab cache name.
    :return: ``struct kmem_cache *``
    """
    if isinstance(name, str):
        name = name.encode()
    for s in for_each_slab_cache(prog):
        if s.name.string_() == name:
            return s
    return None


def print_slab_caches(prog: Program) -> None:
    """Print the name and ``struct kmem_cache *`` value of all slab caches."""
    for s in for_each_slab_cache(prog):
        name = escape_ascii_string(s.name.string_(), escape_backslash=True)
        print(f"{name} ({s.type_.type_name()})0x{s.value_():x}")


# Between SLUB, SLAB, their respective configuration options, and the
# differences between kernel versions, there is a lot of state that we need to
# keep track of to inspect the slab allocator. It isn't pretty, but this class
# and its subclasses track all of that complexity so that we can share code
# between slab helpers.
class _SlabCacheHelper:
    def __init__(self, slab_cache: Object) -> None:
        self._prog = slab_cache.prog_
        self._slab_cache = slab_cache.read_()

    def _page_objects(
        self, page: Object, slab: Object, pointer_type: Type
    ) -> Iterator[Object]:
        raise NotImplementedError()

    def for_each_allocated_object(self, type: Union[str, Type]) -> Iterator[Object]:
        pointer_type = self._prog.pointer_type(self._prog.type(type))
        slab_type = _get_slab_type(self._prog)
        PG_slab_mask = 1 << self._prog.constant("PG_slab")
        for page in for_each_page(self._prog):
            try:
                if not page.flags & PG_slab_mask:
                    continue
            except FaultError:
                continue
            slab = cast(slab_type, page)
            if slab.slab_cache == self._slab_cache:
                yield from self._page_objects(page, slab, pointer_type)

    def object_info(
        self, page: Object, slab: Object, addr: int
    ) -> "Optional[SlabObjectInfo]":
        raise NotImplementedError()


class _SlabCacheHelperSlub(_SlabCacheHelper):
    def __init__(self, slab_cache: Object) -> None:
        super().__init__(slab_cache)

        self._slab_cache_size = slab_cache.size.value_()

        try:
            self._red_left_pad = slab_cache.red_left_pad.value_()
        except AttributeError:
            self._red_left_pad = 0

        # In SLUB, the freelist is a linked list with the next pointer located
        # at ptr + slab_cache->offset.
        freelist_offset = slab_cache.offset.value_()

        # If CONFIG_SLAB_FREELIST_HARDENED is enabled, then the next pointer is
        # obfuscated using slab_cache->random.
        try:
            freelist_random = slab_cache.random.value_()
        except AttributeError:
            self._freelist_dereference: Callable[[int], int] = self._prog.read_word
        else:
            ulong_size = sizeof(self._prog.type("unsigned long"))

            # Since Linux kernel commit 1ad53d9fa3f6 ("slub: improve bit
            # diffusion for freelist ptr obfuscation") in v5.7, a swab() was
            # added to the freelist dereferencing calculation. This commit was
            # backported to all stable branches which have
            # CONFIG_SLAB_FREELIST_HARDENED, but you can still encounter some
            # older stable kernels which don't have it. Unfortunately, there's
            # no easy way to detect whether it is in effect, since the commit
            # adds no struct field or other detectable difference.
            #
            # To handle this, we implement both methods, and we start out with a
            # "trial" function. On the first time we encounter a non-NULL
            # freelist, we try using the method with the swab(), and test
            # whether the resulting pointer may be dereferenced. If it can, we
            # commit to using that method forever. If it cannot, we switch to
            # the version without swab() and commit to using that.

            def _freelist_dereference_swab(ptr_addr: int) -> int:
                # *ptr_addr ^ slab_cache->random ^ byteswap(ptr_addr)
                return (
                    self._prog.read_word(ptr_addr)
                    ^ freelist_random
                    ^ int.from_bytes(ptr_addr.to_bytes(ulong_size, "little"), "big")
                )

            def _freelist_dereference_no_swab(ptr_addr: int) -> int:
                # *ptr_addr ^ slab_cache->random ^ ptr_addr
                return self._prog.read_word(ptr_addr) ^ freelist_random ^ ptr_addr

            def _try_hardened_freelist_dereference(ptr_addr: int) -> int:
                result = _freelist_dereference_swab(ptr_addr)
                if result:
                    try:
                        self._prog.read_word(result)
                        self._freelist_dereference = _freelist_dereference_swab
                    except FaultError:
                        result = _freelist_dereference_no_swab(ptr_addr)
                        self._freelist_dereference = _freelist_dereference_no_swab
                return result

            self._freelist_dereference = _try_hardened_freelist_dereference

        def _slub_get_freelist(freelist: Object, freelist_set: Set[int]) -> None:
            ptr = freelist.value_()
            while ptr:
                freelist_set.add(ptr)
                ptr = self._freelist_dereference(ptr + freelist_offset)

        cpu_freelists: Set[int] = set()
        try:
            # cpu_slab doesn't exist for CONFIG_SLUB_TINY.
            cpu_slab = slab_cache.cpu_slab.read_()
        except AttributeError:
            pass
        else:
            # Since Linux kernel commit bb192ed9aa71 ("mm/slub: Convert most
            # struct page to struct slab by spatch") (in v5.17), the current
            # slab for a CPU is `struct slab *slab`. Before that, it is `struct
            # page *page`.
            cpu_slab_attr = "slab" if hasattr(cpu_slab, "slab") else "page"
            for cpu in for_each_online_cpu(self._prog):
                this_cpu_slab = per_cpu_ptr(cpu_slab, cpu)
                slab = getattr(this_cpu_slab, cpu_slab_attr).read_()
                if slab and slab.slab_cache == slab_cache:
                    _slub_get_freelist(this_cpu_slab.freelist, cpu_freelists)

        self._slub_get_freelist = _slub_get_freelist
        self._cpu_freelists = cpu_freelists

    def _page_objects(
        self, page: Object, slab: Object, pointer_type: Type
    ) -> Iterator[Object]:
        freelist: Set[int] = set()
        self._slub_get_freelist(slab.freelist, freelist)
        addr = page_to_virt(page).value_() + self._red_left_pad
        end = addr + self._slab_cache_size * slab.objects
        while addr < end:
            if addr not in freelist and addr not in self._cpu_freelists:
                yield Object(self._prog, pointer_type, value=addr)
            addr += self._slab_cache_size

    def object_info(self, page: Object, slab: Object, addr: int) -> "SlabObjectInfo":
        first_addr = page_to_virt(page).value_() + self._red_left_pad
        address = (
            first_addr
            + (addr - first_addr) // self._slab_cache_size * self._slab_cache_size
        )
        if address in self._cpu_freelists:
            allocated = False
        else:
            freelist: Set[int] = set()
            self._slub_get_freelist(slab.freelist, freelist)
            allocated = address not in freelist
        return SlabObjectInfo(self._slab_cache, slab, address, allocated)


class _SlabCacheHelperSlab(_SlabCacheHelper):
    def __init__(self, slab_cache: Object) -> None:
        super().__init__(slab_cache)

        self._slab_cache_size = slab_cache.size.value_()

        self._freelist_type = self._prog.type("freelist_idx_t *")
        try:
            self._obj_offset = slab_cache.obj_offset.value_()
        except AttributeError:
            self._obj_offset = 0

        self._slab_cache_num = slab_cache.num.value_()

        cpu_cache = slab_cache.cpu_cache.read_()
        cpu_caches_avail: Set[int] = set()
        for cpu in for_each_online_cpu(self._prog):
            ac = per_cpu_ptr(cpu_cache, cpu)
            for i in range(ac.avail):
                cpu_caches_avail.add(ac.entry[i].value_())
        self._cpu_caches_avail = cpu_caches_avail

    def _slab_freelist(self, slab: Object) -> Set[int]:
        # In SLAB, the freelist is an array of free object indices.
        freelist = cast(self._freelist_type, slab.freelist)
        return {freelist[i].value_() for i in range(slab.active, self._slab_cache_num)}

    def _page_objects(
        self, page: Object, slab: Object, pointer_type: Type
    ) -> Iterator[Object]:
        freelist = self._slab_freelist(slab)
        s_mem = slab.s_mem.value_()
        for i in range(self._slab_cache_num):
            if i in freelist:
                continue
            addr = s_mem + i * self._slab_cache_size + self._obj_offset
            if addr in self._cpu_caches_avail:
                continue
            yield Object(self._prog, pointer_type, value=addr)

    def object_info(self, page: Object, slab: Object, addr: int) -> "SlabObjectInfo":
        s_mem = slab.s_mem.value_()
        object_index = (addr - s_mem) // self._slab_cache_size
        object_address = s_mem + object_index * self._slab_cache_size
        return SlabObjectInfo(
            self._slab_cache,
            slab,
            object_address,
            allocated=object_address not in self._cpu_caches_avail
            and object_index not in self._slab_freelist(slab),
        )


class _SlabCacheHelperSlob(_SlabCacheHelper):
    def for_each_allocated_object(self, type: Union[str, Type]) -> Iterator[Object]:
        raise ValueError("SLOB is not supported")

    def object_info(self, page: Object, slab: Object, addr: int) -> None:
        return None


def _get_slab_cache_helper(slab_cache: Object) -> _SlabCacheHelper:
    prog = slab_cache.prog_
    try:
        type = prog.cache["slab_cache_helper_type"]
    except KeyError:
        try:
            prog.type("freelist_idx_t *")
            type = _SlabCacheHelperSlab
        except LookupError:
            if hasattr(slab_cache, "offset"):
                type = _SlabCacheHelperSlub
            else:
                type = _SlabCacheHelperSlob
        prog.cache["slab_cache_helper_type"] = type
    return type(slab_cache)


def slab_cache_for_each_allocated_object(
    slab_cache: Object, type: Union[str, Type]
) -> Iterator[Object]:
    """
    Iterate over all allocated objects in a given slab cache.

    Only the SLUB and SLAB allocators are supported; SLOB does not store enough
    information to identify objects in a slab cache.

    >>> dentry_cache = find_slab_cache(prog, "dentry")
    >>> next(slab_cache_for_each_allocated_object(dentry_cache, "struct dentry"))
    *(struct dentry *)0xffff905e41404000 = {
        ...
    }

    :param slab_cache: ``struct kmem_cache *``
    :param type: Type of object in the slab cache.
    :return: Iterator of ``type *`` objects.
    """
    return _get_slab_cache_helper(slab_cache).for_each_allocated_object(type)


def _find_containing_slab(
    prog: Program, addr: int
) -> Optional[Tuple[Object, Object, Object]]:
    start_addr = pfn_to_virt(prog["min_low_pfn"]).value_()
    end_addr = (pfn_to_virt(prog["max_low_pfn"]) + prog["PAGE_SIZE"]).value_()
    if addr < start_addr or addr >= end_addr:
        # Not a directly mapped address
        return None

    page = virt_to_page(prog, addr)

    try:
        page = compound_head(page)
        if not PageSlab(page):
            return None
    except FaultError:
        # Page does not exist
        return None

    slab = cast(_get_slab_type(prog), page)
    try:
        return slab.slab_cache, page, slab
    except AttributeError:
        # SLOB
        return None


@overload
def slab_object_info(addr: Object) -> Optional["SlabObjectInfo"]:
    """"""
    ...


@overload
def slab_object_info(prog: Program, addr: IntegerLike) -> "Optional[SlabObjectInfo]":
    """
    Get information about an address if it is in a slab object.

    >>> ptr = find_task(prog, 1).comm.address_of_()
    >>> info = slab_object_info(ptr)
    >>> info
    SlabObjectInfo(slab_cache=Object(prog, 'struct kmem_cache *', address=0xffffdb93c0045e18), slab=Object(prog, 'struct slab *', value=0xffffdb93c0045e00), address=0xffffa2bf81178000, allocated=True)

    Note that :attr:`SlabObjectInfo.address` is the start address of the
    object, which may be less than *addr* if *addr* points to a member inside
    of the object:

    >>> ptr.value_() - info.address
    1496
    >>> offsetof(prog.type("struct task_struct"), "comm")
    1496

    The address can be given as an :class:`~drgn.Object` or as a
    :class:`~drgn.Program` and an integer.

    Note that SLOB does not store enough information to identify slab objects,
    so if the kernel is configured to use SLOB, this will always return
    ``None``.

    :param addr: ``void *``
    :return: :class:`SlabObjectInfo` if *addr* is in a slab object, or ``None``
        if not.
    """
    ...


def slab_object_info(  # type: ignore  # Need positional-only arguments.
    prog_or_addr: Union[Program, Object], addr: Optional[IntegerLike] = None
) -> Optional["SlabObjectInfo"]:
    if addr is None:
        assert isinstance(prog_or_addr, Object)
        prog = prog_or_addr.prog_
        addr = prog_or_addr
    else:
        assert isinstance(prog_or_addr, Program)
        prog = prog_or_addr
    addr = operator.index(addr)
    result = _find_containing_slab(prog, addr)
    if result is None:
        return None
    slab_cache, page, slab = result
    return _get_slab_cache_helper(slab_cache).object_info(page, slab, addr)


class SlabObjectInfo:
    """Information about an object in the slab allocator."""

    slab_cache: Object
    """``struct kmem_cache *`` that the slab object is from."""

    slab: Object
    """
    Slab containing the slab object.

    Since Linux v5.17, this is a ``struct slab *``. Before that, it is a
    ``struct page *``.
    """

    address: int
    """Address of the slab object."""

    allocated: bool
    """``True`` if the object is allocated, ``False`` if it is free."""

    def __init__(
        self, slab_cache: Object, slab: Object, address: int, allocated: bool
    ) -> None:
        self.slab_cache = slab_cache
        self.slab = slab
        self.address = address
        self.allocated = allocated

    def __repr__(self) -> str:
        return f"SlabObjectInfo(slab_cache={self.slab_cache!r}, slab={self.slab!r}, address={hex(self.address)}, allocated={self.allocated})"


@overload
def find_containing_slab_cache(addr: Object) -> Object:
    """"""
    ...


@overload
def find_containing_slab_cache(prog: Program, addr: IntegerLike) -> Object:
    """
    Get the slab cache that an address was allocated from, if any.

    The address can be given as an :class:`~drgn.Object` or as a
    :class:`~drgn.Program` and an integer.

    Note that SLOB does not store enough information to identify objects in a
    slab cache, so if the kernel is configured to use SLOB, this will always
    return ``NULL``.

    :param addr: ``void *``
    :return: ``struct kmem_cache *`` containing *addr*, or ``NULL`` if *addr*
        is not from a slab cache.
    """
    ...


def find_containing_slab_cache(  # type: ignore  # Need positional-only arguments.
    prog_or_addr: Union[Program, Object], addr: Optional[IntegerLike] = None
) -> Object:
    if addr is None:
        assert isinstance(prog_or_addr, Object)
        prog = prog_or_addr.prog_
        addr = prog_or_addr
    else:
        assert isinstance(prog_or_addr, Program)
        prog = prog_or_addr
    addr = operator.index(addr)
    result = _find_containing_slab(prog, addr)
    if result is None:
        return NULL(prog, "struct kmem_cache *")
    return result[0].read_()
