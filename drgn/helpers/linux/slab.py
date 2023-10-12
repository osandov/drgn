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
from drgn.helpers import ValidationError
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.mm import (
    PageSlab,
    compound_head,
    for_each_page,
    page_size,
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
    "slab_cache_for_each_object",
    "slab_cache_for_each_free_object",
    "slab_cache_is_merged",
    "slab_object_info",
    "slab_cache_for_each_slab",
    "slab_cache_validate_object_address",
    "slab_cache_validate_slab",
    "slab_cache_validate_object",
    "slab_cache_validate",
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


def _check_object_bytes(
    slab_cache: Object,
    obj_addr: int,
    what: str,
    start: int,
    key: int,
    size: int,
) -> bool:
    """
    Verify that a specific key is present at all locations of a given area
    within an object.

    param slab_cache: ``struct kmem_cache*``
    param obj_addr: Object address
    param what: Description of what is being searched
    param start: Start of search area
    param key: value to look for in search area
    param size: size of search area

    returns: ``True`` if all bytes in the search area have specified ``key``,
             otherwise return ``False``
    """
    fault = 0
    val = b"\x00"
    prog = slab_cache.prog_

    # Find first occurence of invalid value
    for cnt in range(size):
        val = prog.read(start + cnt, 1)
        if val != key.to_bytes(1, "little"):
            fault = start + cnt
            break
    if not fault:
        return True

    # Find last occurence of invalid value
    end = start + size
    while end > fault:
        if prog.read(end - 1, 1) != key.to_bytes(1, "little"):
            break
        end -= 1

    print(
        "Slab-cache:",
        slab_cache.name.string_(),
        "Object:",
        hex(obj_addr),
        what,
        "overwritten",
    )
    print(
        "Info: ",
        hex(fault),
        "-",
        hex(end - 1),
        " @offset=",
        fault - obj_addr,
        "First byte",
        val.hex(),
        "instead of",
        hex(key),
    )

    return False


def slab_cache_for_each_slab(slab_cache: Object) -> Iterator[Object]:
    """
    Iterate over all slabs of a given slab cache.

    Only the SLUB and SLAB allocators are supported.

    :param slab_cache: ``struct kmem_cache *``
    :return: Iterator of ``slab or page`` objects.
    """
    prog = slab_cache.prog_
    slab_type = _get_slab_type(prog)

    PG_slab_mask = 1 << prog.constant("PG_slab")
    for page in for_each_page(prog):
        try:
            if not page.flags & PG_slab_mask:
                continue
        except FaultError:
            continue
        slab = cast(slab_type, page)
        if slab.slab_cache == slab_cache:
            yield slab


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
    POISON_INUSE = b"\x5a"
    POISON_FREE = b"\x6b"
    POISON_END = b"\xa5"
    SLAB_RED_ZONE = 0x00000400
    SLAB_POISON = 0x00000800
    SLAB_KMALLOC = 0x00001000
    SLAB_STORE_USER = 0x00010000

    def __init__(self, slab_cache: Object) -> None:
        self._prog = slab_cache.prog_
        self._slab_cache = slab_cache.read_()

    def _debug_redzone(self) -> bool:
        return self._slab_cache.flags.value_() & self.SLAB_RED_ZONE

    def _debug_poison(self) -> bool:
        return self._slab_cache.flags.value_() & self.SLAB_POISON

    def _debug_storeuser(self) -> bool:
        return self._slab_cache.flags.value_() & self.SLAB_STORE_USER

    def _is_kmalloc_slab(self) -> bool:
        return self._slab_cache.flags.value_() & self.SLAB_KMALLOC

    def _page_allocated_objects(
        self, page: Object, slab: Object, pointer_type: Type
    ) -> Iterator[Object]:
        raise NotImplementedError()

    def _page_free_objects(
        self, page: Object, slab: Object, pointer_type: Type
    ) -> Iterator[Object]:
        raise NotImplementedError()

    def _page_all_objects(
        self, page: Object, slab: Object, pointer_type: Type
    ) -> Iterator[Object]:
        raise NotImplementedError()

    def for_each_allocated_object(self, type: Union[str, Type]) -> Iterator[Object]:
        pointer_type = self._prog.pointer_type(self._prog.type(type))
        page_type = self._prog.type("struct page *")
        for slab in slab_cache_for_each_slab(self._slab_cache):
            page = cast(page_type, slab)
            yield from self._page_allocated_objects(page, slab, pointer_type)

    def for_each_object(self, type: Union[str, Type]) -> Iterator[Object]:
        pointer_type = self._prog.pointer_type(self._prog.type(type))
        page_type = self._prog.type("struct page *")
        for slab in slab_cache_for_each_slab(self._slab_cache):
            page = cast(page_type, slab)
            yield from self._page_all_objects(page, slab, pointer_type)

    def for_each_free_object(self, type: Union[str, Type]) -> Iterator[Object]:
        raise NotImplementedError()

    def object_info(
        self, page: Object, slab: Object, addr: int
    ) -> "Optional[SlabObjectInfo]":
        raise NotImplementedError()

    def validate_object_address(self, slab: Object, ptr: IntegerLike) -> None:
        raise NotImplementedError()

    def validate_slab(self, slab: Object) -> None:
        raise NotImplementedError()

    def validate_object(self, object_address: int, free: bool) -> None:
        raise NotImplementedError()

    def validate(self, type: Union[str, Type]) -> None:
        raise NotImplementedError()


class _SlabCacheHelperSlub(_SlabCacheHelper):
    SLUB_RED_INACTIVE = b"\xbb"
    SLUB_RED_ACTIVE = b"\xcc"
    OBJECT_POISON = 0x80000000

    def __init__(self, slab_cache: Object) -> None:
        super().__init__(slab_cache)

        self._slab_cache_size = slab_cache.size.value_()

        try:
            self._red_left_pad = slab_cache.red_left_pad.value_()
        except AttributeError:
            self._red_left_pad = 0

        self._inuse = slab_cache.inuse.value_()
        self._object_size = slab_cache.object_size.value_()

        # In SLUB, the freelist is a linked list with the next pointer located
        # at ptr + slab_cache->offset.
        freelist_offset = slab_cache.offset.value_()
        self._freelist_offset = freelist_offset

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

    def _slub_object_poison(self) -> bool:
        return self._slab_cache.flags.value_() & self.OBJECT_POISON

    def _page_allocated_objects(
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

    def _page_free_objects(
        self, page: Object, slab: Object, pointer_type: Type
    ) -> Iterator[Object]:
        freelist: Set[int] = set()
        self._slub_get_freelist(slab.freelist, freelist)
        for addr in freelist:
            yield Object(self._prog, pointer_type, value=addr)

    def _page_all_objects(
        self, page: Object, slab: Object, pointer_type: Type
    ) -> Iterator[Object]:
        addr = page_to_virt(page).value_() + self._red_left_pad
        end = addr + self._slab_cache_size * slab.objects
        while addr < end:
            yield Object(self._prog, pointer_type, value=addr)
            addr += self._slab_cache_size

    def for_each_free_object(self, type: Union[str, Type]) -> Iterator[Object]:
        pointer_type = self._prog.pointer_type(self._prog.type(type))
        page_type = self._prog.type("struct page *")

        # Return objects on lockless freelist first
        for addr in self._cpu_freelists:
            yield Object(self._prog, pointer_type, value=addr)

        # Return objects on each slab's regular freelist
        for slab in slab_cache_for_each_slab(self._slab_cache):
            page = cast(page_type, slab)
            yield from self._page_free_objects(page, slab, pointer_type)

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

    def validate_object_address(self, slab: Object, ptr: IntegerLike) -> None:
        prog = self._prog
        page_type = prog.type("struct page *")
        page = cast(page_type, slab)
        base = page_to_virt(page).value_()
        objects = slab.objects.value_()

        # ptr is object address seen by clients i.e ptr is address
        # of object's payload area. For upcoming calculations we
        # need to move to actual start address of object.
        ptr = ptr - self._red_left_pad
        if ptr < base:
            raise ValidationError(
                f" Address: {hex(ptr + self._red_left_pad)} is not a valid slab address"
                f" 'because \"address - red_left_pad\" comes before slab's start.'"
                f" slab start: {hex(base)} red_left_pad: {self._red_left_pad}"
            )
        elif ptr >= (base + objects * self._slab_cache_size):
            raise ValidationError(
                f" Address: {hex(ptr + self._red_left_pad)} is not a valid slab address"
                f" because it comes after slab's end: {hex(base + objects * self._slab_cache_size)}"
            )
        elif (ptr - base) % self._slab_cache_size:
            raise ValidationError(
                f" Address: {hex(ptr + self._red_left_pad)} is not a valid slab address"
                f' because "address - red_left_pad" is not at valid offset.'
                f" Slab start: {hex(base)} red_left_pad: {self._red_left_pad} Object size: {self._slab_cache_size}"
            )

        return

    def validate_slab(self, slab: Object) -> None:
        prog = self._prog
        page_type = prog.type("struct page *")
        page = cast(page_type, slab)

        def _check_slab_pad() -> None:
            val = b"\x00"
            fault = 0
            start = page_to_virt(page).value_()
            length = page_size(page)
            end = start + length
            remainder = length % self._slab_cache_size
            if not remainder:
                return
            pad = end - remainder
            for cnt in range(remainder):
                val = prog.read(pad + cnt, 1)
                if val != self.POISON_INUSE:
                    fault = pad + cnt
                    break

            if not fault:
                return

            while end > fault:
                if prog.read(end - 1, 1) == self.POISON_INUSE:
                    end -= 1
                else:
                    break

            raise ValidationError(
                f" Slab-cache: {self._slab_cache.name.string_().decode()} page: {page.value_()}"
                f" Padding overwritten. {hex(fault)} - {hex(end - 1)} @offset= {hex(fault - start)}"
            )

        PG_slab_mask = 1 << prog.constant("PG_slab")
        if not page.flags & PG_slab_mask:
            raise ValidationError("Not a valid slab because PG_slab flag is not set")

        if slab.slab_cache != self._slab_cache:
            raise ValidationError(
                "Not a valid slab because it belongs to a different slab cache"
            )

        maxobjs = page_size(page) / self._slab_cache_size  # max objects per slab
        inuse = slab.inuse.value_()
        objects = slab.objects.value_()
        if objects > maxobjs:
            raise ValidationError(
                f" slab: {hex(slab.value_())} objects: hex{objects} > maxobjs (i.e oo): {maxobjs}"
            )

        if inuse > objects:
            raise ValidationError(
                f" slab: {hex(slab.value_())} inuse: {inuse} > objects: {objects}"
            )

        if self._debug_poison():
            _check_slab_pad()

    def validate_object(self, obj_addr: int, free: bool) -> None:
        prog = self._prog
        if free:
            key = int.from_bytes(self.SLUB_RED_INACTIVE, "little")
        else:
            key = int.from_bytes(self.SLUB_RED_ACTIVE, "little")

        def _check_object_pad_bytes() -> bool:
            if self._freelist_offset >= self._inuse:
                padoff = self._inuse + sizeof(prog.type("void *"))
            else:
                padoff = self._inuse

            if self._debug_storeuser():
                padoff += 2 * sizeof(prog.type("struct track"))

            if self._debug_redzone():
                size_from_object = self._slab_cache_size - self._red_left_pad
            else:
                size_from_object = self._slab_cache_size

            if size_from_object == padoff:
                return True

            return _check_object_bytes(
                self._slab_cache,
                obj_addr,
                "Object padding",
                obj_addr + padoff,
                int.from_bytes(self.POISON_INUSE, "little"),
                size_from_object - padoff,
            )

        left_redzone_start = obj_addr - self._red_left_pad
        endobject = obj_addr + self._object_size

        if self._debug_redzone():
            # Check left redzone
            if not _check_object_bytes(
                self._slab_cache,
                obj_addr,
                "Left Redzone",
                left_redzone_start,
                key,
                self._red_left_pad,
            ):
                raise ValidationError("Left Redzone corrupted")

            # Check right redzone
            if not _check_object_bytes(
                self._slab_cache,
                obj_addr,
                "Right Redzone",
                endobject,
                key,
                self._inuse - self._object_size,
            ):
                raise ValidationError("Right Redzone corrupted")
        else:
            # Check poison value in padding bytes
            if self._debug_poison() and self._object_size < self._inuse:
                if not _check_object_bytes(
                    self._slab_cache,
                    obj_addr,
                    "Alignment padding",
                    endobject,
                    int.from_bytes(self.POISON_INUSE, "little"),
                    self._inuse - self._object_size,
                ):
                    raise ValidationError("Alignment padding corrupted")

        if self._debug_poison():
            if (
                key == int.from_bytes(self.SLUB_RED_INACTIVE, "little")
                and self._slub_object_poison()
            ):
                if not _check_object_bytes(
                    self._slab_cache,
                    obj_addr,
                    "Poison",
                    obj_addr,
                    int.from_bytes(self.POISON_FREE, "little"),
                    self._object_size - 1,
                ):
                    raise ValidationError("Poison pattern is not matching POISON_FREE")

                if not _check_object_bytes(
                    self._slab_cache,
                    obj_addr,
                    "Poison",
                    endobject - 1,
                    int.from_bytes(self.POISON_END, "little"),
                    1,
                ):
                    raise ValidationError("Poison pattern is not matching POISON_END")

            if not _check_object_pad_bytes():
                raise ValidationError("Padding bytes corrupted")

    def validate(self, type: Union[str, Type]) -> None:
        self._num_checked_slabs = 0
        self._num_checked_free_objects = 0
        self._num_checked_allocated_objects = 0
        pointer_type = self._prog.pointer_type(self._prog.type(type))
        page_type = self._prog.type("struct page *")
        slab_cache = self._slab_cache
        prog = self._prog
        name = escape_ascii_string(slab_cache.name.string_(), escape_backslash=True)
        print(
            "Starting consistency check for:",
            f"{name} ({slab_cache.type_.type_name()})0x{slab_cache.value_():x}",
        )

        # Check slabs as a whole first
        print("Start checking individual slabs.")
        for slab in slab_cache_for_each_slab(slab_cache):
            self._num_checked_slabs += 1
            print("Checking slab: ", hex(slab.value_()))
            try:
                self.validate_slab(slab)
            except ValidationError as e:
                print("slab in wrong state", e)
        print("Finished checking individual slabs.")

        if not self._num_checked_slabs:
            print("Found no slabs.")
            return

        # Check per-cpu lockless freelist.
        # Here we first check that pointers on freelist are valid pointers (to
        # catch freelist corruption) and only for valid pointers, we go ahead
        # and check pointed to object.
        # Also while checking lockless freelist we go one cpu at a time, so that
        # we have track of per-cpu active slab needed for checking validity of
        # pointers on per-cpu lockless freelist
        print("Start checking free objects.")
        lockless_freelist: Set[int] = set()
        cpu_slab = slab_cache.cpu_slab.read_()
        cpu_slab_attr = "slab" if hasattr(cpu_slab, "slab") else "page"
        for cpu in for_each_online_cpu(prog):
            this_cpu_slab = per_cpu_ptr(cpu_slab, cpu)
            slab = getattr(this_cpu_slab, cpu_slab_attr).read_()
            lockless_freelist.clear()
            if slab and slab.slab_cache == slab_cache:
                self._slub_get_freelist(this_cpu_slab.freelist, lockless_freelist)
                for obj_addr in lockless_freelist:
                    self._num_checked_free_objects += 1
                    try:
                        self.validate_object_address(slab, obj_addr)
                        try:
                            self.validate_object(obj_addr, True)
                        except ValidationError as e:
                            print(e)
                    except ValidationError as e:
                        print(e)
        # Check regular freelist of each slab
        for slab in slab_cache_for_each_slab(slab_cache):
            page = cast(page_type, slab)
            for obj in self._page_free_objects(page, slab, pointer_type):
                self._num_checked_free_objects += 1
                try:
                    self.validate_object_address(slab, obj.value_())
                    try:
                        self.validate_object(obj.value_(), True)
                    except ValidationError as e:
                        print(e)
                except ValidationError as e:
                    print(e)
        print("Finished checking free objects.")

        # Check allocated objects
        print("Start checking allocated objects.")
        for obj in self.for_each_allocated_object(pointer_type):
            self._num_checked_allocated_objects += 1
            try:
                self.validate_object(obj.value_(), False)
            except ValidationError as e:
                print(e)
        print("Finished checking allocated objects.")

        print(
            "Finished consistency check for slab-cache:",
            slab_cache.name.string_().decode(),
        )
        print("Number of checked slabs:", self._num_checked_slabs)
        print(
            "Number of checked allocated objects:", self._num_checked_allocated_objects
        )
        print("Number of checked free objects:", self._num_checked_free_objects)


class _SlabCacheHelperSlab(_SlabCacheHelper):
    RED_INACTIVE = 0x09F911029D74E35B
    RED_ACTIVE = 0xD84156C5635688C0

    def __init__(self, slab_cache: Object) -> None:
        super().__init__(slab_cache)

        self._slab_cache_size = slab_cache.size.value_()

        self._freelist_type = self._prog.type("freelist_idx_t *")
        try:
            self._obj_offset = slab_cache.obj_offset.value_()
        except AttributeError:
            self._obj_offset = 0

        self._slab_cache_num = slab_cache.num.value_()
        self._slab_cache_object_size = slab_cache.object_size.value_()
        self._redzone_size = sizeof(self._prog.type("unsigned long long"))
        self._caller_size = sizeof(self._prog.type("unsigned long long"))

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

    def _page_allocated_objects(
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

    def _page_free_objects(
        self, page: Object, slab: Object, pointer_type: Type
    ) -> Iterator[Object]:
        freelist = self._slab_freelist(slab)
        s_mem = slab.s_mem.value_()
        free_objects: Set[int] = set()
        for i in freelist:
            addr = s_mem + i * self._slab_cache_size + self._obj_offset
            free_objects.add(addr)
        for addr in free_objects:
            yield Object(self._prog, pointer_type, value=addr)

    def _page_all_objects(
        self, page: Object, slab: Object, pointer_type: Type
    ) -> Iterator[Object]:
        s_mem = slab.s_mem.value_()
        for i in range(self._slab_cache_num):
            addr = s_mem + i * self._slab_cache_size + self._obj_offset
            yield Object(self._prog, pointer_type, value=addr)

    def for_each_free_object(self, type: Union[str, Type]) -> Iterator[Object]:
        pointer_type = self._prog.pointer_type(self._prog.type(type))
        page_type = self._prog.type("struct page *")

        # Return per-cpu free objects first
        for addr in self._cpu_caches_avail:
            yield Object(self._prog, pointer_type, value=addr)

        # Return free objects on each slab
        for slab in slab_cache_for_each_slab(self._slab_cache):
            page = cast(page_type, slab)
            yield from self._page_free_objects(page, slab, pointer_type)

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

    def validate_object_address(self, slab: Object, ptr: IntegerLike) -> None:
        s_mem = slab.s_mem.value_()

        # ptr is object address seen by clients i.e ptr is address
        # of object's payload area. For upcoming calculations we
        # need to move to actual start address of object.
        ptr = ptr - self._obj_offset
        if ptr < s_mem:
            raise ValidationError(
                f" Address: {hex(ptr + self._obj_offset)} is not a valid slab address"
                f" 'because \"address - obj_offset\" comes before start of slab's object area.'"
                f" s_mem: {hex(s_mem)} obj_offset: {self._obj_offset}"
            )
        elif (ptr - s_mem) % self._slab_cache_size:
            raise ValidationError(
                f" Address: {hex(ptr + self._obj_offset)} is not a valid slab address"
                f" 'because \"address - obj_offset\" is not at valid offset.'"
                f" s_mem: {hex(s_mem)} Object size: hex{self._slab_cache_size} obj_offset: hex(self._obj_offset)"
            )

        return

    def validate_slab(self, slab: Object) -> None:
        prog = self._prog
        page_type = prog.type("struct page *")
        page = cast(page_type, slab)
        PG_slab_mask = 1 << prog.constant("PG_slab")
        if not page.flags & PG_slab_mask:
            raise ValidationError("Not a valid slab because PG_slab flag is not set")

        if slab.slab_cache != self._slab_cache:
            raise ValidationError(
                "Not a valid slab because it belongs to a different slab cache"
            )

    def validate_object(self, obj_addr: int, free: bool) -> None:
        prog = self._prog
        slab_cache_size = self._slab_cache_size
        slab_cache_object_size = self._slab_cache_object_size
        redzone_size = self._redzone_size
        caller_size = self._caller_size
        left_redzone_start = obj_addr - redzone_size
        obj_offset = self._obj_offset
        if self._debug_storeuser():
            right_redzone_start = (
                obj_addr - obj_offset + slab_cache_size - caller_size - redzone_size
            )
        else:
            right_redzone_start = obj_addr - obj_offset + slab_cache_size - redzone_size

        # Get redzone on both sides of the object
        redzone1 = int.from_bytes(prog.read(left_redzone_start, redzone_size), "little")
        redzone2 = int.from_bytes(
            prog.read(right_redzone_start, redzone_size), "little"
        )

        if free:
            # Free objects should have _RED_INACTIVE in redzones on both sides, should have _POISON_FREE in all
            # bytes of object's payload area except the last byte and should have _POISON_END in the last byte
            # of object's payload area
            if self._debug_redzone():
                # Check redzone on both sides of the object
                if redzone1 != self.RED_INACTIVE or redzone2 != self.RED_INACTIVE:
                    raise ValidationError(
                        f" Slab cache: {self._slab_cache.value_()} object: {hex(obj_addr)} double free or out of bound access detected"
                    )

                if self._debug_poison():
                    if not _check_object_bytes(
                        self._slab_cache,
                        obj_addr,
                        "Poison",
                        obj_addr,
                        int.from_bytes(self.POISON_FREE, "little"),
                        slab_cache_object_size - 1,
                    ):
                        raise ValidationError("Poison pattern not matching POISON_FREE")

                    if not _check_object_bytes(
                        self._slab_cache,
                        obj_addr,
                        "Poison",
                        obj_addr + slab_cache_object_size - 1,
                        int.from_bytes(self.POISON_END, "little"),
                        1,
                    ):
                        raise ValidationError("Poison pattern not matching POISON_END")

        else:
            if self._debug_redzone():
                # Check redzone on both sides of the object
                if redzone1 == self.RED_INACTIVE and redzone2 == self.RED_INACTIVE:
                    raise ValidationError(
                        f" Slab cache: {self._slab_cache.value_()} object: {hex(obj_addr)} double free detected"
                    )
                elif redzone1 == self.RED_ACTIVE and redzone2 == self.RED_INACTIVE:
                    raise ValidationError(
                        f" Slab cache: {self._slab_cache.value_()} object: {hex(obj_addr)} right redzone overwritten"
                    )
                elif redzone1 == self.RED_INACTIVE and redzone2 == self.RED_ACTIVE:
                    raise ValidationError(
                        f" Slab cache: {self._slab_cache.value_()} object: {hex(obj_addr)} left redzone overwritten"
                    )

    def validate(self, type: Union[str, Type]) -> None:
        self._num_checked_free_objects = 0
        self._num_checked_allocated_objects = 0
        pointer_type = self._prog.pointer_type(self._prog.type(type))
        slab_cache = self._slab_cache
        name = escape_ascii_string(slab_cache.name.string_(), escape_backslash=True)
        print(
            "Starting consistency check for:",
            f"{name} ({slab_cache.type_.type_name()})0x{slab_cache.value_():x}",
        )

        # Check free objects
        print("Start checking free objects.")
        for obj in self.for_each_free_object(pointer_type):
            self._num_checked_free_objects += 1
            try:
                self.validate_object(obj.value_(), True)
            except ValidationError as e:
                print(e)
        print("Finished checking free objects.")

        # Check allocated objects
        print("Start checking allocated objects.")
        for obj in self.for_each_allocated_object(pointer_type):
            self._num_checked_allocated_objects += 1
            try:
                self.validate_object(obj.value_(), False)
            except ValidationError as e:
                print(e)
        print("Finished checking allocated objects.")

        print(
            "Finished consistency check for slab-cache:",
            slab_cache.name.string_().decode(),
        )
        print(
            "Number of checked allocated objects:", self._num_checked_allocated_objects
        )
        print("Number of checked free objects:", self._num_checked_free_objects)


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


def slab_cache_for_each_object(
    slab_cache: Object, type: Union[str, Type]
) -> Iterator[Object]:
    """
    Iterate over all objects in a given slab cache.

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
    return _get_slab_cache_helper(slab_cache).for_each_object(type)


def slab_cache_for_each_free_object(
    slab_cache: Object, type: Union[str, Type]
) -> Iterator[Object]:
    """
    Iterate over all free objects in a given slab cache.

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
    return _get_slab_cache_helper(slab_cache).for_each_free_object(type)


def slab_cache_validate_object_address(
    slab_cache: Object, slab: Object, ptr: IntegerLike
) -> None:
    """
    Check if ``ptr`` is a valid ``object`` address.

    :param slab_cache: ``struct kmem_cache *``
    :param slab: ``struct slab/page *``
    :param ptr: ``Address to check``
    :return: ``True`` if ptr is valid, ``False`` otherwise.

    In this case a valid object address is the address seen by clients
    (i.e start address of its payload area) not the actual start address
    of object.
    This distinction is important because for cases involving
    debug options the overall start area of object may lie few bytes
    before the payload area and in those cases if we are checking
    address of payload area against the start of slab, that address
    may not be at proper(multiple of size) offset from start of slab.
    """
    _get_slab_cache_helper(slab_cache).validate_object_address(slab, ptr)
    return


def slab_cache_validate_slab(slab_cache: Object, slab: Object) -> None:
    """
    Check a given slab of specified slab cache.

    :param slab_cache: ``struct kmem_cache *``
    :param slab: ``struct slab/page *``
    :returns: ``True`` if ``slab`` is valid, ``False`` otherwise
    """
    _get_slab_cache_helper(slab_cache).validate_slab(slab)


def slab_cache_validate_object(slab_cache: Object, obj_addr: int, free: bool) -> None:
    """
    Check if object at address ``obj_addr`` is in proper state or not.
    It is assumed that ``obj_addr`` is a valid pointer for this
    ``slab_cache``

    :param slab_cache: ``struct kmem_cache *``
    :param obj_addr: ``Address of object``
    :param free: ``True if we are checking a free object. False otherwise``

    :returns: ``True`` if the object is in proper state, otherwise return
              ``False``
    """
    _get_slab_cache_helper(slab_cache).validate_object(obj_addr, free)


def slab_cache_validate(slab_cache: Object, type: Union[str, Type]) -> None:
    """
    Check consistency of a given slab cache
       Perform following checks in the same order
       1. Check sanity of all slabs
       2. Check per-cpu lockless freelist
              i. Pointers lying on freelist should be valid object addresses
                 for this slab-cache
              ii. Objects pointed by these pointers should be in proper state
                 i.e Redzone and/or Poison values should be correct (if present)
       3. Check per-slab regular freelist
              i. Pointers lying on freelist should be valid object addresses
                 for this slab-cache
              ii. Objects pointed by these pointers should be in proper state
                 i.e Redzone and/or Poison values should be correct (if present)
       4. Check all allocated objects have correct Redzone and/or Poison values
          (if present)

    param slab_cache: ``strucy kmem_cache*`` for slab cache to check
    param type: ``type`` of slab cache objects

    returns: ``True`` if all consistency checks pass, otherwise return ``False``
    """
    _get_slab_cache_helper(slab_cache).validate(type)


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
