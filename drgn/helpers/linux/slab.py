# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

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

from typing import Iterator, Optional, Set, Union

from drgn import FaultError, Object, Program, Type, cast
from drgn.helpers import escape_ascii_string
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.mm import for_each_page, page_to_virt
from drgn.helpers.linux.percpu import per_cpu_ptr

__all__ = (
    "find_slab_cache",
    "for_each_slab_cache",
    "print_slab_caches",
    "slab_cache_for_each_allocated_object",
)


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
    prog = slab_cache.prog_
    slab_cache_size = slab_cache.size.value_()
    pointer_type = prog.pointer_type(prog.type(type))

    try:
        freelist_type = prog.type("freelist_idx_t *")
        slub = False
    except LookupError:
        slub = True

    if slub:
        try:
            red_left_pad = slab_cache.red_left_pad.value_()
        except AttributeError:
            red_left_pad = 0

        try:
            freelist_offset = slab_cache.offset.value_()
        except AttributeError:
            raise ValueError("SLOB is not supported") from None

        def _slub_get_freelist(freelist: Object, freelist_set: Set[int]) -> None:
            # In SLUB, the freelist is a linked list with the next pointer
            # located at ptr + slab_cache->offset.
            ptr = freelist.value_()
            while ptr:
                freelist_set.add(ptr)
                ptr = prog.read_word(ptr + freelist_offset)

        cpu_freelists: Set[int] = set()
        cpu_slab = slab_cache.cpu_slab.read_()
        for cpu in for_each_online_cpu(prog):
            _slub_get_freelist(per_cpu_ptr(cpu_slab, cpu).freelist, cpu_freelists)

        def _slab_page_objects(page: Object, slab: Object) -> Iterator[Object]:
            freelist: Set[int] = set()
            _slub_get_freelist(slab.freelist, freelist)
            addr = page_to_virt(page).value_() + red_left_pad
            end = addr + slab_cache_size * slab.objects
            while addr < end:
                if addr not in freelist and addr not in cpu_freelists:
                    yield Object(prog, pointer_type, value=addr)
                addr += slab_cache_size

    else:
        try:
            obj_offset = slab_cache.obj_offset.value_()
        except AttributeError:
            obj_offset = 0

        slab_cache_num = slab_cache.num.value_()

        cpu_cache = slab_cache.cpu_cache.read_()
        cpu_caches_avail: Set[int] = set()
        for cpu in for_each_online_cpu(prog):
            ac = per_cpu_ptr(cpu_cache, cpu)
            for i in range(ac.avail):
                cpu_caches_avail.add(ac.entry[i].value_())

        def _slab_freelist(slab: Object) -> Set[int]:
            # In SLAB, the freelist is an array of free object indices.
            freelist = cast(freelist_type, slab.freelist)
            return {freelist[i].value_() for i in range(slab.active, slab_cache_num)}

        def _slab_page_objects(page: Object, slab: Object) -> Iterator[Object]:
            freelist = _slab_freelist(slab)
            s_mem = slab.s_mem.value_()
            for i in range(slab_cache_num):
                if i in freelist:
                    continue
                addr = s_mem + i * slab_cache_size + obj_offset
                if addr in cpu_caches_avail:
                    continue
                yield Object(prog, pointer_type, value=addr)

    # Linux kernel commit d122019bf061cccc4583eb9ad40bf58c2fe517be ("mm: Split
    # slab into its own type") (in v5.17) moved slab information from struct
    # page to struct slab. The former can be casted to the latter.
    try:
        slab_type = prog.type("struct slab *")
    except LookupError:
        slab_type = prog.type("struct page *")

    PG_slab_mask = 1 << prog.constant("PG_slab")
    for page in for_each_page(prog):
        try:
            if not page.flags & PG_slab_mask:
                continue
        except FaultError:
            continue
        slab = cast(slab_type, page)
        if slab.slab_cache == slab_cache:
            yield from _slab_page_objects(page, slab)
