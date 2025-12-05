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

import functools
import operator
import os
from typing import Callable, Dict, Iterator, NamedTuple, Optional, Set, Tuple, Union

from drgn import (
    NULL,
    FaultError,
    IntegerLike,
    Object,
    ObjectNotFoundError,
    Program,
    ProgramFlags,
    Type,
    cast,
    container_of,
    sizeof,
)
from drgn.helpers import ValidationError
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.list import list_for_each_entry, validate_list_for_each_entry
from drgn.helpers.linux.mm import (
    PageSlab,
    _get_PageSlab_impl,
    compound_head,
    for_each_page,
    in_direct_map,
    page_to_virt,
    virt_to_page,
)
from drgn.helpers.linux.nodemask import for_each_online_node, nr_node_ids
from drgn.helpers.linux.percpu import per_cpu_ptr
from drgn.helpers.linux.rbtree import rbtree_inorder_for_each_entry
from drgn.helpers.linux.vmstat import global_node_page_state

__all__ = (
    "find_containing_slab_cache",
    "find_slab_cache",
    "for_each_slab_cache",
    "get_slab_cache_aliases",
    "print_slab_caches",
    "slab_cache_for_each_allocated_object",
    "slab_cache_is_merged",
    "slab_cache_objects_per_slab",
    "slab_cache_order",
    "slab_cache_pages_per_slab",
    "slab_cache_usage",
    "slab_object_info",
    "slab_total_usage",
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


_OO_SHIFT = 16
_OO_MASK = (1 << _OO_SHIFT) - 1


def slab_cache_objects_per_slab(slab_cache: Object) -> int:
    """
    Get the number of objects in each slab of the given slab cache.

    This is only applicable to the SLUB and SLAB allocators; SLOB is not
    supported.

    :param slab_cache: ``struct kmem_cache *``
    """
    try:
        oo = slab_cache.oo
    except AttributeError:
        try:
            return slab_cache.num.value_()  # SLAB
        except AttributeError:
            raise ValueError("SLOB is not supported") from None
    else:
        return oo.x.value_() & _OO_MASK  # SLUB


def slab_cache_pages_per_slab(slab_cache: Object) -> int:
    """
    Get the number of pages allocated for each slab of the given slab cache.

    This is only applicable to the SLUB and SLAB allocators; SLOB is not
    supported.

    :param slab_cache: ``struct kmem_cache *``
    """
    return 1 << slab_cache_order(slab_cache)


def slab_cache_order(slab_cache: Object) -> int:
    """
    Get the allocation order (i.e., base 2 logarithm of the number of pages)
    for each slab of the given slab cache.

    This is only applicable to the SLUB and SLAB allocators; SLOB is not
    supported.

    >>> 1 << slab_cache_order(slab_cache) == slab_cache_pages_per_slab(slab_cache)
    True

    :param slab_cache: ``struct kmem_cache *``
    """
    try:
        oo = slab_cache.oo
    except AttributeError:
        try:
            return slab_cache.gfporder.value_()  # SLAB
        except AttributeError:
            raise ValueError("SLOB is not supported") from None
    else:
        return oo.x.value_() >> _OO_SHIFT  # SLUB


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

        find_slab_cache("bar")

    And the following will also return ``struct bar *`` objects errantly casted to
    ``struct foo *``::

        slab_cache_for_each_allocated_object(find_slab_cache("foo"), "struct foo")

    Unfortunately, these issues are difficult to work around generally, so one
    must be prepared to handle them on a case-by-case basis (e.g., by looking
    up the slab cache by its variable name and by checking that members of the
    structure make sense for the expected type).

    :param slab_cache: ``struct kmem_cache *``
    """
    return slab_cache.refcount > 1


@takes_program_or_default
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

    >>> cache_to_merged = get_slab_cache_aliases()
    >>> cache_to_merged["dnotify_struct"]
    'avc_xperms_data'
    >>> "avc_xperms_data" in cache_to_merged
    False
    >>> find_slab_cache("dnotify_struct") is None
    True
    >>> find_slab_cache("avc_xperms_data") is None
    False

    :warning: This function will only work on kernels which are built with
      ``CONFIG_SLUB`` and ``CONFIG_SYSFS`` enabled.

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
            original_name = os.fsdecode(child.name.string_())
            target_name = os.fsdecode(cache.name.string_())
            if original_name != target_name:
                name_map[original_name] = target_name
    return name_map


@takes_program_or_default
def for_each_slab_cache(prog: Program) -> Iterator[Object]:
    """
    Iterate over all slab caches.

    :return: Iterator of ``struct kmem_cache *`` objects.
    """
    return list_for_each_entry(
        "struct kmem_cache", prog["slab_caches"].address_of_(), "list"
    )


@takes_program_or_default
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


@takes_program_or_default
def print_slab_caches(prog: Program) -> None:
    """Print the name and ``struct kmem_cache *`` value of all slab caches."""
    for s in for_each_slab_cache(prog):
        name = escape_ascii_string(s.name.string_(), escape_backslash=True)
        print(f"{name} ({s.type_.type_name()})0x{s.value_():x}")


class SlabCorruptionError(ValidationError):
    """
    Error raised when a corruption is encountered in a slab allocator data
    structure.
    """


class SlabFreelistCycleError(SlabCorruptionError):
    """
    Error raised when a cycle is encountered in a slab allocator freelist.
    """


class SlabPartialListError(SlabCorruptionError):
    """
    Error raised when a corruption is encountered in a list of partial slabs.
    """


# Get the name of a slab cache or fall back to a placeholder.
def _slab_cache_name(slab_cache: Object) -> str:
    try:
        return os.fsdecode(slab_cache.name.string_())
    except FaultError:
        return "slab cache"


# Between SLUB, SLAB, their respective configuration options, and the
# differences between kernel versions, there is a lot of state that we need to
# keep track of to inspect the slab allocator. It isn't pretty, but this class
# and its subclasses track all of that complexity so that we can share code
# between slab helpers.
class _SlabCacheHelper:
    def __init__(self, slab_cache: Object) -> None:
        self._prog = slab_cache.prog_
        self._slab_cache = slab_cache.read_()

    # Not all of the methods need this, so cache it lazily.
    @functools.cached_property
    def _slab_cache_size(self) -> int:
        return self._slab_cache.size.value_()

    def usage(self) -> "SlabCacheUsage":
        raise NotImplementedError()

    def _page_objects(
        self, page: Object, slab: Object, pointer_type: Type
    ) -> Iterator[Object]:
        raise NotImplementedError()

    def for_each_allocated_object(self, type: Union[str, Type]) -> Iterator[Object]:
        pointer_type = self._prog.pointer_type(self._prog.type(type))
        slab_type = _get_slab_type(self._prog)
        # Get the underlying implementation directly to avoid overhead on each
        # page.
        PageSlab = _get_PageSlab_impl(self._prog)
        for page in for_each_page(self._prog):
            try:
                if not PageSlab(page):
                    continue
            except FaultError:
                continue
            slab = cast(slab_type, page)
            if slab.slab_cache == self._slab_cache:
                yield from self._page_objects(page, slab, pointer_type)

    def object_info(self, page: Object, slab: Object, addr: int) -> "SlabObjectInfo":
        raise NotImplementedError()


class _SlubPerCpuInfo(NamedTuple):
    freelists: Set[int]
    num_partial_list_free_objs: int
    error: Optional[Exception]


class _SlabCacheHelperSlub(_SlabCacheHelper):
    @functools.cached_property
    def _red_left_pad(self) -> int:
        try:
            return self._slab_cache.red_left_pad.value_()
        except AttributeError:
            return 0

    def _slub_get_freelist(
        self, freelist_name: Callable[[], str], freelist: Object
    ) -> Set[int]:
        # In SLUB, the freelist is a linked list with the next pointer located
        # at ptr + slab_cache->offset.
        freelist_set: Set[int] = set()
        # This is racy. On live kernels, we retry a limited number of times.
        num_attempts = 1000 if (self._prog.flags & ProgramFlags.IS_LIVE) else 1
        for attempts_remaining in range(num_attempts, -1, -1):
            ptr = freelist.value_()
            while ptr:
                if ptr in freelist_set:
                    if attempts_remaining > 0:
                        # Break the loop over the freelist and retry from the
                        # beginning of the list.
                        break
                    e = SlabFreelistCycleError(
                        f"{_slab_cache_name(self._slab_cache)} {freelist_name()} "
                        "freelist contains cycle; "
                        "may be corrupted or in the middle of update"
                    )
                    # Smuggle the freelist we got so far.
                    e.freelist = freelist_set  # type: ignore[attr-defined]
                    raise e
                freelist_set.add(ptr)
                try:
                    ptr = self._freelist_dereference(ptr + self._freelist_offset)
                except FaultError as e:
                    if attempts_remaining > 0:
                        break
                    e.freelist = freelist_set  # type: ignore[attr-defined]
                    raise
            else:
                return freelist_set

            freelist_set.clear()
        assert False  # Tell mypy that this is unreachable.

    @functools.cached_property
    def _freelist_offset(self) -> int:
        return self._slab_cache.offset.value_()

    @functools.cached_property
    def _freelist_dereference(self) -> Callable[[int], int]:
        # If CONFIG_SLAB_FREELIST_HARDENED is enabled, then the next pointer is
        # obfuscated using slab_cache->random.
        try:
            freelist_random = self._slab_cache.random.value_()
        except AttributeError:
            return self._prog.read_word

        ulong_size = sizeof(self._prog.type("unsigned long"))

        # Since Linux kernel commit 1ad53d9fa3f6 ("slub: improve bit diffusion
        # for freelist ptr obfuscation") in v5.7, a swab() was added to the
        # freelist dereferencing calculation. This commit was backported to all
        # stable branches which have CONFIG_SLAB_FREELIST_HARDENED, but you can
        # still encounter some older stable kernels which don't have it.
        # Unfortunately, there's no easy way to detect whether it is in effect,
        # since the commit adds no struct field or other detectable difference.
        #
        # To handle this, we implement both methods, and we start out with a
        # "trial" function. On the first time we encounter a non-NULL freelist,
        # we try using the method with the swab(), and test whether the
        # resulting pointer may be dereferenced. If it can, we commit to using
        # that method forever. If it cannot, we switch to the version without
        # swab() and commit to using that.

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

        return _try_hardened_freelist_dereference

    def _num_cpu_partial_list_free_objs(self, cpu: int, cpu_slab: Object) -> int:
        try:
            partial = cpu_slab.partial.read_()
        except AttributeError:
            # Since Linux kernel commit a93cf07bc3fb ("mm/slub.c: wrap
            # cpu_slab->partial in CONFIG_SLUB_CPU_PARTIAL") (in v4.13), if
            # CONFIG_SLUB_CPU_PARTIAL=n, then cpu_slab->partial does not exist.
            # Override the method on this instance to avoid checking again.
            self._num_cpu_partial_list_free_objs = lambda cpu, cpu_slab: 0  # type: ignore[method-assign]
            return 0

        # Since Linux kernel commit bb192ed9aa71 ("mm/slub: Convert most struct
        # page to struct slab by spatch") (in v5.17), the number of slabs on
        # the partial list is `->slabs`. Before that, it is `->pages`.
        nr_slabs_member = "slabs" if hasattr(partial, "slabs") else "pages"

        # This is racy. On live kernels, we retry a limited number of times.
        num_attempts = 1000 if (self._prog.flags & ProgramFlags.IS_LIVE) else 1
        for attempts_remaining in range(num_attempts, -1, -1):
            free_objs = 0
            prev_nr_slabs = None
            while partial:
                try:
                    nr_slabs = partial.member_(nr_slabs_member).value_()
                    # We could be stricter and check nr_slabs == prev_nr_slabs - 1, but
                    # the main thing we care about is not getting stuck in a cycle.
                    if prev_nr_slabs is not None and nr_slabs >= prev_nr_slabs:
                        if attempts_remaining > 0:
                            # Break the loop over the slab list and retry from the
                            # beginning of the list.
                            break
                        raise SlabPartialListError(
                            f"{_slab_cache_name(self._slab_cache)} cpu {cpu} "
                            "partial slabs count not decreasing; "
                            "may be corrupted or in the middle of update"
                        )
                    prev_nr_slabs = nr_slabs

                    free_objs += partial.objects.value_() - partial.inuse.value_()
                    partial = partial.next.read_()
                except FaultError:
                    if attempts_remaining > 0:
                        break
                    raise
            else:
                return free_objs

            partial = cpu_slab.partial.read_()
        assert False  # Tell mypy that this is unreachable.

    def _per_cpu_info(
        self, *, count_partial_list_free_objs: bool = False, catch_errors: bool = False
    ) -> _SlubPerCpuInfo:
        freelists: Set[int] = set()
        num_partial_list_free_objs = 0
        error = None

        try:
            # cpu_slab doesn't exist for CONFIG_SLUB_TINY.
            cpu_slab = self._slab_cache.cpu_slab.read_()
        except AttributeError:
            pass
        else:
            # Since Linux kernel commit bb192ed9aa71 ("mm/slub: Convert most
            # struct page to struct slab by spatch") (in v5.17), the current
            # slab for a CPU is `struct slab *slab`. Before that, it is `struct
            # page *page`.
            cpu_slab_member = "slab" if hasattr(cpu_slab, "slab") else "page"
            try:
                for cpu in for_each_online_cpu(self._prog):
                    this_cpu_slab = per_cpu_ptr(cpu_slab, cpu)
                    slab = this_cpu_slab.member_(cpu_slab_member).read_()
                    if slab and slab.slab_cache == self._slab_cache:
                        freelists |= self._slub_get_freelist(
                            lambda: f"cpu {cpu}", this_cpu_slab.freelist
                        )

                    if count_partial_list_free_objs:
                        num_partial_list_free_objs += (
                            self._num_cpu_partial_list_free_objs(cpu, this_cpu_slab)
                        )
            except (SlabCorruptionError, FaultError) as e:
                if not catch_errors:
                    raise
                error = e

        return _SlubPerCpuInfo(
            freelists=freelists,
            num_partial_list_free_objs=num_partial_list_free_objs,
            error=error,
        )

    def usage(self) -> "SlabCacheUsage":
        num_attempts = 1000 if (self._prog.flags & ProgramFlags.IS_LIVE) else 1

        num_slabs = 0
        num_objs = 0
        # SLUB doesn't maintain a counter of free objects. Instead, we have to
        # compute it from three places:
        #
        # 1. Per-node partial lists: sum of slab->objects - slab->inuse for
        #    each slab.
        # 2. Per-CPU partial lists (ditto).
        # 3. Per-CPU freelists. We can't use slab->inuse of the per-CPU active
        #    slabs because it is set to slab->objects for active slabs.
        per_cpu = self._per_cpu_info(count_partial_list_free_objs=True)
        free_objs = len(per_cpu.freelists) + per_cpu.num_partial_list_free_objs

        slab_type = _get_slab_type(self._prog).type
        # Since Linux kernel commit 4da1984edbbe ("mm: combine LRU and main
        # union in struct page") (in v4.18), the slab list_head is slab_list in
        # struct slab or struct page. Before that, it is struct page::lru.
        # (Between that commit and commit 916ac0527837 ("slub: use slab_list
        # instead of lru") (in v5.2), the SLUB code still uses struct page::lru,
        # but it is an alias of struct page::slab_list.)
        slab_list_member = "slab_list" if slab_type.has_member("slab_list") else "lru"
        for node in self._slab_cache.node[: nr_node_ids(self._prog)]:
            try:
                nr_slabs = node.nr_slabs
            except AttributeError:
                raise ValueError(
                    "slab_cache_usage() requires CONFIG_SLUB_DEBUG enabled in the kernel"
                ) from None
            num_slabs += nr_slabs.counter.value_()
            num_objs += node.total_objects.counter.value_()

            # This is racy. On live kernels, we retry a limited number of times.
            for attempts_remaining in range(num_attempts, -1, -1):
                node_free_objs = 0
                try:
                    for slab in validate_list_for_each_entry(
                        slab_type, node.partial.address_of_(), slab_list_member
                    ):
                        node_free_objs += slab.objects.value_() - slab.inuse.value_()
                    break
                except (FaultError, ValidationError):
                    if attempts_remaining == 0:
                        raise
            free_objs += node_free_objs

        return SlabCacheUsage(
            num_slabs=num_slabs, num_objs=num_objs, free_objs=free_objs
        )

    def _page_objects(
        self, page: Object, slab: Object, pointer_type: Type
    ) -> Iterator[Object]:
        freelist = self._slub_get_freelist(lambda: f"slab {hex(slab)}", slab.freelist)
        addr = page_to_virt(page).value_() + self._red_left_pad
        end = addr + self._slab_cache_size * slab.objects
        while addr < end:
            if addr not in freelist and addr not in self._cpu_freelists:
                yield Object(self._prog, pointer_type, value=addr)
            addr += self._slab_cache_size

    def for_each_allocated_object(self, type: Union[str, Type]) -> Iterator[Object]:
        self._cpu_freelists = self._per_cpu_info().freelists
        return super().for_each_allocated_object(type)

    def object_info(self, page: Object, slab: Object, addr: int) -> "SlabObjectInfo":
        first_addr = page_to_virt(page).value_() + self._red_left_pad
        address = (
            first_addr
            + (addr - first_addr) // self._slab_cache_size * self._slab_cache_size
        )
        per_cpu = self._per_cpu_info(catch_errors=True)
        if address in per_cpu.freelists:
            allocated: Optional[bool] = False
        else:
            try:
                freelist = self._slub_get_freelist(
                    lambda: f"slab {hex(slab)}", slab.freelist
                )
            except (SlabCorruptionError, FaultError) as e:
                # On error, _slub_get_freelist() smuggles the partial freelist
                # it got as an attribute on the exception.
                allocated = False if address in getattr(e, "freelist", ()) else None
            else:
                if address in freelist:
                    allocated = False
                elif per_cpu.error:
                    allocated = None
                else:
                    allocated = True
        return SlabObjectInfo(self._slab_cache, slab, address, allocated)


class _SlabCacheHelperSlab(_SlabCacheHelper):
    def __init__(self, slab_cache: Object) -> None:
        super().__init__(slab_cache)
        self._freelist_type = self._prog.type("freelist_idx_t *")

    @functools.cached_property
    def _obj_offset(self) -> int:
        try:
            return self._slab_cache.obj_offset.value_()
        except AttributeError:
            return 0

    @functools.cached_property
    def _slab_cache_num(self) -> int:
        return self._slab_cache.num.value_()

    @staticmethod
    def _slab_add_array_cache(array_caches: Set[int], ac: Object) -> None:
        for i in range(ac.avail):
            array_caches.add(ac.entry[i].value_())

    @functools.cached_property
    def _array_caches(self) -> Set[int]:
        array_caches: Set[int] = set()

        cpu_cache = self._slab_cache.cpu_cache.read_()
        for cpu in for_each_online_cpu(self._prog):
            self._slab_add_array_cache(array_caches, per_cpu_ptr(cpu_cache, cpu))

        nodes = self._slab_cache.node
        for nid in for_each_online_node(self._prog):
            n = nodes[nid].read_()
            shared = n.shared.read_()
            if shared:
                self._slab_add_array_cache(array_caches, shared)
            alien = n.alien.read_()
            if alien:
                for nid2 in for_each_online_node(self._prog):
                    self._slab_add_array_cache(array_caches, alien[nid2])

        return array_caches

    def usage(self) -> "SlabCacheUsage":
        num_slabs = 0
        # SLAB maintains per-node counters of free objects, but the array
        # caches are not included in those counters.
        free_objs = len(self._array_caches)

        for node in self._slab_cache.node[: nr_node_ids(self._prog)]:
            try:
                num_slabs += node.total_slabs.value_()
            except AttributeError:
                # Before Linux kernel commits f728b0a5d72a ("mm, slab: faster
                # active and free stats") and bf00bd345804 ("mm, slab: maintain
                # total slab count instead of active count") (in v4.10), struct
                # kmem_cache_node::total_slabs is named num_slabs instead.
                num_slabs += node.num_slabs.value_()
            free_objs += node.free_objects.value_()

        return SlabCacheUsage(
            num_slabs=num_slabs,
            num_objs=num_slabs * self._slab_cache_num,
            free_objs=free_objs,
        )

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
            if addr in self._array_caches:
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
            allocated=object_address not in self._array_caches
            and object_index not in self._slab_freelist(slab),
        )


class _SlabCacheHelperSlob(_SlabCacheHelper):
    def usage(self) -> "SlabCacheUsage":
        raise ValueError("SLOB is not supported")

    def for_each_allocated_object(self, type: Union[str, Type]) -> Iterator[Object]:
        raise ValueError("SLOB is not supported")

    def object_info(self, page: Object, slab: Object, addr: int) -> "SlabObjectInfo":
        return SlabObjectInfo(self._slab_cache, slab, 0, None)


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


def slab_cache_usage(slab_cache: Object) -> "SlabCacheUsage":
    """
    Get statistics for how many slabs and objects are allocated for a given
    slab cache.

    Only the SLUB and SLAB allocators are supported; SLOB does not track these
    statistics. Additionally, for SLUB, ``CONFIG_SLUB_DEBUG`` must be enabled
    in the kernel (this is the default unless ``CONFIG_SLUB_TINY`` is enabled).

    :param slab_cache: ``struct kmem_cache *``
    """
    return _get_slab_cache_helper(slab_cache).usage()


class SlabCacheUsage(NamedTuple):
    """Slab cache usage statistics returned by :func:`slab_cache_usage()`."""

    num_slabs: int
    """Number of slabs allocated for this slab cache."""

    num_objs: int
    """Total number of objects in this slab cache (free and active)."""

    free_objs: int
    """Number of free objects in this slab cache."""

    @property
    def active_objs(self) -> int:
        """Number of active (allocated) objects in this slab cache."""
        return self.num_objs - self.free_objs


def slab_cache_for_each_allocated_object(
    slab_cache: Object, type: Union[str, Type]
) -> Iterator[Object]:
    """
    Iterate over all allocated objects in a given slab cache.

    Only the SLUB and SLAB allocators are supported; SLOB does not store enough
    information to identify objects in a slab cache.

    >>> dentry_cache = find_slab_cache("dentry")
    >>> next(slab_cache_for_each_allocated_object(dentry_cache, "struct dentry"))
    *(struct dentry *)0xffff905e41404000 = {
        ...
    }

    :param slab_cache: ``struct kmem_cache *``
    :param type: Type of object in the slab cache.
    :return: Iterator of ``type *`` objects.
    """
    return _get_slab_cache_helper(slab_cache).for_each_allocated_object(type)


def _find_containing_slab(prog: Program, addr: int) -> Optional[Tuple[Object, Object]]:
    page = virt_to_page(prog, addr)

    try:
        page = compound_head(page)
        if not PageSlab(page):
            return None
    except FaultError:
        # Page does not exist
        return None

    return page, cast(_get_slab_type(prog), page)


@takes_program_or_default
def slab_object_info(prog: Program, addr: IntegerLike) -> "Optional[SlabObjectInfo]":
    """
    Get information about an address if it is in a slab object.

    >>> ptr = find_task(1).comm.address_of_()
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

    Note that SLOB does not store enough information to identify slab objects,
    so if the kernel is configured to use SLOB, then
    :attr:`SlabObjectInfo.slab_cache` will always be ``NULL`` and
    :attr:`SlabObjectInfo.address` will always be 0. Additionally, for
    allocations of at least one page, SLOB allocates pages directly, so this
    will return ``None``.

    :param addr: ``void *``
    :return: :class:`SlabObjectInfo` if *addr* is in a slab object, or ``None``
        if not.
    """
    addr = operator.index(addr)
    if not in_direct_map(prog, addr):
        return None
    result = _find_containing_slab(prog, addr)
    if result is None:
        return None
    page, slab = result
    try:
        slab_cache = slab.slab_cache.read_()
    except AttributeError:
        # SLOB
        slab_cache = NULL(prog, "struct kmem_cache *")
    return _get_slab_cache_helper(slab_cache).object_info(page, slab, addr)


class SlabObjectInfo:
    """Information about an object in the slab allocator."""

    slab_cache: Object
    """
    ``struct kmem_cache *`` that the slab object is from.

    SLOB does not store enough information to find this, so if the kernel is
    configured to use SLOB, then this will always be ``NULL``.
    """

    slab: Object
    """
    Slab containing the slab object.

    Since Linux v5.17, this is a ``struct slab *``. Before that, it is a
    ``struct page *``.
    """

    address: int
    """
    Address of the slab object.

    SLOB does not store enough information to find this, so if the kernel is
    configured to use SLOB, then this will always be 0.
    """

    allocated: Optional[bool]
    """
    ``True`` if the object is allocated, ``False`` if it is free, or ``None``
    if not known because the slab cache is corrupted or the kernel is
    configured to use SLOB.
    """

    def __init__(
        self, slab_cache: Object, slab: Object, address: int, allocated: Optional[bool]
    ) -> None:
        self.slab_cache = slab_cache
        self.slab = slab
        self.address = address
        self.allocated = allocated

    def __repr__(self) -> str:
        return f"SlabObjectInfo(slab_cache={self.slab_cache!r}, slab={self.slab!r}, address={hex(self.address)}, allocated={self.allocated})"


@takes_program_or_default
def find_containing_slab_cache(prog: Program, addr: IntegerLike) -> Object:
    """
    Get the slab cache that an address was allocated from, if any.

    Note that SLOB does not store enough information to identify objects in a
    slab cache, so if the kernel is configured to use SLOB, this will always
    return ``NULL``.

    :param addr: ``void *``
    :return: ``struct kmem_cache *`` containing *addr*, or ``NULL`` if *addr*
        is not from a slab cache.
    """
    if not in_direct_map(prog, addr):
        return NULL(prog, "struct kmem_cache *")
    result = _find_containing_slab(prog, operator.index(addr))
    if result is not None:
        try:
            return result[1].slab_cache.read_()
        except AttributeError:
            # SLOB
            pass
    return NULL(prog, "struct kmem_cache *")


@takes_program_or_default
def slab_total_usage(prog: Program) -> "SlabTotalUsage":
    """Get the total number of reclaimable and unreclaimable slab pages."""
    # The items were renamed in Linux kernel commit d42f3245c7e2 ("mm: memcg:
    # convert vmstat slab counters to bytes") (in v5.9).
    try:
        return SlabTotalUsage(
            reclaimable_pages=global_node_page_state(prog["NR_SLAB_RECLAIMABLE_B"]),
            unreclaimable_pages=global_node_page_state(prog["NR_SLAB_UNRECLAIMABLE_B"]),
        )
    except ObjectNotFoundError:
        return SlabTotalUsage(
            reclaimable_pages=global_node_page_state(prog["NR_SLAB_RECLAIMABLE"]),
            unreclaimable_pages=global_node_page_state(prog["NR_SLAB_UNRECLAIMABLE"]),
        )


class SlabTotalUsage(NamedTuple):
    """Slab memory usage returned by :func:`slab_total_usage()`."""

    reclaimable_pages: int
    """Number of reclaimable slab pages."""

    unreclaimable_pages: int
    """Number of unreclaimable slab pages."""

    @property
    def total_pages(self) -> int:
        """Total number of slab pages."""
        return self.reclaimable_pages + self.unreclaimable_pages
