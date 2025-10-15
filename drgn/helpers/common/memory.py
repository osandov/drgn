# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Memory
------

The ``drgn.helpers.common.memory`` module provides helpers for working with memory and addresses.
"""

import dataclasses
import operator
from typing import Any, Dict, Iterator, Literal, Optional, Protocol

import drgn
from drgn import IntegerLike, PlatformFlags, Program, Symbol, SymbolKind
from drgn.helpers.common.prog import takes_program_or_default

__all__ = (
    "identify_address",
    "identify_address_all",
    "print_annotated_memory",
)


_SYMBOL_KIND_STR = {
    SymbolKind.OBJECT: "object symbol",
    SymbolKind.FUNC: "function symbol",
}


@takes_program_or_default
def identify_address(
    prog: Program, addr: IntegerLike, *, cache: Optional[Dict[Any, Any]] = None
) -> Optional[str]:
    """
    Try to identify what an address refers to.

    For all programs, this will identify addresses as follows:

    * Object symbols (e.g., addresses in global variables):
      ``object symbol: {symbol_name}+{hex_offset}`` (where ``hex_offset`` is
      the offset from the beginning of the symbol in hexadecimal).
    * Function symbols (i.e., addresses in functions):
      ``function symbol: {symbol_name}+{hex_offset}``.
    * Other symbols: ``symbol: {symbol_name}+{hex_offset}``.

    Additionally, for the Linux kernel, this will identify:

    * Task structures: ``task: {pid} ({comm}) +{hex_offset}`` (where ``pid``
      and ``comm`` identify the task and ``hex_offset`` is the optional offset
      from the beginning of the structure).
    * Task stacks: ``task stack: {pid} ({comm}) +{hex_offset}`` (where
      ``pid`` and ``comm`` identify the task and ``hex_offset`` is the offset
      from the beginning of the stack in hexadecimal).
    * Allocated slab objects: ``slab object: {slab_cache_name}+{hex_offset}``
      (where ``hex_offset`` is the offset from the beginning of the object in
      hexadecimal).
    * Free slab objects: ``free slab object: {slab_cache_name}+{hex_offset}``.
    * Page structures: ``page: pfn {pfn} +{hex_offset}`` (where ``pfn`` is the
      page frame number and ``hex_offset`` is the optional offset from the
      beginning of the structure).
    * Vmap addresses (e.g., vmalloc, ioremap):
      ``vmap: {hex_start_address}-{hex_end_address}``. If the function that
      allocated the vmap is known, this also includes
      ``caller {function_name}+{hex_offset}``.

    This may recognize other types of addresses in the future.

    To get more information instead of just a string, use
    :func:`identify_address_all()`.

    :param addr: ``void *``
    :param cache: Opaque cache used to amortize expensive lookups. If you're
        going to call this function many times in a short period, create an
        empty dictionary and pass the same dictionary as *cache* to each call.
        Don't reuse it indefinitely or you may get stale results.
    :return: Identity as string, or ``None`` if the address is unrecognized.
    """
    for identified in identify_address_all(prog, addr, cache=cache):
        return str(identified)
    return None


@takes_program_or_default
def identify_address_all(
    prog: Program, addr: IntegerLike, *, cache: Optional[Dict[Any, Any]] = None
) -> Iterator["IdentifiedAddress"]:
    """
    Identify everything an address refers to.

    This is a more programmatic variant of :func:`identify_address()` that
    provides the following additional information:

    * Instead of strings, it yields :class:`IdentifiedAddress` instances which
      have attributes describing the identity of the address.
    * If the address can be identified in multiple ways, it yields each one.
      For example, a pointer to a Linux kernel ``task_struct`` can be
      identified as both a task and a slab object.

    For all programs, this can yield:

    * :class:`IdentifiedSymbol`

    Additionally, for the Linux kernel, this can yield:

    * :class:`~drgn.helpers.linux.common.IdentifiedTaskStruct`
    * :class:`~drgn.helpers.linux.common.IdentifiedTaskStack`
    * :class:`~drgn.helpers.linux.common.IdentifiedSlabObject`
    * :class:`~drgn.helpers.linux.common.IdentifiedVmap`
    * :class:`~drgn.helpers.linux.common.IdentifiedPage`

    :param addr: ``void *``
    :param cache: Opaque cache used to amortize expensive lookups. If you're
        going to call this function many times in a short period, create an
        empty dictionary and pass the same dictionary as *cache* to each call.
        Don't reuse it indefinitely or you may get stale results.
    :return: Iterator of identities, from most specific to least specific. If
        the address is unrecognized, this is empty.
    """
    is_linux_kernel = bool(prog.flags & drgn.ProgramFlags.IS_LINUX_KERNEL)
    if is_linux_kernel:
        from drgn.helpers.linux.common import (
            _identify_kernel_address,
            _identify_kernel_symbol,
        )

    addr = operator.index(addr)
    # Check if address is of a symbol:
    symbol: Optional[Symbol]
    try:
        symbol = prog.symbol(addr)
    except LookupError:  # not a symbol
        symbol = None
    else:
        if is_linux_kernel:
            yield from _identify_kernel_symbol(prog, addr, symbol)

        yield IdentifiedSymbol(addr, symbol)

    if is_linux_kernel:
        yield from _identify_kernel_address(prog, addr, bool(symbol), cache)


class IdentifiedAddress(Protocol):
    """Address that was identified by :func:`identify_address_all()`."""

    address: int
    """Address passed to :func:`identify_address_all()`."""

    def __str__(self) -> str:
        """
        Get a human-readable description of the identity.

        This is the same string that is returned from
        :func:`identify_address()`.

        >>> identity
        IdentifiedSymbol(address=18446744071889293504, symbol=Symbol(name='init_task', address=0xffffffff938110c0, size=0x36c0, binding=<SymbolBinding.GLOBAL: 2>, kind=<SymbolKind.OBJECT: 1>))
        >>> str(identity)
        'object symbol: init_task+0x0'
        """
        ...


@dataclasses.dataclass
class IdentifiedSymbol:
    """:class:`IdentifiedAddress` for an address in the symbol table."""

    address: int

    symbol: Symbol
    """Symbol containing the address."""

    def __str__(self) -> str:
        symbol_kind = _SYMBOL_KIND_STR.get(self.symbol.kind, "symbol")
        return f"{symbol_kind}: {self.symbol.name}+{hex(self.address - self.symbol.address)}"


@takes_program_or_default
def print_annotated_memory(
    prog: Program, address: IntegerLike, size: IntegerLike, physical: bool = False
) -> None:
    """
    Print the contents of a range of memory, annotating values that can be
    identified.

    Currently, this will identify any addresses in the memory range with
    :func:`~drgn.helpers.common.memory.identify_address()`.

    See :func:`~drgn.helpers.common.stack.print_annotated_stack()` for a
    similar function that annotates stack traces.

    >>> print_annotated_memory(0xffffffff963eb200, 56)
    ADDRESS           VALUE
    ffffffff963eb200: 00000000000000b8
    ffffffff963eb208: 000000000000a828
    ffffffff963eb210: 0000000000000000
    ffffffff963eb218: ffff8881042948e0 [slab object: mnt_cache+0x20]
    ffffffff963eb220: ffff88810074a540 [slab object: dentry+0x0]
    ffffffff963eb228: ffff8881042948e0 [slab object: mnt_cache+0x20]
    ffffffff963eb230: ffff88810074a540 [slab object: dentry+0x0]

    :param address: Starting address.
    :param size: Number of bytes to read.
    :param physical: Whether *address* is a physical memory address. If
        ``False``, then it is a virtual memory address.
    """
    address = operator.index(address)
    mem = prog.read(address, size, physical)

    # The platform must be known if we were able to read memory.
    assert prog.platform is not None

    byteorder: Literal["little", "big"]
    if prog.platform.flags & PlatformFlags.IS_LITTLE_ENDIAN:
        byteorder = "little"
    else:
        byteorder = "big"

    word_size = prog.address_size()
    if word_size == 8:
        line_format = "{:016x}: {:016x}{}"
        print("ADDRESS           VALUE")
    else:
        line_format = "{:08x}: {:08x}{}"
        print("ADDRESS   VALUE")

    cache: Dict[Any, Any] = {}
    for offset in range(0, len(mem), word_size):
        value = int.from_bytes(mem[offset : offset + word_size], byteorder)
        identified = identify_address(prog, value, cache=cache)
        if identified is None:
            identified = ""
        else:
            identified = f" [{identified}]"
        print(line_format.format(address + offset, value, identified))
