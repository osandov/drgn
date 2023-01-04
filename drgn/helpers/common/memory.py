# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Memory
------

The ``drgn.helpers.common.memory`` module provides helpers for working with memory and addresses.
"""

import operator
from typing import Optional, Union, overload

import drgn
from drgn import IntegerLike, Object, Program, SymbolKind
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.slab import slab_object_info

__all__ = ("identify_address",)


_SYMBOL_KIND_STR = {
    SymbolKind.OBJECT: "object symbol",
    SymbolKind.FUNC: "function symbol",
}


@overload
def identify_address(addr: Object) -> Optional[str]:
    """"""
    ...


@overload
def identify_address(prog: Program, addr: IntegerLike) -> Optional[str]:
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

    * Allocated slab objects: ``slab object: {slab_cache_name}+{hex_offset}``
      (where ``hex_offset`` is the offset from the beginning of the object in
      hexadecimal).
    * Free slab objects: ``free slab object: {slab_cache_name}+{hex_offset}``.

    This may recognize other types of addresses in the future.

    The address can be given as an :class:`~drgn.Object` or as a
    :class:`~drgn.Program` and an integer.

    :param addr: ``void *``
    :return: Identity as string, or ``None`` if the address is unrecognized.
    """
    ...


def identify_address(  # type: ignore  # Need positional-only arguments.
    prog_or_addr: Union[Program, Object], addr: Optional[IntegerLike] = None
) -> Optional[str]:
    if addr is None:
        assert isinstance(prog_or_addr, Object)
        prog = prog_or_addr.prog_
        addr = prog_or_addr
    else:
        assert isinstance(prog_or_addr, Program)
        prog = prog_or_addr
    addr = operator.index(addr)

    if prog.flags & drgn.ProgramFlags.IS_LINUX_KERNEL:
        # Linux kernel-specific identification:
        try:
            slab = slab_object_info(prog, addr)
        except NotImplementedError:
            # Probably because virtual address translation isn't implemented
            # for this architecture.
            pass
        else:
            if slab:
                # address is slab allocated
                cache_name = escape_ascii_string(
                    slab.slab_cache.name.string_(), escape_backslash=True
                )
                maybe_free = "" if slab.allocated else "free "
                return (
                    f"{maybe_free}slab object: {cache_name}+{hex(addr - slab.address)}"
                )

    # Check if address is of a symbol:
    try:
        symbol = prog.symbol(addr)
    except LookupError:  # not a symbol
        # Unrecognized address
        return None

    offset = hex(addr - symbol.address)
    symbol_kind = _SYMBOL_KIND_STR.get(symbol.kind, "symbol")

    return f"{symbol_kind}: {symbol.name}+{offset}"
