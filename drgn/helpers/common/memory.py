# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Memory
------

The ``drgn.helpers.common.memory`` module provides helpers for working with memory and addresses.
"""

import operator
import typing
from typing import Optional

import drgn
from drgn import IntegerLike, PlatformFlags, Program, SymbolKind
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.slab import slab_object_info

__all__ = (
    "identify_address",
    "print_annotated_memory",
)


_SYMBOL_KIND_STR = {
    SymbolKind.OBJECT: "object symbol",
    SymbolKind.FUNC: "function symbol",
}


@takes_program_or_default
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

    :param addr: ``void *``
    :return: Identity as string, or ``None`` if the address is unrecognized.
    """
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

    byteorder: 'typing.Literal["little", "big"]'
    if prog.platform.flags & PlatformFlags.IS_LITTLE_ENDIAN:
        byteorder = "little"
    else:
        byteorder = "big"

    if prog.platform.flags & PlatformFlags.IS_64_BIT:
        word_size = 8
        line_format = "{:016x}: {:016x}{}"
        print("ADDRESS           VALUE")
    else:
        word_size = 4
        line_format = "{:08x}: {:08x}{}"
        print("ADDRESS   VALUE")

    for offset in range(0, len(mem), word_size):
        value = int.from_bytes(mem[offset : offset + word_size], byteorder)
        identified = identify_address(prog, value)
        if identified is None:
            identified = ""
        else:
            identified = f" [{identified}]"
        print(line_format.format(address + offset, value, identified))
