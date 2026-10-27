# Copyright 2026 Anthropic PBC
# (C) Copyright IBM Corp. 2026
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Disassembly
-----------

The ``drgn.helpers.common.disassembly`` module provides helpers for
disassembling machine code.
"""

import operator
from typing import TYPE_CHECKING, Any, Iterator, Literal, Optional, Tuple, Union

if TYPE_CHECKING:
    from _typeshed import SupportsWrite

from _drgn import _parse_addr2line
from drgn import (
    Architecture,
    FaultError,
    IntegerLike,
    Object,
    PlatformFlags,
    Program,
    Symbol,
    SymbolKind,
    TypeKind,
)
from drgn.helpers.common.prog import takes_program_or_default

__all__ = ("disasm",)


# Capstone architecture (CS_ARCH_*), Capstone mode (CS_MODE_*), and maximum
# instruction size. These are looked up by name because old versions of
# Capstone don't support every architecture.
_CAPSTONE_ARCHITECTURES = {
    Architecture.X86_64: ("X86", "64", 15),
    Architecture.I386: ("X86", "32", 15),
    Architecture.AARCH64: ("ARM64", "ARM", 4),
    Architecture.ARM: ("ARM", "ARM", 4),
    Architecture.PPC64: ("PPC", "64", 4),
    Architecture.RISCV64: ("RISCV", "RISCV64", 4),
    Architecture.RISCV32: ("RISCV", "RISCV32", 4),
    Architecture.S390X: ("SYSZ", "BIG_ENDIAN", 6),
    Architecture.S390: ("SYSZ", "BIG_ENDIAN", 6),
}


# Returns the capstone module, a capstone.Cs, and the maximum instruction size.
def _capstone_disassembler(prog: Program) -> Tuple[Any, Any, int]:
    try:
        return prog.cache["capstone_disassembler"]
    except KeyError:
        pass

    # Import Capstone lazily so that it doesn't slow down startup.
    try:
        import capstone  # type: ignore  # No type hints available.
    except ImportError:
        raise NotImplementedError("disassembly requires Capstone")

    if prog.platform is None:
        raise ValueError("program architecture is not known")
    try:
        arch, mode, max_insn_size = _CAPSTONE_ARCHITECTURES[prog.platform.arch]
        cs_arch = getattr(capstone, "CS_ARCH_" + arch)
        cs_mode = getattr(capstone, "CS_MODE_" + mode)
    except (KeyError, AttributeError):
        raise NotImplementedError(
            f"disassembly is not supported for {prog.platform.arch.name}"
        ) from None
    # On other architectures, instruction byte order doesn't depend on data byte
    # order.
    if arch == "PPC" and not (prog.platform.flags & PlatformFlags.IS_LITTLE_ENDIAN):
        cs_mode |= capstone.CS_MODE_BIG_ENDIAN
    if arch == "RISCV":
        # Decode compressed instructions.
        cs_mode |= capstone.CS_MODE_RISCVC

    cs = capstone.Cs(cs_arch, cs_mode)
    # Emit .byte for anything that Capstone can't decode instead of stopping.
    cs.skipdata = True
    # We need operand details to symbolize them.
    cs.detail = True
    syntax_att = capstone.CS_OPT_SYNTAX_ATT
    # Capstone 5.0.1 (which RHEL 10 ships) mistakenly backported constants from
    # Capstone 6 to the Python bindings but not the C library. See
    # https://github.com/capstone-engine/capstone/issues/2145 and
    # https://github.com/capstone-engine/capstone/pull/2240. Work around it by
    # using the C library's values.
    if capstone.cs_version()[0] == 5 and capstone.CS_OPT_ON != 3:
        syntax_att = 2
        # The skipdata setter above passed the wrong CS_OPT_ON, which the C
        # library silently ignored. There's no public way to pass the right
        # one.
        capstone._cs.cs_option(cs.csh, capstone.CS_OPT_SKIPDATA, 3)
    if cs_arch == capstone.CS_ARCH_X86:
        cs.syntax = syntax_att

    ret = capstone, cs, max_insn_size
    prog.cache["capstone_disassembler"] = ret
    return ret


# Read as much of the given range as is readable. If truncated, also return the
# error.
def _read_up_to(
    prog: Program, address: int, size: int
) -> Tuple[bytes, Optional[FaultError]]:
    try:
        return prog.read(address, size), None
    except FaultError as e:
        error = e
    # We can't trust FaultError.address: it may be an address that was read on
    # our behalf (e.g., a page table). Binary search instead.
    data = b""
    while len(data) + 1 < size:
        mid = (len(data) + size) // 2
        try:
            data = prog.read(address, mid)
        except FaultError:
            size = mid
    return data, error


# Yield the addresses that the operands of a capstone.CsInsn may refer to.
def _operand_addresses(
    prog: Program, capstone: Any, cs: Any, insn: Any
) -> Iterator[int]:
    # Skipped data doesn't have operands.
    if insn.id == 0:
        return
    # Capstone returns signed integers.
    mask = (1 << (8 * prog.address_size())) - 1
    for op in insn.operands:
        if op.type == capstone.CS_OP_IMM:
            yield op.imm & mask
        elif (
            cs.arch == capstone.CS_ARCH_X86 and op.type == capstone.x86_const.X86_OP_MEM
        ):
            if op.mem.base == capstone.x86_const.X86_REG_RIP:
                yield (insn.address + insn.size + op.mem.disp) & mask
            elif not op.mem.base:
                yield op.mem.disp & mask


@takes_program_or_default
def disasm(
    prog: Program,
    address: Union[IntegerLike, str],
    *,
    mode: Optional[Literal["symbol", "from", "up_to"]] = None,
    num_insns: Optional[int] = None,
    symbolize: bool = True,
    offset_base: int = 16,
    file: "Optional[SupportsWrite[str]]" = None,
) -> None:
    """
    Print code disassembly.

    The format is subject to change.

    :param address: Code address as an integer, symbol name, or
        ``"symbol_name+offset"`` string.
    :param mode: If ``"symbol"``, disassemble the symbol containing *address*.

        If ``"from"``, disassemble starting from *address*.

        If ``"up_to"``, disassemble starting from the symbol containing
        *address* up to and including the instruction containing *address*.

        If ``None`` (the default), equivalent to ``"symbol"`` if *num_insns* is
        ``None`` and a symbol contains *address*, and ``"from"`` otherwise
        (with a disclaimer if *num_insns* is ``None``).
    :param num_insns: How many instructions to disassemble.

        If *mode* is ``"symbol"``, then this counts from the start of the
        symbol containing *address* and defaults to the whole symbol. It may go
        past the end of the symbol.

        If *mode* is ``"from"``, then this counts from the instruction at
        *address* and defaults to the end of the symbol containing *address* if
        there is one and 1 otherwise. It may go past the end of the symbol.

        If *mode* is ``"up_to"``, then this counts back from the instruction
        containing *address* and defaults to the beginning of the symbol
        containing *address*. It stops at the beginning of the symbol.
    :param symbolize: Whether to include symbol names and offsets for
        instruction addresses and operands.
    :param offset_base: Base to format symbol offsets in (10 or 16).
    :param file: File to print to. Defaults to :data:`sys.stdout`.
    :raises LookupError: if *mode* is ``"symbol"`` or ``"up_to"`` and no symbol
        contains *address*
    :raises NotImplementedError: if Capstone is not installed or does not
        support the program's architecture
    """
    if mode not in (None, "symbol", "from", "up_to"):
        raise ValueError("invalid mode")
    if num_insns is not None and num_insns <= 0:
        raise ValueError("num_insns must be positive")
    if offset_base == 16:
        offset_format = "#x"
    elif offset_base == 10:
        offset_format = "d"
    else:
        raise ValueError("offset_base must be 10 or 16")

    capstone, cs, max_insn_size = _capstone_disassembler(prog)

    symbol = None
    if isinstance(address, str):
        symbol_name, addr = _parse_addr2line(address)
        if symbol_name:
            symbol = prog.symbol(symbol_name)
            addr += symbol.address
    elif (
        isinstance(address, Object)
        and address.type_.unaliased_kind() == TypeKind.FUNCTION
    ):
        addr = address.address_of_().value_()
    else:
        addr = operator.index(address)

    # Find the symbol to use as the bounds of the code. If we were given a
    # symbol name, prefer that symbol.
    if symbol is None or addr - symbol.address >= symbol.size:
        try:
            symbol = prog.symbol(addr)
        except LookupError:
            symbol = None
    # Handwritten assembly may be SymbolKind.UNKNOWN.
    if symbol is not None and (
        symbol.size == 0
        or symbol.kind not in (SymbolKind.FUNC, SymbolKind.IFUNC, SymbolKind.UNKNOWN)
    ):
        symbol = None

    disclaimer = False
    if mode is None:
        if symbol is not None and num_insns is None:
            mode = "symbol"
        else:
            mode = "from"
            disclaimer = num_insns is None

    # Disassemble from start until we have num_insns instructions or, if end is
    # not None, until the first instruction starting at or after end.
    end = None
    if symbol is None:
        if mode != "from":
            raise LookupError(f"could not find function containing {addr:#x}")
        start = addr
        if num_insns is None:
            num_insns = 1
    else:
        start = addr if mode == "from" else symbol.address
        if mode == "up_to":
            # Include the instruction containing addr.
            end = addr + 1
        elif num_insns is None:
            end = symbol.address + symbol.size

    if end is None:
        assert num_insns is not None
        code, error = _read_up_to(prog, start, num_insns * max_insn_size)
        insns = list(cs.disasm(code, start, num_insns))
        if len(insns) >= num_insns:
            error = None
    else:
        # The last instruction may extend past end.
        code, error = _read_up_to(prog, start, end - start + max_insn_size - 1)
        insns = [insn for insn in cs.disasm(code, start) if insn.address < end]
        if insns and insns[-1].address + insns[-1].size >= end:
            error = None
        if mode == "up_to" and num_insns is not None:
            del insns[:-num_insns]
    if error is not None and (not insns or mode == "up_to"):
        raise error

    # Symbol lookups can be slow, and most addresses are in the same symbol as
    # the current instruction, so try that first.
    insn_symbol = symbol

    def symbolized(address: int) -> Tuple[Optional[Symbol], str]:
        if (
            insn_symbol is not None
            and insn_symbol.address <= address < insn_symbol.address + insn_symbol.size
        ):
            symbol = insn_symbol
        else:
            try:
                symbol = prog.symbol(address)
            except LookupError:
                return None, ""
        offset = address - symbol.address
        if offset:
            return symbol, f" <{symbol.name}+{offset:{offset_format}}>"
        else:
            return symbol, f" <{symbol.name}>"

    if disclaimer:
        print(f"(could not find function containing {addr:#x})", file=file)

    mark = mode == "symbol" and addr != start

    # List of marker, address and symbol, and disassembly.
    lines = []
    for insn in insns:
        marker = ""
        if mark:
            marker = "=> " if insn.address <= addr < insn.address + insn.size else "   "
        label = [hex(insn.address)]
        if symbolize:
            insn_symbol, s = symbolized(insn.address)
            label.append(s)
        label.append(":")
        if insn.op_str:
            asm = [f"{insn.mnemonic:7} {insn.op_str}"]
            if symbolize:
                for operand_address in _operand_addresses(prog, capstone, cs, insn):
                    asm.append(symbolized(operand_address)[1])
        else:
            asm = [insn.mnemonic]
        lines.append((marker, "".join(label), "".join(asm)))
    if error is not None:
        unreadable_address = insns[-1].address + insns[-1].size
        label = [hex(unreadable_address)]
        if symbolize:
            label.append(symbolized(unreadable_address)[1])
        label.append(":")
        lines.append(("   " if mark else "", "".join(label), "<unreadable>"))

    label_width = max([len(line[1]) for line in lines])
    for marker, label_str, asm_str in lines:
        print(f"{marker}{label_str:{label_width}}  {asm_str}", file=file)
