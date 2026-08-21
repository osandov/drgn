# (C) Copyright IBM Corp. 2026
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Disassembly
-----------
The ``drgn.helpers.common.disasm`` module provides helpers for disassembling
machine code.
"""

from typing import Optional, Tuple, Union

from _drgn import _parse_addr2line
from drgn import Architecture, IntegerLike, Program
from drgn.helpers.common.prog import takes_program_or_default

__all__ = ("disasm",)

try:
    import capstone  # type: ignore # no type hints available

    _HAVE_CAPSTONE = True
except ImportError:
    _HAVE_CAPSTONE = False


def _resolve_addr(prog: Program, address: str) -> int:
    # Resolve an addr2line string into an address
    # Note that we drop the symbol name here, as
    # it's valid to compute an address using one symbol
    # that falls into the region of another symbol.
    # For example: resloving `__schedule+3022` could
    # be the same as `yeild_to+622`, and we should
    # accept the prior
    sym_name, offset = _parse_addr2line(address)
    if sym_name:
        sym = prog.symbol(sym_name)
        return sym.address + offset
    else:
        return offset


def _make_capstone_disassembler(arch: Architecture) -> "capstone.Cs":
    try:
        capstone_args = {
            Architecture.X86_64: (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            Architecture.I386: (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            Architecture.AARCH64: (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
            Architecture.ARM: (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            Architecture.PPC64: (capstone.CS_ARCH_PPC, capstone.CS_MODE_64),
            Architecture.RISCV32: (
                capstone.CS_ARCH_RISCV,
                capstone.CS_MODE_RISCV32,
            ),
            Architecture.RISCV64: (
                capstone.CS_ARCH_RISCV,
                capstone.CS_MODE_RISCV64,
            ),
            Architecture.S390X: (capstone.CS_ARCH_SYSZ, 0),
            Architecture.S390: (capstone.CS_ARCH_SYSZ, 0),
        }[arch]
    except KeyError:
        raise NotImplementedError(f"disassably not supported on {arch}")
    disassembler = capstone.Cs(*capstone_args)
    try:
        disassembler.syntax = capstone.CS_OPT_SYNTAX_ATT
    except capstone.CsError as cse:
        # An errant backport in capstone 5.0.1 caused mismatched constants
        # between the C library and Python binding. See:
        # https://github.com/capstone-engine/capstone/issues/2145
        # and https://github.com/capstone-engine/capstone/issues/2240
        # Since this is the version RHEL 10 ships, do a bit of monkey patching
        if cse.errno == capstone.CS_ERR_OPTION and capstone.CS_OPT_SYNTAX_ATT == 8:
            disassembler.syntax = 2
        else:
            raise
    # The skipdata mode adds `.byte 0xYY` for instructions that it does not understand
    # This allows for complete disassembly, even when the instruction stream contains
    # invalid instructions or instruction that are newer that the version of Capstone
    # used
    disassembler.skipdata = True
    # The detail mode allows examining the operands
    disassembler.detail = True
    return disassembler


def _get_disasassembler(prog: Program) -> "capstone.Cs":
    # Get a disassembler for this specific program. This may be a cached instance
    # stored in the program's cache attribute.
    if not _HAVE_CAPSTONE:
        raise NotImplementedError("disassembly support requires Capstone")
    if not prog.platform:
        raise ValueError("cannot disassemble without platform")
    try:
        disassembler = prog.cache["disassembler"]
    except KeyError:
        disassembler = _make_capstone_disassembler(prog.platform.arch)
        prog.cache["disassembler"] = disassembler
    return disassembler


def _symbolize(prog: Program, addr: int, offset_base: int) -> Optional[str]:
    try:
        sym = prog.symbol(addr)
    except LookupError:
        return None
    sym_offset = addr - sym.address
    if sym_offset == 0:
        return f"\t<{sym.name}>"
    num_string = f"0x{sym_offset:x}" if offset_base == 16 else f"{sym_offset:d}"
    return f"\t<{sym.name}+{num_string}>"


def _symbolize_dest(
    prog: Program, i: "capstone.CsInsn", offset_base: int
) -> Optional[str]:
    if i.id == 0 or len(i.operands) == 0:
        return None
    op = i.operands[-1]
    if op.type == capstone.CS_OP_IMM:
        # Capstone returns signed integers so use & with a mask of the address
        # size to 'cast to unsigned'. This makes it possible for symbolize to
        # correctly compute offsets and lookup symbols by address.
        op_addr = op.imm & ((1 << 8 * prog.address_size()) - 1)
        symbolized = _symbolize(prog, op_addr, offset_base)
        if symbolized:
            return symbolized
    return None


def _find_mc_forward(prog: Program, start: int, count: int) -> Tuple[int, int]:
    disassembler = _get_disasassembler(prog)
    current_iaddr = start
    for _ in range(count):
        current_ilen = 0
        machine_code = bytearray()
        while True:
            machine_code += prog.read(current_iaddr + current_ilen, 1)
            current_ilen += 1
            try:
                (addr, size, mnem, _) = next(
                    disassembler.disasm_lite(machine_code, current_iaddr, count=1)
                )
            except StopIteration:
                continue
            if mnem == disassembler.skipdata_mnem and size == current_ilen:
                continue
            current_iaddr = addr + size
            break
    total_len = current_iaddr - start
    return (start, total_len)


def _find_mc_reverse(prog: Program, start: int, count: int) -> Tuple[int, int]:
    # We always want to ensure that the instruction listing includes the
    # instruction starting at `addr`. This implies that we should look
    # forward by 1 instruction from `addr`.
    (_, first_instruction_len) = _find_mc_forward(prog, start, 1)
    count -= 1

    # After finding the first instruction, we search backwards for the
    # remaining instructions nibbling a byte at a time
    disassembler = _get_disasassembler(prog)
    current_iaddr = start
    end = start + first_instruction_len
    for _ in range(count):
        current_ilen = 0
        machine_code = bytes()
        while True:
            machine_code = prog.read(current_iaddr - current_ilen, 1) + machine_code
            current_ilen += 1
            try:
                (addr, size, mnem, _) = next(
                    disassembler.disasm_lite(
                        machine_code, current_iaddr - current_ilen, count=1
                    )
                )
            except StopIteration:
                continue
            if size == current_ilen:
                continue
            elif size != current_ilen:
                # We went a nibble too far, and the prior instruction is what we want
                # even if it was a skipdata.
                current_iaddr = addr - 1
                break
            else:
                current_iaddr = addr
                break
    total_len = end - current_iaddr
    return (current_iaddr, total_len)


@takes_program_or_default
def disasm(
    prog: Program,
    address: Union[IntegerLike, str],
    count: Optional[int] = None,
    *,
    reverse: Optional[bool] = None,
    offset_base: int = 10,
) -> None:
    """
    Print a disassembly.

    :param address: the start address.
    :param count: an optional count, in instructions, to disassemble.
        When not present and the address lies within a symbol, the rest of the symbol is disassembled.
        When not present and the address is not within a symbol, one instruction is disassembled.
    :param reverse: The disassembly will end at the specified address instead of
        starting there.
    :param offset_base: print all symbol offsets using this base.
    """
    disassembler = _get_disasassembler(prog)

    if isinstance(address, str):
        addr = _resolve_addr(prog, address)
    else:
        addr = int(address)
    try:
        symbol = prog.symbol(addr)
    except LookupError:
        symbol = None
    if symbol and not count:
        # When no count is specified, we want to disassemble the remainder of
        # the symbol. The upper bound of the number of instructions in a function
        # is certainly <= the number of bytes in a function.
        count = symbol.size
    elif not count:
        count = 1
    if symbol:
        (start, nbytes) = (symbol.address, symbol.size)
    elif not reverse:
        (start, nbytes) = _find_mc_forward(prog, addr, count)
    else:
        (start, nbytes) = _find_mc_reverse(prog, addr, count)
    insns = disassembler.disasm(prog.read(start, nbytes), start)
    if reverse:
        insns = [i for i in insns if i.address <= addr]
        insns = insns[-count:]
    else:
        insns = [i for i in insns if i.address >= addr]
        insns = insns[:count]
    for i in insns:
        addr_str = _symbolize(prog, i.address, offset_base) or ""
        dest_str = _symbolize_dest(prog, i, offset_base) or ""
        print(f"0x{i.address:x}{addr_str}:\t{i.mnemonic}\t{i.op_str}{dest_str}")
