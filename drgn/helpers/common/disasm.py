from typing import Optional, Union

from drgn import Architecture, IntegerLike, Program
from drgn.helpers.common.prog import takes_program_or_default

__all__ = ("disasm",)

try:
    import capstone  # type: ignore # no type hints available

    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False


def _resolve_addr(prog: Program, address: Union[IntegerLike, str]) -> int:
    if not isinstance(address, str):
        return int(address)

    try:
        return int(address, 10)
    except ValueError:
        pass

    try:
        return int(address, 16)
    except ValueError:
        return prog.symbol(address).address


@takes_program_or_default
def disasm(
    prog: Program,
    address: Union[IntegerLike, str],
    size: Optional[int] = None,
    *,
    reverse: Optional[bool] = None,
    offset_base: int = 10,
) -> None:
    """
    Print a dissassembly.

    :param address: the start address.
    :param size: an optional size, in bytes, to disasseble. When not present,
        the address is looked up as a symbol and the symbol size is used.
    :param reverse: use the address as the end address, and compute the disassebly
        starting at address - size
    :param offset_base: print the symbol offset using this base.
    """
    if not HAVE_CAPSTONE:
        raise NotImplementedError()

    if not prog.platform:
        raise NotImplementedError()

    try:
        capstone_args = {
            Architecture.X86_64: (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            Architecture.I386: (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            Architecture.AARCH64: (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
            Architecture.ARM: (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            Architecture.PPC64: (capstone.CS_ARCH_PPC, capstone.CS_MODE_64),
            Architecture.S390X: (capstone.CS_ARCH_SYSZ, 0),
            Architecture.S390: (capstone.CS_ARCH_SYSZ, 0),
        }[prog.platform.arch]
    except LookupError:
        raise NotImplementedError()

    disassembler = capstone.Cs(*capstone_args)
    disassembler.syntax = capstone.CS_OPT_SYNTAX_ATT
    addr = _resolve_addr(prog, address)
    try:
        symbol = prog.symbol(address)
    except LookupError:
        symbol = None
    if size is None and symbol:
        if reverse:
            size = addr - symbol.address
            addr = symbol.address
        else:
            size = symbol.size - (addr - symbol.address)
    size = size or 20
    machine_code = prog.read(addr, size)
    for i in disassembler.disasm(machine_code, addr):
        if symbol:
            offset = i.address - symbol.address
            num_string = f"0x{offset:x}" if offset_base == 16 else f"{offset:d}"
            print(
                f"0x{i.address:x} <{symbol.name:s}+{num_string:s}>:\t{i.mnemonic}\t{i.op_str}"
            )
        else:
            print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
