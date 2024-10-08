# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Kmodify
-------

The ``drgn.helpers.experimental.kmodify`` module provides experimental helpers
for modifying the state of the running kernel. This works by loading a
temporary kernel module, so the kernel must support loadable kernel modules
(``CONFIG_MODULES=y``) and allow loading unsigned modules
(``CONFIG_MODULE_SIG_FORCE=n``). It is currently only implemented for x86-64.

.. warning::
    These helpers are powerful but **extremely** dangerous. Use them with care.
"""

import ctypes
import errno
import operator
import os
import random
import re
import string
import struct
import sys
from typing import (
    TYPE_CHECKING,
    Any,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
    Union,
)

if TYPE_CHECKING:
    from _typeshed import SupportsWrite

    if sys.version_info < (3, 11):
        from typing_extensions import assert_never
    else:
        from typing import assert_never  # novermin

from _drgn_util.elf import ET, SHF, SHN, SHT, STB, STT, STV
from _drgn_util.platform import SYS
from drgn import (
    Architecture,
    FaultError,
    IntegerLike,
    Object,
    ObjectAbsentError,
    PlatformFlags,
    PrimitiveType,
    Program,
    ProgramFlags,
    Type,
    TypeKind,
    alignof,
    cast,
    implicit_convert,
    offsetof,
    sizeof,
)
from drgn.helpers.common.prog import takes_program_or_default

__all__ = (
    "call_function",
    "pass_pointer",
    "write_memory",
    "write_object",
)


_c = ctypes.CDLL(None, use_errno=True)
_syscall = _c.syscall
_syscall.restype = ctypes.c_long


# os.memfd_create() was added in Python 3.8, and only with glibc >= 2.27
# (manylinux2014 uses glibc 2.17). The syscall was added in Linux 3.17, so fall
# back to using it directly.
if hasattr(os, "memfd_create"):
    _memfd_create = os.memfd_create  # novermin
else:

    def _memfd_create(
        name: str,
        flags: int = 1,  # MFD_CLOEXEC
    ) -> int:
        fd = _syscall(
            ctypes.c_long(SYS["memfd_create"]),
            ctypes.c_char_p(os.fsencode(name)),
            ctypes.c_uint(flags),
        )
        if fd < 0:
            errnum = ctypes.get_errno()
            raise OSError(errnum, os.strerror(errnum))
        return fd


class _ElfSection:
    def __init__(
        self,
        *,
        name: str,
        type: SHT,
        flags: SHF = SHF(0),
        data: bytes,
        addr: int = 0,
        link: int = 0,
        info: int = 0,
        addralign: int = 1,
        entsize: int = 0,
    ) -> None:
        self.name = name
        self.type = type
        self.flags = flags
        self.data = data
        self.addr = addr
        self.link = link
        self.info = info
        self.addralign = addralign
        self.entsize = entsize


class _ElfSymbol(NamedTuple):
    name: str
    value: int
    size: int
    section: Union[str, SHN]
    type: STT
    binding: STB
    visibility: STV = STV.DEFAULT


class _ElfRelocation(NamedTuple):
    offset: int
    type: int
    symbol_name: str
    section_symbol: bool
    addend: int = 0


def _write_elf(
    file: "SupportsWrite[bytes]",
    *,
    machine: int,
    is_little_endian: bool,
    is_64_bit: bool,
    rela: bool,
    sections: Sequence[_ElfSection],
    symbols: Sequence[_ElfSymbol],
    relocations: Mapping[str, Sequence[_ElfRelocation]],
) -> None:
    endian = "<" if is_little_endian else ">"
    if is_64_bit:
        ehdr_struct = struct.Struct(endian + "16BHHIQQQIHHHHHH")
        shdr_struct = struct.Struct(endian + "IIQQQQIIQQ")
        rela_struct = struct.Struct(endian + "QQq")

        def r_info(sym: int, type: int) -> int:
            return (sym << 32) | type

        sym_struct = struct.Struct(endian + "IBBHQQ")

        def sym_fields(sym: _ElfSymbol) -> Tuple[int, int, int, int, int]:
            return (
                (sym.binding << 4) + (sym.type & 0xF),
                sym.visibility,
                (
                    section_name_to_index[sym.section]
                    if isinstance(sym.section, str)
                    else sym.section
                ),
                sym.value,
                sym.size,
            )

    else:
        ehdr_struct = struct.Struct(endian + "16BHHIIIIIHHHHHH")
        shdr_struct = struct.Struct(endian + "10I")
        rela_struct = struct.Struct(endian + "IIi")

        def r_info(sym: int, type: int) -> int:
            return (sym << 8) | type

        sym_struct = struct.Struct(endian + "IIIBBH")

        def sym_fields(sym: _ElfSymbol) -> Tuple[int, int, int, int, int]:
            return (
                sym.value,
                sym.size,
                (sym.binding << 4) + (sym.type & 0xF),
                sym.visibility,
                (
                    section_name_to_index[sym.section]
                    if isinstance(sym.section, str)
                    else sym.section
                ),
            )

    section_symbols = [
        _ElfSymbol(
            name="",
            value=0,
            size=0,
            type=STT.SECTION,
            binding=STB.LOCAL,
            section=section.name,
        )
        for section in sections
        if section.type == SHT.PROGBITS
    ]
    section_name_to_symbol_index = {
        sym.section: i for i, sym in enumerate(section_symbols, 1)
    }
    symbol_name_to_index = {
        sym.name: i for i, sym in enumerate(symbols, 1 + len(section_symbols))
    }
    section_symbols.extend(symbols)
    symbols = section_symbols
    del section_symbols

    def relocation_symbol_index(reloc: _ElfRelocation) -> int:
        if reloc.section_symbol:
            return section_name_to_symbol_index[reloc.symbol_name]
        else:
            return symbol_name_to_index[reloc.symbol_name]

    if rela:
        reloc_prefix = ".rela"
        reloc_sht = SHT.RELA
        reloc_size = rela_struct.size

        def relocation_data(relocations: Sequence[_ElfRelocation]) -> bytes:
            data = bytearray(len(relocations) * rela_struct.size)
            for i, relocation in enumerate(relocations):
                rela_struct.pack_into(
                    data,
                    i * rela_struct.size,
                    relocation.offset,
                    r_info(
                        relocation_symbol_index(relocation),
                        relocation.type,
                    ),
                    relocation.addend,
                )
            return data

    else:
        raise NotImplementedError("SHT_REL relocations")

    symtab_section_index = 1 + len(sections) + len(relocations)

    sections = list(sections)
    i = 0
    while i < len(sections):
        section = sections[i]
        try:
            section_relocations = relocations[section.name]
        except KeyError:
            i += 1
            continue
        sections.insert(
            i + 1,
            _ElfSection(
                name=reloc_prefix + section.name,
                type=reloc_sht,
                flags=SHF.INFO_LINK,
                data=relocation_data(section_relocations),
                link=symtab_section_index,
                info=i + 1,
                addralign=8 if is_64_bit else 4,
                entsize=reloc_size,
            ),
        )
        i += 2

    section_name_to_index = {section.name: i for i, section in enumerate(sections, 1)}

    if len(sections) < symtab_section_index - 1:
        raise ValueError(
            f"relocations for unknown section {', '.join(relocations.keys() - section_name_to_index)}"
        )

    symtab_data = bytearray((len(symbols) + 1) * sym_struct.size)
    strtab_data = bytearray(1)

    sym_local_end = 1
    for i, sym in enumerate(symbols, 1):
        if sym.name:
            st_name = len(strtab_data)
            strtab_data.extend(sym.name.encode())
            strtab_data.append(0)
        else:
            st_name = 0

        sym_struct.pack_into(
            symtab_data, i * sym_struct.size, st_name, *sym_fields(sym)
        )
        if sym.binding == STB.LOCAL:
            if sym_local_end != i:
                raise ValueError("local symbol after non-local symbol")
            sym_local_end = i + 1

    sections.append(
        _ElfSection(
            name=".symtab",
            type=SHT.SYMTAB,
            data=symtab_data,
            link=len(sections) + 2,
            info=sym_local_end,
            entsize=sym_struct.size,
        )
    )
    sections.append(_ElfSection(name=".strtab", type=SHT.STRTAB, data=strtab_data))

    shstrtab_data = bytearray(1)
    sh_name = []
    for section in sections:
        sh_name.append(len(shstrtab_data))
        shstrtab_data.extend(section.name.encode())
        shstrtab_data.append(0)
    sh_name.append(len(shstrtab_data))
    shstrtab_data.extend(b".shstrtab\0")
    sections.append(_ElfSection(name=".shstrtab", type=SHT.STRTAB, data=shstrtab_data))

    shnum = len(sections) + 1  # + 1 for the SHT_NULL section
    headers_size = ehdr_struct.size + shdr_struct.size * shnum
    file.write(
        ehdr_struct.pack(
            0x7F,  # ELFMAG0
            ord("E"),  # ELFMAG1
            ord("L"),  # ELFMAG2
            ord("F"),  # ELFMAG3
            2 if is_64_bit else 1,  # EI_CLASS = ELFCLASS64 or ELFCLASS32
            1 if is_little_endian else 2,  # EI_DATA = ELFDATA2LSB or ELFDATA2MSB
            1,  # EI_VERSION = EV_CURRENT
            0,  # EI_OSABI = ELFOSABI_NONE
            0,  # EI_ABIVERSION
            0,
            0,
            0,
            0,
            0,
            0,
            0,  # EI_PAD
            ET.REL,  # e_type
            machine,
            1,  # e_version = EV_CURRENT
            0,  # e_entry
            0,  # e_phoff
            ehdr_struct.size,  # e_shoff
            0,  # e_flags
            ehdr_struct.size,  # e_ehsize
            0,  # e_phentsize
            0,  # e_phnum
            shdr_struct.size,  # e_shentsize
            shnum,  # e_shnum
            shnum - 1,  # e_shstrndx
        )
    )

    # SHT_NULL section.
    file.write(bytes(shdr_struct.size))

    section_data_offset = headers_size
    for i, section in enumerate(sections):
        section_data_offset += -section_data_offset % section.addralign
        file.write(
            shdr_struct.pack(
                sh_name[i],  # sh_name
                section.type,  # sh_type
                section.flags,  # sh_flags
                section.addr,  # sh_addr
                section_data_offset,  # sh_offset
                len(section.data),  # sh_size
                section.link,  # sh_link
                section.info,  # sh_info
                section.addralign,  # sh_addralign
                section.entsize,  # sh_entsize
            )
        )
        section_data_offset += len(section.data)

    section_data_offset = headers_size
    for section in sections:
        padding = -section_data_offset % section.addralign
        if padding:
            file.write(bytes(padding))
        section_data_offset += padding
        file.write(section.data)
        section_data_offset += len(section.data)


# Abstract syntax tree-ish representation of code to inject.
class _Integer:
    def __init__(self, size: int, value: IntegerLike) -> None:
        self.size = size
        self.value = operator.index(value) & ((1 << (size * 8)) - 1)


class _Symbol(NamedTuple):
    name: str
    offset: int = 0
    section: bool = False


class _Call(NamedTuple):
    func: _Symbol
    args: Sequence[Union[_Integer, _Symbol]]


class _StoreReturnValue(NamedTuple):
    size: int
    dst: _Symbol


class _Return(NamedTuple):
    value: _Integer


class _ReturnIfLastReturnValueNonZero(NamedTuple):
    value: _Integer


_FunctionBodyNode = Union[
    _Call, _StoreReturnValue, _Return, _ReturnIfLastReturnValueNonZero
]


class _Function(NamedTuple):
    body: Sequence[_FunctionBodyNode]


class _CodeGen_x86_64:
    _R_X86_64_PC32 = 2
    _R_X86_64_PLT32 = 4
    _R_X86_64_32S = 11

    _rax = 0
    _r11 = 11

    _argument_registers = (
        7,  # rdi
        6,  # rsi,
        2,  # rdx
        1,  # rcx
        8,  # r8
        9,  # r9
    )

    def __init__(self) -> None:
        self.code = bytearray()
        self.relocations: List[_ElfRelocation] = []
        self._epilogue_jumps: List[int] = []

    def enter_frame(self, size: int) -> None:
        if size < 0:
            raise ValueError("invalid stack frame size")

        self.code.extend(
            # endbr64
            # This is only needed if CONFIG_X86_KERNEL_IBT=y, but it's much
            # simpler to do it unconditionally, and it's a no-op if not needed.
            b"\xF3\x0F\x1E\xFA"
            # Set up the frame pointer.
            # push %rbp
            b"\x55"
            # mov %rsp, %rbp
            b"\x48\x89\xE5"
        )

        # The System V ABI requires that rsp % 16 == 0 on function entry. We
        # need to make sure that rsp % 16 == 8 in the function body so that the
        # return address pushed by the call will make rsp % 16 == 0. push %rbp
        # makes rsp % 16 == 8. So, we need to align the requested size up to 16
        # bytes.
        size = (size + 15) & ~15
        if size > 0:
            # sub $size, %rsp
            if size < 128:
                self.code.extend(b"\x48\x83\xEC")
                self.code.append(size)
            else:
                self.code.extend(b"\x48\x81\xEC")
                self.code.extend(size.to_bytes(4, "little", signed=True))

    def leave_frame(self) -> None:
        # Fix up all of the jumps to the epilogue.
        for offset in self._epilogue_jumps:
            self.code[offset - 4 : offset] = (len(self.code) - offset).to_bytes(
                4, "little", signed=True
            )

        self.code.extend(
            # leave
            b"\xC9"
            # ret
            b"\xC3"
        )

    def _mov_imm(self, value: int, reg: int) -> None:
        assert value >= 0 and value <= 0xFFFFFFFFFFFFFFFF
        assert reg < 16
        if value <= 0xFFFFFFFF:
            if reg >= 8:
                self.code.append(0x41)  # REX.B
                reg -= 8
            self.code.append(0xB8 + reg)
            self.code.extend(value.to_bytes(4, "little"))
        else:
            rex = 0x48  # REX.W
            if reg >= 8:
                rex |= 1  # REX.B
                reg -= 8
            self.code.append(rex)
            if value >= 0xFFFFFFFF80000000:
                self.code.append(0xC7)
                self.code.append(0xC0 + reg)
                self.code.extend((value & 0xFFFFFFFF).to_bytes(4, "little"))
            else:
                self.code.append(0xB8 + reg)
                self.code.extend(value.to_bytes(8, "little"))

    def _mov_symbol(self, sym: _Symbol, reg: int) -> None:
        rex = 0x48  # REX.W
        if reg >= 8:
            rex |= 1  # REX.B
            reg -= 8
        self.code.append(rex)
        self.code.append(0xC7)
        self.code.append(0xC0 + reg)
        self.relocations.append(
            _ElfRelocation(
                offset=len(self.code),
                type=self._R_X86_64_32S,
                symbol_name=sym.name,
                section_symbol=sym.section,
                addend=sym.offset,
            )
        )
        self.code.extend(bytes(4))

    def _store_rax_on_stack(self, offset: int) -> None:
        # mov %rax, offset(%rsp)
        if offset == 0:
            self.code.extend(b"\x48\x89\x04\x24")
        elif -128 <= offset < 128:
            self.code.extend(b"\x48\x89\x44\x24")
            self.code.append(offset & 0xFF)
        else:
            self.code.extend(b"\x48\x89\x84\x24")
            self.code.extend(offset.to_bytes(4, "little", signed=True))

    def _store_imm_on_stack(self, value: int, offset: int) -> None:
        if (0 <= value <= 0x7FFFFFFF) or (
            0xFFFFFFFF80000000 <= value <= 0xFFFFFFFFFFFFFFFF
        ):
            # mov $value, offset(%rsp)
            if offset == 0:
                self.code.extend(b"\x48\xC7\x04\x24")
            elif -128 <= offset < 128:
                self.code.extend(b"\x48\xC7\x44\x24")
                self.code.append(offset & 0xFF)
            else:
                self.code.extend(b"\x48\xC7\x84\x24")
                self.code.extend(offset.to_bytes(4, "little", signed=True))
            self.code.extend((value & 0xFFFFFFFF).to_bytes(4, "little"))
        else:
            self._mov_imm(value, self._rax)
            self._store_rax_on_stack(offset)

    def _store_symbol_on_stack(self, sym: _Symbol, offset: int) -> None:
        self._mov_symbol(sym, self._rax)
        self._store_rax_on_stack(offset)

    def call(self, func: _Symbol, args: Sequence[Union[_Integer, _Symbol]]) -> None:
        for i, arg in enumerate(args):
            if i < len(self._argument_registers):
                reg = self._argument_registers[i]
                if isinstance(arg, _Integer):
                    self._mov_imm(arg.value, reg)
                else:
                    self._mov_symbol(arg, reg)
            else:
                stack_offset = 8 * (i - len(self._argument_registers))
                if isinstance(arg, _Integer):
                    self._store_imm_on_stack(arg.value, stack_offset)
                else:
                    self._store_symbol_on_stack(arg, stack_offset)

        # call near
        self.code.append(0xE8)
        self.relocations.append(
            _ElfRelocation(
                offset=len(self.code),
                type=self._R_X86_64_PLT32,
                symbol_name=func.name,
                section_symbol=func.section,
                addend=-4,
            )
        )
        self.code.extend(bytes(4))

    def store_return_value(self, size: int, dst: _Symbol) -> None:
        if size == 1:
            # movb %al, ...
            self.code.extend(b"\x88\x05")
        elif size == 2:
            # movw %ax, ...
            self.code.extend(b"\x66\x89\x05")
        elif size == 4:
            # movl %eax, ...
            self.code.extend(b"\x89\x05")
        elif size == 8:
            # movq %rax, ...
            self.code.extend(b"\x48\x89\x05")
        else:
            raise NotImplementedError("{size}-byte return values not implemented")
        self.relocations.append(
            _ElfRelocation(
                offset=len(self.code),
                type=self._R_X86_64_PC32,
                symbol_name=dst.name,
                section_symbol=dst.section,
                addend=dst.offset - 4,
            )
        )
        # ... 0x0(%rip)
        self.code.extend(bytes(4))

    def return_(self, value: _Integer, last: bool) -> None:
        if value.size > 8:
            raise NotImplementedError(
                "return values larger than 8 bytes not implemented"
            )
        self._mov_imm(value.value, self._rax)
        # Jump to the function epilogue. If this return is the last operation,
        # we can fall through instead of jumping.
        if not last:
            # jmp
            self.code.extend(b"\xE9\x00\x00\x00\x00")
            # The destination needs to be fixed up later.
            self._epilogue_jumps.append(len(self.code))

    def return_if_last_return_value_nonzero(self, value: _Integer) -> None:
        if value.size > 8:
            raise NotImplementedError(
                "return values larger than 8 bytes not implemented"
            )
        # mov %rax, %rdx
        self.code.extend(b"\x48\x89\xC2")
        self._mov_imm(value.value, self._rax)
        # Jump to the function epilogue if the last return value was non-zero.
        self.code.extend(
            # test %rdx, %rdx
            b"\x48\x85\xD2"
            # jnz
            b"\x0F\x85\x00\x00\x00\x00"
        )
        # The destination needs to be fixed up later.
        self._epilogue_jumps.append(len(self.code))


class _Arch_X86_64:
    ELF_MACHINE = 62  # EM_X86_64
    RELA = True
    ABSOLUTE_ADDRESS_RELOCATION_TYPE = 1  # R_X86_64_64

    @staticmethod
    def code_gen(func: _Function) -> Tuple[bytes, Sequence[_ElfRelocation]]:
        needed_stack_size = 0
        for node in func.body:
            if not isinstance(node, _Call):
                continue
            stack_size = len(_CodeGen_x86_64._argument_registers) * -8
            for arg in node.args:
                if isinstance(arg, _Integer):
                    if arg.size > 8:
                        raise NotImplementedError(
                            "passing integers larger than 8 bytes not implemented"
                        )
                    stack_size += 8
                elif isinstance(arg, _Symbol):
                    stack_size += 8
                else:
                    assert_never(arg)
            if stack_size > needed_stack_size:
                needed_stack_size = stack_size

        code_gen = _CodeGen_x86_64()

        code_gen.enter_frame(needed_stack_size)

        for i, node in enumerate(func.body):
            if isinstance(node, _Call):
                code_gen.call(node.func, node.args)
            elif isinstance(node, _StoreReturnValue):
                code_gen.store_return_value(node.size, node.dst)
            elif isinstance(node, _Return):
                code_gen.return_(node.value, last=i == len(func.body) - 1)
            elif isinstance(node, _ReturnIfLastReturnValueNonZero):
                code_gen.return_if_last_return_value_nonzero(node.value)
            else:
                assert_never(node)

        code_gen.leave_frame()

        return code_gen.code, code_gen.relocations


def _find_exported_symbol_in_section(
    prog: Program, name: bytes, start: int, stop: int
) -> int:
    kernel_symbol_type = prog.type("struct kernel_symbol")
    if kernel_symbol_type.has_member("name_offset"):

        def kernel_symbol_name(sym: Object) -> Object:
            return cast("char *", sym.name_offset.address_of_()) + sym.name_offset

    else:

        def kernel_symbol_name(sym: Object) -> Object:
            return sym.name

    syms = Object(prog, prog.pointer_type(kernel_symbol_type), start)
    lo = 0
    hi = (stop - start) // sizeof(kernel_symbol_type)
    while lo < hi:
        mid = (lo + hi) // 2
        sym_name = kernel_symbol_name(syms[mid]).string_()
        if sym_name < name:
            lo = mid + 1
        elif sym_name > name:
            hi = mid
        else:
            return mid
    return -1


# If CONFIG_MODVERSIONS=y, then we need a __versions section containing a CRC
# of each exported symbol that we use. Since we intentionally don't use any
# symbols, we only need it for the special module_layout symbol.
def _get_versions_section(struct_module: Type) -> Optional[_ElfSection]:
    prog = struct_module.prog
    try:
        return prog.cache["kmodify___versions_section"]
    except KeyError:
        pass

    # module_layout is defined if and only if CONFIG_MODVERSIONS=y.
    have_module_layout = False
    try:
        have_module_layout = prog["module_layout"].address_ is not None
    except KeyError:
        pass

    if have_module_layout:
        # We only check the non-GPL-only section because module_layout is
        # non-GPL-only.
        i = _find_exported_symbol_in_section(
            prog,
            b"module_layout",
            prog.symbol("__start___ksymtab").address,
            prog.symbol("__stop___ksymtab").address,
        )
        if i < 0:
            raise LookupError("module_layout not found")

        # Since Linux kernel commit 71810db27c1c ("modversions: treat symbol
        # CRCs as 32 bit quantities") (in v4.10), CRCs are in an array of s32.
        # Before that, they are in an array of unsigned long. Determine the
        # correct type from struct module::crcs.
        module_layout_crc = (
            Object(
                prog,
                struct_module.member("crcs").type,
                prog.symbol("__start___kcrctab").address,
            )[i].value_()
            & 0xFFFFFFFF
        )

        struct_modversion_info = prog.type("struct modversion_info")
        section = _ElfSection(
            name="__versions",
            type=SHT.PROGBITS,
            flags=SHF.ALLOC,
            data=Object(
                prog,
                struct_modversion_info,
                {
                    "crc": module_layout_crc,
                    "name": b"module_layout",
                },
            ).to_bytes_(),
            addralign=alignof(struct_modversion_info),
        )
    else:
        section = None
    prog.cache["kmodify___versions_section"] = section
    return section


class _Kmodify:
    def __init__(self, prog: Program) -> None:
        if prog.flags & (
            ProgramFlags.IS_LINUX_KERNEL | ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL
        ) != (
            ProgramFlags.IS_LINUX_KERNEL | ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL
        ):
            raise ValueError("kmodify is only available for the running kernel")
        platform = prog.platform
        if platform is None:
            raise ValueError("program platform is not known")
        self.prog = prog
        self.is_little_endian = bool(platform.flags & PlatformFlags.IS_LITTLE_ENDIAN)
        self.is_64_bit = bool(platform.flags & PlatformFlags.IS_64_BIT)

        if platform.arch == Architecture.X86_64:
            # When we add support for another architecture, we're going to need
            # an _Arch Protocol.
            self.arch = _Arch_X86_64
        else:
            raise NotImplementedError(
                f"kmodify not implemented for {platform.arch.name} architecture"
            )

    _KMOD_NAME_CHARS = string.digits + string.ascii_letters

    def insert(
        self,
        *,
        name: str,
        code: bytes,
        code_relocations: Sequence[_ElfRelocation],
        data: bytes,
        data_alignment: int,
        symbols: Sequence[_ElfSymbol],
    ) -> int:
        struct_module = self.prog.type("struct module")

        module_name = "".join(
            [
                "drgn_kmodify_",
                # Randomize to avoid name collisions.
                *random.choices(self._KMOD_NAME_CHARS, k=12),
                "_",
                name,
            ]
        ).encode("ascii")[: sizeof(struct_module.member("name").type) - 1]

        sections = [
            _ElfSection(
                name=".init.text",
                type=SHT.PROGBITS,
                flags=SHF.ALLOC | SHF.EXECINSTR,
                data=code,
                # This should be good enough for any supported architecture.
                addralign=16,
            ),
            _ElfSection(
                name=".data",
                type=SHT.PROGBITS,
                flags=SHF.WRITE | SHF.ALLOC,
                data=data,
                addralign=data_alignment,
            ),
            _ElfSection(
                name=".gnu.linkonce.this_module",
                type=SHT.PROGBITS,
                flags=SHF.WRITE | SHF.ALLOC,
                data=Object(
                    self.prog, struct_module, {"name": module_name}
                ).to_bytes_(),
                addralign=alignof(struct_module),
            ),
            _ElfSection(
                name=".modinfo",
                type=SHT.PROGBITS,
                flags=SHF.ALLOC,
                data=b"".join(
                    [
                        b"%b=%b\0" % (key, value)
                        for key, value in (
                            (b"license", b"GPL"),
                            (b"depends", b""),
                            # A retpoline kernel complains when loading a
                            # non-retpoline module. We never make indirect
                            # calls, so we can claim to be a retpoline module.
                            # (Note that it's harmless to set this for
                            # non-retpoline kernels.)
                            (b"retpoline", b"Y"),
                            (b"name", module_name),
                            (b"vermagic", self.prog["vermagic"].string_()),
                        )
                    ]
                ),
            ),
        ]

        # Add the __versions section if needed.
        versions_section = _get_versions_section(struct_module)
        if versions_section is not None:
            sections.append(versions_section)

        symbols = [
            *symbols,
            _ElfSymbol(
                name="init_module",
                value=0,
                size=len(code),
                type=STT.FUNC,
                binding=STB.GLOBAL,
                section=".init.text",
            ),
        ]

        relocations = {
            ".init.text": code_relocations,
            ".gnu.linkonce.this_module": [
                _ElfRelocation(
                    offset=offsetof(struct_module, "init"),
                    type=self.arch.ABSOLUTE_ADDRESS_RELOCATION_TYPE,
                    symbol_name="init_module",
                    section_symbol=False,
                )
            ],
        }

        with open(_memfd_create(module_name.decode() + ".ko"), "wb") as f:
            _write_elf(
                f,
                machine=self.arch.ELF_MACHINE,
                is_little_endian=self.is_little_endian,
                is_64_bit=self.is_64_bit,
                rela=self.arch.RELA,
                sections=sections,
                symbols=symbols,
                relocations=relocations,
            )
            f.flush()

            if _syscall(
                ctypes.c_long(SYS["finit_module"]),
                ctypes.c_int(f.fileno()),
                ctypes.c_char_p(b""),
                ctypes.c_int(0),
            ):
                return -ctypes.get_errno()
            else:
                return 0


@takes_program_or_default
def write_memory(prog: Program, address: IntegerLike, value: bytes) -> None:
    """
    Write a byte string to kernel memory.

    >>> os.uname().sysname
    'Linux'
    >>> write_memory(prog["init_uts_ns"].name.sysname.address_, b"Lol\\0")
    >>> os.uname().sysname
    'Lol'

    .. warning::
        This attempts to detect writes to bad addresses and raise a
        :class:`~drgn.FaultError`, but this is best-effort and may still crash
        the kernel. Writing bad data can of course also cause a crash when the
        data is used. Additionally, this is not atomic, so the data may be
        accessed while it is partially written.

    :param address: Address to write to.
    :param value: Byte string to write.
    :raises FaultError: if the address cannot be written to
    """
    copy_to_kernel_nofault_address = None
    copy_from_kernel_nofault_address = None
    for copy_to_kernel_nofault, copy_from_kernel_nofault in (
        # Names used since Linux kernel commit fe557319aa06 ("maccess: rename
        # probe_kernel_{read,write} to copy_{from,to}_kernel_nofault") (in
        # v5.8-rc2).
        ("copy_to_kernel_nofault", "copy_from_kernel_nofault"),
        # Names used before Linux kernel commit 48c49c0e5f31 ("maccess: remove
        # various unused weak aliases") (in v5.8-rc1).
        ("__probe_kernel_write", "__probe_kernel_read"),
        # Names briefly used between those two commits.
        ("probe_kernel_write", "probe_kernel_read"),
    ):
        try:
            copy_to_kernel_nofault_address = prog[copy_to_kernel_nofault].address_
            copy_from_kernel_nofault_address = prog[copy_from_kernel_nofault].address_
            break
        except KeyError:
            pass
    if copy_to_kernel_nofault_address is None:
        raise LookupError("copy_to_kernel_nofault not found")
    if copy_from_kernel_nofault_address is None:
        raise LookupError("copy_from_kernel_nofault not found")

    kmodify = _Kmodify(prog)
    address = operator.index(address)
    sizeof_int = sizeof(prog.type("int"))
    sizeof_void_p = sizeof(prog.type("void *"))
    sizeof_size_t = sizeof(prog.type("size_t"))
    code, code_relocations = kmodify.arch.code_gen(
        _Function(
            [
                # copy_to_kernel_nofault() can still fault in some cases; see
                # https://lore.kernel.org/all/f0e171cbae576758d9387cee374dd65088e75b07.1725223574.git.osandov@fb.com/
                # copy_from_kernel_nofault() catches some of those cases.
                _Call(
                    _Symbol(copy_from_kernel_nofault),
                    [
                        _Symbol(".data", section=True, offset=len(value)),
                        _Integer(sizeof_void_p, address),
                        _Integer(sizeof_size_t, 1),
                    ],
                ),
                _ReturnIfLastReturnValueNonZero(
                    _Integer(sizeof_int, -errno.EFAULT),
                ),
                _Call(
                    _Symbol(copy_to_kernel_nofault),
                    [
                        _Integer(sizeof_void_p, address),
                        _Symbol(".data", section=True),
                        _Integer(sizeof_size_t, len(value)),
                    ],
                ),
                _ReturnIfLastReturnValueNonZero(
                    _Integer(sizeof_int, -errno.EFAULT),
                ),
                _Return(_Integer(sizeof_int, -errno.EINPROGRESS)),
            ]
        )
    )
    ret = kmodify.insert(
        name=f"write_{len(value)}",
        code=code,
        code_relocations=code_relocations,
        data=value + b"\0",
        # Align generously so that the copy can use larger units and small
        # copies can be slightly less racy.
        data_alignment=16,
        symbols=[
            _ElfSymbol(
                name=copy_to_kernel_nofault,
                value=copy_to_kernel_nofault_address,
                size=0,
                type=STT.FUNC,
                binding=STB.LOCAL,
                section=SHN.ABS,
            ),
            _ElfSymbol(
                name=copy_from_kernel_nofault,
                value=copy_from_kernel_nofault_address,
                size=0,
                type=STT.FUNC,
                binding=STB.LOCAL,
                section=SHN.ABS,
            ),
        ],
    )
    if ret != -errno.EINPROGRESS:
        if ret == -errno.EFAULT:
            raise FaultError("could not write to memory", address)
        elif ret:
            raise OSError(-ret, os.strerror(-ret))
        else:
            raise ValueError("module init did not run")


def _underlying_type(type: Type) -> Type:
    while type.kind == TypeKind.TYPEDEF:
        type = type.type
    return type


def write_object(
    object: Object, value: Any, *, dereference: Optional[bool] = None
) -> None:
    """
    Write to an object in kernel memory.

    >>> os.system("uptime -p")
    up 12 minutes
    >>> write_object(prog["init_time_ns"].offsets.boottime.tv_sec, 1000000000)
    >>> os.system("uptime -p")
    up 3 decades, 1 year, 37 weeks, 1 hour, 59 minutes

    .. warning::
        The warnings about :func:`write_memory()` also apply to
        ``write_object()``.

    :param object: Object to write to.
    :param value: Value to write. This may be an :class:`~drgn.Object` or a
        Python value. Either way, it will be converted to the type of *object*.
    :param dereference: If *object* is a pointer, whether to dereference it. If
        ``True``, then write to the object pointed to by *object*
        (``*ptr = value``). If ``False``, then write to the pointer itself
        (``ptr = value``). This is a common source of confusion, so it is
        required if *object* is a pointer.
    :raises ValueError: if *object* is not a reference object (i.e., its
        address is not known)
    :raises TypeError: if *object* is a pointer and *dereference* is not given
    :raises TypeError: if *object* is not a pointer and *dereference* is
        ``True``
    """
    type = object.type_
    if _underlying_type(type).kind == TypeKind.POINTER:
        if dereference is None:
            raise TypeError(
                "to write to pointed-to object (*ptr = value), use dereference=True; "
                "to write to pointer itself (ptr = value), use dereference=False"
            )
        elif dereference:
            object = object[0]
    elif dereference:
        raise TypeError("object is not a pointer")

    address = object.address_
    if address is None:
        raise ValueError("cannot write to value object")
    if isinstance(value, Object):
        value = implicit_convert(type, value)
    else:
        value = Object(object.prog_, type, value)
    write_memory(object.prog_, address, value.to_bytes_())


def _default_argument_promotions(obj: Object) -> Object:
    type = _underlying_type(obj.type_)
    if type.kind == TypeKind.INT:
        return +obj
    elif type.primitive == PrimitiveType.C_FLOAT:
        return cast("double", obj)
    else:
        return obj


@takes_program_or_default
def call_function(prog: Program, func: Union[str, Object], *args: Any) -> Object:
    """
    Call a function in the kernel.

    Arguments can be either :class:`~drgn.Object`\\ s or Python values. The
    function return value is returned as an :class:`~drgn.Object`:

    >>> # GFP_KERNEL isn't in the kernel debug info
    >>> # We have to use this trick to get it.
    >>> for flag in prog["gfpflag_names"]:
    ...     if flag.name.string_() == b"GFP_KERNEL":
    ...             GFP_KERNEL = flag.mask
    ...             break
    ...
    >>> # kmalloc() is actually a macro.
    >>> # We have to call the underlying function.
    >>> p = call_function("__kmalloc_noprof", 13, GFP_KERNEL)
    >>> p
    (void *)0xffff991701ef43c0
    >>> identify_address(p)
    'slab object: kmalloc-16+0x0'
    >>> call_function("kfree", p)
    (void)<absent>
    >>> identify_address(p)
    'free slab object: kmalloc-16+0x0'

    Variadic functions are also supported:

    >>> call_function("_printk", "Hello, world! %d\\n", Object(prog, "int", 1234))
    (int)18
    >>> os.system("dmesg | tail -1")
    [ 1138.223004] Hello, world! 1234

    Constructed values can be passed by pointer using :class:`pass_pointer()`:

    >>> sb = prog["init_fs"].root.mnt.mnt_sb
    >>> sb.s_shrink.scan_objects
    (unsigned long (*)(struct shrinker *, struct shrink_control *))super_cache_scan+0x0 = 0xffffffffbda4c487
    >>> sc = pass_pointer(Object(prog, "struct shrink_control",
    ...                   {"gfp_mask": GFP_KERNEL, "nr_to_scan": 100, "nr_scanned": 100}))
    >>> call_function(sb.s_shrink.scan_objects, sb.s_shrink, sc)
    (unsigned long)31

    If the function modifies the passed value, the :class:`pass_pointer` object
    is updated:

    >>> sc.object
    (struct shrink_control){
            .gfp_mask = (gfp_t)3264,
            .nid = (int)0,
            .nr_to_scan = (unsigned long)1,
            .nr_scanned = (unsigned long)100,
            .memcg = (struct mem_cgroup *)0x0,
    }

    .. note::
        It is not possible to call some functions, including inlined functions
        and function-like macros. If the unavailable function is a wrapper
        around another function, sometimes the wrapped function can be called
        instead.

    .. warning::
        Calling a function incorrectly may cause the kernel to crash or
        misbehave in various ways.

        The function is called from process context. Note that the function may
        have context, locking, or reference counting requirements.

    :param func: Function to call. May be a function name, function object, or
        function pointer object.
    :param args: Function arguments. :class:`int`, :class:`float`, and
        :class:`bool` arguments are converted as "literals" with
        ``Object(prog, value=...)``. :class:`str` and :class:`bytes` arguments
        are converted to ``char`` array objects. :class:`pass_pointer`
        arguments are copied to the kernel, passed by pointer, and copied back.
    :return: Function return value.
    :raises TypeError: if the passed arguments have incorrect types for the
        function
    :raises ObjectAbsentError: if the function cannot be called because it is
        inlined
    :raises LookupError: if a function with the given name is not found
        (possibly because it is actually a function-like macro)
    """
    if not isinstance(func, Object):
        func = prog.function(func)

    kmodify = _Kmodify(prog)

    func_type = _underlying_type(func.type_)
    try:
        if func_type.kind == TypeKind.FUNCTION:
            func_pointer = func.address_of_()
        elif func_type.kind == TypeKind.POINTER:
            func_type = _underlying_type(func_type.type)
            if func_type.kind != TypeKind.FUNCTION:
                raise TypeError("func must be function or function pointer")
            func_pointer = func.read_()
        else:
            raise TypeError("func must be function or function pointer")
    except ObjectAbsentError:
        raise ObjectAbsentError("function is absent, likely inlined") from None

    return_type = _underlying_type(func_type.type)
    if return_type.kind not in {
        TypeKind.VOID,
        TypeKind.INT,
        TypeKind.BOOL,
        TypeKind.ENUM,
        TypeKind.POINTER,
    }:
        raise NotImplementedError(f"{return_type} return values not implemented")

    if len(args) < len(func_type.parameters):
        raise TypeError(f"not enough arguments for {func_pointer}; got {len(args)}")
    if not func_type.is_variadic and len(args) > len(func_type.parameters):
        raise TypeError(f"too many arguments for {func_pointer}; got {len(args)}")

    call_args: List[Union[_Integer, _Symbol]] = []
    out_pointers = []
    data = bytearray()
    data_alignment = 1

    def align_data(alignment: int) -> None:
        nonlocal data_alignment
        if alignment > data_alignment:
            data_alignment = alignment
        data.extend(bytes(-len(data) % alignment))

    for i, arg in enumerate(args):
        if i < len(func_type.parameters):
            parameter_type = _underlying_type(func_type.parameters[i].type)

        if (
            (
                isinstance(arg, (str, bytes, bytearray))
                or (
                    isinstance(arg, pass_pointer)
                    and isinstance(arg.object, (str, bytes, bytearray))
                )
            )
            and i < len(func_type.parameters)
            and parameter_type.kind == TypeKind.POINTER
            and _underlying_type(parameter_type.type).primitive
            in (
                PrimitiveType.C_CHAR,
                PrimitiveType.C_SIGNED_CHAR,
                PrimitiveType.C_UNSIGNED_CHAR,
            )
        ):
            # Convert strings to null-terminated character arrays.
            if not isinstance(arg, pass_pointer):
                arg = pass_pointer(arg)
            if isinstance(arg.object, str):
                arg.object = arg.object.encode()
            arg.object = Object(
                prog,
                prog.array_type(
                    parameter_type.type,
                    len(arg.object) + 1,
                    language=func_type.language,
                ),
                arg.object,
            )
        elif (
            isinstance(arg, Object)
            and _underlying_type(arg.type_).kind == TypeKind.ARRAY
        ):
            # Convert arrays to pointers.
            if arg.address_ is None:
                arg = pass_pointer(arg)
            else:
                arg = arg + 0

        if isinstance(arg, pass_pointer):
            if not isinstance(arg.object, Object):
                arg.object = Object(prog, value=arg.object)
            type = arg.object.type_
            underlying_type = _underlying_type(type)
            if underlying_type.kind == TypeKind.ARRAY:
                type = underlying_type.type
            if i < len(func_type.parameters):
                # We don't need the result, just type checking.
                implicit_convert(
                    func_type.parameters[i].type,
                    Object(prog, prog.pointer_type(type), 0),
                )
            value = arg.object.to_bytes_()

            align_data(alignof(arg.object.type_))
            out_pointers.append((arg, len(data)))
            call_args.append(_Symbol(".data", section=True, offset=len(data)))
            data.extend(value)
        else:
            if isinstance(arg, Object):
                if i < len(func_type.parameters):
                    arg = implicit_convert(func_type.parameters[i].type, arg)
                else:
                    arg = _default_argument_promotions(arg)
            else:
                arg = Object(prog, value=arg)

            type = _underlying_type(arg.type_)
            if type.kind not in {
                TypeKind.INT,
                TypeKind.BOOL,
                TypeKind.ENUM,
                TypeKind.POINTER,
            }:
                if type.kind in {
                    TypeKind.FLOAT,
                    TypeKind.STRUCT,
                    TypeKind.UNION,
                    TypeKind.CLASS,
                }:
                    raise NotImplementedError(
                        f"passing {type} by value not implemented"
                    )
                else:
                    raise ValueError(f"cannot pass {type} by value")

            call_args.append(_Integer(sizeof(type), arg.value_()))

    function_body: List[_FunctionBodyNode] = [_Call(_Symbol("func"), call_args)]
    symbols = [
        _ElfSymbol(
            name="func",
            value=func_pointer.value_(),
            size=0,
            type=STT.FUNC,
            binding=STB.LOCAL,
            section=SHN.ABS,
        )
    ]

    if return_type.kind != TypeKind.VOID:
        align_data(alignof(return_type))
        return_offset = len(data)
        return_size = sizeof(return_type)
        data.extend(bytes(return_size))
        function_body.append(
            _StoreReturnValue(
                return_size,
                _Symbol(".data", section=True, offset=return_offset),
            )
        )

    # copy_to_user() is the more obvious choice, but it's an inline function.
    copy_to_user_nofault_address = None
    for copy_to_user_nofault in (
        # Name used since Linux kernel commit c0ee37e85e0e ("maccess: rename
        # probe_user_{read,write} to copy_{from,to}_user_nofault") (in
        # v5.8-rc2).
        "copy_to_user_nofault",
        # Name used before Linux kernel commit 48c49c0e5f31 ("maccess: remove
        # various unused weak aliases") (in v5.8-rc1).
        "__probe_user_write",
        # Name briefly used between those two commits.
        "probe_user_write",
    ):
        try:
            copy_to_user_nofault_address = prog[copy_to_user_nofault].address_
            break
        except KeyError:
            continue
    if copy_to_user_nofault_address is None:
        raise LookupError("copy_to_user_nofault not found")

    sizeof_int = sizeof(prog.type("int"))
    if data:
        out_buf = ctypes.create_string_buffer(len(data))
        function_body.append(
            _Call(
                _Symbol(copy_to_user_nofault),
                [
                    _Integer(sizeof(prog.type("void *")), ctypes.addressof(out_buf)),
                    _Symbol(".data", section=True),
                    _Integer(sizeof(prog.type("size_t")), len(data)),
                ],
            )
        )
        function_body.append(
            _ReturnIfLastReturnValueNonZero(_Integer(sizeof_int, -errno.EFAULT))
        )
        symbols.append(
            _ElfSymbol(
                name=copy_to_user_nofault,
                value=copy_to_user_nofault_address,
                size=0,
                type=STT.FUNC,
                binding=STB.LOCAL,
                section=SHN.ABS,
            )
        )

    function_body.append(_Return(_Integer(sizeof_int, -errno.EINPROGRESS)))

    code, code_relocations = kmodify.arch.code_gen(_Function(function_body))

    kmod_name = "call"
    try:
        symbol_name_match = re.match(r"[0-9a-zA-Z_]+", prog.symbol(func_pointer).name)
        if symbol_name_match:
            kmod_name = "call_" + symbol_name_match.group()
    except LookupError:
        pass

    ret = kmodify.insert(
        name=kmod_name,
        code=code,
        code_relocations=code_relocations,
        data=data,
        data_alignment=data_alignment,
        symbols=symbols,
    )
    if ret != -errno.EINPROGRESS:
        if ret:
            raise OSError(-ret, os.strerror(-ret))
        else:
            raise ValueError("module init did not run")

    for out_pointer, offset in out_pointers:
        out_pointer.object = Object.from_bytes_(
            prog, out_pointer.object.type_, out_buf, bit_offset=offset * 8
        )

    if return_type.kind == TypeKind.VOID:
        return Object(prog, func_type.type)
    else:
        return Object.from_bytes_(
            prog, func_type.type, out_buf, bit_offset=return_offset * 8
        )


class pass_pointer:
    object: Any
    """
    Wrapped object. Updated to an :class:`~drgn.Object` containing the final
    value after the function call.
    """

    def __init__(self, object: Any) -> None:
        """
        Wrapper used to pass values to :func:`call_function()` by pointer.

        :param object: :class:`~drgn.Object` or Python value to wrap.
        """
        self.object = object

    def __repr__(self) -> str:
        return f"pass_pointer({self.object!r})"
