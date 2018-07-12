# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

import os.path
import platform
import struct
import sys
from typing import cast, Any, Dict, Generator, Iterable, List, Optional, Tuple

from drgn.corereader import CoreReader
from drgn.dwarfindex import DwarfIndex
from drgn.elf import ElfFile, ET_CORE, NT_FILE, PT_LOAD
from drgn.kernelvariableindex import KernelVariableIndex
from drgn.program import Program
from drgn.typeindex import DwarfTypeIndex, TypeIndex
from drgn.util import (
    FileMapping,
    find_vmlinux_debuginfo,
    find_modules_debuginfo,
    parse_proc_maps,
    parse_vmcoreinfo,
)
from drgn.variableindex import UserspaceVariableIndex, VariableIndex


def kernel_type_index(release: Optional[str] = None,
                      verbose: bool = False) -> TypeIndex:
    if release is None:
        release = platform.release()
    vmlinux = find_vmlinux_debuginfo(release)
    modules = find_modules_debuginfo(release)
    if not modules and verbose:
        print('Could not find kernel modules; continuing anyways',
              file=sys.stderr)
    dwarf_index = DwarfIndex(vmlinux, *modules)
    indexed_files = dwarf_index.files
    if len(indexed_files) < len(modules) + 1:
        if vmlinux not in indexed_files:
            raise ValueError('vmlinux does not have debugging symbols')
        elif verbose:
            missing = set(modules) - set(indexed_files)
            num_missing = len(missing)
            print(f"Missing symbols for {num_missing} module{'' if num_missing == 1 else 's'}:",
                  file=sys.stderr)
            for i, m in enumerate(sorted(missing)):
                if i == 5:
                    print('...', file=sys.stderr)
                    break
                print(m, file=sys.stderr)
    return DwarfTypeIndex(dwarf_index)


def program_type_index(paths: Iterable[str],
                       verbose: bool = False) -> TypeIndex:
    dwarf_index = DwarfIndex(*paths)
    return DwarfTypeIndex(dwarf_index)


def _read_vmcoreinfo_from_sysfs(core_reader: CoreReader) -> Dict[str, Any]:
    with open('/sys/kernel/vmcoreinfo', 'r') as f:
        tokens = f.read().split()
        address = int(tokens[0], 16)
        size = int(tokens[1], 16)
    note = core_reader.read(address, size, physical=True)
    # The first 12 bytes are the Elf{32,64}_Nhdr (it's the same in both
    # formats). We can ignore the type.
    namesz, descsz = struct.unpack_from('=II', note)
    if namesz != 11 or note[12:22] != b'VMCOREINFO':
        raise ValueError('VMCOREINFO in /sys/kernel/vmcoreinfo is invalid')
    # The name is padded up to 4 bytes, so the descriptor starts at
    # byte 24.
    return parse_vmcoreinfo(note[24:24 + descsz])


def program(core: Optional[str] = None, pid: Optional[int] = None,
            verbose: bool = False) -> Program:
    if core is None and pid is None:
        raise ValueError('either core or pid should be given')
    if core is not None and pid is not None:
        raise ValueError('only one of core or pid should be given')

    if pid is not None:
        core = f'/proc/{pid}/mem'
    assert core is not None

    file_mappings = None
    vmcoreinfo = None
    segments: List[Tuple[int, int, int, int, int]]

    core_file = open(core, 'rb')
    try:
        if pid is None:
            core_elf_file = ElfFile(core_file)
            if core_elf_file.ehdr.e_type != ET_CORE:
                raise ValueError('ELF file is not a core dump')

            # p_offset, p_vaddr, p_paddr, p_filesz, p_memsz
            segments = [phdr[2:7] for phdr in core_elf_file.phdrs
                        if phdr.p_type == PT_LOAD]
        else:
            if sys.maxsize >= 2**32:
                max_address = 2**64 - 1
            else:
                max_address = 2**32 - 1
            segments = [(0, 0, 0, max_address, max_address)]
        core_reader = CoreReader(core_file, segments)
    except:
        core_file.close()
        raise

    try:
        if pid is None:
            if os.path.abspath(core) == '/proc/kcore':
                vmcoreinfo = _read_vmcoreinfo_from_sysfs(core_reader)
            else:
                for note in core_elf_file.notes():
                    if note.name == b'CORE' and note.type == NT_FILE:
                        file_mappings = core_elf_file.parse_nt_file(note.data)
                        break
                    elif note.name == b'VMCOREINFO':
                        vmcoreinfo = parse_vmcoreinfo(note.data)
                        break

        variable_index: VariableIndex
        if vmcoreinfo is not None:
            type_index = kernel_type_index(vmcoreinfo['OSRELEASE'], verbose)
            kaslr_offset = vmcoreinfo.get('KERNELOFFSET', 0)
            variable_index = KernelVariableIndex(cast(DwarfTypeIndex, type_index),
                                                 kaslr_offset)
        else:
            if pid is not None:
                file_mappings = parse_proc_maps(f'/proc/{pid}/maps')
            elif file_mappings is None:
                raise ValueError('core dump has no NT_FILE or VMCOREINFO note')
            type_index = program_type_index({mapping.path for mapping in file_mappings},
                                            verbose)
            variable_index = UserspaceVariableIndex(cast(DwarfTypeIndex, type_index),
                                                    file_mappings)

        return Program(reader=core_reader, type_index=type_index,
                       variable_index=variable_index)
    except:
        core_reader.close()
        raise
