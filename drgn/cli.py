# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

import argparse
import builtins
import code
import glob
import os
import os.path
import re
import runpy
import struct
import sys
from typing import Any, Dict, List, Tuple, Union

import drgn
from drgn.corereader import CoreReader
from drgn.dwarfindex import DwarfIndex
from drgn.elf import ElfFile, ET_CORE, NT_FILE, PT_LOAD
from drgn.kernelvariableindex import KernelVariableIndex
from drgn.program import Program, ProgramObject
from drgn.type import Type
from drgn.typeindex import DwarfTypeIndex, TypeIndex
from drgn.util import FileMapping
from drgn.variableindex import UserspaceVariableIndex, VariableIndex


def displayhook(value: Any) -> None:
    if value is None:
        return
    setattr(builtins, '_', None)
    text = str(value) if isinstance(value, (ProgramObject, Type)) else repr(value)
    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:
        encoded = text.encode(sys.stdout.encoding, 'backslashreplace')
        if hasattr(sys.stdout, 'buffer'):
            sys.stdout.buffer.write(encoded)
        else:
            text = encoded.decode(sys.stdout.encoding, 'strict')
            sys.stdout.write(text)
    sys.stdout.write('\n')
    setattr(builtins, '_', value)


def find_vmlinux(release: str) -> str:
    paths = [
        f'/usr/lib/debug/lib/modules/{release}/vmlinux',
        f'/boot/vmlinux-{release}',
        f'/lib/modules/{release}/build/vmlinux',
    ]
    for path in paths:
        if os.path.exists(path):
            return path
    else:
        raise ValueError('could not find vmlinux file')


def find_modules(release: str) -> List[str]:
    patterns = [
        f'/usr/lib/debug/lib/modules/{release}/kernel/**/*.ko.debug',
        f'/lib/modules/{release}/kernel/**/*.ko',
    ]
    for pattern in patterns:
        paths = glob.glob(pattern, recursive=True)
        if paths:
            return paths
    else:
        return []


def read_vmcoreinfo_from_sysfs(core_reader: CoreReader) -> bytes:
    with open('/sys/kernel/vmcoreinfo', 'r') as f:
        tokens = f.read().split()
        address = int(tokens[0], 16)
        size = int(tokens[1], 16)
    note = core_reader.read(address, size, physical=True)
    # The first 12 bytes are the Elf{32,64}_Nhdr (it's the same in both
    # formats). We can ignore the type.
    namesz, descsz = struct.unpack_from('=II', note)
    if namesz != 11 or note[12:22] != b'VMCOREINFO':
        sys.exit('VMCOREINFO in /sys/kernel/vmcoreinfo is invalid')
    # The name is padded up to 4 bytes, so the descriptor starts at
    # byte 24.
    return note[24:24 + descsz]


def parse_vmcoreinfo(data: bytes) -> Dict[str, Any]:
    fields = {}
    for line in data.splitlines():
        tokens = line.split(b'=', 1)
        key = tokens[0].decode('ascii')
        value: Any
        if re.match(r'PAGESIZE|LENGTH\(|NUMBER\(|OFFSET\(|SIZE\(', key):
            value = int(tokens[1], 10)
        elif re.match(r'KERNELOFFSET|SYMBOL\(', key):
            value = int(tokens[1], 16)
        else:
            value = tokens[1].decode('ascii')
        fields[key] = value
    return fields


def index_kernel(vmcoreinfo: Dict[str, Any],
                 verbose: bool) -> Tuple[TypeIndex, VariableIndex]:
    vmlinux = find_vmlinux(vmcoreinfo['OSRELEASE'])
    modules = find_modules(vmcoreinfo['OSRELEASE'])
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
    type_index = DwarfTypeIndex(dwarf_index)
    variable_index = KernelVariableIndex(type_index,
                                         vmcoreinfo.get('KERNELOFFSET', 0))
    return type_index, variable_index


def index_program(file_mappings: List[FileMapping],
                  verbose: bool) -> Tuple[TypeIndex, VariableIndex]:
    dwarf_index = DwarfIndex(*{mapping.path for mapping in file_mappings})
    type_index = DwarfTypeIndex(dwarf_index)
    return type_index, UserspaceVariableIndex(type_index, file_mappings)


def main() -> None:
    python_version = '.'.join(str(v) for v in sys.version_info[:3])
    version = f'drgn {drgn.__version__} (using Python {python_version})'
    parser = argparse.ArgumentParser(
        prog='drgn', description='Scriptable debugger')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '-c', '--core', metavar='PATH', type=str,
        help='debug the given core dump')
    group.add_argument(
        '-k', '--kernel', action='store_const', const='/proc/kcore', dest='core',
        help='debug the running kernel')
    parser.add_argument(
        'script', metavar='ARG', type=str, nargs='*',
        help='script to execute instead of running in interactive mode')
    parser.add_argument('--version', action='version', version=version)

    args = parser.parse_args()

    with open(args.core, 'rb') as core_file:
        core_elf_file = ElfFile(core_file)
        if core_elf_file.ehdr.e_type != ET_CORE:
            sys.exit('ELF file is not a core dump')

        # p_offset, p_vaddr, p_paddr, p_filesz, p_memsz
        segments = [phdr[2:7] for phdr in core_elf_file.phdrs
                    if phdr.p_type == PT_LOAD]
        core_reader = CoreReader(core_file.fileno(), segments)

        nt_file_data = None
        vmcoreinfo_data = None
        if os.path.abspath(args.core) == '/proc/kcore':
            vmcoreinfo_data = read_vmcoreinfo_from_sysfs(core_reader)
        else:
            for note in core_elf_file.notes():
                if note.name == b'CORE' and note.type == NT_FILE:
                    nt_file_data = note.data
                    break
                elif note.name == b'VMCOREINFO':
                    vmcoreinfo_data = note.data
                    break

        if vmcoreinfo_data is not None:
            vmcoreinfo = parse_vmcoreinfo(vmcoreinfo_data)
            type_index, variable_index = index_kernel(
                vmcoreinfo, verbose=not args.script)
        elif nt_file_data is not None:
            file_mappings = core_elf_file.parse_nt_file(nt_file_data)
            type_index, variable_index = index_program(
                file_mappings, verbose=not args.script)
        else:
            sys.exit('Core dump has no NT_FILE or VMCOREINFO note')

        prog = Program(reader=core_reader, type_index=type_index,
                       variable_index=variable_index)
        if isinstance(variable_index, KernelVariableIndex):
            variable_index.set_program(prog)

        init_globals: Dict[str, Any] = {'drgn': drgn, 'prog': prog}
        if args.script:
            sys.argv = args.script
            runpy.run_path(args.script[0], init_globals=init_globals,
                           run_name='__main__')
        else:
            import atexit
            import readline

            from drgn.rlcompleter import Completer

            init_globals['__name__'] = '__main__'
            init_globals['__doc__'] = None

            histfile = os.path.expanduser('~/.drgn_history')
            try:
                readline.read_history_file(histfile)
            except FileNotFoundError:
                pass
            readline.parse_and_bind('tab: complete')
            readline.set_history_length(1000)
            atexit.register(readline.write_history_file, histfile)

            readline.set_completer(Completer(init_globals).complete)
            atexit.register(lambda: readline.set_completer(None))

            sys.displayhook = displayhook

            banner = version + '\nFor help, type help(drgn).'
            code.interact(banner=banner, exitmsg='', local=init_globals)


if __name__ == '__main__':
    main()
