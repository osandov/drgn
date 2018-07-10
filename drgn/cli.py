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
from drgn.elf import ElfFile, ET_CORE, PT_LOAD
from drgn.kernelvariableindex import KernelVariableIndex
from drgn.program import Program, ProgramObject
from drgn.type import Type
from drgn.typeindex import DwarfTypeIndex


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
        raise ValueError()


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
        sys.exit('VMCOREINFO is invalid')
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


def main() -> None:
    python_version = '.'.join(str(v) for v in sys.version_info[:3])
    version = f'drgn {drgn.__version__} (using Python {python_version})'
    parser = argparse.ArgumentParser(
        prog='drgn', description='Scriptable debugger')
    parser.add_argument(
        '-k', '--kernel', action='store_true',
        help='debug the kernel instead of a userspace program')
    parser.add_argument(
        '-c', '--core', metavar='PATH', type=str,
        help='use the given core file (default: /proc/kcore in kernel mode)')
    parser.add_argument(
        '-e', '--executable', metavar='PATH', type=str,
        help='use the given executable file')
    parser.add_argument(
        'script', metavar='ARG', type=str, nargs='*',
        help='script to execute instead of running in interactive mode')
    parser.add_argument('--version', action='version', version=version)

    args = parser.parse_args()

    if not args.kernel:
        sys.exit('Only --kernel mode is currently implemented')

    if args.core is None:
        args.core = '/proc/kcore'

    with open(args.core, 'rb') as core_file:
        core_elf_file = ElfFile(core_file)
        if core_elf_file.ehdr.e_type != ET_CORE:
            sys.exit('ELF file is not a core dump')

        # p_offset, p_vaddr, p_paddr, p_filesz, p_memsz
        segments = [phdr[2:7] for phdr in core_elf_file.phdrs
                    if phdr.p_type == PT_LOAD]
        core_reader = CoreReader(core_file.fileno(), segments)

        if os.path.abspath(args.core) == '/proc/kcore':
            vmcoreinfo_data = read_vmcoreinfo_from_sysfs(core_reader)
        else:
            for name, _, vmcoreinfo_data in core_elf_file.notes():
                if name == b'VMCOREINFO':
                    break
            else:
                sys.exit('Could not find VMCOREINFO note; not a kernel vmcore?')
        vmcoreinfo = parse_vmcoreinfo(vmcoreinfo_data)

        release = vmcoreinfo['OSRELEASE']
        if args.executable is None:
            try:
                args.executable = find_vmlinux(release)
            except ValueError:
                sys.exit('Could not find vmlinux file; install the proper debuginfo package or use --executable')

        modules = find_modules(release)
        if not modules and not args.script:
            print('Could not find kernel modules; continuing anyways',
                  file=sys.stderr)
        dwarf_index = DwarfIndex(args.executable, *modules)
        type_index = DwarfTypeIndex(dwarf_index)
        variable_index = KernelVariableIndex(type_index,
                                             vmcoreinfo.get('KERNELOFFSET', 0))
        prog = Program(reader=core_reader, type_index=type_index,
                       variable_index=variable_index)
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
