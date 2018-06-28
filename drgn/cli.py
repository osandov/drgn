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
from drgn.dwarf import DW_TAG, DwarfAttribNotFoundError
from drgn.dwarfindex import DwarfIndex
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


def parse_vmcoreinfo(data: bytes) -> Dict[str, Any]:
    # VMCOREINFO is an ELF note, so the first 12 bytes are the Elf{32,64}_Nhdr
    # (it's the same in both formats). The type isn't set to anything
    # meaningful by the kernel, so we just ignore it.
    namesz, descsz = struct.unpack_from('=II', data)

    if namesz != 11 or data[12:23] != b'VMCOREINFO\0':
        raise ValueError('VMCOREINFO is invalid')

    fields = {}
    # The name is padded up to 4 bytes, so the descriptor starts at byte 24.
    for line in data[24:24 + descsz].splitlines():
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
        '-e', '--executable', metavar='PATH', type=str,
        help='use the given executable file')
    parser.add_argument(
        'script', metavar='ARG', type=str, nargs='*',
        help='script to execute instead of running in interactive mode')
    parser.add_argument('--version', action='version', version=version)

    args = parser.parse_args()

    if not args.kernel:
        sys.exit('Only --kernel mode is currently implemented')

    with CoreReader('/proc/kcore') as core_reader:
        from drgn.helpers.kernel import list_for_each_entry

        with open('/sys/kernel/vmcoreinfo', 'r') as f:
            tokens = f.read().split()
            vmcoreinfo_address = int(tokens[0], 16)
            vmcoreinfo_size = int(tokens[1], 16)
        vmcoreinfo_data = core_reader.read(vmcoreinfo_address, vmcoreinfo_size,
                                           physical=True)
        vmcoreinfo = parse_vmcoreinfo(vmcoreinfo_data)

        release = vmcoreinfo['OSRELEASE']
        if args.executable is None:
            try:
                args.executable = find_vmlinux(release)
            except ValueError:
                sys.exit('Could not find vmlinux file; install the proper debuginfo package or use --executable')

        dwarf_index = DwarfIndex()
        modules = find_modules(release)
        if not modules and not args.script:
            print('Could not find kernel modules; continuing anyways',
                  file=sys.stderr)
        dwarf_index.add(args.executable, *modules)

        type_index = DwarfTypeIndex(dwarf_index)

        def lookup_variable(prog: Program, name: str) -> Tuple[int, Type]:
            variable = dwarf_index.find(name, DW_TAG.variable)[0]
            address = variable.location()
            elf_file = variable.cu.dwarf_file.elf_file
            file_name = os.path.basename(elf_file.path).split('.', 1)[0]
            if file_name == 'vmlinux':
                address += vmcoreinfo['KERNELOFFSET']
            else:
                module_name = file_name.replace('-', '_').encode('ascii')
                for mod in list_for_each_entry('struct module',
                                               prog['modules'].address_of_(), 'list'):
                    if mod.name.string_() == module_name:
                        break
                else:
                    raise ValueError(f'{module_name.decode()} is not loaded')
                for sym in elf_file.symbols[name]:
                    if sym.st_value == address:
                        break
                else:
                    raise ValueError(f'Could not find {name} symbol')
                section_name = elf_file.shdrs[sym.st_shndx].name.encode()
                mod_sects = mod.sect_attrs.attrs
                for i in range(mod.sect_attrs.nsections):
                    attr = mod.sect_attrs.attrs[i]
                    if attr.name.string_() == section_name:
                        address += attr.address.value_()
                        break
                else:
                    raise ValueError(f'Could not find module section {section_name.decode()}')
            try:
                dwarf_type = variable.type()
            except DwarfAttribNotFoundError:
                dwarf_type = variable.specification().type()
            return address, type_index.find_dwarf_type(dwarf_type)

        init_globals: Dict[str, Any] = {
            'prog': Program(reader=core_reader, type_index=type_index,
                            lookup_variable_fn=lookup_variable),
            'drgn': drgn,
        }
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
