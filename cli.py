import code
import argparse
import glob
import os
import os.path
import platform
import runpy
import sys

from drgn.coredump import Coredump, CoredumpObject
from drgn.dwarf import DW_TAG
from drgn.dwarfindex import DwarfIndex
from drgn.elf import ElfFile
import drgn.type
from drgn.util import parse_symbol_file


def find_vmlinux(release):
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


def find_modules(release):
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


def main():
    parser = argparse.ArgumentParser(prog='drgn')
    parser.add_argument(
        '-k', '--kernel', action='store_true',
        help='debug the kernel instead of a userspace program')
    parser.add_argument(
        '-e', '--executable', metavar='PATH', type=str,
        help='use the given executable file')
    parser.add_argument(
        'script', metavar='ARG', type=str, nargs='*',
        help='script to execute instead of running an interactive shell')

    args = parser.parse_args()

    if not args.kernel:
        sys.exit('Only --kernel mode is currently implemented')

    release = platform.release()

    if args.executable is None:
        try:
            args.executable = find_vmlinux(release)
        except ValueError:
            sys.exit('Could not find vmlinux file; install the proper debuginfo package or use --executable')

    paths = find_modules(release)
    if not paths and not args.script:
        print('Could not find kernel modules; continuing anyways',
              file=sys.stderr)
    paths.append(args.executable)

    if not args.script:
        print('Reading symbols...')
    dwarf_index = DwarfIndex(paths)

    with open('/proc/kallsyms', 'r') as f:
        symbols = parse_symbol_file(f)

    with open('/proc/kcore', 'rb') as core_file:
        core_elf_file = ElfFile(core_file)

        def lookup_type(type_name):
            return drgn.type.from_dwarf_type_name(dwarf_index, type_name)

        def lookup_variable(name):
            address = symbols[name][-1]
            dwarf_type = dwarf_index.find(name, DW_TAG.variable).type()
            type_ = drgn.type.from_dwarf_type(dwarf_index, dwarf_type)
            return address, type_

        def read_memory(address, size):
            for phdr in core_elf_file.phdrs():
                if phdr.p_vaddr <= address <= phdr.p_vaddr + phdr.p_memsz:
                    break
            else:
                raise ValueError(f'could not find memory segment containing 0x{address:x}')
            return os.pread(core_file.fileno(), size,
                            phdr.p_offset + address - phdr.p_vaddr)

        init_globals = {
            'core': Coredump(lookup_type_fn=lookup_type,
                             lookup_variable_fn=lookup_variable,
                             read_memory_fn=read_memory),
            'CoredumpObject': CoredumpObject,
        }
        if args.script:
            sys.argv = args.script
            runpy.run_path(args.script[0], init_globals=init_globals,
                           run_name='__main__')
        else:
            init_globals['__name__'] = '__main__'
            init_globals['__doc__'] = None
            code.interact(banner='', exitmsg='', local=init_globals)

if __name__ == '__main__':
    main()
