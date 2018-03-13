import code
import argparse
import glob
import os.path
import platform
import runpy
import sys

from drgn.coredump import Coredump
from drgn.dwarf import DwarfFile, DwarfIndex
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
    dwarf_index = DwarfIndex()
    for path in paths:
        with open(path, 'rb') as f:
            dwarf_file = DwarfFile.from_file(f)
            for cu in dwarf_file.cu_headers():
                dwarf_index.index_cu(cu)

    with open('/proc/kallsyms', 'r') as f:
        symbols = parse_symbol_file(f)

    with open('/proc/kcore', 'rb') as core_file:
        core = Coredump(core_file, dwarf_index, symbols)
        if args.script:
            sys.argv = args.script
            runpy.run_path(args.script[0], init_globals={'core': core},
                           run_name='__main__')
        else:
            code.interact(banner='', exitmsg='', local={
                'core': core,
                '__name__': '__name__',
                '__doc__': None,
            })

if __name__ == '__main__':
    main()
