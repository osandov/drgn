# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

import argparse
import builtins
import code
import glob
import os
import os.path
import platform
import runpy
import sys
from typing import Any, Dict, List, Tuple, Union

import drgn
from drgn.corereader import CoreReader
from drgn.dwarf import DW_TAG, DwarfAttribNotFoundError
from drgn.dwarfindex import DwarfIndex
from drgn.program import Program, ProgramObject
from drgn.type import Type
from drgn.typeindex import DwarfTypeIndex
from drgn.util import parse_symbol_file


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

    release = platform.release()

    if args.executable is None:
        try:
            args.executable = find_vmlinux(release)
        except ValueError:
            sys.exit('Could not find vmlinux file; install the proper debuginfo package or use --executable')

    modules = find_modules(release)
    if not modules and not args.script:
        print('Could not find kernel modules; continuing anyways',
              file=sys.stderr)

    dwarf_index = DwarfIndex()
    dwarf_index.add(args.executable)
    dwarf_index.add(*modules)
    type_index = DwarfTypeIndex(dwarf_index)

    with open('/proc/kallsyms', 'r') as f:
        symbols = parse_symbol_file(f)

    with CoreReader('/proc/kcore') as core_reader:
        def lookup_variable(name: str) -> Tuple[int, Type]:
            address = symbols[name][-1]
            variable = dwarf_index.find(name, DW_TAG.variable)[0]
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
