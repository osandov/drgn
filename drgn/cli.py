# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

import argparse
import builtins
import code
import os.path
import runpy
import sys
from typing import Any, Dict

import drgn
from drgn.lib import program
from drgn.program import ProgramObject
from drgn.type import Type


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
    group.add_argument(
        '-p', '--pid', metavar='PID',
        help='debug the running program with the given PID')
    parser.add_argument(
        'script', metavar='ARG', type=str, nargs='*',
        help='script to execute instead of running in interactive mode')
    parser.add_argument('--version', action='version', version=version)

    args = parser.parse_args()

    if args.pid is not None:
        args.core = f'/proc/{args.pid}/mem'

    with program(args.core, args.pid, verbose=not args.script) as prog:
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
