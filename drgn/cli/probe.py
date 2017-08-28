from drgn.dwarf import DwarfProgram
from drgn.dwarf.defs import *
from drgn.ftrace import Kprobe, FtraceInstance
import re
import os


def sanitize_probe_name(name: str) -> str:
    name = re.sub('[^0-9A-Za-z]', '_', name)
    if name[0].isdigit():
        name = '_' + name
    return name


def cmd_probe(args):
    if args.line or (not args.function and ':' in args.location):
        function = None
        filename, lineno = args.location.rsplit(':', 1)
        # TODO: catch ValueError
        lineno = int(lineno)
        probe_name = sanitize_probe_name(f'{filename}_{lineno}')
    else:
        function = args.location
        probe_name = sanitize_probe_name(function)
    probe_name = f'drgn/{probe_name}'

    binary = f'/lib/modules/{os.uname().release}/build/vmlinux'
    with DwarfProgram(binary) as dwarf_program:
        if function is not None:
            scope = dwarf_program.find_subprogram_by_name(function)
            probe_addr = scope.cu.file.die_address(scope)
            probe_location = function
        else:
            cu = dwarf_program.find_cu_by_name(filename)
            row = dwarf_program.find_breakpoint(cu, filename, lineno)
            scope = dwarf_program.find_scope_containing_address(cu, row.address)

            subprogram = scope
            while subprogram.tag != DW_TAG.subprogram:
                subprogram = subprogram.parent
            subprogram_name = cu.file.die_name(subprogram)
            subprogram_addr = cu.file.die_address(subprogram)

            assert row.address >= subprogram_addr
            probe_addr = row.address
            probe_location = f'{subprogram_name}+0x{row.address - subprogram_addr:x}'

        for var in args.variables:
            resolved = dwarf_program.resolve_variable(scope, var)

    # TODO: deal with probe name collisions
    with FtraceInstance(f'drgn_{os.getpid()}') as instance, \
         Kprobe(probe_name, probe_location) as probe:
        probe.enable(instance)
        try:
            import subprocess
            subprocess.call(['cat', f'/sys/kernel/debug/tracing/instances/{instance.name}/trace_pipe'])
        finally:
            probe.disable(instance)


def register(subparsers):
    subparser = subparsers.add_parser(
        'probe')

    subparser.add_argument(
        'location', metavar='LOCATION',
        help='location to probe; either a function name or file:line')

    subparser.add_argument(
        'variables', metavar='VAR', nargs='*', help='variables to fetch')

    group = subparser.add_mutually_exclusive_group()
    group.add_argument(
        '--line', '-l', action='store_true',
        help='force location to be treated as file:line')
    group.add_argument(
        '--function', '-f', action='store_true',
        help='force location to be treated as function name')

    subparser.set_defaults(func=cmd_probe)
