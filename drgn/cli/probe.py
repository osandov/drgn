from copy import copy
from drgn.dwarf import DwarfProgram, CompilationUnitHeader, Die
from drgn.dwarfdefs import *
from drgn.ftrace import Kprobe, FtraceInstance
import re
import os
from typing import Sequence

from drgn.cli.dump import dump_cu, dump_die  # XXX


class DiePath:
    def __init__(self, *args):
        if len(args) == 1:
            self.dies = [(args[0],)]
            self.slots = [0]
        elif len(args) == 2:
            self.dies = args[0]
            self.slots = args[1]
        else:
            assert False

    def append(self, dies: Sequence[Die], slot: int):
        self.slots.append(slot)
        self.dies.append(dies)

    def last(self) -> Die:
        return self.dies[-1][self.slots[-1]]

    def __copy__(self):
        return DiePath(copy(self.dies), copy(self.slots))


def sanitize_probe_name(name: str) -> str:
    name = re.sub('[^0-9A-Za-z]', '_', name)
    if name[0].isdigit():
        name = '_' + name
    return name


def find_cu_by_addr(program: DwarfProgram, addr: int) -> CompilationUnitHeader:
    for art in program.arange_tables():
        for arange in art.table:
            if arange.address <= addr < arange.address + arange.length:
                return program.cu_header(art.debug_info_offset)
    else:
        raise ValueError('CU containing address not found')


def find_subprogram_by_name(program: DwarfProgram, name: str) -> DiePath:
    symbols = program.symbols()[name]
    if len(symbols) != 1:
        raise ValueError('symbol is ambiguous')

    cu = find_cu_by_addr(program, symbols[0].st_value)
    die = cu.die()
    path = DiePath(die)
    children = die.children()
    for i, child in enumerate(children):
        if child.tag == DW_TAG.subprogram and child.name() == name:
            path.append(children, i)
            return path
    else:
        raise ValueError('subprogram not found')


def resolve_variable(path: DiePath, var: str) -> DiePath:
    path = copy(path)
    children = path.last().children()
    path.append(children, len(children))
    while len(path.dies):
        for i, child in enumerate(path.dies[-1]):
            if ((child.tag == DW_TAG.formal_parameter or
                 child.tag == DW_TAG.variable or
                 child.tag == DW_TAG.constant) and
                child.name() == var):
                path.slots[-1] = i
                return path
        del path.dies[-1]
        del path.slot[-1]
    raise ValueError(f'could not resolve {var!r}')


# typedef counts as a qualifier here
def unqualified_type(die: Die) -> Die:
    if die.tag not in TYPE_TAGS:
        raise ValueError('not a type DIE')
    while die.tag == DW_TAG.typedef or die.tag not in UNQUALIFIED_TYPE_TAGS:
        die = die.type()
    return die


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

    if args.vmlinux is None:
        binary = f'/lib/modules/{os.uname().release}/build/vmlinux'
    else:
        binary = args.vmlinux
    with DwarfProgram(binary) as program:
        if function is not None:
            path = find_subprogram_by_name(program, function)
            probe_addr = path.last().address()
            probe_location = function
        else:
            assert False, 'TODO'
            cu = program.find_cu_by_name(filename)
            row = program.find_breakpoint(cu, filename, lineno)
            scope = program.find_scope_containing_address(cu, row.address)

            subprogram = scope
            while subprogram.tag != DW_TAG.subprogram:
                subprogram = subprogram.parent
            subprogram_name = cu.file.die_name(subprogram)
            subprogram_addr = cu.file.die_address(subprogram)

            assert row.address >= subprogram_addr
            probe_addr = row.address
            probe_location = f'{subprogram_name}+0x{row.address - subprogram_addr:x}'

        for var in args.variables:
            resolved = resolve_variable(path, var).last()
            var_type = unqualified_type(resolved.type())
            dump_die(resolved)
            dump_die(resolved.type())
            print(resolved.location(probe_addr))
        print(probe_name, probe_location)
        return

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
    group.add_argument('--vmlinux', type=str, default=None)
    group.add_argument(
        '--line', '-l', action='store_true',
        help='force location to be treated as file:line')
    group.add_argument(
        '--function', '-f', action='store_true',
        help='force location to be treated as function name')

    subparser.set_defaults(func=cmd_probe)
