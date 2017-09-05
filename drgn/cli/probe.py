from copy import copy
from drgn.arch import DWARF_REG_TO_FETCHARG
from drgn.dwarf import (
    CompilationUnitHeader, Die, DwarfAttribNotFoundError,
    DwarfLocationNotFoundError, DwarfProgram, LineNumberRow,
)
from drgn.dwarfdefs import *
from drgn.ftrace import Kprobe, FtraceInstance
import re
import os
import os.path
import sys
from typing import List, Sequence, Tuple


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
        raise ValueError(f'could not find {name!r}')


def find_cu_by_name(program: DwarfProgram, filename: str) -> CompilationUnitHeader:
    filename = os.path.normpath(filename)
    for cu in program.cu_headers():
        if os.path.normpath(cu.name()) == filename:
            return cu
    else:
        raise ValueError(f'could not find {filename!r}')


def find_breakpoints(cu: CompilationUnitHeader, filename: str,
                     lineno: int) -> List[LineNumberRow]:
    rows = []
    for row in cu.line_number_program().execute():
        if row.is_stmt and row.line == lineno and row.path() == filename:
            rows.append(row)
    if not rows:
        raise ValueError(f"could not find address of {filename + ':' + str(lineno)!r}")
    return rows


def find_scope_containing_address(cu: CompilationUnitHeader, addr: int) -> DiePath:
    die = cu.die()
    path = DiePath(die)
    assert die.contains_address(addr)
    while True:
        children = die.children()
        for i, child in enumerate(children):
            if ((child.tag == DW_TAG.subprogram or child.tag == DW_TAG.lexical_block) and
                 child.contains_address(addr)):
                path.append(children, i)
                die = child
                break
        else:
            return path


def find_enclosing_subprogram(path: DiePath) -> DiePath:
    path = copy(path)
    while len(path.dies):
        if path.last().tag == DW_TAG.subprogram:
            return path
        del path.dies[-1]
        del path.slots[-1]
    assert False


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
        del path.slots[-1]
    raise ValueError(f'could not resolve {var!r}')


# typedef counts as a qualifier here
def unqualified_type(die: Die) -> Die:
    if die.tag not in TYPE_TAGS:
        raise ValueError('not a type DIE')
    while die.tag == DW_TAG.typedef or die.tag not in UNQUALIFIED_TYPE_TAGS:
        die = die.type()
    return die


def dwarf_to_fetcharg_type(dwarf_type: Die) -> str:
    if dwarf_type.tag == DW_TAG.base_type:
        encoding = dwarf_type.find_constant(DW_AT.encoding)
        if (encoding == DW_ATE.unsigned or encoding == DW_ATE.unsigned_char or
            encoding == DW_ATE.signed or encoding == DW_ATE.signed_char):
            # TODO: also check for bit_size and {data_,}bit_offset
            bit_size = 8 * dwarf_type.find_constant(DW_AT.byte_size)
            if encoding == DW_ATE.signed or encoding == DW_ATE.signed_char:
                return f's{bit_size}'
            else:
                return f'u{bit_size}'
    elif dwarf_type.tag == DW_TAG.pointer_type:
        deref_type = unqualified_type(dwarf_type.type())
        if deref_type.tag == DW_TAG.base_type:
            encoding = deref_type.find_constant(DW_AT.encoding)
            if encoding == DW_ATE.signed_char or encoding == DW_ATE.unsigned_char:
                return 'string'
        bit_size = 8 * dwarf_type.find_constant(DW_AT.byte_size)
        return f'x{bit_size}'
    else:
        raise ValueError(f"don't know how to fetch type {tag_name(dwarf_type.tag)}")


def dwarf_to_fetcharg_location(dwarf_location: bytes) -> str:
    if len(dwarf_location) == 1 and DW_OP.reg0 <= dwarf_location[0] <= DW_OP.reg31:
        return DWARF_REG_TO_FETCHARG[dwarf_location[0] - DW_OP.reg0]
    else:
        raise ValueError("don't know how to evaluate location")


def get_fetchargs(vars: List[str], path: DiePath, addr: int) -> List[str]:
    fetchargs = []
    for var in vars:
        resolved_var = resolve_variable(path, var).last()

        var_type = unqualified_type(resolved_var.type())
        fetcharg_type = dwarf_to_fetcharg_type(var_type)

        try:
            var_location = resolved_var.location(addr)
        except DwarfAttribNotFoundError:
            print(f'warning: {var!r} was optimized out', file=sys.stderr)
            continue
        except DwarfLocationNotFoundError:
            print(f'warning: {var!r} is not available at 0x{addr:x}', file=sys.stderr)
            continue
        fetcharg_location = dwarf_to_fetcharg_location(var_location)

        if fetcharg_type == 'string':
            fetchargs.append(f'{var}=+0x0({fetcharg_location}):string')
        else:
            fetchargs.append(f'{var}={fetcharg_location}:{fetcharg_type}')
    return fetchargs


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
    kprobes = []
    with DwarfProgram(binary) as program:
        if function is not None:
            path = find_subprogram_by_name(program, function)
            fetchargs = get_fetchargs(args.variables, path, path.last().address())
            kprobes.append(Kprobe(probe_name, function, fetchargs))
        else:
            cu = find_cu_by_name(program, filename)
            for i, row in enumerate(find_breakpoints(cu, filename, lineno)):
                path = find_scope_containing_address(cu, row.address)
                subprogram = find_enclosing_subprogram(path).last()

                subprogram_addr = subprogram.address()
                assert row.address >= subprogram_addr
                fetchargs = get_fetchargs(args.variables, path, row.address)
                location = f'{subprogram.name()}+0x{row.address - subprogram_addr:x}'
                kprobes.append(Kprobe(f'{probe_name}_{i}', location, fetchargs))

    # TODO: deal with probe name collisions
    with FtraceInstance(f'drgn_{os.getpid()}') as instance:
        try:
            for probe in kprobes:
                probe.create()
                probe.enable(instance)
            import subprocess
            subprocess.call(['cat', f'/sys/kernel/debug/tracing/instances/{instance.name}/trace_pipe'])
        finally:
            for probe in kprobes:
                probe.disable(instance)
                probe.destroy()


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
