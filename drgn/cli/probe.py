from drgn.dwarf import DwarfFile
from drgn.dwarf.defs import DW_TAG
from drgn.ftrace import Kprobe, FtraceInstance
import os
import signal


def find_cu_by_name(dwarf_file, name):
    for cu in dwarf_file.cu_headers():
        die = dwarf_file.cu_die(cu)
        try:
            cu_name = dwarf_file.die_name(die).decode()
        except KeyError:
            continue
        if cu_name == name:
            return cu, die
    else:
        raise ValueError('CU not found')


def find_addresses_for_line(dwarf_file, filename, lineno):
    cu, die = find_cu_by_name(dwarf_file, filename)
    lnp = dwarf_file.cu_line_number_program_header(cu, die)
    matrix = dwarf_file.execute_line_number_program(lnp)

    rows = []
    for row in matrix:
        if (dwarf_file.line_number_row_name(cu, lnp, row) == filename and
            row.line == lineno):
            rows.append(row)
    return cu, die, rows


def best_breakpoint_address(rows):
    for row in rows:
        if row.is_stmt:
            return row
    return rows[0]


def find_subprogram_containing_address(dwarf_file, cu, die, address):
    dwarf_file.parse_die_children(cu, die)
    for child in die.children:
        if child.tag != DW_TAG.subprogram:
            continue
        if dwarf_file.die_contains_address(child, address):
            return child
    assert False  # XXX


def create_probe(dwarf_file, filename, lineno):
    cu, die, rows = find_addresses_for_line(dwarf_file, filename, lineno)
    row = best_breakpoint_address(rows)
    subprogram = find_subprogram_containing_address(dwarf_file, cu, die, row.address)
    subprogram_name = dwarf_file.die_name(subprogram).decode()
    subprogram_address = dwarf_file.die_address(subprogram)

    name = f'drgn/{subprogram_name}_{os.getpid()}'
    location = f'{subprogram_name}+{row.address - subprogram_address}'
    return name, location


def cmd_probe(args):
    # XXX check in argparse
    filename, lineno = args.line.rsplit(':', 1)
    lineno = int(lineno)
    with DwarfFile(args.vmlinux) as dwarf_file:
        name, location = create_probe(dwarf_file, filename, lineno)

    with Kprobe(name, location) as probe, \
         FtraceInstance(f'drgn_{os.getpid()}') as instance:
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
            '--line', '-l', metavar='FILE:LINE',
            help='probe a source location')
    subparser.add_argument(
        'vmlinux', help='vmlinux file to use')
    subparser.set_defaults(func=cmd_probe)
