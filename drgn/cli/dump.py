from drgn.dwarf import DwarfFile
from drgn.dwarf.defs import *
import fnmatch
import os.path


def dump_cu(dwarf_file, cu, cu_name, *, indent=0):
    prefix = ' ' * indent
    debug_info = dwarf_file.section('.debug_info')
    print(f'{prefix}<{cu.offset - debug_info.sh_offset}> compilation unit', end='')
    if cu_name:
        print(f' ({cu_name!r})')
    else:
        print()
    print(f'{prefix}  unit_length = {cu.unit_length}')
    print(f'{prefix}  version = {cu.version}')
    print(f'{prefix}  debug_abbrev_offset = {cu.debug_abbrev_offset}')
    print(f'{prefix}  address_size = {cu.address_size}')
    print(f'{prefix}  is_64_bit = {cu.is_64_bit}')


def dump_die(dwarf_file, cu, die, *, indent=0, recurse=False):
    prefix = ' ' * indent
    print(f'{prefix}<{die.cu_offset}> {tag_name(die.tag)}')
    for name, form, value in die:
        if form == DW_FORM.string or form == DW_FORM.strp:
            value = repr(dwarf_file.at_string(cu, form, value))[1:]
        elif form in {DW_FORM.data1, DW_FORM.data2, DW_FORM.data4, DW_FORM.data8}:
            value = repr(value)[1:]
        print(f'{prefix}  {at_name(name)} ({form_name(form)}) = {value}')
    if recurse:
        try:
            children = die.children
        except AttributeError:
            pass
        else:
            if children is not None:
                for child in children:
                    dump_die(dwarf_file, cu, child, indent=indent + 2, recurse=True)


def dump_lnp_include_directories(lnp, *, indent=0):
    prefix = ' ' * indent
    print(f'{prefix}include_directories = {{')
    for directory in lnp.include_directories:
        directory = directory.decode()
        print(f'{prefix}  {directory!r},')
    print(f'{prefix}}}')


def dump_lnp_file_names(lnp, *, indent=0):
    prefix = ' ' * indent
    print(f'{prefix}file_names = {{')
    for file_name, directory_index, mtime, file_size in lnp.file_names:
        file_name = file_name.decode()
        if directory_index > 0:
            directory = lnp.include_directories[directory_index - 1].decode()
            path = os.path.join(directory, file_name)
        else:
            path = file_name
        print(f'{prefix}  {path!r},')
    print(f'{prefix}}}')


def dump_lnp_header(dwarf_file, lnp, *, indent=0):
    prefix = ' ' * indent
    debug_line = dwarf_file.section('.debug_line')
    print(f'{prefix}<{lnp.offset - debug_line.sh_offset}> line number program')
    print(f'{prefix}  unit_length = {lnp.unit_length}')
    print(f'{prefix}  version = {lnp.version}')
    print(f'{prefix}  header_length = {lnp.header_length}')
    print(f'{prefix}  minimum_instruction_length = {lnp.minimum_instruction_length}')
    print(f'{prefix}  maximum_operations_per_instruction = {lnp.maximum_operations_per_instruction}')
    print(f'{prefix}  default_is_stmt = {lnp.default_is_stmt}')
    print(f'{prefix}  line_base = {lnp.line_base}')
    print(f'{prefix}  line_range = {lnp.line_range}')
    print(f'{prefix}  opcode_base = {lnp.opcode_base}')
    print(f'{prefix}  standard_opcode_lengths = {lnp.standard_opcode_lengths}')
    print(f'{prefix}  is_64_bit = {lnp.is_64_bit}')


def dump_lnp_ops(dwarf_file, lnp, *, indent=0):
    prefix = ' ' * indent
    print(f'{prefix}opcodes = {{')
    for type_, opcode, args in dwarf_file.decode_line_number_program(lnp):
        print(f'{prefix}  ', end='')
        if type_ == 'standard':
            if len(args) > 2:
                print(f'{lns_name(opcode)} {args}')
            elif len(args) == 1:
                print(f'{lns_name(opcode)} {args[0]}')
            else:
                print(lns_name(opcode))
        elif type_ == 'extended':
            if args[0]:
                print(f'{lne_name(opcode)} {repr(args[0])[1:]}')
            else:
                print(f'{lne_name(opcode)}')
        else:
            assert type_ == 'special'
            print(f'special op+={args[0]} ', end='')
            if args[1] < 0:
                print(f'line-={-args[1]}')
            else:
                print(f'line+={args[1]}')
    print(f'{prefix}}}')


def dump_line_number_matrix(cu, lnp, matrix, *, indent=0):
    prefix = ' ' * indent
    print(f'{prefix}lines = {{')
    for row in matrix:
        if row.end_sequence:
            continue
        if row.file == 0:
            path = cu_name(cu)
        else:
            file_name, directory_index, mtime, file_size = lnp.file_names[row.file - 1]
            if directory_index > 0:
                directory = lnp.include_directories[directory_index - 1]
                path = directory + b'/' + file_name
            else:
                path = file_name
        print(f'{prefix}  0x{row.address:016x} is {repr(path)[2:-1]}:{row.line}', end='')

        flags = []
        if row.is_stmt:
            flags.append('is_stmt')
        if row.basic_block:
            flags.append('basic_block')
        if row.prologue_end:
            flags.append('prologue_end')
        if row.epilogue_begin:
            flags.append('epilogue_begin')
        if flags:
            print(f" ({', '.join(flags)})")
        else:
            print()
    print(f'{prefix}}}')


def dump_cus(dwarf_file, args):
    for cu in dwarf_file.cu_headers():
        cu_name = dwarf_file.cu_name(cu).decode()
        for pattern in args.cu:
            if fnmatch.fnmatch(cu_name, pattern):
                break
        else:
            continue

        dump_cu(dwarf_file, cu, cu_name)
        if args.die:
            die = dwarf_file.cu_die(cu)
            if args.recursive:
                dwarf_file.parse_die_children(cu, die, recurse=True)
            dump_die(dwarf_file, cu, die, indent=2, recurse=args.recursive)
        if (args.include_directories or args.file_names or args.lines or
            args.line_number_program):
            lnp = dwarf_file.cu_line_number_program_header(cu)
            if args.include_directories:
                dump_lnp_include_directories(lnp, indent=2)
            if args.file_names:
                dump_lnp_file_names(lnp, indent=2)
            if args.lines:
                matrix = dwarf_file.execute_line_number_program(lnp)
                dump_line_number_matrix(cu, lnp, matrix, indent=2)
            if args.line_number_program:
                dump_lnp_header(dwarf_file, lnp, indent=2)
                dump_lnp_ops(dwarf_file, lnp, indent=4)


def dump_arange(dwarf_file, art, arange, *, indent=0):
    prefix = ' ' * indent
    print(f'{prefix}', end='')
    if art.segment_size:
        print(f'segment={arange.segment} ', end='')
    print(f'address=0x{arange.address:x} length={arange.length}')


def dump_arange_table_header(dwarf_file, art, *, indent=0):
    prefix = ' ' * indent
    debug_aranges = dwarf_file.section('.debug_aranges')
    print(f'{prefix}<{art.offset - debug_aranges.sh_offset}> address range table')
    print(f'{prefix}  unit_length = {art.unit_length}')
    print(f'{prefix}  version = {art.version}')
    print(f'{prefix}  debug_abbrev_offset = {art.debug_info_offset}')
    print(f'{prefix}  address_size = {art.address_size}')
    print(f'{prefix}  segment_size = {art.segment_size}')
    print(f'{prefix}  is_64_bit = {art.is_64_bit}')
    print(f'{prefix}  aranges = {{')
    for arange in dwarf_file.arange_table(art):
        dump_arange(dwarf_file, art, arange, indent=indent + 4)
    print(f'{prefix}  }}')


def dump_aranges(dwarf_file):
    for art in dwarf_file.arange_table_headers():
        dump_arange_table_header(dwarf_file, art)


def cmd_dump(args):
    with DwarfFile(args.file) as dwarf_file:
        if args.cu:
            dump_cus(dwarf_file, args)
        if args.symtab:
            symbols = sorted(dwarf_file.symbols().items())
            for name, syms in symbols:
                print(name)
                for sym in syms:
                    print(f'    value=0x{sym.st_value:x} size=0x{sym.st_size:x}')
        if args.aranges:
            dump_aranges(dwarf_file)


def register(subparsers):
    subparser = subparsers.add_parser(
        'dump', help='dump raw debugging information')
    subparser.add_argument(
        '--cu', action='append', metavar='GLOB',
        help='dump compilation units with names matching the given pattern (may be specified multiple times)')
    subparser.add_argument(
        '--die', action='store_true', help="also dump each compilation unit's debugging information entry")
    subparser.add_argument(
        '--recursive', action='store_true', help='dump debugging information entries recursively')
    subparser.add_argument(
        '--include-directories', action='store_true', help="also dump each compilation unit's include directories")
    subparser.add_argument(
        '--file-names', action='store_true', help="also dump each compilation unit's source files")
    subparser.add_argument(
        '--aranges', action='store_true', help='also dump the address range tables')
    subparser.add_argument(
        '--lines', action='store_true', help='also dump the line number matrix')
    subparser.add_argument(
        '--line-number-program', '--lnp', action='store_true', help='also dump the line number program')
    subparser.add_argument(
        '--symtab', action='store_true', help='dump the symbol table')
    subparser.add_argument(
        'file', help='file to dump')
    subparser.set_defaults(func=cmd_dump)
