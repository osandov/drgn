from drgn.dwarf import (
    Die, DwarfAttribNotFoundError, DwarfFile, DwarfFile,
    DW_AT, DW_FORM, DW_LNE, DW_LNS, DW_OP, DW_TAG,
    LineNumberProgram, parse_uleb128_and_offset, parse_sleb128_and_offset,
)
import fnmatch
import os.path
import sys


def dump_cu(cu, name=None, *, indent=0):
    if name is None:
        name = cu.die().name()
    prefix = ' ' * indent
    print(f'{prefix}<{cu.offset}> compilation unit', end='')
    print(f' ({name!r})')
    print(f'{prefix}  unit_length = {cu.unit_length}')
    print(f'{prefix}  version = {cu.version}')
    print(f'{prefix}  debug_abbrev_offset = {cu.debug_abbrev_offset}')
    print(f'{prefix}  address_size = {cu.address_size}')
    print(f'{prefix}  is_64_bit = {cu.is_64_bit}')


def dump_die(die: Die, *, indent: int=0, recurse: bool=False,
             location: bool=False) -> None:
    prefix = ' ' * indent
    print(f'{prefix}<{die.offset}> {DW_TAG.str(die.tag)}', end='')
    try:
        name = die.name()
    except DwarfAttribNotFoundError:
        print()
    else:
        print(f' ({name!r})')
    for name, form, value in die:
        repr_value = repr(value)
        if isinstance(value, bytes):
            repr_value = repr_value[1:]
        print(f'{prefix}  {DW_AT.str(name)} ({DW_FORM.str(form)}) = {repr_value}', end='')
        if location and (name == DW_AT.frame_base or name == DW_AT.location):
            dump_die_location(die, form, value, indent=indent + 2)
        else:
            print()
    if recurse:
        for child in die.children():
            dump_die(child, indent=indent + 2, recurse=True, location=location)


def dump_die_location(die, form, value, *, indent: int=0):
    prefix = ' ' * indent
    print(f' = {{')
    if form == DW_FORM.exprloc:
        dump_expression(value, die.cu.address_size, die.cu.is_64_bit, indent=indent + 2)
    else:
        dump_location_list(die, form, value, indent=indent+2)
    print(f'{prefix}}}')


def dump_location_list(die, form, value, *, indent: int=0):
    prefix = ' ' * indent
    buffer = die.dwarf_file.mmap
    address_size = die.cu.address_size
    offset = die.dwarf_file.debug_loc.sh_offset
    if form == DW_FORM.data4:
        offset += int.from_bytes(value, sys.byteorder)
    elif form == DW_FORM.sec_offset:
        offset += value
    else:
        assert False

    while True:
        start = int.from_bytes(buffer[offset:offset + address_size], sys.byteorder)
        offset += address_size
        end = int.from_bytes(buffer[offset:offset + address_size], sys.byteorder)
        offset += address_size

        if start == (1 << (8 * address_size)) - 1:
            print(f'{prefix}base address = 0x{end:x}')
            continue

        if start == 0 and end == 0:
            break

        length = int.from_bytes(buffer[offset:offset + 2], sys.byteorder)
        offset += 2

        print(f'{prefix}0x{start:x}-0x{end:x} = {{')
        dump_expression(buffer[offset:offset + length], address_size,
                        die.cu.is_64_bit, indent=indent + 2)
        print(f'{prefix}}}')
        offset += length


def dump_expression(value, address_size: int, is_64_bit: bool, *, indent: int=0):
    prefix = ' ' * indent
    offset = 0
    while offset < len(value):
        opcode = value[offset]
        offset += 1
        print(f'{prefix}{DW_OP.str(opcode)} ', end='')
        if opcode == DW_OP.addr:
            print(hex(int.from_bytes(value[offset:offset + address_size], sys.byteorder)))
            offset += address_size
        elif opcode == DW_OP.deref:
            print()
        elif opcode == DW_OP.const1u:
            print(hex(value[offset]))
            offset += 1
        elif opcode == DW_OP.const1s:
            const = int.from_bytes(value[offset:offset + 1], sys.byteorder,
                                   signed=True)
            offset += 1
            print(hex(const))
        elif opcode == DW_OP.const2u:
            const = int.from_bytes(value[offset:offset + 2], sys.byteorder)
            offset += 2
            print(hex(const))
        elif opcode == DW_OP.const2s:
            const = int.from_bytes(value[offset:offset + 2], sys.byteorder,
                                   signed=True)
            offset += 2
            print(hex(const))
        elif opcode == DW_OP.const4u:
            const = int.from_bytes(value[offset:offset + 4], sys.byteorder)
            offset += 4
            print(hex(const))
        elif opcode == DW_OP.const4s:
            const = int.from_bytes(value[offset:offset + 4], sys.byteorder,
                                   signed=True)
            offset += 4
            print(hex(const))
        elif opcode == DW_OP.const8u:
            const = int.from_bytes(value[offset:offset + 8], sys.byteorder)
            offset += 8
            print(hex(const))
        elif opcode == DW_OP.const8s:
            const = int.from_bytes(value[offset:offset + 8], sys.byteorder,
                                   signed=True)
            offset += 8
            print(hex(const))
        elif opcode == DW_OP.constu:
            const, offset = parse_uleb128_and_offset(value, offset)
            print(hex(const))
        elif opcode == DW_OP.consts:
            const, offset = parse_sleb128_and_offset(value, offset)
            print(hex(const))
        elif (opcode == DW_OP.dup or
              opcode == DW_OP.drop or
              opcode == DW_OP.over):
            print()
        elif opcode == DW_OP.pick:
            print(hex(value[offset]))
            offset += 1
        elif (opcode == DW_OP.swap or
              opcode == DW_OP.rot or
              opcode == DW_OP.xderef or
              opcode == DW_OP.abs or
              opcode == DW_OP.and_ or
              opcode == DW_OP.div or
              opcode == DW_OP.minus or
              opcode == DW_OP.mod or
              opcode == DW_OP.mul or
              opcode == DW_OP.neg or
              opcode == DW_OP.not_ or
              opcode == DW_OP.or_ or
              opcode == DW_OP.plus):
            print()
        elif opcode == DW_OP.plus_uconst:
            addend, offset = parse_uleb128_and_offset(value, offset)
            print(hex(addend))
        elif (opcode == DW_OP.shl or
              opcode == DW_OP.shr or
              opcode == DW_OP.shra or
              opcode == DW_OP.xor):
            print()
        elif opcode == DW_OP.bra:
            branch_offset = int.from_bytes(value[offset:offset + 2],
                                           sys.byteorder, signed=True)
            offset += 2
            print(hex(branch_offset))
        elif (opcode == DW_OP.eq or
              opcode == DW_OP.ge or
              opcode == DW_OP.gt or
              opcode == DW_OP.le or
              opcode == DW_OP.lt or
              opcode == DW_OP.ne):
            print()
        elif opcode == DW_OP.skip:
            skip_offset = int.from_bytes(value[offset:offset + 2],
                                         sys.byteorder, signed=True)
            offset += 2
            print(hex(skip_offset))
        elif DW_OP.lit0 <= opcode <= DW_OP.lit31:
            print()
        elif DW_OP.reg0 <= opcode <= DW_OP.reg31:
            print()
        elif DW_OP.breg0 <= opcode <= DW_OP.breg31:
            reg_offset, offset = parse_sleb128_and_offset(value, offset)
            print(hex(reg_offset))
        elif opcode == DW_OP.regx:
            register, offset = parse_uleb128_and_offset(value, offset)
            print(hex(register))
        elif opcode == DW_OP.fbreg:
            reg_offset, offset = parse_sleb128_and_offset(value, offset)
            print(hex(reg_offset))
        elif opcode == DW_OP.bregx:
            register, offset = parse_uleb128_and_offset(value, offset)
            reg_offset, offset = parse_sleb128_and_offset(value, offset)
            print(hex(register), hex(reg_offset))
        elif opcode == DW_OP.piece:
            size, offset = parse_uleb128_and_offset(value, offset)
            print(hex(size))
        elif opcode == DW_OP.deref_size:
            print(hex(value[offset]))
            offset += 1
        elif opcode == DW_OP.xderef_size:
            print(hex(value[offset]))
            offset += 1
        elif (opcode == DW_OP.nop or
              opcode == DW_OP.push_object_address):
            print()
        elif opcode == DW_OP.call2:
            die_offset = int.from_bytes(value[offset:offset + 2], sys.byteorder)
            offset += 2
            print(hex(die_offset))
        elif opcode == DW_OP.call4:
            die_offset = int.from_bytes(value[offset:offset + 4], sys.byteorder)
            offset += 4
            print(hex(die_offset))
        elif opcode == DW_OP.call_ref:
            size = 8 if is_64_bit else 4
            die_offset = int.from_bytes(value[offset:offset + size], sys.byteorder)
            offset += size
            print(hex(die_offset))
        elif (opcode == DW_OP.form_tls_address or
              opcode == DW_OP.call_frame_cfa):
            print()
        elif opcode == DW_OP.bit_piece:
            piece_size, offset = parse_uleb128_and_offset(value, offset)
            piece_offset, offset = parse_uleb128_and_offset(value, offset)
            print(hex(piece_size), hex(piece_offset))
        elif opcode == DW_OP.implicit_value:
            size, offset = parse_uleb128_and_offset(value, offset)
            print(hex(size), repr(value[offset:offset + size])[1:])
            offset += size
        elif opcode == DW_OP.stack_value:
            print()
        else:
            raise ValueError(f'unknown opcode {DW_OP.str(opcode)}')


def dump_lnp(lnp: LineNumberProgram, *, indent: int=0):
    prefix = ' ' * indent
    print(f'{prefix}<{lnp.offset}> line number program')
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
    print(f'{prefix}  include_directories = {{')
    for directory in lnp.include_directories:
        print(f'{prefix}    {directory!r},')
    print(f'{prefix}  }}')
    print(f'{prefix}  file_names = {{')
    for filename in lnp.file_names:
        if filename.directory_index > 0:
            directory = lnp.include_directories[filename.directory_index - 1]
            path = os.path.join(directory, filename.name)
        else:
            path = filename.name
        print(f'{prefix}    {path!r},')
    print(f'{prefix}  }}')
    print(f'{prefix}  is_64_bit = {lnp.is_64_bit}')
    dump_lnp_ops(lnp, indent=indent + 2)


def dump_lnp_ops(lnp: LineNumberProgram, *, indent: int=0):
    prefix = ' ' * indent
    print(f'{prefix}opcodes = {{')
    offset = lnp.dwarf_file.debug_line.sh_offset + lnp.program_offset()
    end = lnp.dwarf_file.debug_line.sh_offset + lnp.end_offset()
    while offset < end:
        opcode = lnp.dwarf_file.mmap[offset]
        offset += 1
        if opcode == 0:
            length, offset = parse_uleb128_and_offset(lnp.dwarf_file.mmap, offset)
            opcode = lnp.dwarf_file.mmap[offset]
            length -= 1
            offset += 1
            arg = lnp.dwarf_file.mmap[offset:offset + length]
            if arg:
                print(f'{prefix}  {DW_LNE.str(opcode)} {repr(arg)[1:]}')
            else:
                print(f'{prefix}  {DW_LNE.str(opcode)}')
            offset += length
        elif opcode < lnp.opcode_base:
            if opcode == DW_LNS.fixed_advance_pc:
                args = [int.from_bytes(lnp.dwarf_file.mmap[offset:offset + 2], sys.byteorder)]
                offset += 2
            else:
                args = []
                for i in range(lnp.standard_opcode_lengths[opcode - 1]):
                    arg, offset = parse_uleb128_and_offset(lnp.dwarf_file.mmap, offset)
                    args.append(arg)
            if len(args) > 2:
                print(f'{prefix}  {DW_LNS.str(opcode)} {args}')
            elif len(args) == 1:
                print(f'{prefix}  {DW_LNS.str(opcode)} {args[0]}')
            else:
                print(f'{prefix}  {DW_LNS.str(opcode)}')
        else:
            opcode -= lnp.opcode_base
            operation_advance = opcode // lnp.line_range
            line_increment = lnp.line_base + (opcode % lnp.line_range)
            print(f'{prefix}  special op+={operation_advance} ', end='')
            if line_increment < 0:
                print(f'line-={-line_increment}')
            else:
                print(f'line+={line_increment}')
    print(f'{prefix}}}')


def dump_line_number_matrix(lnp, matrix, *, indent=0):
    prefix = ' ' * indent
    print(f'{prefix}lines = {{')
    for row in matrix:
        if row.end_sequence:
            continue
        print(f'{prefix}  0x{row.address:016x} is {repr(row.path())[1:-1]}:{row.line}', end='')

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


def dump_cus(dwarf_file: DwarfFile, args) -> None:
    for cu in dwarf_file.cu_headers():
        die = cu.die()
        name = die.name()
        for pattern in args.cu:
            if fnmatch.fnmatch(name, pattern):
                break
        else:
            continue

        dump_cu(cu, name)
        if args.die:
            dump_die(cu.die(), indent=2, recurse=args.recursive, location=args.location)
        if args.line_number_program or args.lines:
            lnp = cu.line_number_program()
            if args.line_number_program:
                dump_lnp(lnp, indent=2)
            if args.lines:
                matrix = lnp.execute()
                dump_line_number_matrix(lnp, matrix, indent=2)


def dump_arange(dwarf_file, art, arange, *, indent=0):
    prefix = ' ' * indent
    print(f'{prefix}', end='')
    if art.segment_size:
        print(f'segment={arange.segment} ', end='')
    print(f'address=0x{arange.address:x} length={arange.length}')


def dump_arange_table(dwarf_file, art, *, indent=0):
    prefix = ' ' * indent
    print(f'{prefix}<{art.offset}> address range table')
    print(f'{prefix}  unit_length = {art.unit_length}')
    print(f'{prefix}  version = {art.version}')
    print(f'{prefix}  debug_info_offset = {art.debug_info_offset}')
    print(f'{prefix}  address_size = {art.address_size}')
    print(f'{prefix}  segment_size = {art.segment_size}')
    print(f'{prefix}  is_64_bit = {art.is_64_bit}')
    print(f'{prefix}  aranges = {{')
    for arange in art.table:
        dump_arange(dwarf_file, art, arange, indent=indent + 4)
    print(f'{prefix}  }}')


def dump_aranges(dwarf_file):
    for art in dwarf_file.arange_tables():
        dump_arange_table(dwarf_file, art)


def cmd_dump(args):
    with open(args.file, 'rb') as f:
        dwarf_file = DwarfFile.from_file(f)
        if args.cu:
            dump_cus(dwarf_file, args)
        if args.aranges:
            dump_aranges(dwarf_file)


def register(subparsers):
    subparser = subparsers.add_parser(
        'dump', help='dump raw debugging information')
    subparser.add_argument(
        '--cu', action='append', metavar='GLOB',
        help='dump compilation units with names matching the given pattern (may be specified multiple times)')
    subparser.add_argument(
        '--die', action='store_true',
        help="also dump each compilation unit's debugging information entry")
    subparser.add_argument(
        '--recursive', '--recurse', '-r', action='store_true',
        help='dump debugging information entries recursively')
    subparser.add_argument(
        '--location', action='store_true',
        help='also dump DIE locations')
    subparser.add_argument(
        '--aranges', action='store_true',
        help='also dump the address range tables')
    subparser.add_argument(
        '--line-number-program', '--lnp', action='store_true',
        help='also dump the line number program')
    subparser.add_argument(
        '--lines', action='store_true', help='also dump the line number matrix')
    subparser.add_argument('file', help='file to dump')
    subparser.set_defaults(func=cmd_dump)
