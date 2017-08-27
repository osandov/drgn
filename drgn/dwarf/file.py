import mmap
import drgn.lldwarf as lldwarf
from drgn.dwarf.defs import *
from drgn.elf import parse_elf_header, parse_elf_sections, parse_elf_symtab
import os.path
import sys
from typing import List


def lnp_program_offset(lnp):
    return lnp.offset + (22 if lnp.is_64_bit else 10) + lnp.header_length


def lnp_end_offset(lnp):
    return lnp.offset + (12 if lnp.is_64_bit else 4) + lnp.unit_length


class DwarfFile:
    """DWARF file parser

    A DwarfFile manages parsing a single DWARF file, abstracting away the
    details of reading the file.
    """

    def __init__(self, path):
        """
        DwarfFile(path) -> new DWARF file parser
        Create a new DWARF file parser.

        Arguments:
        path -- file path
        """
        self._closed = False
        self._file = open(path, 'rb')
        self._mmap = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)

        self._ehdr = parse_elf_header(self._mmap)
        self._sections = parse_elf_sections(self._mmap, self._ehdr)

        self._abbrev_tables = {}
        self._symbols = None

    def close(self):
        if not self._closed:
            if hasattr(self, '_mmap'):
                self._mmap.close()
            if hasattr(self, '_file'):
                self._file.close()
            self._closed = True

    def __del__(self):
        self.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def section(self, name: str):
        return self._sections[name]

    def string_at(self, offset):
        nul = self._mmap.find(b'\0', offset)
        assert nul != -1  # XXX
        return self._mmap[offset:nul]

    def symbols(self):
        if self._symbols is None:
            symtab = self.section('.symtab')
            strtab = self.section('.strtab')
            symbols = {}
            for sym in parse_elf_symtab(self._mmap, symtab):
                if sym.st_name:
                    sym_name = self.string_at(strtab.sh_offset + sym.st_name).decode()
                else:
                    sym_name = ''
                try:
                    symbols[sym_name].append(sym)
                except KeyError:
                    symbols[sym_name] = [sym]
            self._symbols = symbols
        return self._symbols

    def symbol(self, name: str, *, all: bool=False):
        syms = self.symbols()[name]
        if all:
            return syms
        else:
            if len(syms) > 1:
                raise ValueError('multiple symbols with given name')
            return syms[0]

    def at_string(self, cu: lldwarf.CompilationUnitHeader,
                  form: DW_FORM, value) -> bytes:
        if form == DW_FORM.string:
            offset = cu.offset + value[0]
            return self._mmap[offset:offset + value[1]]
        else:
            assert form == DW_FORM.strp
            debug_str = self.section('.debug_str')
            return self.string_at(debug_str.sh_offset + value)

    def at_sec_offset(self, form: DW_FORM, value) -> int:
        if form == DW_FORM.data4:
            # DWARF 2 and 3
            return int.from_bytes(value, sys.byteorder)
        else:
            # DWARF 4
            assert form == DW_FORM.sec_offset
            return value

    def abbrev_table(self, offset: int) -> lldwarf.AbbrevDecl:
        try:
            return self._abbrev_tables[offset]
        except KeyError:
            pass

        debug_abbrev = self.section('.debug_abbrev')
        offset += debug_abbrev.sh_offset
        abbrev_table = lldwarf.parse_abbrev_table(self._mmap, offset)
        self._abbrev_tables[offset] = abbrev_table
        return abbrev_table

    # Compilation units

    def cu_headers(self):
        debug_info = self.section('.debug_info')
        offset = debug_info.sh_offset
        end = debug_info.sh_offset + debug_info.sh_size
        while offset < end:
            cu = lldwarf.parse_compilation_unit_header(self._mmap, offset)
            cu.offset = offset
            yield cu
            offset += (12 if cu.is_64_bit else 4) + cu.unit_length

    def cu_header(self, offset: int) -> lldwarf.CompilationUnitHeader:
        debug_info = self.section('.debug_info')
        offset += debug_info.sh_offset
        cu = lldwarf.parse_compilation_unit_header(self._mmap, offset)
        cu.offset = offset
        return cu

    def cu_name(self, cu: lldwarf.CompilationUnitHeader) -> bytes:
        try:
            return self.die_name(cu, self.cu_die(cu))
        except KeyError:
            return b''

    # Debugging information entries

    def cu_die(self, cu: lldwarf.CompilationUnitHeader, *,
               recurse: bool=False) -> lldwarf.DwarfDie:
        try:
            return cu.die
        except AttributeError:
            pass

        debug_info = self.section('.debug_info')
        abbrev_table = self.abbrev_table(cu.debug_abbrev_offset)
        die_offset = cu.offset + (23 if cu.is_64_bit else 11)
        die = lldwarf.parse_die(cu, abbrev_table, cu.offset, self._mmap,
                                die_offset, recurse=recurse)
        cu.die = die
        return die

    def parse_die_children(self, cu: lldwarf.CompilationUnitHeader,
                           die: lldwarf.DwarfDie, *, recurse: bool=False) -> None:
        if not hasattr(die, 'children'):
            debug_info = self.section('.debug_info')
            abbrev_table = self.abbrev_table(cu.debug_abbrev_offset)
            offset = cu.offset + die.cu_offset + die.die_length
            die.children = lldwarf.parse_die_siblings(cu, abbrev_table,
                                                      cu.offset, self._mmap,
                                                      offset=offset,
                                                      recurse=recurse)

    def die_contains_address(self, die: lldwarf.DwarfDie, address: int) -> bool:
        try:
            ranges_form, ranges_value = die.find(DW_AT.ranges)
            assert False
        except KeyError:
            pass
        try:
            low_pc_form, low_pc = die.find(DW_AT.low_pc)
        except KeyError:
            return False
        high_pc_form, high_pc_value = die.find(DW_AT.high_pc)
        assert low_pc_form == DW_FORM.addr
        if at_class_constant_int(high_pc_form):
            high_pc = low_pc + high_pc_value
        elif at_class_constant_bytes(high_pc_form):
            high_pc = low_pc + int.from_bytes(high_pc_value, sys.byteorder)
        else:
            assert high_pc_form == DW_FORM.addr
            high_pc = high_pc_value
        return low_pc <= address < high_pc

    def die_name(self, cu: lldwarf.CompilationUnitHeader,
                 die: lldwarf.DwarfDie) -> bytes:
        form, value = die.find(DW_AT.name)
        return self.at_string(cu, form, value)

    def die_address(self, die: lldwarf.DwarfDie) -> int:
        try:
            ranges_form, ranges_value = die.find(DW_AT.ranges)
            assert False
        except KeyError:
            pass
        form, value = die.find(DW_AT.low_pc)
        assert form == DW_FORM.addr
        return value

    # Address range tables

    def arange_table_headers(self):
        debug_aranges = self.section('.debug_aranges')
        offset = debug_aranges.sh_offset
        end = debug_aranges.sh_offset + debug_aranges.sh_size
        while offset < end:
            art = lldwarf.parse_arange_table_header(self._mmap, offset)
            art.offset = offset
            yield art
            offset += (12 if art.is_64_bit else 4) + art.unit_length

    def arange_table(self, art: lldwarf.ArangeTableHeader):
        try:
            return art.table
        except AttributeError:
            pass

        assert art.version == 2
        table_offset = art.offset + (24 if art.is_64_bit else 12)
        alignment = art.segment_size + 2 * art.address_size
        if table_offset % alignment:
            table_offset += (alignment - table_offset % alignment)
        return lldwarf.parse_arange_table(art.segment_size, art.address_size,
                                          self._mmap, table_offset)

    # Line number programs

    def cu_line_number_program_header(self, cu: lldwarf.CompilationUnitHeader) -> lldwarf.LineNumberProgramHeader:
        debug_line = self.section('.debug_line')
        die = self.cu_die(cu)
        try:
            form, value = die.find(DW_AT.stmt_list)
        except KeyError:
            return None
        offset = debug_line.sh_offset + self.at_sec_offset(form, value)
        lnp = lldwarf.parse_line_number_program_header(self._mmap, offset)
        lnp.offset = offset
        return lnp

    def execute_line_number_program(self, lnp: lldwarf.LineNumberProgramHeader) -> List[lldwarf.LineNumberRow]:
        return lldwarf.execute_line_number_program(lnp, lnp_end_offset(lnp),
                                                   self._mmap,
                                                   lnp_program_offset(lnp))

    def line_number_row_name(self, cu: lldwarf.CompilationUnitHeader,
                             lnp: lldwarf.LineNumberProgramHeader,
                             row: lldwarf.LineNumberRow) -> str:
        if row.file == 0:
            return self.cu_name(cu).decode()

        file_name, directory_index, mtime, file_size = lnp.file_names[row.file - 1]
        file_name = file_name.decode()
        if directory_index > 0:
            directory = lnp.include_directories[directory_index - 1].decode()
            return os.path.join(directory, file_name)
        else:
            return file_name

    def decode_line_number_program(self, lnp: lldwarf.LineNumberProgramHeader):
        offset = lnp_program_offset(lnp)
        end = lnp_end_offset(lnp)
        while offset < end:
            opcode = self._mmap[offset]
            offset += 1
            if opcode == 0:
                length, offset = lldwarf.parse_uleb128_offset(self._mmap, offset)
                opcode = self._mmap[offset]
                length -= 1
                offset += 1
                yield 'extended', opcode, [self._mmap[offset:offset + length]]
                offset += length
            elif opcode < lnp.opcode_base:
                if opcode == DW_LNS.fixed_advance_pc:
                    args = [int.from_bytes(self._mmap[offset:offset + 2], sys.byteorder)]
                    offset += 2
                else:
                    args = []
                    for i in range(lnp.standard_opcode_lengths[opcode - 1]):
                        arg, offset = lldwarf.parse_uleb128_offset(self._mmap, offset)
                        args.append(arg)
                yield 'standard', opcode, args
            else:
                opcode -= lnp.opcode_base
                operation_advance = opcode // lnp.line_range
                line_increment = lnp.line_base + (opcode % lnp.line_range)
                yield 'special', opcode, (operation_advance, line_increment)
