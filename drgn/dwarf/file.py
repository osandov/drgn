import mmap
import drgn.lldwarf as lldwarf
from drgn.dwarf.defs import *
from drgn.elf import parse_elf_header, parse_elf_sections
import os.path
import sys


class DwarfFile:
    def __init__(self, path):
        self._closed = False
        self._file = open(path, 'rb')
        self._mmap = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)

        self._ehdr = parse_elf_header(self._mmap)
        self._sections = parse_elf_sections(self._mmap, self._ehdr)

        self._abbrev_tables = {}

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

    def section(self, name):
        return self._sections[name]

    def at_string(self, form, value):
        if form == DW_FORM.string:
            return self._mmap[value[0]:value[0] + value[1]]
        else:
            assert form == DW_FORM.strp
            debug_str = self.section('.debug_str')
            offset = debug_str.sh_offset + value
            nul = self._mmap.find(b'\0', offset)
            assert nul != -1  # XXX
            return self._mmap[offset:nul]

    def at_sec_offset(self, form, value):
        if form == DW_FORM.data4:
            # DWARF 2 and 3
            return int.from_bytes(value, sys.byteorder)
        else:
            # DWARF 4
            assert form == DW_FORM.sec_offset
            return value

    def abbrev_table(self, offset):
        try:
            return self._abbrev_tables[offset]
        except KeyError:
            pass

        debug_abbrev = self.section('.debug_abbrev')
        offset += debug_abbrev.sh_offset
        abbrev_table = lldwarf.parse_abbrev_table(self._mmap, offset)
        self._abbrev_tables[offset] = abbrev_table
        return abbrev_table

    def cu_headers(self):
        debug_info = self.section('.debug_info')
        offset = debug_info.sh_offset
        end = debug_info.sh_offset + debug_info.sh_size
        while offset < end:
            cu = lldwarf.parse_compilation_unit_header(self._mmap, offset)
            yield cu
            offset = cu.next_offset()

    def cu_die(self, cu, *, recurse=False):
        debug_info = self.section('.debug_info')
        abbrev_table = self.abbrev_table(cu.debug_abbrev_offset)
        return lldwarf.parse_die(cu, abbrev_table, self._mmap, cu.die_offset(),
                                 recurse=recurse)

    def parse_die_children(self, cu, die, *, recurse=False):
        if not hasattr(die, 'children'):
            debug_info = self.section('.debug_info')
            abbrev_table = self.abbrev_table(cu.debug_abbrev_offset)
            die.children = lldwarf.parse_die_siblings(cu, abbrev_table,
                                                      self._mmap,
                                                      offset=die.offset + die.die_length,
                                                      recurse=recurse)

    def die_contains_address(self, die, address):
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

    def die_name(self, die):
        form, value = die.find(DW_AT.name)
        return self.at_string(form, value)

    def die_address(self, die):
        try:
            ranges_form, ranges_value = die.find(DW_AT.ranges)
            assert False
        except KeyError:
            pass
        form, value = die.find(DW_AT.low_pc)
        assert form == DW_FORM.addr
        return value

    def cu_line_number_program_header(self, cu, die):
        debug_line = self.section('.debug_line')
        try:
            form, value = die.find(DW_AT.stmt_list)
        except KeyError:
            return None
        offset = debug_line.sh_offset + self.at_sec_offset(form, value)
        return lldwarf.parse_line_number_program_header(self._mmap, offset)

    def execute_line_number_program(self, lnp):
        return lldwarf.execute_line_number_program(lnp, self._mmap,
                                                   lnp.program_offset())

    def line_number_row_name(self, cu, lnp, row):
        if row.file == 0:
            return cu_name(cu)

        file_name, directory_index, mtime, file_size = lnp.file_names[row.file - 1]
        file_name = file_name.decode()
        if directory_index > 0:
            directory = lnp.include_directories[directory_index - 1].decode()
            return os.path.join(directory, file_name)
        else:
            return file_name

    def decode_line_number_program(self, lnp):
        offset = lnp.program_offset()
        end = lnp.end_offset()
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
