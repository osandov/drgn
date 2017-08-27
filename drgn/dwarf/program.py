import drgn.lldwarf as lldwarf
from drgn.dwarf.defs import *
from drgn.dwarf.file import DwarfFile
from typing import List, Tuple


class DwarfProgram:
    def __init__(self, path):
        self._closed = False
        self._file = DwarfFile(path)
        self._files = {path: self._file}

    def close(self):
        if hasattr(self, '_files'):
            for file in self._files.values():
                file.close()

    def __del__(self):
        self.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def find_cu_by_name(self, name: str) -> Tuple[DwarfFile, lldwarf.CompilationUnitHeader]:
        for cu in self._file.cu_headers():
            die = self._file.cu_die(cu)
            try:
                cu_name = self._file.die_name(die).decode()
            except KeyError:
                continue
            if cu_name == name:
                return self._file, cu
        else:
            raise ValueError('CU not found')

    def find_cu_by_addr(self, addr: int) -> Tuple[DwarfFile, lldwarf.CompilationUnitHeader]:
        dwarf_file = self._file
        for art in dwarf_file.arange_table_headers():
            for arange in dwarf_file.arange_table(art):
                if arange.address <= addr <= arange.address + arange.length:
                    return dwarf_file, dwarf_file.cu_header(art.debug_info_offset)
        else:
            raise ValueError('CU containing address not found')


    def find_subprogram_by_name(self, name: str):
        dwarf_file = self._file
        symbol = dwarf_file.symbol(name)
        dwarf_file, cu = self.find_cu_by_addr(symbol.st_value)
        die = self._file.cu_die(cu)
        dwarf_file.parse_die_children(cu, die)
        for child in die.children:
            if (child.tag == DW_TAG.subprogram and
                dwarf_file.die_name(cu, child).decode() == name):
                return child
        else:
            raise ValueError('subprogram not found')

    @staticmethod
    def _best_breakpoint_row(dwarf_file: DwarfFile,
                             cu: lldwarf.CompilationUnitHeader,
                             lnp: lldwarf.LineNumberProgramHeader,
                             matrix: List[lldwarf.LineNumberRow],
                             filename: str,
                             lineno: int) -> lldwarf.LineNumberRow:
        # Find the first row which is a statement, or the first row if none are
        # statements.
        first_row = None
        for row in matrix:
            if (dwarf_file.line_number_row_name(cu, lnp, row) == filename and row.line == lineno):
                if row.is_stmt:
                    return row
                if first_row is None:
                    first_row = row
        else:
            assert first_row is not None  # XXX
            return first_row

    @staticmethod
    def _find_subprogram_containing_address(dwarf_file: DwarfFile,
                                            cu: lldwarf.CompilationUnitHeader,
                                            addr: int) -> lldwarf.DwarfDie:
        die = dwarf_file.cu_die(cu)
        dwarf_file.parse_die_children(cu, die)
        for child in die.children:
            if (child.tag == DW_TAG.subprogram and
                dwarf_file.die_contains_address(child, addr)):
                return child
        assert False  # XXX

    def find_breakpoint_location(self, filename: str, lineno: int) -> str:
        dwarf_file, cu = self.find_cu_by_name(filename)
        lnp = dwarf_file.cu_line_number_program_header(cu)
        matrix = dwarf_file.execute_line_number_program(lnp)

        row = self._best_breakpoint_row(dwarf_file, cu, lnp, matrix, filename, lineno)

        subprogram = self._find_subprogram_containing_address(dwarf_file, cu, row.address)
        subprogram_name = dwarf_file.die_name(cu, subprogram).decode()
        subprogram_address = dwarf_file.die_address(subprogram)
        assert row.address >= subprogram_address
        return f'{subprogram_name}+0x{row.address - subprogram_address:x}'
