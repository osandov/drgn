from drgn import lldwarf
from drgn.dwarf.defs import *
from drgn.dwarf.file import DwarfFile
from typing import List, Tuple


def best_breakpoint(rows: List[lldwarf.LineNumberRow]) -> lldwarf.LineNumberRow:
    # The first row which is a statement, or the first row if none are
    # statements.
    for row in rows:
        if row.is_stmt:
            return row
    else:
        return rows[0]


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

    def find_cu_by_name(self, name: str) -> lldwarf.CompilationUnitHeader:
        for cu in self._file.cu_headers():
            if self._file.cu_name(cu) == name:
                return cu
        else:
            raise ValueError('CU not found')

    def find_cu_by_addr(self, addr: int) -> lldwarf.CompilationUnitHeader:
        dwarf_file = self._file
        for art in dwarf_file.arange_table_headers():
            for arange in dwarf_file.arange_table(art):
                if arange.address <= addr <= arange.address + arange.length:
                    return dwarf_file.cu_header(art.debug_info_offset)
        else:
            raise ValueError('CU containing address not found')


    def find_subprogram_by_name(self, name: str) -> lldwarf.DwarfDie:
        symbol = self._file.symbol(name)
        cu = self.find_cu_by_addr(symbol.st_value)
        dwarf_file = cu.file
        die = self._file.cu_die(cu)
        for child in dwarf_file.die_children(die):
            if (child.tag == DW_TAG.subprogram and
                dwarf_file.die_name(child) == name):
                return child
        else:
            raise ValueError('subprogram not found')

    def find_subprogram_containing_address(self, cu: lldwarf.CompilationUnitHeader,
                                           addr: int) -> lldwarf.DwarfDie:
        dwarf_file = cu.file
        die = dwarf_file.cu_die(cu)
        for child in dwarf_file.die_children(die):
            if (child.tag == DW_TAG.subprogram and
                dwarf_file.die_contains_address(child, addr)):
                return child
        assert False  # XXX

    def find_scope_containing_address(self, cu: lldwarf.CompilationUnitHeader,
                                      addr: int) -> lldwarf.DwarfDie:
        dwarf_file = cu.file
        die = dwarf_file.cu_die(cu)
        assert dwarf_file.die_contains_address(die, addr)
        while True:
            for child in dwarf_file.die_children(die):
                if ((child.tag == DW_TAG.subprogram or child.tag == DW_TAG.lexical_block) and
                    dwarf_file.die_contains_address(child, addr)):
                    die = child
                    break
            else:
                return die

    def find_lines(self, cu: lldwarf.CompilationUnitHeader,
                   filename: str, lineno: int) -> List[lldwarf.LineNumberRow]:
        dwarf_file = cu.file
        lnp = dwarf_file.cu_line_number_program_header(cu)

        rows = []
        for row in dwarf_file.execute_line_number_program(lnp):
            if (dwarf_file.line_number_row_name(cu, lnp, row) == filename and row.line == lineno):
                rows.append(row)
        return rows

    def find_breakpoint(self, cu: lldwarf.CompilationUnitHeader,
                        filename: str, lineno: int) -> lldwarf.LineNumberRow:
        return best_breakpoint(self.find_lines(cu, filename, lineno))

    def resolve_variable(self, die: lldwarf.DwarfDie, var: str):
        dwarf_file = die.cu.file
        while die is not None:
            for child in dwarf_file.die_children(die):
                if ((child.tag == DW_TAG.formal_parameter or
                     child.tag == DW_TAG.variable) and
                    dwarf_file.die_name(child) == var):
                    return child
            die = die.parent
        raise ValueError('could not resolve variable')
