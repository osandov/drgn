from cpython.buffer cimport PyObject_GetBuffer, PyBuffer_Release, Py_buffer, PyBUF_SIMPLE
from libc.stdint cimport UINT32_MAX, UINT64_MAX

from drgn.read cimport *
import mmap

cdef extern from "Python.h":
    void *PyMem_RawMalloc(size_t n)
    void *PyMem_RawCalloc(size_t nelem, size_t elsize)
    void *PyMem_RawRealloc(void *p, size_t n)
    void PyMem_RawFree(void *p)

    void *PyMem_Calloc(size_t nelem, size_t elsize)
    void PyMem_Free(void *p)


cdef class DwarfFormatError(Exception):
    pass


cdef class DwarfAttribNotFoundError(Exception):
    pass


cdef class DwarfLocationNotFoundError(Exception):
    pass


cdef struct Section:
    uint64_t offset
    uint64_t size


cdef set_section(Section *section, object section_object):
    if section_object is not None:
        section.offset = section_object.offset
        section.size = section_object.size


cdef class DwarfFile:
    cdef bint _closed
    cdef bint _release_buffer

    cdef public object mmap

    cdef Section debug_abbrev
    cdef Section debug_aranges
    cdef Section debug_info
    cdef Section debug_line
    cdef Section debug_loc
    cdef Section debug_ranges
    cdef Section debug_str

    cdef Py_buffer buffer

    def __cinit__(self, file, sections):
        self.mmap = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ)
        PyObject_GetBuffer(self.mmap, &self.buffer, PyBUF_SIMPLE)
        self._release_buffer = True

        set_section(&self.debug_abbrev, sections['.debug_abbrev'])
        set_section(&self.debug_aranges, sections['.debug_aranges'])
        set_section(&self.debug_info, sections['.debug_info'])
        set_section(&self.debug_line, sections.get('.debug_line'))
        set_section(&self.debug_loc, sections.get('.debug_loc'))
        set_section(&self.debug_ranges, sections.get('.debug_ranges'))
        set_section(&self.debug_str, sections.get('.debug_str'))

    def close(self):
        if not self._closed:
            if self._release_buffer:
                PyBuffer_Release(&self.buffer)
            if self.mmap is not None:
                self.mmap.close()
            self._closed = True

    def __del__(self):
        self.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    cpdef CompilationUnitHeader cu_header(self, Py_ssize_t offset):
        offset += self.debug_info.offset
        cdef CompilationUnitHeader cu = parse_compilation_unit_header(&self.buffer, &offset, self)
        offset = self.debug_abbrev.offset + cu.debug_abbrev_offset
        parse_abbrev_table(&self.buffer, &offset, &cu._abbrev_table)
        return cu

    def cu_headers(self):
        cdef Py_ssize_t offset = 0
        cdef Py_ssize_t end = self.debug_info.size
        while offset < end:
            cu = self.cu_header(offset)
            yield cu
            offset = cu.end_offset()

    cdef ArangeTable arange_table(self, Py_ssize_t offset):
        offset += self.debug_aranges.offset
        cdef ArangeTable art = parse_arange_table(&self.buffer, &offset, self)
        return art

    def arange_tables(self):
        cdef Py_ssize_t offset = 0
        cdef Py_ssize_t end = self.debug_aranges.size
        while offset < end:
            art = self.arange_table(offset)
            yield art
            offset = art.end_offset()


cdef class AddressRange:
    cdef public uint64_t segment
    cdef public uint64_t address
    cdef public uint64_t length

    def __cinit__(self, uint64_t segment, uint64_t address, uint64_t length):
        self.segment = segment
        self.address = address
        self.length = length


cdef class ArangeTable:
    # Offset from the beginning of the section.
    cdef public Py_ssize_t offset
    cdef public uint64_t unit_length
    cdef public uint16_t version
    cdef public uint64_t debug_info_offset
    cdef public uint8_t address_size
    cdef public uint8_t segment_size
    cdef public bint is_64_bit
    cdef public list table

    cpdef Py_ssize_t end_offset(self):
        return self.offset + (12 if self.is_64_bit else 4) + self.unit_length


cdef struct AttribSpec:
    uint64_t name
    uint64_t form


cdef struct AbbrevDecl:
    uint64_t tag
    bint children
    uint64_t num_attribs
    AttribSpec *attribs


# Technically, abbreviation codes don't have to be sequential. In practice, GCC
# seems to always generate sequential codes, so we can get away with a flat
# array.
cdef struct AbbrevTable:
    uint64_t num_decls
    AbbrevDecl *decls


cdef class CompilationUnitHeader:
    cdef public DwarfFile dwarf_file
    # Offset from the beginning of .debug_info (or whatever section it was
    # parsed from).
    cdef public Py_ssize_t offset

    cdef public uint64_t unit_length
    cdef public uint16_t version
    cdef public uint64_t debug_abbrev_offset
    cdef public uint8_t address_size
    cdef public bint is_64_bit

    cdef str _name

    cdef AbbrevTable _abbrev_table

    def __dealloc__(self):
        for i in range(self._abbrev_table.num_decls):
            PyMem_RawFree(self._abbrev_table.decls[i].attribs)
        PyMem_RawFree(self._abbrev_table.decls)

    cpdef str name(self):
        if self._name is not None:
            return self._name

        self._name = self.die().name()
        return self._name

    cpdef Py_ssize_t end_offset(self):
        return self.offset + (12 if self.is_64_bit else 4) + self.unit_length

    cpdef Py_ssize_t die_offset(self):
        return self.offset + (23 if self.is_64_bit else 11)

    cdef AbbrevDecl *abbrev_decl(self, uint64_t code):
        if code < 1 or code > self._abbrev_table.num_decls:
            return NULL
        return &self._abbrev_table.decls[code - 1]

    cpdef Die die(self):
        assert self.dwarf_file is not None
        cdef Py_ssize_t offset = self.dwarf_file.debug_info.offset + self.die_offset()
        return parse_die(&self.dwarf_file.buffer, &offset, self, False)

    cpdef LineNumberProgram line_number_program(self):
        cdef Die die = self.die()
        cdef uint64_t stmt_list = Die.attrib_sec_offset(die.find_attrib(DW_AT_stmt_list))
        cdef Py_ssize_t offset = self.dwarf_file.debug_line.offset + stmt_list
        return parse_line_number_program(&self.dwarf_file.buffer, &offset,
                                         self)



cdef struct DieAttribValuePtr:
    # Offset from the beginning of the section.
    Py_ssize_t offset
    Py_ssize_t length


cdef union DieAttribValue:
    # DW_FORM_addr, DW_FORM_udata, DW_FORM_flag{,_present},
    # DW_FORM_sec_offset, DW_FORM_ref{1,2,4,8,_sig8,_udata,_addr},
    # and DW_FORM_strp. For DW_FORM_flag_present, always 1.
    uint64_t u

    # DW_FORM_sdata.
    int64_t s

    # DW_FORM_data{1,2,4,8}
    char data[8]

    # DW_FORM_block{,1,2,4}, DW_FORM_exprloc, and DW_FORM_string.
    DieAttribValuePtr ptr


cdef struct DieAttrib:
    uint64_t name
    uint64_t form
    DieAttribValue value


cdef class Die:
    cdef public DwarfFile dwarf_file
    cdef public CompilationUnitHeader cu
    # Offset from the beginning of the section.
    cdef public Py_ssize_t offset
    cdef public Py_ssize_t length
    cdef public uint64_t tag
    cdef list _children
    # XXX: Cython doesn't support variable-size objects.
    cdef DieAttrib *attribs
    cdef Py_ssize_t num_attribs

    def __dealloc__(self):
        PyMem_Free(self.attribs)

    def __len__(self):
        return self.num_attribs

    def __getitem__(self, i):
        if i < 0 or i >= self.num_attribs:
            raise IndexError('attribute index out of range')
        cdef const DieAttrib *attrib = &self.attribs[i]
        return (attrib.name, attrib.form, self.attrib_value(attrib))

    def find(self, at):
        cdef const DieAttrib *attrib = self.find_attrib(at)
        return attrib.form, self.attrib_value(attrib)

    def find_constant(self, at):
        cdef const DieAttrib *attrib = self.find_attrib(at)
        if attrib.form == DW_FORM_data1:
            return (<const uint8_t *>&attrib.value.data[0])[0]
        elif attrib.form == DW_FORM_data2:
            return (<const uint16_t *>&attrib.value.data[0])[0]
        elif attrib.form == DW_FORM_data4:
            return (<const uint32_t *>&attrib.value.data[0])[0]
        elif attrib.form == DW_FORM_data8:
            return (<const uint64_t *>&attrib.value.data[0])[0]
        elif attrib.form == DW_FORM_udata:
            return attrib.value.u
        elif attrib.form == DW_FORM_sdata:
            return attrib.value.s
        else:
            raise DwarfFormatError(f'unknown form 0x{attrib.form:x} for constant')

    def find_flag(self, at):
        cdef const DieAttrib *attrib
        try:
            attrib = self.find_attrib(at)
        except DwarfAttribNotFoundError:
            return False
        if attrib.form == DW_FORM_flag_present:
            return True
        elif attrib.form == DW_FORM_flag:
            return bool(attrib.value.u)
        else:
            raise DwarfFormatError(f'unknown form 0x{attrib.form:x} for flag')

    cpdef list children(self):
        # Note that _children isn't a cache; it's used for DIEs with no
        # children or DIEs which we had to parse the children for anyways when
        # we were parsing a list of siblings.
        if self._children is not None:
            return self._children

        assert self.dwarf_file is not None and self.cu is not None
        cdef Py_ssize_t offset = self.dwarf_file.debug_info.offset + self.offset + self.length
        return parse_die_siblings(&self.dwarf_file.buffer, &offset, self.cu)

    cpdef str name(self):
        return self.attrib_string(self.find_attrib(DW_AT_name))

    cpdef uint64_t address(self):
        cdef const DieAttrib *low_pc = self.find_attrib(DW_AT_low_pc)
        if low_pc.form != DW_FORM_addr:
            raise DwarfFormatError(f'unknown form 0x{low_pc.form:x} for DW_AT_low_pc')
        return low_pc.value.u

    cpdef Die type(self):
        cdef const DieAttrib *attrib = self.find_attrib(DW_AT_type)
        cdef Py_ssize_t offset = self.dwarf_file.debug_info.offset

        if (attrib.form == DW_FORM_ref1 or attrib.form == DW_FORM_ref2 or
            attrib.form == DW_FORM_ref4 or attrib.form == DW_FORM_ref8 or
            attrib.form == DW_FORM_ref_udata):
            offset += self.cu.offset + attrib.value.u
        elif attrib.form == DW_FORM_ref_addr:
            raise NotImplementedError('DW_FORM_ref_addr is not implemented')
        elif attrib.form == DW_FORM_ref_sig8:
            raise NotImplementedError('DW_FORM_ref_sig8 is not implemented')
        else:
            raise DwarfFormatError(f'unknown form 0x{attrib.form:x} for DW_AT_type')

        return parse_die(&self.dwarf_file.buffer, &offset, self.cu, False)

    cpdef bytes location(self, uint64_t addr):
        cdef const DieAttrib *attrib = self.find_attrib(DW_AT_location)
        cdef Py_ssize_t offset

        if attrib.form == DW_FORM_exprloc:
            offset = self.dwarf_file.debug_info.offset + attrib.value.ptr.offset
            return read_bytes(&self.dwarf_file.buffer, &offset,
                              attrib.value.ptr.length)
        else:
            return self.location_list_entry(attrib, addr)

    cdef bytes location_list_entry(self, const DieAttrib *attrib, uint64_t addr):
        cdef Py_ssize_t offset
        cdef uint64_t base_addr
        cdef uint64_t start
        cdef uint64_t end
        cdef uint16_t lle_length

        offset = self.dwarf_file.debug_loc.offset + Die.attrib_sec_offset(attrib)

        try:
            base_addr = self.cu.die().address()
        except DwarfAttribNotFoundError:
            base_addr = 0

        while True:
            if self.cu.address_size == 4:
                read_u32_into_u64(&self.dwarf_file.buffer, &offset, &start)
                read_u32_into_u64(&self.dwarf_file.buffer, &offset, &end)
                if start == UINT32_MAX:
                    base_addr = end
                    continue
            elif self.cu.address_size == 8:
                read_u64(&self.dwarf_file.buffer, &offset, &start)
                read_u64(&self.dwarf_file.buffer, &offset, &end)
                if start == UINT64_MAX:
                    base_addr = end
                    continue
            else:
                raise DwarfFormatError(f'unsupported address size {self.cu.address_size}')

            if start == 0 and end == 0:
                break

            read_u16(&self.dwarf_file.buffer, &offset, &lle_length)

            if base_addr + start <= addr < base_addr + end:
                return read_bytes(&self.dwarf_file.buffer, &offset, lle_length)

        raise DwarfLocationNotFoundError(f'could not find location list entry for address 0x{addr:x}')

    cpdef bint contains_address(self, uint64_t addr):
        cdef const DieAttrib *ranges_attrib
        try:
            ranges_attrib = self.find_attrib(DW_AT_ranges)
        except DwarfAttribNotFoundError:
            pass
        else:
            return self.ranges_contains_address(ranges_attrib, addr)

        cdef uint64_t low_pc
        cdef const DieAttrib *high_pc
        try:
            low_pc = self.address()
            high_pc = self.find_attrib(DW_AT_high_pc)
        except DwarfAttribNotFoundError:
            raise DwarfAttribNotFoundError('DIE does not have address range information')

        if high_pc.form == DW_FORM_addr:
            return low_pc <= addr < high_pc.value.u
        else:
            return low_pc <= addr < low_pc + Die.attrib_uconstant(high_pc)

    cdef bint ranges_contains_address(self, const DieAttrib *attrib, uint64_t addr):
        cdef Py_ssize_t offset
        cdef uint64_t base_addr
        cdef uint64_t start
        cdef uint64_t end

        offset = self.dwarf_file.debug_ranges.offset + Die.attrib_sec_offset(attrib)

        try:
            base_addr = self.cu.die().address()
        except DwarfAttribNotFoundError:
            base_addr = 0

        while True:
            if self.cu.address_size == 4:
                read_u32_into_u64(&self.dwarf_file.buffer, &offset, &start)
                read_u32_into_u64(&self.dwarf_file.buffer, &offset, &end)
                if start == UINT32_MAX:
                    base_addr = end
                    continue
            elif self.cu.address_size == 8:
                read_u64(&self.dwarf_file.buffer, &offset, &start)
                read_u64(&self.dwarf_file.buffer, &offset, &end)
                if start == UINT64_MAX:
                    base_addr = end
                    continue
            else:
                raise DwarfFormatError(f'unsupported address size {self.cu.address_size}')

            if start == 0 and end == 0:
                break

            if base_addr + start <= addr < base_addr + end:
                return True

        return False

    cdef const DieAttrib *find_attrib(self, uint64_t name) except NULL:
        for i in range(self.num_attribs):
            if self.attribs[i].name == name:
                return &self.attribs[i]
        else:
            raise DwarfAttribNotFoundError(f'no attribute with name 0x{name:x}')

    cdef str attrib_string(self, const DieAttrib *attrib):
        cdef Py_ssize_t offset

        if attrib.form == DW_FORM_strp:
            offset = self.dwarf_file.debug_str.offset + attrib.value.u
            # XXX: should limit length to the size of .debug_str.
            return read_str(&self.dwarf_file.buffer, &offset)
        elif attrib.form == DW_FORM_string:
            offset = self.dwarf_file.debug_info.offset + attrib.value.ptr.offset
            return PyUnicode_FromStringAndSize(<const char *>self.dwarf_file.buffer.buf + offset,
                                               attrib.value.ptr.length)
        else:
            raise DwarfFormatError(f'unknown form 0x{attrib.form:x} for string')

    @staticmethod
    cdef uint64_t attrib_uconstant(const DieAttrib *attrib):
        if attrib.form == DW_FORM_data1:
            return (<const uint8_t *>&attrib.value.data[0])[0]
        elif attrib.form == DW_FORM_data2:
            return (<const uint16_t *>&attrib.value.data[0])[0]
        elif attrib.form == DW_FORM_data4:
            return (<const uint32_t *>&attrib.value.data[0])[0]
        elif attrib.form == DW_FORM_data8:
            return (<const uint64_t *>&attrib.value.data[0])[0]
        elif attrib.form == DW_FORM_udata:
            return attrib.value.u
        else:
            raise DwarfFormatError(f'unknown form 0x{attrib.form:x} for unsigned constant')

    @staticmethod
    cdef uint64_t attrib_sec_offset(const DieAttrib *attrib):
        if attrib.form == DW_FORM_data4:
            # DWARF 2 and 3
            return (<const uint32_t *>&attrib.value.data[0])[0]
        elif attrib.form == DW_FORM_sec_offset:
            return attrib.value.u
        else:
            raise DwarfFormatError(f'unknown form 0x{attrib.form:x} for section offset')

    cdef object attrib_value(self, const DieAttrib *attrib):
        cdef Py_ssize_t offset

        if (attrib.form == DW_FORM_addr or
            attrib.form == DW_FORM_udata or
            attrib.form == DW_FORM_ref_udata or
            attrib.form == DW_FORM_ref1 or
            attrib.form == DW_FORM_ref2 or
            attrib.form == DW_FORM_ref4 or
            attrib.form == DW_FORM_ref8 or
            attrib.form == DW_FORM_ref_sig8 or
            attrib.form == DW_FORM_sec_offset or
            attrib.form == DW_FORM_strp):
            return attrib.value.u
        elif (attrib.form == DW_FORM_block1 or
              attrib.form == DW_FORM_block2 or
              attrib.form == DW_FORM_block4 or
              attrib.form == DW_FORM_block or
              attrib.form == DW_FORM_exprloc or
              attrib.form == DW_FORM_string):
            assert self.dwarf_file is not None
            offset = self.dwarf_file.debug_info.offset + attrib.value.ptr.offset
            return PyBytes_FromStringAndSize(<const char *>self.dwarf_file.buffer.buf + offset,
                                             attrib.value.ptr.length)
        elif attrib.form == DW_FORM_data1:
            return PyBytes_FromStringAndSize(attrib.value.data, 1)
        elif attrib.form == DW_FORM_data2:
            return PyBytes_FromStringAndSize(attrib.value.data, 2)
        elif attrib.form == DW_FORM_data4:
            return PyBytes_FromStringAndSize(attrib.value.data, 4)
        elif attrib.form == DW_FORM_data8:
            return PyBytes_FromStringAndSize(attrib.value.data, 8)
        elif attrib.form == DW_FORM_sdata:
            return attrib.value.s
        elif attrib.form == DW_FORM_flag:
            return bool(attrib.value.u)
        elif attrib.form == DW_FORM_flag_present:
            return True
        else:
            raise DwarfFormatError(f'unknown form 0x{attrib.form:x}')


cdef class LineNumberProgram:
    cdef public DwarfFile dwarf_file
    cdef public CompilationUnitHeader cu
    # Offset from the beginning of the section.
    cdef public Py_ssize_t offset

    cdef public uint64_t unit_length
    cdef public uint16_t version
    cdef public uint64_t header_length
    cdef public uint8_t minimum_instruction_length
    cdef public uint8_t maximum_operations_per_instruction
    cdef public bint default_is_stmt
    cdef public int8_t line_base
    cdef public uint8_t line_range
    cdef public uint8_t opcode_base
    cdef public list standard_opcode_lengths
    cdef public list include_directories
    cdef public list file_names
    cdef public bint is_64_bit

    cpdef Py_ssize_t program_offset(self):
        return self.offset + (22 if self.is_64_bit else 10) + self.header_length

    cpdef Py_ssize_t end_offset(self):
        return self.offset + (12 if self.is_64_bit else 4) + self.unit_length

    cdef init_state(self, LineNumberRow state):
        state.address = 0
        state.op_index = 0
        state.file = 1
        state.line = 1
        state.column = 0
        state.is_stmt = self.default_is_stmt
        state.basic_block = False
        state.end_sequence = False
        state.prologue_end = False
        state.epilogue_begin = False
        state.isa = 0
        state.discriminator = 0

    @staticmethod
    cdef reset_state(LineNumberRow state):
        state.basic_block = False
        state.prologue_end = False
        state.epilogue_begin = False
        state.discriminator = 0

    cpdef list execute(self):
        cdef Py_ssize_t offset = self.dwarf_file.debug_line.offset + self.program_offset()
        cdef Py_ssize_t end = self.dwarf_file.debug_line.offset + self.end_offset()

        cdef LineNumberRow state = LineNumberRow.__new__(LineNumberRow, self)
        self.init_state(state)

        cdef list matrix = []
        cdef uint8_t opcode
        while offset < end:
            read_u8(&self.dwarf_file.buffer, &offset, &opcode)
            self.execute_opcode(&self.dwarf_file.buffer, &offset, state, matrix, opcode)
        return matrix

    cdef execute_opcode(self, Py_buffer *buffer, Py_ssize_t *offset,
                        LineNumberRow state, list matrix, uint8_t opcode):
        if opcode == 0:
            self.execute_extended_opcode(buffer, offset, state, matrix)
        elif opcode < self.opcode_base:
            self.execute_standard_opcode(buffer, offset, state, matrix, opcode)
        else:
            self.execute_special_opcode(state, matrix, opcode)

    cdef execute_extended_opcode(self, Py_buffer *buffer, Py_ssize_t *offset,
                                 LineNumberRow state, list matrix):
        cdef uint64_t op_length
        read_uleb128(buffer, offset, &op_length)
        read_check_bounds(buffer, offset[0], op_length)
        cdef Py_ssize_t end = offset[0] + op_length

        cdef uint8_t opcode
        read_u8(buffer, offset, &opcode)
        if opcode == DW_LNE_end_sequence:
            state.end_sequence = True
            matrix.append(LineNumberRow.__new__(LineNumberRow, self, state))
            self.init_state(state)
        elif opcode == DW_LNE_set_address:
            if op_length == 9:
                read_u64(buffer, offset, &state.address)
            elif op_length == 5:
                read_u32_into_u64(buffer, offset, &state.address)
            else:
                raise DwarfFormatError(f'unsupported address size {op_length}')
            state.op_index = 0
        elif opcode == DW_LNE_define_file:
            raise NotImplementedError('DW_LNE_define_file is not implemented')
        elif opcode == DW_LNE_set_discriminator:
            read_uleb128(buffer, offset, &state.discriminator)
        else:
            raise DwarfFormatError(f'unknown extended opcode {opcode}')

    cdef advance_pc(self, LineNumberRow state, uint64_t operation_advance):
        state.address += (self.minimum_instruction_length *
                          ((state.op_index + operation_advance) /
                            self.maximum_operations_per_instruction))
        state.op_index = ((state.op_index + operation_advance) %
                           self.maximum_operations_per_instruction)

    cdef execute_standard_opcode(self, Py_buffer *buffer, Py_ssize_t *offset,
                                 LineNumberRow state, list matrix, uint8_t opcode):
        cdef uint64_t arg
        cdef int64_t sarg

        if opcode == DW_LNS_copy:
            matrix.append(LineNumberRow.__new__(LineNumberRow, self, state))
            LineNumberProgram.reset_state(state)
        elif opcode == DW_LNS_advance_pc:
            read_uleb128(buffer, offset, &arg)
            self.advance_pc(state, arg)
        elif opcode == DW_LNS_advance_line:
            read_sleb128(buffer, offset, &sarg)
            state.line += sarg
        elif opcode == DW_LNS_set_file:
            read_uleb128(buffer, offset, &state.file)
        elif opcode == DW_LNS_set_column:
            read_uleb128(buffer, offset, &state.column)
        elif opcode == DW_LNS_negate_stmt:
            state.is_stmt = not state.is_stmt
        elif opcode == DW_LNS_set_basic_block:
            state.basic_block = True
        elif opcode == DW_LNS_const_add_pc:
            self.advance_pc(state, (255 - self.opcode_base) / self.line_range)
        elif opcode == DW_LNS_fixed_advance_pc:
            self.advance_pc(state, (255 - self.opcode_base) / self.line_range)
            read_u16_into_u64(buffer, offset, &arg)
            state.address += arg
            state.op_index = 0
        elif opcode == DW_LNS_set_prologue_end:
            state.prologue_end = True
        elif opcode == DW_LNS_set_epilogue_begin:
            state.epilogue_begin = True
        elif opcode == DW_LNS_set_isa:
            read_uleb128(buffer, offset, &state.isa)
        else:
            raise DwarfFormatError(f'unknown standard opcode {opcode}')

    cdef execute_special_opcode(self, LineNumberRow state, list matrix, uint8_t opcode):
        cdef uint8_t adjusted_opcode = opcode - self.opcode_base
        cdef uint8_t operation_advance = adjusted_opcode / self.line_range

        self.advance_pc(state, operation_advance)
        state.line += self.line_base + (adjusted_opcode % self.line_range)
        matrix.append(LineNumberRow.__new__(LineNumberRow, self, state))
        LineNumberProgram.reset_state(state)


cdef class LineNumberRow:
    cdef public LineNumberProgram lnp

    cdef public uint64_t address
    cdef public uint64_t file
    cdef public uint64_t line
    cdef public uint64_t column
    cdef public uint64_t isa
    cdef public uint64_t discriminator
    cdef public uint8_t op_index
    cdef public bint is_stmt
    cdef public bint basic_block
    cdef public bint end_sequence
    cdef public bint prologue_end
    cdef public bint epilogue_begin

    def __cinit__(self, LineNumberProgram lnp, LineNumberRow row=None):
        self.lnp = lnp
        if row is not None:
            self.address = row.address
            self.file = row.file
            self.line = row.line
            self.column = row.column
            self.isa = row.isa
            self.discriminator = row.discriminator
            self.op_index = row.op_index
            self.is_stmt = row.is_stmt
            self.basic_block = row.basic_block
            self.end_sequence = row.end_sequence
            self.prologue_end = row.prologue_end
            self.epilogue_begin = row.epilogue_begin

    def path(self):
        assert self.lnp is not None
        if self.file == 0:
            assert self.lnp.cu is not None
            return self.lnp.cu.name()
        else:
            filename = self.lnp.file_names[self.file - 1]
            if filename.directory_index > 0:
                directory = self.lnp.include_directories[filename.directory_index - 1]
                return directory + '/' + filename.name
            else:
                return filename.name


cdef class LineNumberFilename:
    cdef public str name
    cdef public uint64_t directory_index
    cdef public uint64_t mtime
    cdef public uint64_t file_size


cdef read_uleb128(Py_buffer *buffer, Py_ssize_t *offset, uint64_t *ret):
    cdef int shift = 0
    cdef uint8_t byte

    ret[0] = 0
    while True:
        read_u8(buffer, offset, &byte)
        if shift == 63 and byte > 1:
            raise OverflowError('ULEB128 overflowed unsigned 64-bit integer')
        ret[0] |= <uint64_t>(byte & 0x7f) << shift
        shift += 7
        if not (byte & 0x80):
            break


cdef read_sleb128(Py_buffer *buffer, Py_ssize_t *offset, int64_t *ret):
    cdef int shift = 0
    cdef uint8_t byte

    ret[0] = 0
    while True:
        read_u8(buffer, offset, &byte)
        if shift == 63 and byte != 0 and byte != 0x7f:
            raise OverflowError('ULEB128 overflowed unsigned 64-bit integer')
        ret[0] |= <int64_t>(byte & 0x7f) << shift
        shift += 7
        if not (byte & 0x80):
            break
    if shift < 64 and (byte & 0x40):
        ret[0] |= -(<int64_t>1 << shift)


def parse_uleb128(s, Py_ssize_t offset):
    cdef uint64_t ret
    cdef Py_buffer buffer
    PyObject_GetBuffer(s, &buffer, PyBUF_SIMPLE)
    try:
        read_uleb128(&buffer, &offset, &ret)
        return ret, offset
    finally:
        PyBuffer_Release(&buffer)


def parse_sleb128(s, Py_ssize_t offset):
    cdef int64_t ret
    cdef Py_buffer buffer
    PyObject_GetBuffer(s, &buffer, PyBUF_SIMPLE)
    try:
        read_sleb128(&buffer, &offset, &ret)
        return ret, offset
    finally:
        PyBuffer_Release(&buffer)


cdef int realloc_abbrev_decls(AbbrevDecl **abbrev_decls, Py_ssize_t n) except -1:
    if n > PY_SSIZE_T_MAX / <Py_ssize_t>sizeof(AbbrevDecl):
        raise MemoryError()

    cdef AbbrevDecl *tmp = <AbbrevDecl *>PyMem_RawRealloc(abbrev_decls[0],
                                                          n * sizeof(AbbrevDecl))
    if tmp == NULL:
        raise MemoryError()

    abbrev_decls[0] = tmp
    return 0


cdef int realloc_attrib_specs(AttribSpec **attrib_specs, Py_ssize_t n) except -1:
    if n > PY_SSIZE_T_MAX / <Py_ssize_t>sizeof(AttribSpec):
        raise MemoryError()

    cdef AttribSpec *tmp = <AttribSpec *>PyMem_RawRealloc(attrib_specs[0],
                                                          n * sizeof(AttribSpec))
    if tmp == NULL:
        raise MemoryError()

    attrib_specs[0] = tmp
    return 0


cdef int parse_abbrev_decl(Py_buffer *buffer, Py_ssize_t *offset,
                           AbbrevTable *abbrev_table,
                           uint64_t *decls_capacity) except -1:
    cdef uint64_t code

    try:
        read_uleb128(buffer, offset, &code)
    except EOFError:
        raise DwarfFormatError('abbreviation declaration code is truncated')
    if code == 0:
        return 0
    if code != abbrev_table.num_decls + 1:
        raise NotImplementedError('abbreviation table is not sequential')

    if abbrev_table.num_decls >= decls_capacity[0]:
        decls_capacity[0] *= 2
        realloc_abbrev_decls(&abbrev_table.decls, decls_capacity[0])

    cdef AbbrevDecl *decl = &abbrev_table.decls[abbrev_table.num_decls]
    decl.attribs = NULL
    decl.num_attribs = 0
    abbrev_table.num_decls += 1

    try:
        read_uleb128(buffer, offset, &decl.tag)
    except EOFError:
        raise DwarfFormatError('abbreviation declaration tag is truncated')
    cdef uint8_t children
    try:
        read_u8(buffer, offset, &children)
    except EOFError:
        raise DwarfFormatError('abbreviation declaration children flag is truncated')
    decl.children = children != DW_CHILDREN_no

    cdef uint64_t attribs_capacity = 1  # XXX: is this a good first guess?
    realloc_attrib_specs(&decl.attribs, attribs_capacity)

    cdef uint64_t name, form
    while True:
        try:
            read_uleb128(buffer, offset, &name)
        except EOFError:
            raise DwarfFormatError('abbreviation specification name is truncated')
        try:
            read_uleb128(buffer, offset, &form)
        except EOFError:
            raise DwarfFormatError('abbreviation specification form is truncated')
        if name == 0 and form == 0:
            break

        if decl.num_attribs >= attribs_capacity:
            attribs_capacity *= 2
            realloc_attrib_specs(&decl.attribs, attribs_capacity)

        decl.attribs[decl.num_attribs].name = name
        decl.attribs[decl.num_attribs].form = form
        decl.num_attribs += 1

    realloc_attrib_specs(&decl.attribs, decl.num_attribs)
    return 1


cdef int parse_abbrev_table(Py_buffer *buffer, Py_ssize_t *offset,
                            AbbrevTable *abbrev_table) except -1:
    cdef uint64_t decls_capacity = 1  # XXX: is this a good first guess?

    abbrev_table.decls = NULL
    abbrev_table.num_decls = 0
    realloc_abbrev_decls(&abbrev_table.decls, decls_capacity)

    while parse_abbrev_decl(buffer, offset, abbrev_table, &decls_capacity):
        pass
    realloc_abbrev_decls(&abbrev_table.decls, abbrev_table.num_decls)
    return 0


cdef ArangeTable parse_arange_table(Py_buffer *buffer, Py_ssize_t *offset,
                                    DwarfFile dwarf_file):
    cdef ArangeTable art = ArangeTable.__new__(ArangeTable)
    art.offset = offset[0] - dwarf_file.debug_aranges.offset

    cdef uint32_t tmp
    read_u32(buffer, offset, &tmp)
    art.is_64_bit = tmp == 0xffffffffUL
    if art.is_64_bit:
        read_u64(buffer, offset, &art.unit_length)
    else:
        art.unit_length = tmp

    read_u16(buffer, offset, &art.version)
    if art.version != 2:
        raise DwarfFormatError(f'unknown arange table version {art.version}')

    if art.is_64_bit:
        read_u64(buffer, offset, &art.debug_info_offset)
    else:
        read_u32_into_u64(buffer, offset, &art.debug_info_offset)

    read_u8(buffer, offset, &art.address_size)
    read_u8(buffer, offset, &art.segment_size)

    if art.segment_size != 4 and art.segment_size != 8 and art.segment_size != 0:
        raise DwarfFormatError(f'unsupported segment size {art.segment_size}')
    if art.address_size != 4 and art.address_size != 8:
        raise DwarfFormatError(f'unsupported address size {art.address_size}')

    cdef Py_ssize_t align = art.segment_size + 2 * art.address_size
    if offset[0] % align:
        offset[0] += align - (offset[0] % align)

    cdef uint64_t segment, address, length_
    art.table = []
    while True:
        if art.segment_size == 4:
            read_u32_into_u64(buffer, offset, &segment)
        elif art.segment_size == 8:
            read_u64(buffer, offset, &segment)
        else:  # art.segment_size == 0
            segment = 0

        if art.address_size == 4:
            read_u32_into_u64(buffer, offset, &address)
            read_u32_into_u64(buffer, offset, &length_)
        else:  # art.address_size == 8
            read_u64(buffer, offset, &address)
            read_u64(buffer, offset, &length_)

        if segment == 0 and address == 0 and length_ == 0:
            break

        art.table.append(AddressRange.__new__(AddressRange, segment, address, length_))

    return art


cdef CompilationUnitHeader parse_compilation_unit_header(Py_buffer *buffer,
                                                         Py_ssize_t *offset,
                                                         DwarfFile dwarf_file):
    cdef CompilationUnitHeader cu = CompilationUnitHeader.__new__(CompilationUnitHeader)
    cu.dwarf_file = dwarf_file
    cu.offset = offset[0] - dwarf_file.debug_info.offset

    cdef uint32_t tmp
    read_u32(buffer, offset, &tmp)
    cu.is_64_bit = tmp == 0xffffffffUL
    if cu.is_64_bit:
        read_u64(buffer, offset, &cu.unit_length)
    else:
        cu.unit_length = tmp

    read_u16(buffer, offset, &cu.version)
    if cu.version != 2 and cu.version != 3 and cu.version != 4:
        raise DwarfFormatError(f'unknown CU version {cu.version}')

    if cu.is_64_bit:
        read_u64(buffer, offset, &cu.debug_abbrev_offset)
    else:
        read_u32_into_u64(buffer, offset, &cu.debug_abbrev_offset)

    read_u8(buffer, offset, &cu.address_size)

    return cu


cdef parse_die_attrib(Py_buffer *buffer, Py_ssize_t *offset,
                      DwarfFile dwarf_file, DieAttrib *attrib,
                      uint8_t address_size, bint is_64_bit):
    cdef uint64_t tmp

    # address
    if attrib.form == DW_FORM_addr:
        if address_size == 4:
            read_u32_into_u64(buffer, offset, &attrib.value.u)
        elif address_size == 8:
            read_u64(buffer, offset, &attrib.value.u)
        else:
            raise DwarfFormatError(f'unsupported address size {address_size}')
    elif (attrib.form == DW_FORM_block1 or  # block
          attrib.form == DW_FORM_block2 or
          attrib.form == DW_FORM_block4 or
          attrib.form == DW_FORM_exprloc):  # exprloc
        if attrib.form == DW_FORM_block1:
            read_u8_into_ssize_t(buffer, offset, &attrib.value.ptr.length)
        elif attrib.form == DW_FORM_block2:
            read_u16_into_ssize_t(buffer, offset, &attrib.value.ptr.length)
        elif attrib.form == DW_FORM_block4:
            read_u32_into_ssize_t(buffer, offset, &attrib.value.ptr.length)
        elif attrib.form == DW_FORM_exprloc:
            read_uleb128(buffer, offset, &tmp)
            if tmp > <uint64_t>PY_SSIZE_T_MAX:
                raise DwarfFormatError('attribute length too big')
            attrib.value.ptr.length = tmp
        read_check_bounds(buffer, offset[0], attrib.value.ptr.length)
        attrib.value.ptr.offset = offset[0] - dwarf_file.debug_info.offset
        offset[0] += attrib.value.ptr.length
    # constant
    elif attrib.form == DW_FORM_data1:
        read_buffer(buffer, offset, &attrib.value.data, 1)
    elif attrib.form == DW_FORM_data2:
        read_buffer(buffer, offset, &attrib.value.data, 2)
    elif attrib.form == DW_FORM_data4:
        read_buffer(buffer, offset, &attrib.value.data, 4)
    elif attrib.form == DW_FORM_data8:
        read_buffer(buffer, offset, &attrib.value.data, 8)
    elif attrib.form == DW_FORM_sdata:
        read_sleb128(buffer, offset, &attrib.value.s)
    elif (attrib.form == DW_FORM_udata or     # constant
          attrib.form == DW_FORM_ref_udata):  # reference
        read_uleb128(buffer, offset, &attrib.value.u)
    elif (attrib.form == DW_FORM_ref_addr or    # reference
          attrib.form == DW_FORM_sec_offset or  # lineptr, loclistptr, macptr, rangelistptr
          attrib.form == DW_FORM_strp):         # string
        if is_64_bit:
            read_u64(buffer, offset, &attrib.value.u)
        else:
            read_u32_into_u64(buffer, offset, &attrib.value.u)
    # string
    elif attrib.form == DW_FORM_string:
        attrib.value.ptr.offset = offset[0] - dwarf_file.debug_info.offset
        attrib.value.ptr.length = read_strlen(buffer, offset)
    # flag
    elif attrib.form == DW_FORM_flag_present:
        attrib.value.u = 1
    elif (attrib.form == DW_FORM_flag or  # flag
          attrib.form == DW_FORM_ref1):   # reference
        read_u8_into_u64(buffer, offset, &attrib.value.u)
    # reference
    elif attrib.form == DW_FORM_ref2:
        read_u16_into_u64(buffer, offset, &attrib.value.u)
    elif attrib.form == DW_FORM_ref4:
        read_u32_into_u64(buffer, offset, &attrib.value.u)
    elif (attrib.form == DW_FORM_ref8 or attrib.form == DW_FORM_ref_sig8):
        read_u64(buffer, offset, &attrib.value.u)
    elif DW_FORM_indirect:
        raise DwarfFormatError('DW_FORM_indirect is not supported')
    else:
        raise DwarfFormatError(f'unknown form 0x{attrib.form:x}')


cdef list no_children = []


cdef list parse_die_siblings(Py_buffer *buffer, Py_ssize_t *offset,
                             CompilationUnitHeader cu):
    cdef list children = []
    cdef Die child

    while True:
        child = parse_die(buffer, offset, cu, True)
        if child is None:
            break
        children.append(child)

    return children


cdef Die parse_die(Py_buffer *buffer, Py_ssize_t *offset,
                   CompilationUnitHeader cu, bint jump_to_sibling):
    cdef Die die = Die.__new__(Die)
    die.dwarf_file = cu.dwarf_file
    die.cu = cu
    die.offset = offset[0] - cu.dwarf_file.debug_info.offset

    cdef uint64_t code
    read_uleb128(buffer, offset, &code)
    if code == 0:
        return None

    cdef AbbrevDecl *decl = cu.abbrev_decl(code)
    if decl == NULL:
        raise DwarfFormatError(f'unknown abbreviation code {code}')

    die.tag = decl.tag
    die.attribs = <DieAttrib *>PyMem_Calloc(decl.num_attribs, sizeof(DieAttrib))
    if die.attribs == NULL:
        raise MemoryError()
    die.num_attribs = decl.num_attribs

    cdef uint64_t sibling_form = 0
    cdef Py_ssize_t sibling = 0
    for i in range(die.num_attribs):
        die.attribs[i].name = decl.attribs[i].name
        die.attribs[i].form = decl.attribs[i].form
        parse_die_attrib(buffer, offset, cu.dwarf_file, &die.attribs[i],
                         cu.address_size, cu.is_64_bit)
        if die.attribs[i].name == DW_AT_sibling:
            sibling_form = die.attribs[i].form
            sibling = die.attribs[i].value.u

    die.length = offset[0] - cu.dwarf_file.debug_info.offset - die.offset

    if not decl.children:
        die._children = no_children
    elif jump_to_sibling and sibling == 0:
        die._children = parse_die_siblings(buffer, offset, cu)
    elif jump_to_sibling:
        if sibling_form == DW_FORM_ref_addr:
            offset[0] = cu.dwarf_file.debug_info.offset + sibling
        else:
            offset[0] = cu.dwarf_file.debug_info.offset + cu.offset + sibling

    return die


cdef LineNumberProgram parse_line_number_program(Py_buffer *buffer,
                                                 Py_ssize_t *offset,
                                                 CompilationUnitHeader cu):
    cdef LineNumberProgram lnp = LineNumberProgram.__new__(LineNumberProgram)
    lnp.dwarf_file = cu.dwarf_file
    lnp.cu = cu
    lnp.offset = offset[0] - cu.dwarf_file.debug_line.offset

    cdef uint32_t tmp
    read_u32(buffer, offset, &tmp)
    lnp.is_64_bit = tmp == 0xffffffffUL
    if lnp.is_64_bit:
        read_u64(buffer, offset, &lnp.unit_length)
    else:
        lnp.unit_length = tmp

    read_u16(buffer, offset, &lnp.version)
    if lnp.version != 2 and lnp.version != 3 and lnp.version != 4:
        raise DwarfFormatError(f'unknown line number program version {lnp.version}')

    if lnp.is_64_bit:
        read_u64(buffer, offset, &lnp.header_length)
    else:
        read_u32_into_u64(buffer, offset, &lnp.header_length)

    read_u8(buffer, offset, &lnp.minimum_instruction_length)
    if lnp.version >= 4:
        read_u8(buffer, offset, &lnp.maximum_operations_per_instruction)
    else:
        lnp.maximum_operations_per_instruction = 1
    cdef uint8_t default_is_stmt
    read_u8(buffer, offset, &default_is_stmt)
    lnp.default_is_stmt = default_is_stmt
    read_s8(buffer, offset, &lnp.line_base)
    read_u8(buffer, offset, &lnp.line_range)
    read_u8(buffer, offset, &lnp.opcode_base)

    if lnp.opcode_base == 0:
        raise DwarfFormatError('opcode_base is 0')
    lnp.standard_opcode_lengths = []
    cdef uint8_t opcode_length
    for i in range(lnp.opcode_base - 1):
        read_u8(buffer, offset, &opcode_length)
        lnp.standard_opcode_lengths.append(opcode_length)

    lnp.include_directories = []
    cdef str directory
    while True:
        directory = read_str(buffer, offset)
        if not directory:
            break
        lnp.include_directories.append(directory)

    lnp.file_names = []
    cdef str name
    cdef LineNumberFilename file
    while True:
        name = read_str(buffer, offset)
        if not name:
            break
        file = LineNumberFilename.__new__(LineNumberFilename)
        file.name = name
        read_uleb128(buffer, offset, &file.directory_index)
        read_uleb128(buffer, offset, &file.mtime)
        read_uleb128(buffer, offset, &file.file_size)
        lnp.file_names.append(file)

    return lnp
