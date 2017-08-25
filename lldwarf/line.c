#include "lldwarf.h"
#include "dwarfdefs.h"

static void LineNumberProgramHeader_dealloc(LineNumberProgramHeader *self)
{
	Py_XDECREF(self->standard_opcode_lengths);
	Py_XDECREF(self->include_directories);
	Py_XDECREF(self->file_names);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int LineNumberProgramHeader_traverse(LineNumberProgramHeader *self,
					    visitproc visit, void *arg)
{
	Py_VISIT(self->standard_opcode_lengths);
	Py_VISIT(self->include_directories);
	Py_VISIT(self->file_names);
	return 0;
}

PyObject *LineNumberProgramHeader_program_offset(LineNumberProgramHeader *self)
{
	uint64_t before_header_length_length = self->is_64_bit ? 22 : 10;
	uint64_t header_length;
	Py_ssize_t ret;

	if (__builtin_add_overflow(self->header_length, before_header_length_length, &header_length) ||
	    __builtin_add_overflow(self->offset, header_length, &ret)) {
		PyErr_SetString(PyExc_OverflowError, "program offset too large");
		return NULL;
	}

	return PyLong_FromSsize_t(ret);
}

static Py_ssize_t lnp_end_offset(LineNumberProgramHeader *self)
{
	uint64_t unit_length_length = self->is_64_bit ? 12 : 4;
	uint64_t unit_length;
	Py_ssize_t ret;

	if (__builtin_add_overflow(self->unit_length, unit_length_length, &unit_length) ||
	    __builtin_add_overflow(self->offset, unit_length, &ret)) {
		PyErr_SetString(PyExc_OverflowError, "end offset too large");
		return -1;
	}

	return ret;
}

PyObject *LineNumberProgramHeader_end_offset(LineNumberProgramHeader *self)
{
	Py_ssize_t ret;

	ret = lnp_end_offset(self);
	if (ret == -1)
		return NULL;

	return PyLong_FromSsize_t(ret);
}

static PyObject *parse_standard_opcode_lengths(Py_buffer *buffer,
					       Py_ssize_t *offset,
					       uint8_t opcode_base)
{
	PyObject *lengths;
	uint8_t i;

	if (opcode_base == 0) {
		PyErr_SetString(PyExc_ValueError, "opcode_base is 0");
		return NULL;
	}

	lengths = PyList_New(opcode_base - 1);
	if (!lengths)
		return NULL;

	for (i = 0; i < opcode_base - 1; i++) {
		PyObject *item;
		uint8_t length;

		if (read_u8(buffer, offset, &length) == -1)
			goto err;

		item = PyLong_FromUnsignedLong(length);
		if (!item)
			goto err;

		PyList_SET_ITEM(lengths, i, item);
	}

	return lengths;

err:
	Py_DECREF(lengths);
	return NULL;
}

static PyObject *parse_include_directories(Py_buffer *buffer,
					   Py_ssize_t *offset)
{
	PyObject *directories;

	directories = PyList_New(0);
	if (!directories)
		return NULL;

	for (;;) {
		const char *str;
		Py_ssize_t len;
		PyObject *directory;

		str = (char *)buffer->buf + *offset;
		if (read_strlen(buffer, offset, &len) == -1)
			goto err;
		if (len == 0)
			break;

		directory = PyBytes_FromStringAndSize(str, len);
		if (!directory)
			goto err;

		if (PyList_Append(directories, directory) == -1) {
			Py_DECREF(directory);
			goto err;
		}

		Py_DECREF(directory);
	}

	return directories;

err:
	Py_DECREF(directories);
	return NULL;
}

static PyObject *parse_file_names(Py_buffer *buffer, Py_ssize_t *offset)
{
	PyObject *file_names;

	file_names = PyList_New(0);

	for (;;) {
		const char *str;
		Py_ssize_t len;
		uint64_t directory_index;
		uint64_t mtime;
		uint64_t file_size;
		PyObject *item;

		str = (char *)buffer->buf + *offset;
		if (read_strlen(buffer, offset, &len) == -1)
			goto err;
		if (len == 0)
			break;

		if (read_uleb128(buffer, offset, &directory_index) == -1)
			goto err;
		if (read_uleb128(buffer, offset, &mtime) == -1)
			goto err;
		if (read_uleb128(buffer, offset, &file_size) == -1)
			goto err;

		item = Py_BuildValue("y#KKK", str, len,
				     (unsigned long long)directory_index,
				     (unsigned long long)mtime,
				     (unsigned long long)file_size);
		if (!item)
			goto err;

		if (PyList_Append(file_names, item) == -1) {
			Py_DECREF(item);
			goto err;
		}

		Py_DECREF(item);
	}

	return file_names;

err:
	Py_DECREF(file_names);
	return NULL;
}

PyObject *LLDwarf_ParseLineNumberProgramHeader(Py_buffer *buffer,
					       Py_ssize_t *offset)
{
	LineNumberProgramHeader *lnp;
	uint32_t length;
	uint8_t default_is_stmt;

	lnp = PyObject_New(LineNumberProgramHeader, &LineNumberProgramHeader_type);
	if (!lnp)
		return NULL;

	lnp->offset = *offset;

	if (read_u32(buffer, offset, &length) == -1)
		goto err;

	lnp->is_64_bit = length == UINT32_C(0xffffffff);
	if (lnp->is_64_bit) {
		if (read_u64(buffer, offset, &lnp->unit_length) == -1)
			goto err;
	} else {
		lnp->unit_length = length;
	}

	if (read_u16(buffer, offset, &lnp->version) == -1)
		goto err;

	if (lnp->is_64_bit) {
		if (read_u64(buffer, offset, &lnp->header_length) == -1)
			goto err;
	} else {
		if (read_u32(buffer, offset, &length) == -1)
			goto err;
		lnp->header_length = length;
	}

	if (read_u8(buffer, offset, &lnp->minimum_instruction_length) == -1)
		goto err;
	if (lnp->version >= 4) {
		if (read_u8(buffer, offset, &lnp->maximum_operations_per_instruction) == -1)
			goto err;
	} else {
		lnp->maximum_operations_per_instruction = 1;
	}
	if (read_u8(buffer, offset, &default_is_stmt) == -1)
		goto err;
	lnp->default_is_stmt = (bool)default_is_stmt;
	if (read_s8(buffer, offset, &lnp->line_base) == -1)
		goto err;
	if (read_u8(buffer, offset, &lnp->line_range) == -1)
		goto err;
	if (read_u8(buffer, offset, &lnp->opcode_base) == -1)
		goto err;

	lnp->standard_opcode_lengths =
		parse_standard_opcode_lengths(buffer, offset, lnp->opcode_base);
	if (!lnp->standard_opcode_lengths)
		goto err;
	lnp->include_directories = parse_include_directories(buffer, offset);
	if (!lnp->include_directories)
		goto err;
	lnp->file_names = parse_file_names(buffer, offset);
	if (!lnp->file_names)
		goto err;

	return (PyObject *)lnp;

err:
	PyErr_SetString(PyExc_ValueError,
			"line number program header is truncated");
	Py_DECREF(lnp);
	return NULL;
}

static PyMethodDef LineNumberProgramHeader_methods[] = {
	{"program_offset", (PyCFunction)LineNumberProgramHeader_program_offset,
	 METH_NOARGS,
	 "program_offset() -> int\n\n"
	 "Get the offset into the file where the line number program itself\n"
	 "starts. This is the starting offset of the line number program\n"
	 "header plus the length of the header."},
	{"end_offset", (PyCFunction)LineNumberProgramHeader_end_offset,
	 METH_NOARGS,
	 "end_offset() -> int\n\n"
	 "Get the offset into the file where the line number program ends.\n"
	 "This is the starting offset of the line number program header plus\n"
	 "the length of the unit, including the header."},
	{},
};

static PyMemberDef LineNumberProgramHeader_members[] = {
	{"offset", T_PYSSIZET,
	 offsetof(LineNumberProgramHeader, offset), 0,
	 "offset into the file where this line number program starts"},
	{"unit_length", T_UINT64T,
	 offsetof(LineNumberProgramHeader, unit_length), 0,
	 "length of this line number program, not including the unit_length field"},
	{"version", T_UINT16T, offsetof(LineNumberProgramHeader, version), 0,
	 "format version of this line number program"},
	{"header_length", T_UINT64T,
	 offsetof(LineNumberProgramHeader, header_length), 0,
	 "length of this line number program header, not including the\n"
	 "unit_length, version, or header_length fields"},
	{"minimum_instruction_length", T_UINT8T,
	 offsetof(LineNumberProgramHeader, minimum_instruction_length), 0,
	 "size of the smallest target machine instruction"},
	{"maximum_operations_per_instruction", T_UINT8T,
	 offsetof(LineNumberProgramHeader, maximum_operations_per_instruction), 0,
	 "maximum number of operations that may be encoded in an instruction"},
	{"default_is_stmt", T_BOOL,
	 offsetof(LineNumberProgramHeader, default_is_stmt), 0,
	 "initial value of the is_stmt register"},
	{"line_base", T_INT8T, offsetof(LineNumberProgramHeader, line_base), 0,
	 "parameter for special opcodes"},
	{"line_range", T_UINT8T,
	  offsetof(LineNumberProgramHeader, line_range), 0,
	 "parameter for special opcodes"},
	{"opcode_base", T_UINT8T,
	  offsetof(LineNumberProgramHeader, opcode_base), 0,
	 "number assigned to the first special opcode"},
	{"standard_opcode_lengths", T_OBJECT,
	  offsetof(LineNumberProgramHeader, standard_opcode_lengths), 0,
	 "list of number of operands for each standard opcode"},
	{"include_directories", T_OBJECT,
	  offsetof(LineNumberProgramHeader, include_directories), 0,
	 "list of path names that were searched for included source files"},
	{"file_names", T_OBJECT,
	  offsetof(LineNumberProgramHeader, file_names), 0,
	 "list of (path name, directory index, mtime, file size)"},
	{"is_64_bit", T_BOOL, offsetof(LineNumberProgramHeader, is_64_bit), 0,
	 "whether this CU is using the 64-bit format"},
	{},
};

#define LineNumberProgramHeader_DOC						\
	"LineNumberProgramHeader(offset, unit_length, version, header_length,\n"\
	"                        minimum_instruction_length,\n"			\
	"                        maximum_operations_per_instruction,\n"		\
	"                        default_is_stmt, line_base, line_range,\n"	\
	"                        opcode_base, standard_opcode_lengths,\n"	\
	"                        include_directories, file_names,\n"		\
	"                        is_64_bit) -> new line number program header\n\n"	\
	"Create a new DWARF line number program header.\n\n"			\
	"Arguments:\n"								\
	"offset -- integer offset\n"						\
	"unit_length -- integer length\n"					\
	"version -- integer format version\n"					\
	"header_length -- integer length\n"					\
	"minimum_instruction_length -- integer length\n"			\
	"maximum_operations_per_instruction -- integer\n"			\
	"default_is_stmt -- boolean\n"						\
	"line_base -- integer\n"						\
	"line_range -- integer\n"						\
	"opcode_base -- integer\n"						\
	"standard_opcode_lengths -- list of integers\n"				\
	"include_directories -- list of strings\n"				\
	"file_names -- list of (string, integer, integer, integer)\n"		\
	"is_64_bit -- boolean"

PyTypeObject LineNumberProgramHeader_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"drgn.lldwarf.LineNumberProgramHeader",	/* tp_name */
	sizeof(LineNumberProgramHeader),	/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)LineNumberProgramHeader_dealloc,	/* tp_dealloc */
	NULL,					/* tp_print */
	NULL,					/* tp_getattr */
	NULL,					/* tp_setattr */
	NULL,					/* tp_as_async */
	LLDwarfObject_repr,			/* tp_repr */
	NULL,					/* tp_as_number */
	NULL,					/* tp_as_sequence */
	NULL,					/* tp_as_mapping */
	NULL,					/* tp_hash  */
	NULL,					/* tp_call */
	NULL,					/* tp_str */
	NULL,					/* tp_getattro */
	NULL,					/* tp_setattro */
	NULL,					/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,			/* tp_flags */
	LineNumberProgramHeader_DOC,		/* tp_doc */
	(traverseproc)LineNumberProgramHeader_traverse,	/* tp_traverse */
	NULL,					/* tp_clear */
	LLDwarfObject_richcompare,		/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	NULL,					/* tp_iter */
	NULL,					/* tp_iternext */
	LineNumberProgramHeader_methods,	/* tp_methods */
	LineNumberProgramHeader_members,	/* tp_members */
	NULL,					/* tp_getset */
	NULL,					/* tp_base */
	NULL,					/* tp_dict */
	NULL,					/* tp_descr_get */
	NULL,					/* tp_descr_set */
	0,					/* tp_dictoffset */
	LLDwarfObject_init,			/* tp_init */
};

static void LineNumberRow_dealloc(PyObject *self)
{
	Py_TYPE(self)->tp_free(self);
}

static void init_state(LineNumberProgramHeader *lnp, LineNumberRow *state)
{
	state->address = 0;
	state->op_index = 0;
	state->file = 1;
	state->line = 1;
	state->column = 0;
	state->is_stmt = lnp->default_is_stmt;
	state->basic_block = false;
	state->end_sequence = false;
	state->prologue_end = false;
	state->epilogue_begin = false;
	state->isa = 0;
	state->discriminator = 0;
}

static void reset_state(LineNumberRow *state)
{
	state->basic_block = false;
	state->prologue_end = false;
	state->epilogue_begin = false;
	state->discriminator = 0;
}

static int append_row(PyObject *matrix, LineNumberRow *state)
{
	LineNumberRow *row;
	int ret;

	row = PyMem_Malloc(sizeof(LineNumberRow));
	if (!row)
		return -1;
	*row = *state;
	PyObject_Init((PyObject *)row, &LineNumberRow_type);

	ret = PyList_Append(matrix, (PyObject *)row);
	Py_DECREF((PyObject *)row);
	return ret;
}

static int execute_extended_opcode(LineNumberProgramHeader *lnp,
				   LineNumberRow *state, PyObject *matrix,
				   Py_buffer *buffer, Py_ssize_t *offset)
{
	Py_ssize_t end;
	uint64_t length;
	uint8_t opcode;

	if (read_uleb128(buffer, offset, &length) == -1)
		return -1;
	if (read_check_bounds(buffer, *offset, length) == -1)
		return -1;
	end = *offset + length;

	if (read_u8(buffer, offset, &opcode) == -1)
		return -1;

	switch (opcode) {
	case DW_LNE_end_sequence:
		state->end_sequence = true;
		if (append_row(matrix, state) == -1)
			return -1;
		init_state(lnp, state);
		return 0;
	case DW_LNE_set_address:
		if (length == 9) {
			if (read_u64(buffer, offset, &state->address) == -1)
				return -1;
		} else if (length == 5) {
			uint32_t address;

			if (read_u32(buffer, offset, &address) == -1)
				return -1;
			state->address = address;
		} else {
			PyErr_Format(PyExc_ValueError, "unsupported address size %llu",
				     (unsigned long long)(length - 1));
			return -1;
		}
		state->op_index = 0;
		return 0;
	case DW_LNE_define_file:
		PyErr_Format(PyExc_NotImplementedError, "DW_LNE_define_file is not implemented");
		*offset = end;
		return -1;
	case DW_LNE_set_discriminator:
		return read_uleb128(buffer, offset, &state->discriminator);
	default:
		PyErr_Format(PyExc_ValueError, "unknown extended opcode %u",
			     (unsigned int)opcode);
		return -1;
	}
}

static void advance_pc(LineNumberProgramHeader *lnp, LineNumberRow *state,
		       uint64_t operation_advance)
{
	state->address += (lnp->minimum_instruction_length *
			   ((state->op_index + operation_advance) /
			    lnp->maximum_operations_per_instruction));
	state->op_index = ((state->op_index + operation_advance) %
			   lnp->maximum_operations_per_instruction);
}

static int execute_standard_opcode(LineNumberProgramHeader *lnp,
				   LineNumberRow *state, PyObject *matrix,
				   uint8_t opcode, Py_buffer *buffer,
				   Py_ssize_t *offset)
{
	uint64_t arg;
	int64_t sarg;
	uint16_t u16;

	switch (opcode) {
	case DW_LNS_copy:
		if (append_row(matrix, state) == -1)
			return -1;
		reset_state(state);
		return 0;
	case DW_LNS_advance_pc:
		if (read_uleb128(buffer, offset, &arg) == -1)
			return -1;
		advance_pc(lnp, state, arg);
		return 0;
	case DW_LNS_advance_line:
		if (read_sleb128(buffer, offset, &sarg) == -1)
			return -1;
		state->line += sarg;
		return 0;
	case DW_LNS_set_file:
		return read_uleb128(buffer, offset, &state->file);
	case DW_LNS_set_column:
		return read_uleb128(buffer, offset, &state->column);
	case DW_LNS_negate_stmt:
		state->is_stmt = !state->is_stmt;
		return 0;
	case DW_LNS_set_basic_block:
		state->basic_block = true;
		return 0;
	case DW_LNS_const_add_pc:
		advance_pc(lnp, state,
			   (255 - lnp->opcode_base) / lnp->line_range);
		return 0;
	case DW_LNS_fixed_advance_pc:
		if (read_u16(buffer, offset, &u16) == -1)
			return -1;
		state->address += u16;
		state->op_index = 0;
		return 0;
	case DW_LNS_set_prologue_end:
		state->prologue_end = true;
		return 0;
	case DW_LNS_set_epilogue_begin:
		state->epilogue_begin = true;
		return 0;
	case DW_LNS_set_isa:
		return read_uleb128(buffer, offset, &state->isa);
	default:
		PyErr_Format(PyExc_ValueError, "unknown standard opcode %u",
			     (unsigned int)opcode);
		return -1;
	}
}

static int execute_special_opcode(LineNumberProgramHeader *lnp,
				  LineNumberRow *state, PyObject *matrix,
				  uint8_t opcode)
{
	uint8_t adjusted_opcode = opcode - lnp->opcode_base;
	uint8_t operation_advance = adjusted_opcode / lnp->line_range;

	advance_pc(lnp, state, operation_advance);
	state->line += lnp->line_base + (adjusted_opcode % lnp->line_range);
	if (append_row(matrix, state) == -1)
		return -1;
	reset_state(state);
	return 0;
}

static int execute_opcode(LineNumberProgramHeader *lnp, LineNumberRow *state,
			  PyObject *matrix, uint8_t opcode, Py_buffer *buffer,
			  Py_ssize_t *offset)
{
	if (opcode == 0) {
		return execute_extended_opcode(lnp, state, matrix, buffer, offset);
	} else if (opcode < lnp->opcode_base) {
		return execute_standard_opcode(lnp, state, matrix, opcode,
					       buffer, offset);
	} else {
		return execute_special_opcode(lnp, state, matrix, opcode);
	}
}

PyObject *LLDwarf_ExecuteLineNumberProgram(LineNumberProgramHeader *lnp,
					   Py_buffer *buffer,
					   Py_ssize_t *offset)
{
	LineNumberRow state = {};
	Py_ssize_t end_offset;
	PyObject *matrix;

	if (lnp->line_range == 0) {
		PyErr_SetString(PyExc_ValueError, "line_range is 0");
		return NULL;
	}

	init_state(lnp, &state);

	end_offset = lnp_end_offset(lnp);
	if (end_offset == -1)
		return NULL;

	matrix = PyList_New(0);
	if (!matrix)
		return NULL;

	while (*offset < end_offset) {
		uint8_t opcode;

		if (read_u8(buffer, offset, &opcode))
			goto err;

		if (execute_opcode(lnp, &state, matrix, opcode, buffer, offset) == -1)
			goto err;
	}

	return matrix;

err:
	Py_DECREF(matrix);
	return NULL;
}

PyMemberDef LineNumberRow_members[] = {
	{"address", T_UINT64T, offsetof(LineNumberRow, address), 0,
	 "the program counter value of this instruction"},
	{"op_index", T_UINT8T, offsetof(LineNumberRow, op_index), 0,
	 "index of an operation within a VLIW instruction"},
	{"file", T_UINT64T, offsetof(LineNumberRow, file), 0,
	 "source file as an index into file_names list"},
	{"line", T_UINT64T, offsetof(LineNumberRow, line), 0,
	 "source line number, or 0 if the instruction cannot be attributed\n"
	 "to a source line"},
	{"column", T_UINT64T, offsetof(LineNumberRow, column), 0,
	 "column number within a source line, or 0 for the left edge"},
	{"is_stmt", T_BOOL, offsetof(LineNumberRow, is_stmt), 0,
	 "whether the instruction represents a line or statement and thus\n"
	 "is a recommended breakpoint location"},
	{"basic_block", T_BOOL, offsetof(LineNumberRow, basic_block), 0,
	 "whether the instruction is the beginning of a basic block"},
	{"end_sequence", T_BOOL, offsetof(LineNumberRow, end_sequence), 0,
	 "whether this instruction address is the first byte after the\n"
	 "end of a sequence of instructions; if this is true, only the\n"
	 "address is meaningful"},
	{"prologue_end", T_BOOL, offsetof(LineNumberRow, prologue_end), 0,
	 "whether this instruction is a recommended function entry\n"
	 "breakpoint location"},
	{"epilogue_begin", T_BOOL, offsetof(LineNumberRow, epilogue_begin), 0,
	 "whether this instruction is a recommended function exit\n"
	 "breakpoint location"},
	{"isa", T_UINT64T, offsetof(LineNumberRow, isa), 0,
	 "the instruction set architecture of the current instruction"},
	{"discriminator", T_UINT64T, offsetof(LineNumberRow, discriminator), 0,
	 "arbitrary identifier of the block to which the instruction\n"
	 "belongs, or 0 if only one block exists for the given source position"},
	{},
};

#define LineNumberRow_DOC						\
	"LineNumberRow(address, op_index, file, line, column,\n"	\
	"              is_stmt, basic_block, end_sequence,\n"		\
	"              prologue_end, epilogue_begin, isa,\n"		\
	"              discriminator) -> new line number matrix row\n\n"	\
	"Create a new DWARF line number matrix row.\n\n"		\
	"Arguments:\n"							\
	"address -- integer address\n"					\
	"op_index -- integer index\n"					\
	"file -- integer file index\n"					\
	"line -- integer line number\n"					\
	"column -- integer column number\n"				\
	"is_stmt -- boolean\n"						\
	"basic_block -- boolean\n"					\
	"end_sequence -- boolean\n"					\
	"prologue_end -- boolean\n"					\
	"epilogue_begin -- boolean"

PyTypeObject LineNumberRow_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"dwarfbh.LineNumberRow",	/* tp_name */
	sizeof(LineNumberRow),		/* tp_basicsize */
	0,				/* tp_itemsize */
	LineNumberRow_dealloc,		/* tp_dealloc */
	NULL,				/* tp_print */
	NULL,				/* tp_getattr */
	NULL,				/* tp_setattr */
	NULL,				/* tp_as_async */
	LLDwarfObject_repr,		/* tp_repr */
	NULL,				/* tp_as_number */
	NULL,				/* tp_as_sequence */
	NULL,				/* tp_as_mapping */
	NULL,				/* tp_hash  */
	NULL,				/* tp_call */
	NULL,				/* tp_str */
	NULL,				/* tp_getattro */
	NULL,				/* tp_setattro */
	NULL,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,		/* tp_flags */
	LineNumberRow_DOC,		/* tp_doc */
	NULL,				/* tp_traverse */
	NULL,				/* tp_clear */
	LLDwarfObject_richcompare,	/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	NULL,				/* tp_iter */
	NULL,				/* tp_iternext */
	NULL,				/* tp_methods */
	LineNumberRow_members,		/* tp_members */
	NULL,				/* tp_getset */
	NULL,				/* tp_base */
	NULL,				/* tp_dict */
	NULL,				/* tp_descr_get */
	NULL,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	LLDwarfObject_init,		/* tp_init */
};
