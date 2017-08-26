#ifndef LLDWARF_H
#define LLDWARF_H

#define PY_SSIZE_T_CLEAN

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <Python.h>
#include "structmember.h"

struct AttribSpec {
	uint64_t name;
	uint64_t form;
};

typedef struct {
	PyObject_VAR_HEAD
	uint64_t tag;
	bool children;
	struct AttribSpec attribs[];
} AbbrevDecl;

extern PyTypeObject AbbrevDecl_type;

typedef struct {
	PyObject_VAR_HEAD
	uint64_t segment;
	uint64_t address;
	uint64_t length;
} AddressRange;

extern PyTypeObject AddressRange_type;

typedef struct {
	PyObject_VAR_HEAD
	Py_ssize_t offset;
	uint64_t unit_length;
	uint16_t version;
	uint64_t debug_info_offset;
	uint8_t address_size;
	uint8_t segment_size;
	bool is_64_bit;
} ArangeTableHeader;

extern PyTypeObject ArangeTableHeader_type;

typedef struct {
	PyObject_HEAD
	Py_ssize_t offset;
	uint64_t unit_length;
	uint16_t version;
	uint64_t debug_abbrev_offset;
	uint8_t address_size;
	bool is_64_bit;
} CompilationUnitHeader;

extern PyTypeObject CompilationUnitHeader_type;

struct DwarfAttrib {
	uint64_t name;
	uint64_t form;
	union {
		/*
		 * DW_FORM_addr, DW_FORM_udata, DW_FORM_flag{,_present},
		 * DW_FORM_sec_offset, DW_FORM_ref{1,2,4,8,_sig8,_udata}, and
		 * DW_FORM_strp. For DW_FORM_flag_present, always 1.
		 */
		uint64_t u;

		/* DW_FORM_sdata. */
		int64_t s;

		/* DW_FORM_data{1,2,4,8} */
		char data[8];

		/*
		 * DW_FORM_block{,1,2,4}, DW_FORM_exprloc, and DW_FORM_string.
		 * Offset from the beginning of the buffer that the DIE was
		 * parsed from.
		 */
		struct {
			Py_ssize_t offset;
			Py_ssize_t length;
		};
	};
};

typedef struct {
	PyObject_VAR_HEAD
	Py_ssize_t offset;
	Py_ssize_t die_length;
	uint64_t tag;
	PyObject *children;
	struct DwarfAttrib attribs[];
} DwarfDie;

extern PyTypeObject DwarfDie_type;

typedef struct {
	PyObject_HEAD
	Py_ssize_t offset;
	uint64_t unit_length;
	uint16_t version;
	uint64_t header_length;
	uint8_t minimum_instruction_length;
	uint8_t maximum_operations_per_instruction;
	bool default_is_stmt;
	int8_t line_base;
	uint8_t line_range;
	uint8_t opcode_base;
	PyObject *standard_opcode_lengths;
	PyObject *include_directories;
	PyObject *file_names;
	bool is_64_bit;
} LineNumberProgramHeader;

extern PyTypeObject LineNumberProgramHeader_type;

typedef struct {
	PyObject_HEAD
	uint64_t address;
	uint64_t file;
	uint64_t line;
	uint64_t column;
	uint64_t isa;
	uint64_t discriminator;
	uint8_t op_index;
	bool is_stmt;
	bool basic_block;
	bool end_sequence;
	bool prologue_end;
	bool epilogue_begin;
} LineNumberRow;

extern PyTypeObject LineNumberRow_type;

#ifdef TEST_LLDWARFOBJECT
extern PyTypeObject TestObject_type;
#endif

int LLDwarfObject_init(PyObject *self, PyObject *args, PyObject *kwds);
PyObject *LLDwarfObject_repr(PyObject *self);
int LLDwarfObject_RichCompareBool(PyObject *self, PyObject *other, int op);
PyObject *LLDwarfObject_richcompare(PyObject *self, PyObject *other, int op);

PyObject *LLDwarf_ParseAbbrevTable(Py_buffer *buffer, Py_ssize_t *offset);
PyObject *LLDwarf_ParseArangeTable(Py_buffer *buffer, Py_ssize_t *offset,
				   Py_ssize_t segment_size,
				   Py_ssize_t address_size);
PyObject *LLDwarf_ParseArangeTableHeader(Py_buffer *buffer, Py_ssize_t *offset);
PyObject *LLDwarf_ParseCompilationUnitHeader(Py_buffer *buffer,
					     Py_ssize_t *offset);
PyObject *LLDwarf_ParseDie(Py_buffer *buffer, Py_ssize_t *offset,
			   CompilationUnitHeader *cu, PyObject *abbrev_table,
			   bool recurse, bool jump_to_sibling);
PyObject *LLDwarf_ParseDieSiblings(Py_buffer *buffer, Py_ssize_t *offset,
				   CompilationUnitHeader *cu,
				   PyObject *abbrev_table, bool recurse);
PyObject *LLDwarf_ParseLineNumberProgramHeader(Py_buffer *buffer,
					       Py_ssize_t *offset);
PyObject *LLDwarf_ExecuteLineNumberProgram(LineNumberProgramHeader *lnp,
					   Py_buffer *buffer,
					   Py_ssize_t *offset);

int read_uleb128(Py_buffer *buffer, Py_ssize_t *offset, uint64_t *ret);
int read_sleb128(Py_buffer *buffer, Py_ssize_t *offset, int64_t *ret);

int read_strlen(Py_buffer *buffer, Py_ssize_t *offset, Py_ssize_t *len);

static inline int read_check_bounds(Py_buffer *buffer, Py_ssize_t offset,
				    Py_ssize_t size)
{
	if (buffer->len < size || offset > buffer->len - size) {
		PyErr_SetString(PyExc_EOFError, "");
		return -1;
	}

	return 0;
}

static inline int read_buffer(Py_buffer *buffer, Py_ssize_t *offset,
			      void *ret, Py_ssize_t size)
{
	if (read_check_bounds(buffer, *offset, size))
		return -1;

	memcpy(ret, (char *)buffer->buf + *offset, size);
	*offset += size;
	return 0;
}

#define read_type(name, type)						\
static inline int read_##name(Py_buffer *buffer, Py_ssize_t *offset,	\
			      type *ret)				\
{									\
	return read_buffer(buffer, offset, ret, sizeof(*ret));		\
}

read_type(u8, uint8_t)
read_type(u16, uint16_t)
read_type(u32, uint32_t)
read_type(u64, uint64_t)

read_type(s8, int8_t)
read_type(s16, int16_t)
read_type(s32, int32_t)
read_type(s64, int64_t)

static inline char PyLong_AsChar(PyObject *pylong)
{
	long ret;

	ret = PyLong_AsLong(pylong);
	if (PyErr_Occurred())
		return ret;

	if (ret < CHAR_MIN || ret > CHAR_MAX)
		PyErr_SetString(PyExc_OverflowError, "int too big to convert");

	return ret;
}

static inline unsigned char PyLong_AsUnsignedChar(PyObject *pylong)
{
	unsigned long ret;

	ret = PyLong_AsUnsignedLong(pylong);
	if (PyErr_Occurred())
		return ret;

	if (ret > UCHAR_MAX)
		PyErr_SetString(PyExc_OverflowError, "int too big to convert");

	return ret;
}

static inline short PyLong_AsShort(PyObject *pylong)
{
	long ret;

	ret = PyLong_AsLong(pylong);
	if (PyErr_Occurred())
		return ret;

	if (ret < SHRT_MIN || ret > SHRT_MAX)
		PyErr_SetString(PyExc_OverflowError, "int too big to convert");

	return ret;
}

static inline unsigned short PyLong_AsUnsignedShort(PyObject *pylong)
{
	unsigned long ret;

	ret = PyLong_AsUnsignedLong(pylong);
	if (PyErr_Occurred())
		return ret;

	if (ret > USHRT_MAX)
		PyErr_SetString(PyExc_OverflowError, "int too big to convert");

	return ret;
}

static inline int PyLong_AsInt(PyObject *pylong)
{
	long ret;

	ret = PyLong_AsLong(pylong);
	if (PyErr_Occurred())
		return ret;

	if (ret < INT_MIN || ret > INT_MAX)
		PyErr_SetString(PyExc_OverflowError, "int too big to convert");

	return ret;
}

static inline unsigned int PyLong_AsUnsignedInt(PyObject *pylong)
{
	unsigned long ret;

	ret = PyLong_AsUnsignedLong(pylong);
	if (PyErr_Occurred())
		return ret;

	if (ret > UINT_MAX)
		PyErr_SetString(PyExc_OverflowError, "int too big to convert");

	return ret;
}

/* The T_* Python constants haven't caught up to stdint.h */
#define T_INT8T T_BYTE
#define T_UINT8T T_UBYTE
#define T_UINT16T T_USHORT
#define T_UINT32T T_UINT
#define T_UINT64T T_ULONGLONG

static inline uint8_t PyLong_AsUint8_t(PyObject *pylong)
{
	unsigned long ret;

	ret = PyLong_AsUnsignedLong(pylong);
	if (PyErr_Occurred())
		return ret;

	if (ret > UINT8_MAX)
		PyErr_SetString(PyExc_OverflowError, "int too big to convert");

	return ret;
}

static inline int8_t PyLong_AsInt8_t(PyObject *pylong)
{
	long ret;

	ret = PyLong_AsLong(pylong);
	if (PyErr_Occurred())
		return ret;

	if (ret < INT8_MIN || ret > INT8_MAX)
		PyErr_SetString(PyExc_OverflowError, "int too big to convert");

	return ret;
}

static inline uint16_t PyLong_AsUint16_t(PyObject *pylong)
{
	unsigned long ret;

	ret = PyLong_AsUnsignedLong(pylong);
	if (PyErr_Occurred())
		return ret;

	if (ret > UINT16_MAX)
		PyErr_SetString(PyExc_OverflowError, "int too big to convert");

	return ret;
}

static inline uint64_t PyLong_AsUint64_t(PyObject *pylong)
{
	return PyLong_AsUnsignedLongLong(pylong);
}

static inline int64_t PyLong_AsInt64_t(PyObject *pylong)
{
	return PyLong_AsLongLong(pylong);
}

#endif /* LLDWARF_H */
