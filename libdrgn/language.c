// Copyright 2020 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include "internal.h"
#include "language.h"

const struct drgn_language drgn_languages[] = {
	[DRGN_LANGUAGE_C] = {
		.name = "C",
		.void_type = {
			{
				.kind = DRGN_TYPE_VOID,
				.primitive = DRGN_C_TYPE_VOID,
				.language = &drgn_language_c,
			},
		},
		.format_type_name = c_format_type_name,
		.format_type = c_format_type,
		.format_object = c_format_object,
		.find_type = c_find_type,
		.bit_offset = c_bit_offset,
		.integer_literal = c_integer_literal,
		.bool_literal = c_bool_literal,
		.float_literal = c_float_literal,
		.op_cast = c_op_cast,
		.op_bool = c_op_bool,
		.op_cmp = c_op_cmp,
		.op_add = c_op_add,
		.op_sub = c_op_sub,
		.op_mul = c_op_mul,
		.op_div = c_op_div,
		.op_mod = c_op_mod,
		.op_lshift = c_op_lshift,
		.op_rshift = c_op_rshift,
		.op_and = c_op_and,
		.op_or = c_op_or,
		.op_xor = c_op_xor,
		.op_pos = c_op_pos,
		.op_neg = c_op_neg,
		.op_not = c_op_not,
	},
	[DRGN_LANGUAGE_CPP] = {
		.name = "C++",
		.void_type = {
			{
				.kind = DRGN_TYPE_VOID,
				.primitive = DRGN_C_TYPE_VOID,
				.language = &drgn_language_cpp,
			},
		},
		.format_type_name = c_format_type_name,
		.format_type = c_format_type,
		.format_object = c_format_object,
		.find_type = c_find_type,
		.bit_offset = c_bit_offset,
		.integer_literal = c_integer_literal,
		.bool_literal = c_bool_literal,
		.float_literal = c_float_literal,
		.op_cast = c_op_cast,
		.op_bool = c_op_bool,
		.op_cmp = c_op_cmp,
		.op_add = c_op_add,
		.op_sub = c_op_sub,
		.op_mul = c_op_mul,
		.op_div = c_op_div,
		.op_mod = c_op_mod,
		.op_lshift = c_op_lshift,
		.op_rshift = c_op_rshift,
		.op_and = c_op_and,
		.op_or = c_op_or,
		.op_xor = c_op_xor,
		.op_pos = c_op_pos,
		.op_neg = c_op_neg,
		.op_not = c_op_not,
	},
};

struct drgn_error *drgn_language_from_die(Dwarf_Die *die,
					  const struct drgn_language **ret)
{
	Dwarf_Die cudie;

	if (dwarf_cu_info(die->cu, NULL, NULL, &cudie, NULL, NULL, NULL, NULL))
		return drgn_error_libdw();
	switch (dwarf_srclang(&cudie)) {
	case DW_LANG_C:
	case DW_LANG_C89:
	case DW_LANG_C99:
	case DW_LANG_C11:
		*ret = &drgn_language_c;
		break;
	case DW_LANG_C_plus_plus:
	case DW_LANG_C_plus_plus_03:
	case DW_LANG_C_plus_plus_11:
	case DW_LANG_C_plus_plus_14:
		*ret = &drgn_language_cpp;
		break;
	default:
		*ret = NULL;
		break;
	}
	return NULL;
}
