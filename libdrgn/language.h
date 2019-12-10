// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * Language support.
 *
 * See @ref Languages.
 */

#ifndef DRGN_LANGUAGE_H
#define DRGN_LANGUAGE_H

#include "drgn.h"

/**
 * @ingroup Internals
 *
 * @defgroup Languages Languages
 *
 * Language support.
 *
 * This defines the interface which support for a language must implement,
 * including operators and parsing.
 *
 * @{
 */

struct drgn_type_index;

/**
 * Language implementation.
 *
 * This mainly provides callbacks used to implement the higher-level libdrgn
 * helpers. These callbacks handle the language-specific parts of the helpers.
 *
 * In particular, the operator callbacks should do appropriate type checking for
 * the language and call the implementation in @ref ObjectInternals.
 */
struct drgn_language {
	/** Name of this programming language. */
	const char *name;
	/** Implement @ref drgn_format_type_name(). */
	struct drgn_error *(*format_type_name)(struct drgn_qualified_type,
					       char **);
	/** Implement @ref drgn_format_type(). */
	struct drgn_error *(*format_type)(struct drgn_qualified_type, char **);
	/** Implement @ref drgn_format_object(). */
	struct drgn_error *(*format_object)(const struct drgn_object *, size_t,
					    enum drgn_format_object_flags,
					    char **);
	/**
	 * Implement @ref drgn_type_index_find().
	 *
	 * This should parse @p name and call @ref
	 * drgn_type_index_find_parsed().
	 */
	struct drgn_error *(*find_type)(struct drgn_type_index *tindex,
					const char *name, const char *filename,
					struct drgn_qualified_type *ret);
	/**
	 * Get the offset of a member in a type.
	 *
	 * This should parse @p member_designator (which may include one or more
	 * member references and zero or more array subscripts) and calculate
	 * the offset, in bits, of that member from the beginning of @p type.
	 */
	struct drgn_error *(*bit_offset)(struct drgn_program *prog,
					 struct drgn_type *type,
					 const char *member_designator,
					 uint64_t *ret);
	/**
	 * Set an object to an integer literal.
	 *
	 * This should set @p res to the given value and appropriate type for an
	 * integer literal in the language.
	 */
	struct drgn_error *(*integer_literal)(struct drgn_object *res,
					      uint64_t uvalue);
	/**
	 * Set an object to a boolean literal.
	 *
	 * This should set @p res to the given value and the boolean type in the
	 * language.
	 */
	struct drgn_error *(*bool_literal)(struct drgn_object *res,
					   bool bvalue);
	/**
	 * Set an object to a floating-point literal.
	 *
	 * This should set @p res to the given value and appropriate type for a
	 * floating-point literal in the language.
	 */
	struct drgn_error *(*float_literal)(struct drgn_object *res,
					    double fvalue);
	/** Implement @ref drgn_object_cast(). */
	struct drgn_error *(*op_cast)(struct drgn_object *res,
				      struct drgn_qualified_type qualified_type,
				      const struct drgn_object *obj);
	struct drgn_error *(*op_bool)(const struct drgn_object *obj, bool *ret);
	struct drgn_error *(*op_cmp)(const struct drgn_object *lhs,
				     const struct drgn_object *rhs, int *ret);
	drgn_binary_op *op_add;
	drgn_binary_op *op_sub;
	drgn_binary_op *op_mul;
	drgn_binary_op *op_div;
	drgn_binary_op *op_mod;
	drgn_binary_op *op_lshift;
	drgn_binary_op *op_rshift;
	drgn_binary_op *op_and;
	drgn_binary_op *op_or;
	drgn_binary_op *op_xor;
	drgn_unary_op *op_pos;
	drgn_unary_op *op_neg;
	drgn_unary_op *op_not;
};

/** The C programming language. */
extern const struct drgn_language drgn_language_c;

/**
 * Return flags that should be passed through when formatting an object
 * recursively.
 */
static inline enum drgn_format_object_flags
drgn_passthrough_format_object_flags(enum drgn_format_object_flags flags)
{
	return (flags & (DRGN_FORMAT_OBJECT_SYMBOLIZE |
			 DRGN_FORMAT_OBJECT_STRING |
			 DRGN_FORMAT_OBJECT_CHAR |
			 DRGN_FORMAT_OBJECT_MEMBER_TYPE_NAMES |
			 DRGN_FORMAT_OBJECT_ELEMENT_TYPE_NAMES |
			 DRGN_FORMAT_OBJECT_MEMBERS_SAME_LINE |
			 DRGN_FORMAT_OBJECT_ELEMENTS_SAME_LINE |
			 DRGN_FORMAT_OBJECT_MEMBER_NAMES |
			 DRGN_FORMAT_OBJECT_ELEMENT_INDICES |
			 DRGN_FORMAT_OBJECT_IMPLICIT_MEMBERS |
			 DRGN_FORMAT_OBJECT_IMPLICIT_ELEMENTS));
}

/** Return flags that should be passed when formatting object members. */
static inline enum drgn_format_object_flags
drgn_member_format_object_flags(enum drgn_format_object_flags flags)
{
	return (drgn_passthrough_format_object_flags(flags) |
		(flags & DRGN_FORMAT_OBJECT_MEMBER_TYPE_NAMES) >> 1);
}

/** Return flags that should be passed when formatting object elements. */
static inline enum drgn_format_object_flags
drgn_element_format_object_flags(enum drgn_format_object_flags flags)
{
	return (drgn_passthrough_format_object_flags(flags) |
		(flags & DRGN_FORMAT_OBJECT_ELEMENT_TYPE_NAMES) >> 2);
}

/** @} */

#endif /* DRGN_LANGUAGE_H */
