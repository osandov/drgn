// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

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
 * @defgroup LanguageInternals Languages
 *
 * Language support.
 *
 * This defines the interface which support for a language must implement,
 * including operators and parsing.
 *
 * To add a new language:
 * - Add a @ref drgn_language_number for it.
 * - Define a @ref drgn_language for it, and set @ref drgn_language::number to
 *   the corresponding @ref drgn_language_number.
 * - Add it to drgn.h.
 * - Add it to @ref drgn_languages.
 * - Add it to add_languages() in the Python bindings.
 * - Add it to _drgn.pyi.
 * @{
 */

/**
 * Language numbers.
 *
 * These can be used as indices for storing language-specific data in an array.
 */
enum drgn_language_number {
	DRGN_LANGUAGE_C,
	DRGN_LANGUAGE_CPP,
	DRGN_NUM_LANGUAGES,
};

typedef struct drgn_error *drgn_format_type_fn(struct drgn_qualified_type,
					       char **);
typedef struct drgn_error *drgn_format_object_fn(const struct drgn_object *,
						 size_t,
						 enum drgn_format_object_flags,
						 char **);
typedef struct drgn_error *drgn_find_type_fn(const struct drgn_language *lang,
					     struct drgn_program *prog,
					     const char *name,
					     const char *filename,
					     struct drgn_qualified_type *ret);
typedef struct drgn_error *drgn_bit_offset_fn(struct drgn_program *prog,
					      struct drgn_type *type,
					      const char *member_designator,
					      uint64_t *ret);
typedef struct drgn_error *drgn_integer_literal_fn(struct drgn_object *res,
						   uint64_t uvalue);
typedef struct drgn_error *drgn_bool_literal_fn(struct drgn_object *res,
						bool bvalue);
typedef struct drgn_error *drgn_float_literal_fn(struct drgn_object *res,
						 double fvalue);
typedef struct drgn_error *
drgn_cast_op(struct drgn_object *res, struct drgn_qualified_type qualified_type,
	     const struct drgn_object *obj);
typedef struct drgn_error *drgn_bool_op(const struct drgn_object *obj, bool *ret);
typedef struct drgn_error *drgn_cmp_op(const struct drgn_object *lhs,
				       const struct drgn_object *rhs, int *ret);

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
	/** Number of this programming language. */
	enum drgn_language_number number;
	/** Implement @ref drgn_format_type_name(). */
	drgn_format_type_fn *format_type_name;
	/** Implement @ref drgn_format_type(). */
	drgn_format_type_fn *format_type;
	/** Implement @ref drgn_format_object(). */
	drgn_format_object_fn *format_object;
	/**
	 * Implement @ref drgn_program_find_type().
	 *
	 * This should parse @p name and call @ref
	 * drgn_program_find_type_impl().
	 */
	drgn_find_type_fn *find_type;
	/**
	 * Get the offset of a member in a type.
	 *
	 * This should parse @p member_designator (which may include one or more
	 * member references and zero or more array subscripts) and calculate
	 * the offset, in bits, of that member from the beginning of @p type.
	 */
	drgn_bit_offset_fn *bit_offset;
	/**
	 * Set an object to an integer literal.
	 *
	 * This should set @p res to the given value and appropriate type for an
	 * integer literal in the language.
	 */
	drgn_integer_literal_fn *integer_literal;
	/**
	 * Set an object to a boolean literal.
	 *
	 * This should set @p res to the given value and the boolean type in the
	 * language.
	 */
	drgn_bool_literal_fn *bool_literal;
	/**
	 * Set an object to a floating-point literal.
	 *
	 * This should set @p res to the given value and appropriate type for a
	 * floating-point literal in the language.
	 */
	drgn_float_literal_fn *float_literal;
	drgn_cast_op *op_cast;
	drgn_bool_op *op_bool;
	drgn_cmp_op *op_cmp;
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

/** Mapping from @ref drgn_language_number to @ref drgn_language. */
extern const struct drgn_language * const drgn_languages[];

/** Language to be used when actual language is unknown. */
#define drgn_default_language drgn_language_c

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
