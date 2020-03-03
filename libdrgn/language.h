// Copyright 2018-2020 - Omar Sandoval
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
#include <dwarf.h>

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

typedef struct drgn_error *drgn_format_type_fn(struct drgn_qualified_type,
					       char **);
typedef struct drgn_error *drgn_format_object_fn(const struct drgn_object *,
						 size_t,
						 enum drgn_format_object_flags,
						 char **);
typedef struct drgn_error *drgn_find_type_fn(struct drgn_type_index *tindex,
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
	/** Void type for this language. See @ref drgn_void_type(). */
	struct drgn_type void_type;
	/** Implement @ref drgn_format_type_name(). */
	drgn_format_type_fn *format_type_name;
	/** Implement @ref drgn_format_type(). */
	drgn_format_type_fn *format_type;
	/** Implement @ref drgn_format_object(). */
	drgn_format_object_fn *format_object;
	/**
	 * Implement @ref drgn_type_index_find().
	 *
	 * This should parse @p name and call @ref
	 * drgn_type_index_find_parsed().
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

drgn_format_type_fn c_format_type_name;
drgn_format_type_fn c_format_type;
drgn_format_object_fn c_format_object;
drgn_find_type_fn c_find_type;
drgn_bit_offset_fn c_bit_offset;
drgn_integer_literal_fn c_integer_literal;
drgn_bool_literal_fn c_bool_literal;
drgn_float_literal_fn c_float_literal;
drgn_cast_op c_op_cast;
drgn_bool_op c_op_bool;
drgn_cmp_op c_op_cmp;
drgn_binary_op c_op_add;
drgn_binary_op c_op_sub;
drgn_binary_op c_op_mul;
drgn_binary_op c_op_div;
drgn_binary_op c_op_mod;
drgn_binary_op c_op_lshift;
drgn_binary_op c_op_rshift;
drgn_binary_op c_op_and;
drgn_binary_op c_op_or;
drgn_binary_op c_op_xor;
drgn_unary_op c_op_pos;
drgn_unary_op c_op_neg;
drgn_unary_op c_op_not;

enum {
	DRGN_LANGUAGE_C,
	DRGN_LANGUAGE_CPP,
	DRGN_NUM_LANGUAGES,
};

extern const struct drgn_language drgn_languages[DRGN_NUM_LANGUAGES];

#define drgn_language_cpp drgn_languages[DRGN_LANGUAGE_CPP]
#define drgn_language_c drgn_languages[DRGN_LANGUAGE_C]

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

/**
 * Return the given @ref drgn_language if it is non-@c NULL or the default if it
 * is @c NULL.
 */
static inline const struct drgn_language *
drgn_language_or_default(const struct drgn_language *lang)
{
	return lang ? lang : &drgn_language_c;
}

/**
 * Return the @ref drgn_language of the CU of the given DIE.
 *
 * @param[out] ret Returned language. May be returned as @c NULL if the language
 * is unknown.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_language_from_die(Dwarf_Die *die,
					  const struct drgn_language **ret);

/** @} */

#endif /* DRGN_LANGUAGE_H */
