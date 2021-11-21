// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file
 *
 * Object internals.
 *
 * See @ref ObjectInternals.
 */

#ifndef DRGN_OBJECT_H
#define DRGN_OBJECT_H

#include <stdlib.h>
#include <string.h>

#include "drgn.h"
#include "type.h"

/**
 * @ingroup Internals
 *
 * @defgroup ObjectInternals Objects
 *
 * Object internals.
 *
 * This provides the language-agnostic part of operator implementations. The
 * operators have defined behavior for various cases where C is undefined or
 * implementation-defined (e.g., signed arithmetic is modular, signed bitwise
 * operators operate on the two's complement representation, right shifts are
 * arithmetic).
 *
 * @{
 */

/** Allocate a zero-initialized @ref drgn_value. */
static inline bool drgn_value_zalloc(uint64_t size, union drgn_value *value_ret,
				     char **buf_ret)
{
	if (size <= sizeof(value_ret->ibuf)) {
		memset(value_ret->ibuf, 0, sizeof(value_ret->ibuf));
		*buf_ret = value_ret->ibuf;
	} else {
		if (size > SIZE_MAX)
			return false;
		char *buf = calloc(1, size);
		if (!buf)
			return false;
		value_ret->bufp = *buf_ret = buf;
	}
	return true;
}

/**
 * Get whether an object is zero.
 *
 * For scalars, this is true iff its value is zero. For structures, unions, and
 * classes, this is true iff all of its members are zero. For arrays, this is
 * true iff all of its elements are zero. Note that this ignores padding.
 */
struct drgn_error *drgn_object_is_zero(const struct drgn_object *obj,
				       bool *ret);

/** Type-related fields from @ref drgn_object. */
struct drgn_object_type {
	struct drgn_type *type;
	/* Cached underlying type of @c type. */
	struct drgn_type *underlying_type;
	uint64_t bit_size;
	enum drgn_qualifiers qualifiers;
	enum drgn_object_encoding encoding;
	bool is_bit_field;
	bool little_endian;
};

/** Convert a @ref drgn_object_type to a @ref drgn_qualified_type. */
static inline struct drgn_qualified_type
drgn_object_type_qualified(const struct drgn_object_type *type)
{
	return (struct drgn_qualified_type){
		.type = type->type,
		.qualifiers = type->qualifiers,
	};
}

/**
 * Type of an operand or operator result.
 *
 * This is basically @ref drgn_qualified_type plus a bit field size and cached
 * underlying type.
 */
struct drgn_operand_type {
	struct drgn_type *type;
	enum drgn_qualifiers qualifiers;
	struct drgn_type *underlying_type;
	uint64_t bit_field_size;
};

/** Get the @ref drgn_operand_type of a @ref drgn_object. */
static inline struct drgn_operand_type
drgn_object_operand_type(const struct drgn_object *obj)
{
	return (struct drgn_operand_type){
		.type = obj->type,
		.qualifiers = obj->qualifiers,
		.underlying_type = drgn_underlying_type(obj->type),
		.bit_field_size = obj->is_bit_field ? obj->bit_size : 0,
	};
}

/**
 * Deinitialize the value of a @ref drgn_object and reinitialize the kind and
 * type fields.
 */
static inline void drgn_object_reinit(struct drgn_object *obj,
				      const struct drgn_object_type *type,
				      enum drgn_object_kind kind)
{
	drgn_object_deinit(obj);
	obj->type = type->type;
	obj->qualifiers = type->qualifiers;
	obj->bit_size = type->bit_size;
	obj->encoding = type->encoding;
	obj->is_bit_field = type->is_bit_field;
	obj->little_endian = type->little_endian;
	obj->kind = kind;
}

/**
 * Compute the type-related fields of a @ref drgn_object from a @ref
 * drgn_qualified_type and a bit field size.
 */
struct drgn_error *
drgn_object_type(struct drgn_qualified_type qualified_type,
		 uint64_t bit_field_size, struct drgn_object_type *ret);

/**
 * Like @ref drgn_object_set_signed() but @ref drgn_object_type() was already
 * called and the type is already known to be a signed integer type.
 */
void drgn_object_set_signed_internal(struct drgn_object *res,
				     const struct drgn_object_type *type,
				     int64_t svalue);

/**
 * Like @ref drgn_object_set_unsigned() but @ref drgn_object_type() was already
 * called and the type is already known to be an unsigned integer type.
 */
void drgn_object_set_unsigned_internal(struct drgn_object *res,
				       const struct drgn_object_type *type,
				       uint64_t uvalue);

/**
 * Like @ref drgn_object_set_from_buffer() but @ref drgn_object_type() was
 * already called and the bounds of the buffer have already been checked.
 */
struct drgn_error *
drgn_object_set_from_buffer_internal(struct drgn_object *res,
				     const struct drgn_object_type *type,
				     const void *buf, uint64_t bit_offset);

/**
 * Like @ref drgn_object_set_reference() but @ref drgn_object_type() was already
 * called.
 */
struct drgn_error *
drgn_object_set_reference_internal(struct drgn_object *res,
				   const struct drgn_object_type *type,
				   uint64_t address, uint64_t bit_offset);

/**
 * Binary operator implementation.
 *
 * Operator implementations with this type convert @p lhs and @p rhs to @p
 * op_type, apply the operator, and store the result in @p res.
 *
 * @param[out] res Operator result. May be the same as @p lhs and/or @p rhs.
 * @param[in] op_type Result type.
 * @param[in] lhs Operator left hand side.
 * @param[in] rhs Operator right hand side.
 * @return @c NULL on success, non-@c NULL on error. @p res is not modified on
 * error.
 */
typedef struct drgn_error *
drgn_binary_op_impl(struct drgn_object *res,
		    const struct drgn_operand_type *op_type,
		    const struct drgn_object *lhs,
		    const struct drgn_object *rhs);
/**
 * Shift operator implementation.
 *
 * Operator implementations with this type convert @p lhs to @p lhs_type and @p
 * rhs to @p rhs_type and store the result in @p res.
 *
 * @param[out] res Operator result. May be the same as @p lhs and/or @p rhs.
 * @param[in] lhs Operator left hand side.
 * @param[in] lhs_type Type of left hand side and result.
 * @param[in] rhs Operator right hand side.
 * @param[in] rhs_type Type of right hand side.
 * @return @c NULL on success, non-@c NULL on error. @p res is not modified on
 * error.
 */
typedef struct drgn_error *
drgn_shift_op_impl(struct drgn_object *res,
		   const struct drgn_object *lhs,
		   const struct drgn_operand_type *lhs_type,
		   const struct drgn_object *rhs,
		   const struct drgn_operand_type *rhs_type);

/**
 * Unary operator implementation.
 *
 * Operator implementations with this type convert @p obj to @p op_type and
 * store the result in @p res.
 *
 * @param[out] res Operator result. May be the same as @p obj.
 * @param[in] op_type Result type.
 * @param[in] obj Operand.
 * @return @c NULL on success, non-@c NULL on error. @p res is not modified on
 * error.
 */
typedef struct drgn_error *
drgn_unary_op_impl(struct drgn_object *res,
		   const struct drgn_operand_type *op_type,
		   const struct drgn_object *obj);

/**
 * Implement addition for signed, unsigned, and floating-point objects.
 *
 * Integer results are reduced modulo 2^width.
 */
drgn_binary_op_impl drgn_op_add_impl;
/**
 * Implement subtraction for signed, unsigned, and floating-point objects.
 *
 * Integer results are reduced modulo 2^width.
 */
drgn_binary_op_impl drgn_op_sub_impl;
/**
 * Implement multiplication for signed, unsigned, and floating-point objects.
 *
 * Integer results are reduced modulo 2^width.
 */
drgn_binary_op_impl drgn_op_mul_impl;
/**
 * Implement division for signed, unsigned, and floating-point objects.
 *
 * Integer results are truncated towards zero. A @ref DRGN_ERROR_ZERO_DIVISION
 * error is returned if @p rhs is zero.
 */
drgn_binary_op_impl drgn_op_div_impl;
/**
 * Implement modulo for signed and unsigned objects.
 *
 * The result has the sign of the dividend. A @ref DRGN_ERROR_ZERO_DIVISION
 * error is returned if @p rhs is zero.
 */
drgn_binary_op_impl drgn_op_mod_impl;
/**
 * Implement left shift for signed and unsigned objects.
 *
 * For signed integers, this acts on the two's complement representation. The
 * result is reduced modulo 2^width. In particular, if @p rhs is greater than
 * the width of the result, then the result is zero. An error is returned if @p
 * rhs is negative.
 */
drgn_shift_op_impl drgn_op_lshift_impl;
/**
 * Implement right shift for signed and unsigned objects.
 *
 * For signed integers, this is an arithmetic shift. For unsigned integers, it
 * is logical. The result is reduced modulo 2^width. In particular, if @p rhs is
 * greater than the width of the result, then the result is zero. An error is
 * returned if @p rhs is negative.
 */
drgn_shift_op_impl drgn_op_rshift_impl;
/**
 * Implement bitwise and for signed and unsigned objects.
 *
 * For signed integers, this acts on the two's complement representation.
 */
drgn_binary_op_impl drgn_op_and_impl;
/**
 * Implement bitwise or for signed and unsigned objects.
 *
 * For signed integers, this acts on the two's complement representation.
 */
drgn_binary_op_impl drgn_op_or_impl;
/**
 * Implement bitwise xor for signed and unsigned objects.
 *
 * For signed integers, this acts on the two's complement representation.
 */
drgn_binary_op_impl drgn_op_xor_impl;
/**
 * Implement the unary plus operator for signed, unsigned, and floating-point
 * objects.
 *
 * This converts @p obj without otherwise changing the value.
 */
drgn_unary_op_impl drgn_op_pos_impl;
/**
 * Implement negation for signed, unsigned, and floating-point objects.
 *
 * Integer results are reduced modulo 2^width.
 */
drgn_unary_op_impl drgn_op_neg_impl;
/**
 * Implement bitwise negation for signed and unsigned objects.
 *
 * For signed integers, this acts on the two's complement representation.
 */
drgn_unary_op_impl drgn_op_not_impl;

/**
 * Implement object type casting.
 *
 * If @p obj_type is a pointer type and @c obj is a buffer, then the reference
 * address of @p obj is used.
 */
struct drgn_error *drgn_op_cast(struct drgn_object *res,
				struct drgn_qualified_type qualified_type,
				const struct drgn_object *obj,
				const struct drgn_operand_type *obj_type);

/**
 * Implement object comparison for signed, unsigned, and floating-point objects.
 *
 * This converts @p lhs and @p rhs to @p type before comparing.
 */
struct drgn_error *drgn_op_cmp_impl(const struct drgn_object *lhs,
				    const struct drgn_object *rhs,
				    const struct drgn_operand_type *op_type,
				    int *ret);

/**
 * Implement object comparison for pointers and reference buffer objects.
 *
 * When comparing reference buffer objects, their address is used.
 */
struct drgn_error *drgn_op_cmp_pointers(const struct drgn_object *lhs,
					const struct drgn_object *rhs,
					int *ret);

/**
 * Implement pointer arithmetic.
 *
 * This converts @p ptr to @p op_type, adds or subtracts
 * <tt>index * referenced_size</tt>, and stores the result in @p res.
 *
 * @param[out] res Operator result. May be the same as @p ptr or @p index.
 * @param[in] op_type Result type.
 * @param[in] referenced_size Size of the object pointed to by @p ptr.
 * @param[in] negate Subtract @p index instead of adding.
 * @param[in] ptr Pointer.
 * @param[in] index Value to add to/subtract from pointer.
 * @return @c NULL on success, non-@c NULL on error. @p res is not modified on
 * error.
 */
struct drgn_error *
drgn_op_add_to_pointer(struct drgn_object *res,
		       const struct drgn_operand_type *op_type,
		       uint64_t referenced_size, bool negate,
		       const struct drgn_object *ptr,
		       const struct drgn_object *index);

/**
 * Implement pointer subtraction.
 *
 * This stores <tt>(lhs - rhs) / referenced_size</tt> in @p res.
 *
 * @param[out] res Operator result. May be the same as @p lhs and/or @p rhs.
 * @param[in] referenced_size Size of the object pointed to by @p lhs and @p
 * rhs.
 * @param[in] op_type Result type. Must be a signed integer type.
 * @param[in] lhs Operator left hand side.
 * @param[in] rhs Operator right hand side.
 * @return @c NULL on success, non-@c NULL on error. @p res is not modified on
 * error.
 */
struct drgn_error *drgn_op_sub_pointers(struct drgn_object *res,
					const struct drgn_operand_type *op_type,
					uint64_t referenced_size,
					const struct drgn_object *lhs,
					const struct drgn_object *rhs);

/** @} */

#endif /* DRGN_OBJECT_H */
