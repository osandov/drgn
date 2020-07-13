// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * Object internals.
 *
 * See @ref ObjectInternals.
 */

#ifndef DRGN_OBJECT_H
#define DRGN_OBJECT_H

#include <stdint.h>

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

/**
 * Get whether an object is zero.
 *
 * For scalars, this is true iff its value is zero. For structures, unions, and
 * classes, this is true iff all of its members are zero. For arrays, this is
 * true iff all of its elements are zero. Note that this ignores padding.
 */
struct drgn_error *drgn_object_is_zero(const struct drgn_object *obj,
				       bool *ret);

/**
 * Type of an object.
 *
 * This is used to contain the types of operands and operator results.
 */
struct drgn_object_type {
	/** See @ref drgn_qualified_type::type. */
	struct drgn_type *type;
	/** See @ref drgn_qualified_type::qualifiers. */
	enum drgn_qualifiers qualifiers;
	/**
	 * Cached underlying type of @c type.
	 *
	 * See @ref drgn_underlying_type().
	 */
	struct drgn_type *underlying_type;
	/**
	 * If the object is a bit field, the size of the field in bits.
	 * Otherwise, 0.
	 */
	uint64_t bit_field_size;
};

/** Get the @ref drgn_object_type of a @ref drgn_object. */
static inline struct drgn_object_type
drgn_object_type(const struct drgn_object *obj)
{
	return (struct drgn_object_type){
		.type = obj->type,
		.qualifiers = obj->qualifiers,
		.underlying_type = drgn_underlying_type(obj->type),
		.bit_field_size = obj->is_bit_field ? obj->bit_size : 0,
	};
}

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
 * Reinitialize the fields of a @ref drgn_object, excluding the program and
 * value.
 */
static inline void drgn_object_reinit(struct drgn_object *obj,
				      const struct drgn_object_type *type,
				      enum drgn_object_kind kind,
				      uint64_t bit_size, bool is_reference)
{
	drgn_object_deinit(obj);
	obj->type = type->type;
	obj->qualifiers = type->qualifiers;
	obj->kind = kind;
	obj->bit_size = bit_size;
	obj->is_bit_field = type->bit_field_size != 0;
	obj->is_reference = is_reference;
}

/**
 * Get the @ref drgn_object_kind and size in bits for an object given its type.
 */
struct drgn_error *
drgn_object_type_kind_and_size(const struct drgn_object_type *type,
			       enum drgn_object_kind *kind_ret,
			       uint64_t *bit_size_ret);

/** Prepare to reinitialize an object. */
struct drgn_error *
drgn_object_set_common(struct drgn_qualified_type qualified_type,
		       uint64_t bit_field_size,
		       struct drgn_object_type *type_ret,
		       enum drgn_object_kind *kind_ret, uint64_t *bit_size_ret);

/**
 * Sanity check that the given bit size and bit field size are valid for the
 * given kind of object.
 */
struct drgn_error *sanity_check_object(enum drgn_object_kind kind,
				       uint64_t bit_field_size,
				       uint64_t bit_size);

/**
 * Like @ref drgn_object_set_signed() but @ref drgn_object_set_common() was
 * already called.
 */
struct drgn_error *
drgn_object_set_signed_internal(struct drgn_object *res,
				const struct drgn_object_type *type,
				uint64_t bit_size, int64_t svalue);

/**
 * Like @ref drgn_object_set_unsigned() but @ref drgn_object_set_common() was
 * already called.
 */
struct drgn_error *
drgn_object_set_unsigned_internal(struct drgn_object *res,
				  const struct drgn_object_type *type,
				  uint64_t bit_size, uint64_t uvalue);

/**
 * Like @ref drgn_object_set_buffer() but @ref drgn_object_set_common() was
 * already called.
 */
struct drgn_error *
drgn_object_set_buffer_internal(struct drgn_object *res,
				const struct drgn_object_type *type,
				enum drgn_object_kind kind, uint64_t bit_size,
				const void *buf, uint8_t bit_offset,
				bool little_endian);

/** Convert a @ref drgn_byte_order to a boolean. */
struct drgn_error *
drgn_byte_order_to_little_endian(struct drgn_program *prog,
				 enum drgn_byte_order byte_order, bool *ret);

/**
 * Binary operator implementation.
 *
 * Operator implementations with this type convert @p lhs and @p rhs to @p type,
 * apply the operator, and store the result in @p res.
 *
 * @param[out] res Operator result. May be the same as @p lhs and/or @p rhs.
 * @param[in] type Result type.
 * @param[in] lhs Operator left hand side.
 * @param[in] rhs Operator right hand side.
 * @return @c NULL on success, non-@c NULL on error. @p res is not modified on
 * error.
 */
typedef struct drgn_error *
drgn_binary_op_impl(struct drgn_object *res,
		    const struct drgn_object_type *type,
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
		   const struct drgn_object_type *lhs_type,
		   const struct drgn_object *rhs,
		   const struct drgn_object_type *rhs_type);

/**
 * Unary operator implementation.
 *
 * Operator implementations with this type convert @p obj to @p type and store
 * the result in @p res.
 *
 * @param[out] res Operator result. May be the same as @p obj.
 * @param[in] type Result type.
 * @param[in] obj Operand.
 * @return @c NULL on success, non-@c NULL on error. @p res is not modified on
 * error.
 */
typedef struct drgn_error *
drgn_unary_op_impl(struct drgn_object *res,
		   const struct drgn_object_type *type,
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
				struct drgn_object_type *obj_type);

/**
 * Implement object comparison for signed, unsigned, and floating-point objects.
 *
 * This converts @p lhs and @p rhs to @p type before comparing.
 */
struct drgn_error *drgn_op_cmp_impl(const struct drgn_object *lhs,
				    const struct drgn_object *rhs,
				    const struct drgn_object_type *type,
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
 * This converts @p ptr to @p type, adds or subtracts
 * <tt>index * referenced_size</tt>, and stores the result in @p res.
 *
 * @param[out] res Operator result. May be the same as @p ptr or @p index.
 * @param[in] type Result type.
 * @param[in] referenced_size Size of the object pointed to by @p ptr.
 * @param[in] negate Subtract @p index instead of adding.
 * @param[in] ptr Pointer.
 * @param[in] index Value to add to/subtract from pointer.
 * @return @c NULL on success, non-@c NULL on error. @p res is not modified on
 * error.
 */
struct drgn_error *drgn_op_add_to_pointer(struct drgn_object *res,
					  const struct drgn_object_type *type,
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
 * @param[in] type Result type. Must be a signed integer type.
 * @param[in] lhs Operator left hand side.
 * @param[in] rhs Operator right hand side.
 * @return @c NULL on success, non-@c NULL on error. @p res is not modified on
 * error.
 */
struct drgn_error *drgn_op_sub_pointers(struct drgn_object *res,
					const struct drgn_object_type *type,
					uint64_t referenced_size,
					const struct drgn_object *lhs,
					const struct drgn_object *rhs);

/** @} */

#endif /* DRGN_OBJECT_H */
