// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "cleanup.h"
#include "drgn_internal.h"
#include "error.h"
#include "language.h"
#include "minmax.h"
#include "object.h"
#include "program.h"
#include "serialize.h"
#include "type.h"
#include "util.h"

#define DRGN_OBJECT_INITIALIZER(prog)				\
	(struct drgn_object){					\
		.type = &(prog)->void_types[DRGN_LANGUAGE_C],	\
		.encoding = DRGN_OBJECT_ENCODING_NONE,		\
		.kind = DRGN_OBJECT_ABSENT,			\
		.absence_reason = DRGN_ABSENCE_REASON_OTHER,	\
	}

LIBDRGN_PUBLIC
struct drgn_object drgn_object_initializer(struct drgn_program *prog)
{
	return DRGN_OBJECT_INITIALIZER(prog);
}

LIBDRGN_PUBLIC void drgn_object_init(struct drgn_object *obj,
				     struct drgn_program *prog)
{
	*obj = DRGN_OBJECT_INITIALIZER(prog);
}

static void drgn_value_deinit(const struct drgn_object *obj,
			      const union drgn_value *value)
{
	if ((obj->encoding == DRGN_OBJECT_ENCODING_BUFFER
	     && !drgn_object_is_inline(obj))
	    || obj->encoding == DRGN_OBJECT_ENCODING_SIGNED_BIG
	    || obj->encoding == DRGN_OBJECT_ENCODING_UNSIGNED_BIG)
		free(value->bufp);
}

LIBDRGN_PUBLIC void drgn_object_deinit_value(const struct drgn_object *obj,
					     const union drgn_value *value)
{
	if (value != &obj->value)
		drgn_value_deinit(obj, value);
}

LIBDRGN_PUBLIC void drgn_object_deinit(struct drgn_object *obj)
{
	if (obj->kind == DRGN_OBJECT_VALUE)
		drgn_value_deinit(obj, &obj->value);
}

/* Copy everything from src to dst but the kind and value. */
static inline void drgn_object_reinit_copy(struct drgn_object *dst,
					   const struct drgn_object *src)
{
	drgn_object_deinit(dst);
	dst->type = src->type;
	dst->qualifiers = src->qualifiers;
	dst->encoding = src->encoding;
	dst->bit_size = src->bit_size;
	dst->is_bit_field = src->is_bit_field;
	dst->little_endian = src->little_endian;
}

static struct drgn_error *
drgn_object_type_impl(struct drgn_type *type, struct drgn_type *underlying_type,
		      enum drgn_qualifiers qualifiers, uint64_t bit_field_size,
		      struct drgn_object_type *ret)
{
	struct drgn_error *err;

	ret->type = type;
	ret->underlying_type = underlying_type;
	ret->qualifiers = qualifiers;

	if (drgn_type_is_complete(underlying_type)
	    && drgn_type_kind(underlying_type) != DRGN_TYPE_FUNCTION) {
		err = drgn_type_bit_size(type, &ret->bit_size);
		if (err)
			return err;
	} else {
		ret->bit_size = 0;
	}

	struct drgn_type *compatible_type = underlying_type;
	SWITCH_ENUM(drgn_type_kind(compatible_type)) {
	case DRGN_TYPE_ENUM:
		if (!drgn_type_is_complete(compatible_type)) {
			ret->encoding = DRGN_OBJECT_ENCODING_INCOMPLETE_INTEGER;
			break;
		}
		compatible_type = drgn_type_type(compatible_type).type;
		fallthrough;
	case DRGN_TYPE_INT:
	case DRGN_TYPE_BOOL: {
		if (bit_field_size != 0) {
			if (bit_field_size > ret->bit_size) {
				return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
							 "bit field size is larger than type size");
			}
			ret->bit_size = bit_field_size;
		}
		// The maximum bit size we can represent is UINT64_MAX. However,
		// pick an arbitrary smaller limit to keep things from getting
		// out of hand: 2^24 is the maximum bit width that Clang 13
		// allows for _ExtInt() (limited by the LLVM IR representation;
		// technically it's 2^24-1, but it gets rounded up to a
		// DW_AT_byte_size of 2^24/8).
		if (ret->bit_size < 1 || ret->bit_size > 16777216) {
			return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
						 "unsupported integer bit size (%" PRIu64 ")",
						 ret->bit_size);
		}
		bool is_signed =
			drgn_type_kind(compatible_type) == DRGN_TYPE_INT
			&& drgn_type_is_signed(compatible_type);
		if (ret->bit_size <= 64 && is_signed)
			ret->encoding = DRGN_OBJECT_ENCODING_SIGNED;
		else if (ret->bit_size <= 64)
			ret->encoding = DRGN_OBJECT_ENCODING_UNSIGNED;
		else if (is_signed)
			ret->encoding = DRGN_OBJECT_ENCODING_SIGNED_BIG;
		else
			ret->encoding = DRGN_OBJECT_ENCODING_UNSIGNED_BIG;
		break;
	}
	case DRGN_TYPE_POINTER:
		ret->encoding = DRGN_OBJECT_ENCODING_UNSIGNED;
		break;
	case DRGN_TYPE_FLOAT:
		if (ret->bit_size < 1 || ret->bit_size > 256) {
			return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
						 "unsupported floating-point bit size (%" PRIu64 ")",
						 ret->bit_size);
		}
		ret->encoding = DRGN_OBJECT_ENCODING_FLOAT;
		break;
	case DRGN_TYPE_STRUCT:
	case DRGN_TYPE_UNION:
	case DRGN_TYPE_CLASS:
	case DRGN_TYPE_ARRAY:
		if (drgn_type_is_complete(compatible_type))
			ret->encoding = DRGN_OBJECT_ENCODING_BUFFER;
		else
			ret->encoding = DRGN_OBJECT_ENCODING_INCOMPLETE_BUFFER;
		break;
	case DRGN_TYPE_VOID:
	case DRGN_TYPE_FUNCTION:
		ret->encoding = DRGN_OBJECT_ENCODING_NONE;
		break;
	// This is already the underlying type, so it can't be a typedef.
	case DRGN_TYPE_TYPEDEF:
	default:
		UNREACHABLE();
	}

	if (bit_field_size != 0
	    && drgn_type_kind(compatible_type) != DRGN_TYPE_INT
	    && drgn_type_kind(compatible_type) != DRGN_TYPE_BOOL) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "bit field must be integer");
	}
	ret->is_bit_field = bit_field_size != 0;

	ret->little_endian = (drgn_type_has_little_endian(compatible_type)
			      && drgn_type_little_endian(compatible_type));
	return NULL;
}

struct drgn_error *
drgn_object_type(struct drgn_qualified_type qualified_type,
		 uint64_t bit_field_size, struct drgn_object_type *ret)
{
	return drgn_object_type_impl(qualified_type.type,
				     drgn_underlying_type(qualified_type.type),
				     qualified_type.qualifiers, bit_field_size,
				     ret);
}

static struct drgn_error *
drgn_object_type_operand(const struct drgn_operand_type *op_type,
			 struct drgn_object_type *ret)
{
	struct drgn_error *err;
	err = drgn_object_type_impl(op_type->type, op_type->underlying_type,
				    op_type->qualifiers,
				    op_type->bit_field_size, ret);
	if (err)
		return err;
	if (ret->encoding == DRGN_OBJECT_ENCODING_SIGNED_BIG
	    || ret->encoding == DRGN_OBJECT_ENCODING_UNSIGNED_BIG) {
		return drgn_error_create(DRGN_ERROR_NOT_IMPLEMENTED,
					 "operations on integer values larger than 64 bits are not yet supported");
	}
	return NULL;
}

struct drgn_error *
drgn_object_set_signed_internal(struct drgn_object *res,
				const struct drgn_object_type *type,
				int64_t svalue)
{
	if (type->encoding == DRGN_OBJECT_ENCODING_SIGNED_BIG) {
		uint64_t size = drgn_value_size(type->bit_size);
		void *buf = malloc64(size);
		if (!buf)
			return &drgn_enomem;
		copy_lsbytes_fill(buf, size, type->little_endian, &svalue,
				  sizeof(svalue), HOST_LITTLE_ENDIAN,
				  svalue < 0 ? -1 : 0);
		drgn_object_reinit(res, type, DRGN_OBJECT_VALUE);
		res->value.bufp = buf;
		return NULL;
	}
	drgn_object_reinit(res, type, DRGN_OBJECT_VALUE);
	res->value.svalue = truncate_signed(svalue, type->bit_size);
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_set_signed(struct drgn_object *res,
		       struct drgn_qualified_type qualified_type,
		       int64_t svalue, uint64_t bit_field_size)
{
	struct drgn_error *err;
	struct drgn_object_type type;
	err = drgn_object_type(qualified_type, bit_field_size, &type);
	if (err)
		return err;
	if (type.encoding != DRGN_OBJECT_ENCODING_SIGNED
	    && type.encoding != DRGN_OBJECT_ENCODING_SIGNED_BIG) {
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "not a signed integer type");
	}
	return drgn_object_set_signed_internal(res, &type, svalue);
}

struct drgn_error *
drgn_object_set_unsigned_internal(struct drgn_object *res,
				  const struct drgn_object_type *type,
				  uint64_t uvalue)
{
	if (type->encoding == DRGN_OBJECT_ENCODING_UNSIGNED_BIG) {
		uint64_t size = drgn_value_size(type->bit_size);
		void *buf = malloc64(size);
		if (!buf)
			return &drgn_enomem;
		copy_lsbytes(buf, size, type->little_endian, &uvalue,
			     sizeof(uvalue), HOST_LITTLE_ENDIAN);
		drgn_object_reinit(res, type, DRGN_OBJECT_VALUE);
		res->value.bufp = buf;
		return NULL;
	}
	drgn_object_reinit(res, type, DRGN_OBJECT_VALUE);
	res->value.uvalue = truncate_unsigned(uvalue, type->bit_size);
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_set_unsigned(struct drgn_object *res,
			 struct drgn_qualified_type qualified_type,
			 uint64_t uvalue, uint64_t bit_field_size)
{
	struct drgn_error *err;
	struct drgn_object_type type;
	err = drgn_object_type(qualified_type, bit_field_size, &type);
	if (err)
		return err;
	if (type.encoding != DRGN_OBJECT_ENCODING_UNSIGNED
	    && type.encoding != DRGN_OBJECT_ENCODING_UNSIGNED_BIG) {
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "not an unsigned integer type");
	}
	return drgn_object_set_unsigned_internal(res, &type, uvalue);
}

static struct drgn_error drgn_float_size_unsupported = {
	.code = DRGN_ERROR_NOT_IMPLEMENTED,
	.message = "float values which are not 32 or 64 bits are not yet supported",
};

struct drgn_error *
drgn_object_set_float_internal(struct drgn_object *res,
			       const struct drgn_object_type *type,
			       double fvalue)
{
	if (type->bit_size != 32 && type->bit_size != 64)
		return &drgn_float_size_unsupported;
	drgn_object_reinit(res, type, DRGN_OBJECT_VALUE);
	if (type->bit_size == 32)
		res->value.fvalue = (float)fvalue;
	else
		res->value.fvalue = fvalue;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_set_float(struct drgn_object *res,
		      struct drgn_qualified_type qualified_type, double fvalue)
{
	struct drgn_error *err;
	struct drgn_object_type type;
	err = drgn_object_type(qualified_type, 0, &type);
	if (err)
		return err;
	if (type.encoding != DRGN_OBJECT_ENCODING_FLOAT) {
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "not a floating-point type");
	}
	return drgn_object_set_float_internal(res, &type, fvalue);
}

static void drgn_value_deserialize(union drgn_value *value, const void *buf,
				   uint8_t bit_offset,
				   enum drgn_object_encoding encoding,
				   uint64_t bit_size, bool little_endian)
{
	union {
		int64_t svalue;
		uint64_t uvalue;
		double fvalue64;
		struct {
#if !HOST_LITTLE_ENDIAN
			float pad;
#endif
			float fvalue32;
		};
	} tmp;

	tmp.uvalue = deserialize_bits(buf, bit_offset, bit_size, little_endian);
	switch (encoding) {
	case DRGN_OBJECT_ENCODING_SIGNED:
		value->svalue = truncate_signed(tmp.svalue, bit_size);
		break;
	case DRGN_OBJECT_ENCODING_UNSIGNED:
		value->uvalue = tmp.uvalue;
		break;
	case DRGN_OBJECT_ENCODING_FLOAT:
		value->fvalue = bit_size == 32 ? tmp.fvalue32 : tmp.fvalue64;
		break;
	default:
		UNREACHABLE();
	}
}

struct drgn_error *
drgn_object_set_from_buffer_internal(struct drgn_object *res,
				     const struct drgn_object_type *type,
				     const void *buf, uint64_t bit_offset)
{
	const char *p = (const char *)buf + (bit_offset / CHAR_BIT);
	bit_offset %= CHAR_BIT;
	/*
	 * buf may point inside of res->value or drgn_object_buffer(res), so we
	 * copy to a temporary value before freeing or modifying the old value.
	 */
	union drgn_value value;
	if (type->encoding == DRGN_OBJECT_ENCODING_BUFFER
	    || type->encoding == DRGN_OBJECT_ENCODING_SIGNED_BIG
	    || type->encoding == DRGN_OBJECT_ENCODING_UNSIGNED_BIG) {
		if (type->encoding == DRGN_OBJECT_ENCODING_BUFFER
		    && bit_offset != 0) {
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "non-scalar must be byte-aligned");
		}
		uint64_t size = drgn_value_size(type->bit_size);
		void *dst;
		if (size <= sizeof(res->value.ibuf)) {
			dst = value.ibuf;
		} else {
			dst = malloc64(size);
			if (!dst)
				return &drgn_enomem;
			value.bufp = dst;
		}
		int dst_bit_offset = 0;
		if (type->encoding != DRGN_OBJECT_ENCODING_BUFFER
		    && !type->little_endian)
			dst_bit_offset = -type->bit_size % 8;
		((uint8_t *)dst)[0] = 0;
		((uint8_t *)dst)[size - 1] = 0;
		copy_bits(dst, dst_bit_offset, p, bit_offset, type->bit_size,
			  type->little_endian);
		if (type->encoding == DRGN_OBJECT_ENCODING_SIGNED_BIG
		    && type->bit_size % 8 != 0) {
			int8_t *dst_p;
			if (type->little_endian)
				dst_p = (int8_t *)dst + size - 1;
			else
				dst_p = (int8_t *)dst;
			*dst_p = truncate_signed8(*dst_p, type->bit_size % 8);
		}
	} else if (drgn_object_encoding_is_complete(type->encoding)) {
		if (type->encoding == DRGN_OBJECT_ENCODING_FLOAT
		    && type->bit_size != 32 && type->bit_size != 64)
			return &drgn_float_size_unsupported;
		drgn_value_deserialize(&value, p, bit_offset, type->encoding,
				       type->bit_size, type->little_endian);
	} else {
		return drgn_error_incomplete_type("cannot create object with %s type",
						  type->type);
	}
	drgn_object_reinit(res, type, DRGN_OBJECT_VALUE);
	res->value = value;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_set_from_buffer(struct drgn_object *res,
			    struct drgn_qualified_type qualified_type,
			    const void *buf, size_t buf_size,
			    uint64_t bit_offset, uint64_t bit_field_size)
{
	struct drgn_error *err;
	struct drgn_object_type type;
	err = drgn_object_type(qualified_type, bit_field_size, &type);
	if (err)
		return err;
	if (type.bit_size > UINT64_MAX - bit_offset ||
	    buf_size < drgn_value_size(bit_offset + type.bit_size)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "buffer is too small");
	}
	return drgn_object_set_from_buffer_internal(res, &type, buf,
						    bit_offset);
}

struct drgn_error *
drgn_object_set_reference_internal(struct drgn_object *res,
				   const struct drgn_object_type *type,
				   uint64_t address, uint64_t bit_offset)
{
	uint64_t address_mask;
	struct drgn_error *err =
		drgn_program_address_mask(drgn_object_program(res),
					  &address_mask);
	if (err)
		return err;

	address += bit_offset / 8;
	address &= address_mask;
	bit_offset %= 8;
	if (bit_offset != 0) {
		SWITCH_ENUM(type->encoding) {
		case DRGN_OBJECT_ENCODING_SIGNED:
		case DRGN_OBJECT_ENCODING_UNSIGNED:
		case DRGN_OBJECT_ENCODING_SIGNED_BIG:
		case DRGN_OBJECT_ENCODING_UNSIGNED_BIG:
		case DRGN_OBJECT_ENCODING_FLOAT:
		case DRGN_OBJECT_ENCODING_INCOMPLETE_INTEGER:
			break;
		case DRGN_OBJECT_ENCODING_NONE:
		case DRGN_OBJECT_ENCODING_BUFFER:
		case DRGN_OBJECT_ENCODING_INCOMPLETE_BUFFER:
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "non-scalar must be byte-aligned");
		default:
			UNREACHABLE();
		}
	}
	if (type->bit_size > UINT64_MAX - bit_offset) {
		return drgn_error_format(DRGN_ERROR_OVERFLOW,
					 "object is too large");
	}

	drgn_object_reinit(res, type, DRGN_OBJECT_REFERENCE);
	res->address = address;
	res->bit_offset = bit_offset;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_set_reference(struct drgn_object *res,
			  struct drgn_qualified_type qualified_type,
			  uint64_t address, uint64_t bit_offset,
			  uint64_t bit_field_size)
{
	struct drgn_error *err;
	struct drgn_object_type type;
	err = drgn_object_type(qualified_type, bit_field_size, &type);
	if (err)
		return err;
	return drgn_object_set_reference_internal(res, &type, address,
						  bit_offset);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_set_absent(struct drgn_object *res,
		       struct drgn_qualified_type qualified_type,
		       enum drgn_absence_reason reason,
		       uint64_t bit_field_size)
{
	struct drgn_error *err;
	struct drgn_object_type type;
	err = drgn_object_type(qualified_type, bit_field_size, &type);
	if (err)
		return err;
	drgn_object_set_absent_internal(res, &type, reason);
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_copy(struct drgn_object *res, const struct drgn_object *obj)
{
	if (res == obj)
		return NULL;

	if (drgn_object_program(res) != drgn_object_program(obj)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "objects are from different programs");
	}

	SWITCH_ENUM(obj->kind) {
	case DRGN_OBJECT_VALUE:
		if (obj->encoding == DRGN_OBJECT_ENCODING_BUFFER
		    || obj->encoding == DRGN_OBJECT_ENCODING_SIGNED_BIG
		    || obj->encoding == DRGN_OBJECT_ENCODING_UNSIGNED_BIG) {
			size_t size = drgn_object_size(obj);
			char *dst;
			const char *src;
			if (size <= sizeof(obj->value.ibuf)) {
				dst = res->value.ibuf;
				src = obj->value.ibuf;
			} else {
				dst = malloc(size);
				if (!dst)
					return &drgn_enomem;
				src = obj->value.bufp;
			}
			drgn_object_reinit_copy(res, obj);
			res->kind = DRGN_OBJECT_VALUE;
			memcpy(dst, src, size);
			if (dst != res->value.ibuf)
				res->value.bufp = dst;
		} else {
			drgn_object_reinit_copy(res, obj);
			res->kind = DRGN_OBJECT_VALUE;
			res->value = obj->value;
		}
		break;
	case DRGN_OBJECT_REFERENCE:
		drgn_object_reinit_copy(res, obj);
		res->kind = DRGN_OBJECT_REFERENCE;
		res->address = obj->address;
		res->bit_offset = obj->bit_offset;
		break;
	case DRGN_OBJECT_ABSENT:
		drgn_object_reinit_copy(res, obj);
		res->kind = DRGN_OBJECT_ABSENT;
		break;
	default:
		UNREACHABLE();
	}
	return NULL;
}

struct drgn_error *
drgn_object_fragment_internal(struct drgn_object *res,
			      const struct drgn_object *obj,
			      const struct drgn_object_type *type,
			      int64_t bit_offset, uint64_t bit_field_size)
{
	struct drgn_error *err;

	SWITCH_ENUM(obj->kind) {
	case DRGN_OBJECT_VALUE: {
		uint64_t bit_end;
		if (bit_offset < 0
		    || __builtin_add_overflow(bit_offset, type->bit_size,
					      &bit_end)
		    || bit_end > obj->bit_size) {
			return drgn_error_create(DRGN_ERROR_OUT_OF_BOUNDS,
						 "out of bounds of value");
		}
		char small_buf[8];
		const void *buf;
		_cleanup_free_ char *free_buf = NULL;
		if (obj->encoding == DRGN_OBJECT_ENCODING_BUFFER) {
			buf = drgn_object_buffer(obj);
		} else {
			size_t size = drgn_object_size(obj);
			if (size <= sizeof(small_buf)) {
				buf = small_buf;
			} else {
				buf = free_buf = malloc(size);
				if (!buf)
					return &drgn_enomem;
			}
			err = drgn_object_read_bytes(obj, (void *)buf);
			if (err)
				return err;
		}
		return drgn_object_set_from_buffer_internal(res, type, buf,
							    bit_offset);
	}
	case DRGN_OBJECT_REFERENCE: {
		// obj->bit_offset + bit_offset can overflow, so apply the
		// byte-aligned part of bit_offset now.
		//
		// / and % truncate towards 0. Here, we want to truncate towards
		// negative infinity. We can accomplish that by replacing "/ 8"
		// with an arithmetic shift ">> 3" and "% 8" with "& 7".
		uint64_t address = obj->address + (bit_offset >> 3);
		bit_offset &= 7;
		return drgn_object_set_reference_internal(res, type, address,
							  obj->bit_offset
							  + bit_offset);
	}
	case DRGN_OBJECT_ABSENT:
		return &drgn_error_object_absent;
	default:
		UNREACHABLE();
	}
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_fragment(struct drgn_object *res, const struct drgn_object *obj,
		     struct drgn_qualified_type qualified_type,
		     int64_t bit_offset, uint64_t bit_field_size)
{
	struct drgn_error *err;
	if (drgn_object_program(res) != drgn_object_program(obj)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "objects are from different programs");
	}
	struct drgn_object_type type;
	err = drgn_object_type(qualified_type, bit_field_size, &type);
	if (err)
		return err;
	return drgn_object_fragment_internal(res, obj, &type, bit_offset,
					     bit_field_size);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_dereference_offset(struct drgn_object *res,
			       const struct drgn_object *obj,
			       struct drgn_qualified_type qualified_type,
			       int64_t bit_offset, uint64_t bit_field_size)
{
	struct drgn_error *err;
	uint64_t address;

	err = drgn_object_read_unsigned(obj, &address);
	if (err)
		return err;

	/*
	 * / and % truncate towards 0. Here, we want to truncate towards
	 * negative infinity. We can accomplish that by replacing "/ 8" with an
	 * arithmetic shift ">> 3" and "% 8" with "& 7".
	 */
	address += bit_offset >> 3;
	bit_offset &= 7;
	return drgn_object_set_reference(res, qualified_type, address,
					 bit_offset, bit_field_size);
}

static struct drgn_error *
drgn_object_read_reference(const struct drgn_object *obj,
			   union drgn_value *value)
{
	struct drgn_error *err;

	assert(obj->kind == DRGN_OBJECT_REFERENCE);

	if (!drgn_object_encoding_is_complete(obj->encoding)) {
		return drgn_error_incomplete_type("cannot read object with %s type",
						  obj->type);
	}

	if (obj->encoding == DRGN_OBJECT_ENCODING_BUFFER
	    || obj->encoding == DRGN_OBJECT_ENCODING_SIGNED_BIG
	    || obj->encoding == DRGN_OBJECT_ENCODING_UNSIGNED_BIG) {
		int dst_bit_offset = 0;
		if (obj->encoding != DRGN_OBJECT_ENCODING_BUFFER
		    && !obj->little_endian)
			dst_bit_offset = -obj->bit_size % 8;

		uint64_t size = drgn_object_size(obj);
		void *dst;
		if (obj->bit_offset == 0 && dst_bit_offset == 0) {
			if (size <= sizeof(value->ibuf)) {
				dst = value->ibuf;
			} else {
				dst = malloc64(size);
				if (!dst)
					return &drgn_enomem;
			}
			err = drgn_program_read_memory(drgn_object_program(obj),
						       dst, obj->address, size,
						       false);
			if (err) {
				if (dst != value->ibuf)
					free(dst);
				return err;
			}
			if (obj->encoding == DRGN_OBJECT_ENCODING_UNSIGNED_BIG
			    && obj->bit_size % 8 != 0) {
				// dst_bit_offset == 0 && obj->bit_size % 8 != 0
				// implies obj->little_endian.
				uint8_t *p = (uint8_t *)dst + size - 1;
				*p = truncate_unsigned8(*p, obj->bit_size % 8);
			}
		} else {
			// bit_offset + bit_size is guaranteed not to overflow
			// because bit_offset can only be non-zero for
			// SIGNED_BIG and UNSIGNED_BIG, which we limit to a
			// reasonable bit_size.
			uint64_t read_size =
				drgn_value_size(obj->bit_offset + obj->bit_size);

			// We could probably read directly into dst and move the
			// bits in place if we really wanted to, but this is
			// easier.
			_cleanup_free_ void *tmp = malloc64(read_size);
			if (!tmp)
				return &drgn_enomem;
			err = drgn_program_read_memory(drgn_object_program(obj),
						       tmp, obj->address,
						       read_size, false);
			if (err)
				return err;
			if (size <= sizeof(value->ibuf)) {
				dst = value->ibuf;
			} else {
				dst = malloc64(size);
				if (!dst)
					return &drgn_enomem;
			}
			((uint8_t *)dst)[0] = 0;
			((uint8_t *)dst)[size - 1] = 0;
			copy_bits(dst, dst_bit_offset, tmp, obj->bit_offset,
				  obj->bit_size, obj->little_endian);
		}
		if (obj->encoding == DRGN_OBJECT_ENCODING_SIGNED_BIG
		    && obj->bit_size % 8 != 0) {
			int8_t *p;
			if (obj->little_endian)
				p = (int8_t *)dst + size - 1;
			else
				p = (int8_t *)dst;
			*p = truncate_signed8(*p, obj->bit_size % 8);
		}
		if (size > sizeof(value->ibuf))
			value->bufp = dst;
		return NULL;
	} else {
		uint64_t bit_size = obj->bit_size;
		if (obj->encoding == DRGN_OBJECT_ENCODING_FLOAT
		    && bit_size != 32 && bit_size != 64)
			return &drgn_float_size_unsupported;
		uint8_t bit_offset = obj->bit_offset;
		uint64_t read_size = drgn_value_size(bit_offset + bit_size);
		char buf[9];
		assert(read_size <= sizeof(buf));
		err = drgn_program_read_memory(drgn_object_program(obj), buf,
					       obj->address, read_size, false);
		if (err)
			return err;
		drgn_value_deserialize(value, buf, bit_offset, obj->encoding,
				       bit_size, obj->little_endian);
		return NULL;
	}
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_read(struct drgn_object *res, const struct drgn_object *obj)
{
	struct drgn_error *err;

	SWITCH_ENUM(obj->kind) {
	case DRGN_OBJECT_VALUE:
		return drgn_object_copy(res, obj);
	case DRGN_OBJECT_REFERENCE: {
		if (drgn_object_program(res) != drgn_object_program(obj)) {
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "objects are from different programs");
		}
		union drgn_value value;
		err = drgn_object_read_reference(obj, &value);
		if (err)
			return err;
		drgn_object_reinit_copy(res, obj);
		res->kind = DRGN_OBJECT_VALUE;
		res->value = value;
		return NULL;
	}
	case DRGN_OBJECT_ABSENT:
		return &drgn_error_object_absent;
	default:
		UNREACHABLE();
	}
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_read_value(const struct drgn_object *obj, union drgn_value *value,
		       const union drgn_value **ret)
{
	struct drgn_error *err;

	SWITCH_ENUM(obj->kind) {
	case DRGN_OBJECT_VALUE:
		*ret = &obj->value;
		return NULL;
	case DRGN_OBJECT_REFERENCE:
		err = drgn_object_read_reference(obj, value);
		if (!err)
			*ret = value;
		return err;
	case DRGN_OBJECT_ABSENT:
		return &drgn_error_object_absent;
	default:
		UNREACHABLE();
	}
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_read_bytes(const struct drgn_object *obj, void *buf)
{
	struct drgn_error *err;

	if (!drgn_object_encoding_is_complete(obj->encoding)) {
		return drgn_error_incomplete_type("cannot read object with %s type",
						  obj->type);
	}

	SWITCH_ENUM(obj->kind) {
	case DRGN_OBJECT_VALUE:
		if (obj->encoding == DRGN_OBJECT_ENCODING_BUFFER
		    || obj->encoding == DRGN_OBJECT_ENCODING_SIGNED_BIG
		    || obj->encoding == DRGN_OBJECT_ENCODING_UNSIGNED_BIG) {
			if (obj->bit_size % 8 == 0) {
				memcpy(buf, drgn_object_buffer(obj),
				       drgn_object_size(obj));
			} else {
				int bit_offset = 0;
				if (obj->encoding != DRGN_OBJECT_ENCODING_BUFFER
				    && !obj->little_endian)
					bit_offset = -obj->bit_size % 8;
				((uint8_t *)buf)[drgn_object_size(obj) - 1] = 0;
				copy_bits(buf, 0, drgn_object_buffer(obj),
					  bit_offset, obj->bit_size,
					  obj->little_endian);
			}
		} else {
			union {
				uint64_t uvalue;
				struct {
#if !HOST_LITTLE_ENDIAN
					uint32_t pad;
#endif
					float fvalue32;
#if HOST_LITTLE_ENDIAN
					uint32_t pad;
#endif
				};
			} tmp;
			((uint8_t *)buf)[drgn_object_size(obj) - 1] = 0;
			if (obj->encoding == DRGN_OBJECT_ENCODING_FLOAT &&
			    obj->bit_size == 32) {
				tmp.fvalue32 = (float)obj->value.fvalue;
				tmp.pad = 0;
			} else {
				tmp.uvalue = obj->value.uvalue;
			}
			serialize_bits(buf, 0,
				       truncate_unsigned(tmp.uvalue, obj->bit_size),
				       obj->bit_size, obj->little_endian);
		}
		return NULL;
	case DRGN_OBJECT_REFERENCE: {
		uint64_t size = drgn_object_size(obj);
		if (obj->bit_offset == 0) {
			err = drgn_program_read_memory(drgn_object_program(obj),
						       buf, obj->address, size,
						       false);
			if (err)
				return err;
			if (obj->bit_size % 8 != 0) {
				uint8_t *p = (uint8_t *)buf + size - 1;
				if (obj->little_endian)
					*p = truncate_unsigned8(*p, obj->bit_size % 8);
				else
					*p &= 0xff00U >> (obj->bit_size % 8);
			}
		} else {
			uint64_t read_size =
				drgn_value_size(obj->bit_offset + obj->bit_size);

			void *tmp;
			char tmp_small[9];
			_cleanup_free_ void *tmp_large = NULL;
			if (read_size > sizeof(tmp_small)) {
				tmp_large = malloc64(read_size);
				if (!tmp_large)
					return &drgn_enomem;
				tmp = tmp_large;
			} else {
				tmp = tmp_small;
			}
			err = drgn_program_read_memory(drgn_object_program(obj),
						       tmp, obj->address,
						       read_size, false);
			if (err)
				return err;
			((uint8_t *)buf)[size - 1] = 0;
			copy_bits(buf, 0, tmp, obj->bit_offset, obj->bit_size,
				  obj->little_endian);
		}
		return NULL;
	}
	case DRGN_OBJECT_ABSENT:
		return &drgn_error_object_absent;
	default:
		UNREACHABLE();
	}
}

static struct drgn_error *
drgn_object_value_signed(const struct drgn_object *obj, int64_t *ret)
{
	struct drgn_error *err;
	union drgn_value value_mem;
	const union drgn_value *value;

	assert(obj->encoding == DRGN_OBJECT_ENCODING_SIGNED);

	err = drgn_object_read_value(obj, &value_mem, &value);
	if (err)
		return err;
	*ret = value->svalue;
	drgn_object_deinit_value(obj, value);
	return err;
}

static struct drgn_error *
drgn_object_value_unsigned(const struct drgn_object *obj, uint64_t *ret)
{
	struct drgn_error *err;
	union drgn_value value_mem;
	const union drgn_value *value;

	assert(obj->encoding == DRGN_OBJECT_ENCODING_UNSIGNED);

	err = drgn_object_read_value(obj, &value_mem, &value);
	if (err)
		return err;
	*ret = value->uvalue;
	drgn_object_deinit_value(obj, value);
	return err;
}

static struct drgn_error *
drgn_object_value_float(const struct drgn_object *obj, double *ret)
{
	struct drgn_error *err;
	union drgn_value value_mem;
	const union drgn_value *value;

	assert(obj->encoding == DRGN_OBJECT_ENCODING_FLOAT);

	err = drgn_object_read_value(obj, &value_mem, &value);
	if (err)
		return err;
	*ret = value->fvalue;
	drgn_object_deinit_value(obj, value);
	return err;
}

static struct drgn_error drgn_integer_too_big = {
	.code = DRGN_ERROR_OVERFLOW,
	.message = "integer type is too big",
};

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_read_signed(const struct drgn_object *obj, int64_t *ret)
{
	if (obj->encoding == DRGN_OBJECT_ENCODING_SIGNED_BIG) {
		return &drgn_integer_too_big;
	} else if (obj->encoding != DRGN_OBJECT_ENCODING_SIGNED) {
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "not a signed integer");
	}
	return drgn_object_value_signed(obj, ret);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_read_unsigned(const struct drgn_object *obj, uint64_t *ret)
{
	if (obj->encoding == DRGN_OBJECT_ENCODING_UNSIGNED_BIG) {
		return &drgn_integer_too_big;
	} else if (obj->encoding != DRGN_OBJECT_ENCODING_UNSIGNED) {
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "not an unsigned integer");
	}
	return drgn_object_value_unsigned(obj, ret);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_read_integer(const struct drgn_object *obj, union drgn_value *ret)
{
	struct drgn_error *err;
	union drgn_value value_mem;
	const union drgn_value *value;

	if (obj->encoding == DRGN_OBJECT_ENCODING_SIGNED_BIG
	    || obj->encoding == DRGN_OBJECT_ENCODING_UNSIGNED_BIG)
		return &drgn_integer_too_big;
	else if (obj->encoding != DRGN_OBJECT_ENCODING_SIGNED
		 && obj->encoding != DRGN_OBJECT_ENCODING_UNSIGNED)
		return drgn_error_create(DRGN_ERROR_TYPE, "not an integer");
	err = drgn_object_read_value(obj, &value_mem, &value);
	if (err)
		return err;
	*ret = *value;
	drgn_object_deinit_value(obj, value);
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_read_float(const struct drgn_object *obj, double *ret)
{
	if (obj->encoding != DRGN_OBJECT_ENCODING_FLOAT) {
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "not floating-point");
	}
	return drgn_object_value_float(obj, ret);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_read_c_string(const struct drgn_object *obj, char **ret)
{
	struct drgn_error *err;
	struct drgn_type *underlying_type;
	uint64_t address;
	size_t max_size;

	underlying_type = drgn_underlying_type(obj->type);
	switch (drgn_type_kind(underlying_type)) {
	case DRGN_TYPE_POINTER:
		err = drgn_object_value_unsigned(obj, &address);
		if (err)
			return err;
		max_size = SIZE_MAX;
		break;
	case DRGN_TYPE_ARRAY:
		if (drgn_type_is_complete(underlying_type)) {
			uint64_t size;

			err = drgn_type_sizeof(underlying_type, &size);
			if (err)
				return err;
			max_size = min(size, (uint64_t)SIZE_MAX);
		} else {
			max_size = SIZE_MAX;
		}
		SWITCH_ENUM(obj->kind) {
		case DRGN_OBJECT_VALUE: {
			const char *buf;
			uint64_t value_size;
			size_t len;
			char *p, *str;

			buf = drgn_object_buffer(obj);
			value_size = drgn_object_size(obj);
			len = min(value_size, (uint64_t)max_size);
			p = memchr(buf, 0, len);
			if (p)
				len = p - buf;
			str = malloc(len + 1);
			if (!str)
				return &drgn_enomem;
			memcpy(str, buf, len);
			str[len] = '\0';
			*ret = str;
			return NULL;
		}
		case DRGN_OBJECT_REFERENCE:
			address = obj->address;
			break;
		case DRGN_OBJECT_ABSENT:
			return &drgn_error_object_absent;
		default:
			UNREACHABLE();
		}
		break;
	default:
		return drgn_type_error("string() argument must be an array or pointer, not '%s'",
				       obj->type);
	}

	return drgn_program_read_c_string(drgn_object_program(obj), address,
					  false, max_size, ret);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_format_object(const struct drgn_object *obj,
		   const struct drgn_format_object_options *options,
		   char **ret)
{

	const struct drgn_language *lang = drgn_object_language(obj);

	if (options) {
		if (options->flags & ~DRGN_FORMAT_OBJECT_VALID_FLAGS) {
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "invalid format object flags");
		}
		if (options->integer_base != 8
		    && options->integer_base != 10
		    && options->integer_base != 16) {
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "invalid integer base");
		}
	} else {
		static const struct drgn_format_object_options default_options = {
			.columns = SIZE_MAX,
			.flags = DRGN_FORMAT_OBJECT_PRETTY,
			.integer_base = 10,
		};
		options = &default_options;
	}
	return lang->format_object(obj, options, ret);
}

static struct drgn_error *
drgn_object_convert_signed(const struct drgn_object *obj, uint64_t bit_size,
			   int64_t *ret)
{
	struct drgn_error *err;
	union drgn_value value_mem;
	const union drgn_value *value;

	err = drgn_object_read_value(obj, &value_mem, &value);
	if (err)
		return err;
	switch (obj->encoding) {
	case DRGN_OBJECT_ENCODING_SIGNED:
	case DRGN_OBJECT_ENCODING_UNSIGNED:
		*ret = truncate_signed(value->svalue, bit_size);
		break;
	case DRGN_OBJECT_ENCODING_FLOAT:
		*ret = truncate_signed(value->fvalue, bit_size);
		break;
	case DRGN_OBJECT_ENCODING_SIGNED_BIG:
	case DRGN_OBJECT_ENCODING_UNSIGNED_BIG:
		return &drgn_integer_too_big;
	default:
		err = drgn_error_create(DRGN_ERROR_TYPE,
					"object cannot be converted to integer");
		break;
	}
	drgn_object_deinit_value(obj, value);
	return err;
}

static struct drgn_error *
drgn_object_convert_unsigned(const struct drgn_object *obj, uint64_t bit_size,
			     uint64_t *ret)
{
	struct drgn_error *err;
	union drgn_value value_mem;
	const union drgn_value *value;

	err = drgn_object_read_value(obj, &value_mem, &value);
	if (err)
		return err;
	switch (obj->encoding) {
	case DRGN_OBJECT_ENCODING_SIGNED:
	case DRGN_OBJECT_ENCODING_UNSIGNED:
		*ret = truncate_unsigned(value->uvalue, bit_size);
		break;
	case DRGN_OBJECT_ENCODING_FLOAT:
		*ret = truncate_unsigned(value->fvalue, bit_size);
		break;
	case DRGN_OBJECT_ENCODING_SIGNED_BIG:
	case DRGN_OBJECT_ENCODING_UNSIGNED_BIG:
		return &drgn_integer_too_big;
	default:
		err = drgn_error_create(DRGN_ERROR_TYPE,
					"object cannot be converted to integer");
		break;
	}
	drgn_object_deinit_value(obj, value);
	return err;
}

static struct drgn_error *
drgn_object_convert_float(const struct drgn_object *obj, double *fvalue)
{
	struct drgn_error *err;
	union drgn_value value_mem;
	const union drgn_value *value;

	err = drgn_object_read_value(obj, &value_mem, &value);
	if (err)
		return err;
	switch (obj->encoding) {
	case DRGN_OBJECT_ENCODING_SIGNED:
		*fvalue = value->svalue;
		break;
	case DRGN_OBJECT_ENCODING_UNSIGNED:
		*fvalue = value->uvalue;
		break;
	case DRGN_OBJECT_ENCODING_FLOAT:
		*fvalue = value->fvalue;
		break;
	case DRGN_OBJECT_ENCODING_SIGNED_BIG:
	case DRGN_OBJECT_ENCODING_UNSIGNED_BIG:
		return &drgn_integer_too_big;
	default:
		err = drgn_error_create(DRGN_ERROR_TYPE,
					"object cannot be converted to floating-point");
		break;
	}
	drgn_object_deinit_value(obj, value);
	return err;
}

static struct drgn_error *
drgn_object_is_zero_impl(const struct drgn_object *obj, bool *ret);

static struct drgn_error *
drgn_compound_object_is_zero(const struct drgn_object *obj,
			     struct drgn_type *underlying_type, bool *ret)
{
	struct drgn_error *err;
	struct drgn_type_member *members;
	size_t num_members, i;

	DRGN_OBJECT(member, drgn_object_program(obj));
	members = drgn_type_members(underlying_type);
	num_members = drgn_type_num_members(underlying_type);
	for (i = 0; i < num_members; i++) {
		struct drgn_qualified_type member_type;
		uint64_t member_bit_field_size;
		err = drgn_member_type(&members[i], &member_type,
				       &member_bit_field_size);
		if (err)
			return err;

		err = drgn_object_fragment(&member, obj, member_type,
					   members[i].bit_offset,
					   member_bit_field_size);
		if (err)
			return err;

		err = drgn_object_is_zero_impl(&member, ret);
		if (err || !*ret)
			return err;
	}
	return NULL;
}

static struct drgn_error *
drgn_array_object_is_zero(const struct drgn_object *obj,
			  struct drgn_type *underlying_type, bool *ret)
{
	struct drgn_error *err;
	struct drgn_qualified_type element_type;
	uint64_t element_bit_size, length, i;

	element_type = drgn_type_type(underlying_type);
	err = drgn_type_bit_size(element_type.type, &element_bit_size);
	if (err)
		return err;

	DRGN_OBJECT(element, drgn_object_program(obj));
	length = drgn_type_length(underlying_type);
	for (i = 0; i < length; i++) {
		err = drgn_object_fragment(&element, obj, element_type,
					   i * element_bit_size, 0);
		if (err)
			return err;

		err = drgn_object_is_zero_impl(&element, ret);
		if (err || !*ret)
			return err;
	}
	return NULL;
}

static struct drgn_error *
drgn_object_is_zero_impl(const struct drgn_object *obj, bool *ret)
{
	struct drgn_error *err;

	switch (obj->encoding) {
	case DRGN_OBJECT_ENCODING_SIGNED: {
		int64_t svalue;

		err = drgn_object_value_signed(obj, &svalue);
		if (err)
			return err;
		if (svalue)
			*ret = false;
		return NULL;
	}
	case DRGN_OBJECT_ENCODING_UNSIGNED: {
		uint64_t uvalue;

		err = drgn_object_value_unsigned(obj, &uvalue);
		if (err)
			return err;
		if (uvalue)
			*ret = false;
		return NULL;
	}
	case DRGN_OBJECT_ENCODING_SIGNED_BIG:
	case DRGN_OBJECT_ENCODING_UNSIGNED_BIG: {
		union drgn_value value_mem;
		const union drgn_value *value;
		err = drgn_object_read_value(obj, &value_mem, &value);
		if (err)
			return err;
		size_t size = drgn_object_size(obj);
		for (size_t i = 0; i < size; i++) {
			if (value->bufp[i] != 0) {
				*ret = false;
				break;
			}
		}
		drgn_object_deinit_value(obj, value);
		return NULL;
	}
	case DRGN_OBJECT_ENCODING_FLOAT: {
		double fvalue;

		err = drgn_object_value_float(obj, &fvalue);
		if (err)
			return err;
		if (fvalue)
			*ret = false;
		return NULL;
	}
	case DRGN_OBJECT_ENCODING_BUFFER: {
		struct drgn_type *underlying_type;

		underlying_type = drgn_underlying_type(obj->type);
		switch (drgn_type_kind(underlying_type)) {
		case DRGN_TYPE_STRUCT:
		case DRGN_TYPE_UNION:
		case DRGN_TYPE_CLASS:
			return drgn_compound_object_is_zero(obj,
							    underlying_type,
							    ret);
		case DRGN_TYPE_ARRAY:
			return drgn_array_object_is_zero(obj, underlying_type,
							 ret);
		default:
			break;
		}
		fallthrough;
	}
	default:
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "object cannot be converted to boolean");
	}
}

struct drgn_error *drgn_object_is_zero(const struct drgn_object *obj, bool *ret)
{
	*ret = true;
	return drgn_object_is_zero_impl(obj, ret);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_cast(struct drgn_object *res,
		 struct drgn_qualified_type qualified_type,
		 const struct drgn_object *obj)
{
	const struct drgn_language *lang = drgn_type_language(qualified_type.type);

	if (drgn_object_program(res) != drgn_object_program(obj)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "objects are from different programs");
	}
	return lang->op_cast(res, qualified_type, obj);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_implicit_convert(struct drgn_object *res,
			     struct drgn_qualified_type qualified_type,
			     const struct drgn_object *obj)
{
	const struct drgn_language *lang = drgn_type_language(qualified_type.type);

	if (drgn_object_program(res) != drgn_object_program(obj)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "objects are from different programs");
	}
	return lang->op_implicit_convert(res, qualified_type, obj);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_reinterpret(struct drgn_object *res,
			struct drgn_qualified_type qualified_type,
			const struct drgn_object *obj)
{
	return drgn_object_fragment(res, obj, qualified_type, 0, 0);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_integer_literal(struct drgn_object *res, uint64_t uvalue)
{
	const struct drgn_language *lang =
		drgn_program_language(drgn_object_program(res));
	return lang->integer_literal(res, uvalue);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_bool_literal(struct drgn_object *res, bool bvalue)
{
	const struct drgn_language *lang =
		drgn_program_language(drgn_object_program(res));
	return lang->bool_literal(res, bvalue);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_float_literal(struct drgn_object *res, double fvalue)
{
	const struct drgn_language *lang =
		drgn_program_language(drgn_object_program(res));
	return lang->float_literal(res, fvalue);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_bool(const struct drgn_object *obj, bool *ret)
{
	const struct drgn_language *lang = drgn_object_language(obj);

	return lang->op_bool(obj, ret);
}

LIBDRGN_PUBLIC struct drgn_error *drgn_object_cmp(const struct drgn_object *lhs,
						  const struct drgn_object *rhs,
						  int *ret)
{
	const struct drgn_language *lang = drgn_object_language(lhs);
	if (drgn_object_program(lhs) != drgn_object_program(rhs)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "objects are from different programs");
	}
	return lang->op_cmp(lhs, rhs, ret);
}

struct drgn_error *drgn_error_binary_op(const char *op_name,
					struct drgn_operand_type *lhs_type,
					struct drgn_operand_type *rhs_type)
{
	struct drgn_error *err;
	_cleanup_free_ char *lhs_type_name = NULL;
	err = drgn_format_type_name(drgn_operand_type_qualified(lhs_type),
				    &lhs_type_name);
	if (err)
		return err;
	_cleanup_free_ char *rhs_type_name = NULL;
	err = drgn_format_type_name(drgn_operand_type_qualified(rhs_type),
				    &rhs_type_name);
	if (err)
		return err;
	return drgn_error_format(DRGN_ERROR_TYPE,
				 "invalid operands to %s ('%s' and '%s')",
				 op_name, lhs_type_name, rhs_type_name);

}

struct drgn_error *drgn_error_unary_op(const char *op_name,
				       struct drgn_operand_type *type)
{
	struct drgn_error *err;
	_cleanup_free_ char *type_name = NULL;
	err = drgn_format_type_name(drgn_operand_type_qualified(type),
				    &type_name);
	if (err)
		return err;
	return drgn_error_format(DRGN_ERROR_TYPE,
				 "invalid operand to %s ('%s')", op_name,
				 type_name);
}

#define BINARY_OP(op_name)							\
LIBDRGN_PUBLIC struct drgn_error *						\
drgn_object_##op_name(struct drgn_object *res, const struct drgn_object *lhs,	\
		      const struct drgn_object *rhs)				\
{										\
	const struct drgn_language *lang = drgn_object_language(lhs);		\
										\
	if (drgn_object_program(lhs) != drgn_object_program(res) ||		\
	    drgn_object_program(rhs) != drgn_object_program(res)) {		\
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,		\
					 "objects are from different programs");\
	}									\
	if (!lang->op_##op_name) {						\
		return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,		\
					 "%s does not implement " #op_name,	\
					 lang->name);				\
	}									\
	return lang->op_##op_name(res, lhs, rhs);				\
}
BINARY_OP(add)
BINARY_OP(sub)
BINARY_OP(mul)
BINARY_OP(div)
BINARY_OP(mod)
BINARY_OP(lshift)
BINARY_OP(rshift)
BINARY_OP(and)
BINARY_OP(or)
BINARY_OP(xor)
#undef BINARY_OP

#define UNARY_OP(op_name)							\
LIBDRGN_PUBLIC struct drgn_error *						\
drgn_object_##op_name(struct drgn_object *res, const struct drgn_object *obj)	\
{										\
	const struct drgn_language *lang = drgn_object_language(obj);		\
										\
	if (drgn_object_program(res) != drgn_object_program(obj)) {		\
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,		\
					 "objects are from different programs");\
	}									\
	if (!lang->op_##op_name) {						\
		return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,		\
					 "%s does not implement " #op_name,	\
					 lang->name);				\
	}									\
	return lang->op_##op_name(res, obj);					\
}
UNARY_OP(pos)
UNARY_OP(neg)
UNARY_OP(not)
#undef UNARY_OP

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_address_of(struct drgn_object *res, const struct drgn_object *obj)
{
	if (drgn_object_program(res) != drgn_object_program(obj)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "objects are from different programs");
	}

	SWITCH_ENUM(obj->kind) {
	case DRGN_OBJECT_VALUE:
		return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
					 "cannot take address of value");
	case DRGN_OBJECT_REFERENCE:
		break;
	case DRGN_OBJECT_ABSENT:
		return &drgn_error_object_absent;
	default:
		UNREACHABLE();
	}

	if (obj->is_bit_field || obj->bit_offset) {
		return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
					 "cannot take address of bit field");
	}

	struct drgn_qualified_type qualified_type =
		drgn_object_qualified_type(obj);
	uint8_t address_size;
	struct drgn_error *err =
		drgn_program_address_size(drgn_object_program(obj),
					  &address_size);
	if (err)
		return err;
	struct drgn_qualified_type result_type;
	err = drgn_pointer_type_create(drgn_object_program(obj), qualified_type,
				       address_size, DRGN_PROGRAM_ENDIAN,
				       drgn_type_language(qualified_type.type),
				       &result_type.type);
	if (err)
		return err;
	result_type.qualifiers = 0;
	return drgn_object_set_unsigned(res, result_type,
					obj->address, 0);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_subscript(struct drgn_object *res, const struct drgn_object *obj,
		      int64_t index)
{
	struct drgn_error *err;
	struct drgn_element_info element;

	if (drgn_object_program(res) != drgn_object_program(obj)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "objects are from different programs");
	}

	err = drgn_program_element_info(drgn_object_program(obj), obj->type,
					&element);
	if (err)
		return err;

	if (obj->encoding == DRGN_OBJECT_ENCODING_UNSIGNED) {
		return drgn_object_dereference_offset(res, obj,
						      element.qualified_type,
						      index * element.bit_size,
						      0);
	} else {
		return drgn_object_fragment(res, obj, element.qualified_type,
					    index * element.bit_size, 0);
	}
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_object_slice(struct drgn_object *res,
				     const struct drgn_object *obj,
				     int64_t start, int64_t end)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_object_program(obj);

	if (drgn_object_program(res) != prog) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "objects are from different programs");
	}

	struct drgn_element_info element;
	err = drgn_program_element_info(drgn_object_program(obj), obj->type,
					&element);
	if (err)
		return err;

	struct drgn_qualified_type array_type;
	err = drgn_array_type_create(prog, element.qualified_type,
				     end > start ? end - start : 0,
				     drgn_type_language(element.qualified_type.type),
				     &array_type.type);
	if (err)
		return err;
	array_type.qualifiers = 0;

	if (obj->encoding == DRGN_OBJECT_ENCODING_UNSIGNED) {
		return drgn_object_dereference_offset(res, obj, array_type,
						      start * element.bit_size,
						      0);
	} else {
		return drgn_object_fragment(res, obj, array_type,
					    start * element.bit_size, 0);
	}
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_member(struct drgn_object *res, const struct drgn_object *obj,
		   const char *member_name)
{
	struct drgn_error *err;

	if (drgn_object_program(res) != drgn_object_program(obj)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "objects are from different programs");
	}

	struct drgn_type_member *member;
	uint64_t member_bit_offset;
	err = drgn_type_find_member(obj->type, member_name, &member,
				    &member_bit_offset);
	if (err)
		return err;
	struct drgn_qualified_type member_type;
	uint64_t member_bit_field_size;
	err = drgn_member_type(member, &member_type, &member_bit_field_size);
	if (err)
		return err;
	return drgn_object_fragment(res, obj, member_type, member_bit_offset,
				    member_bit_field_size);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_member_dereference(struct drgn_object *res,
			       const struct drgn_object *obj,
			       const char *member_name)
{
	struct drgn_error *err;

	if (drgn_object_program(res) != drgn_object_program(obj)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "objects are from different programs");
	}

	struct drgn_type *underlying_type = drgn_underlying_type(obj->type);
	if (drgn_type_kind(underlying_type) != DRGN_TYPE_POINTER) {
		return drgn_type_error("'%s' is not a pointer to a structure, union, or class",
				       obj->type);
	}

	struct drgn_type_member *member;
	uint64_t member_bit_offset;
	err = drgn_type_find_member(drgn_type_type(underlying_type).type,
				    member_name, &member, &member_bit_offset);
	if (err)
		return err;
	struct drgn_qualified_type member_type;
	uint64_t member_bit_field_size;
	err = drgn_member_type(member, &member_type, &member_bit_field_size);
	if (err)
		return err;
	return drgn_object_dereference_offset(res, obj, member_type,
					      member_bit_offset,
					      member_bit_field_size);
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_object_subobject(struct drgn_object *res,
					 const struct drgn_object *obj,
					 const char *designator)
{
	struct drgn_error *err;
	const struct drgn_language *lang = drgn_object_language(obj);
	struct drgn_qualified_type qualified_type;
	uint64_t bit_offset, bit_field_size;
	err = lang->type_subobject(obj->type, designator, false,
				   &qualified_type, &bit_offset,
				   &bit_field_size);
	if (err)
		return err;
	return drgn_object_fragment(res, obj, qualified_type, bit_offset,
				    bit_field_size);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_container_of(struct drgn_object *res, const struct drgn_object *obj,
			 struct drgn_qualified_type qualified_type,
			 const char *member_designator)
{
	struct drgn_error *err;

	if (drgn_object_program(res) != drgn_object_program(obj)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "objects are from different programs");
	}

	if (drgn_type_kind(drgn_underlying_type(obj->type)) !=
	    DRGN_TYPE_POINTER) {
		return drgn_type_error("container_of() argument must be a pointer, not '%s'",
				       obj->type);
	}

	uint64_t offset;
	err = drgn_type_offsetof(qualified_type.type, member_designator,
				 &offset);
	if (err)
		return err;

	uint64_t address;
	err = drgn_object_value_unsigned(obj, &address);
	if (err)
		return err;

	uint8_t address_size;
	err = drgn_program_address_size(drgn_object_program(obj),
					&address_size);
	if (err)
		return err;
	struct drgn_qualified_type result_type;
	err = drgn_pointer_type_create(drgn_object_program(obj), qualified_type,
				       address_size, DRGN_PROGRAM_ENDIAN,
				       drgn_type_language(qualified_type.type),
				       &result_type.type);
	if (err)
		return err;
	result_type.qualifiers = 0;
	return drgn_object_set_unsigned(res, result_type, address - offset, 0);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_sizeof(const struct drgn_object *obj, uint64_t *ret)
{
	if (obj->is_bit_field) {
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "cannot get size of bit field");
	}
	return drgn_type_sizeof(obj->type, ret);
}

static inline struct drgn_error *
binary_operands_signed(const struct drgn_object *lhs,
		       const struct drgn_object *rhs, uint64_t bit_size,
		       int64_t *lhs_ret, int64_t *rhs_ret)
{
	struct drgn_error *err;

	err = drgn_object_convert_signed(lhs, bit_size, lhs_ret);
	if (err)
		return err;
	return drgn_object_convert_signed(rhs, bit_size, rhs_ret);
}

static inline struct drgn_error *
binary_operands_unsigned(const struct drgn_object *lhs,
			 const struct drgn_object *rhs, uint64_t bit_size,
			 uint64_t *lhs_ret, uint64_t *rhs_ret)
{
	struct drgn_error *err;

	err = drgn_object_convert_unsigned(lhs, bit_size, lhs_ret);
	if (err)
		return err;
	return drgn_object_convert_unsigned(rhs, bit_size, rhs_ret);
}

static inline struct drgn_error *
binary_operands_float(const struct drgn_object *lhs,
		      const struct drgn_object *rhs, double *lhs_ret,
		      double *rhs_ret)
{
	struct drgn_error *err;

	err = drgn_object_convert_float(lhs, lhs_ret);
	if (err)
		return err;
	return drgn_object_convert_float(rhs, rhs_ret);
}

static struct drgn_error *pointer_operand(const struct drgn_object *ptr,
					  uint64_t *ret)
{
	switch (ptr->encoding) {
	case DRGN_OBJECT_ENCODING_UNSIGNED:
		return drgn_object_value_unsigned(ptr, ret);
	case DRGN_OBJECT_ENCODING_SIGNED_BIG:
	case DRGN_OBJECT_ENCODING_UNSIGNED_BIG:
		return &drgn_integer_too_big;
	case DRGN_OBJECT_ENCODING_BUFFER:
	case DRGN_OBJECT_ENCODING_NONE:
	case DRGN_OBJECT_ENCODING_INCOMPLETE_BUFFER:
		SWITCH_ENUM(ptr->kind) {
		case DRGN_OBJECT_VALUE:
			return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
						 "cannot get address of value");
		case DRGN_OBJECT_REFERENCE:
			*ret = ptr->address;
			return NULL;
		case DRGN_OBJECT_ABSENT:
			return &drgn_error_object_absent;
		default:
			UNREACHABLE();
		}
	default:
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "invalid operand type for pointer arithmetic");
	}
}

struct drgn_error *drgn_op_cast(struct drgn_object *res,
				const struct drgn_object_type *type,
				const struct drgn_object *obj,
				const struct drgn_operand_type *obj_type)
{
	struct drgn_error *err;

	bool is_pointer = (drgn_type_kind(obj_type->underlying_type) ==
			   DRGN_TYPE_POINTER);
	switch (type->encoding) {
	case DRGN_OBJECT_ENCODING_BUFFER:
		return drgn_qualified_type_error("cannot cast to '%s'",
						 drgn_object_type_qualified(type));
	case DRGN_OBJECT_ENCODING_SIGNED: {
		union {
			int64_t svalue;
			uint64_t uvalue;
		} tmp;
		if (is_pointer) {
			err = pointer_operand(obj, &tmp.uvalue);
		} else {
			err = drgn_object_convert_signed(obj, type->bit_size,
							 &tmp.svalue);
		}
		if (err)
			goto err;
		return drgn_object_set_signed_internal(res, type, tmp.svalue);
	}
	case DRGN_OBJECT_ENCODING_UNSIGNED: {
		uint64_t uvalue;
		if (is_pointer) {
			err = pointer_operand(obj, &uvalue);
		} else {
			err = drgn_object_convert_unsigned(obj, type->bit_size,
							   &uvalue);
		}
		if (err)
			goto err;
		return drgn_object_set_unsigned_internal(res, type, uvalue);
	}
	case DRGN_OBJECT_ENCODING_FLOAT: {
		if (is_pointer)
			goto type_error;

		double fvalue;
		err = drgn_object_convert_float(obj, &fvalue);
		if (err)
			goto err;
		return drgn_object_set_float_internal(res, type, fvalue);
	}
	default:
		if (!drgn_object_encoding_is_complete(type->encoding)) {
			return drgn_error_incomplete_type("cannot cast to %s type",
							  type->type);
		}
		goto type_error;
	}

err:
	if (err->code == DRGN_ERROR_TYPE) {
		drgn_error_destroy(err);
		goto type_error;
	}
	return err;

type_error:
	return drgn_2_qualified_types_error("cannot convert '%s' to '%s'",
					    drgn_operand_type_qualified(obj_type),
					    drgn_object_type_qualified(type));
}

/*
 * Two's complement operator. Avoid undefined/implementation-defined behavior
 * (due to overflow or signed integer representation) for an arithmetic or
 * bitwise operator by doing the operation on unsigned operands and then
 * converting back to a signed integer.
 */
#define BINARY_OP_SIGNED_2C(res, type, lhs, op, rhs) ({				\
	struct drgn_error *_err;						\
	const struct drgn_object_type *_type = (type);				\
	union {									\
		int64_t svalue;							\
		uint64_t uvalue;						\
	} lhs_tmp, rhs_tmp, tmp;						\
	_err = binary_operands_signed((lhs), (rhs), _type->bit_size,		\
				      &lhs_tmp.svalue, &rhs_tmp.svalue);	\
	if (!_err) {								\
		tmp.uvalue = lhs_tmp.uvalue op rhs_tmp.uvalue;			\
		_err = drgn_object_set_signed_internal((res), _type,		\
						       tmp.svalue);		\
	}									\
	_err;									\
})

#define BINARY_OP_UNSIGNED(res, type, lhs, op, rhs) ({				\
	struct drgn_error *_err;						\
	const struct drgn_object_type *_type = (type);				\
	uint64_t lhs_uvalue, rhs_uvalue;					\
										\
	_err = binary_operands_unsigned((lhs), (rhs), _type->bit_size,		\
					&lhs_uvalue, &rhs_uvalue);		\
	if (!_err) {								\
		_err = drgn_object_set_unsigned_internal((res), _type,		\
							 lhs_uvalue op rhs_uvalue);\
	}									\
	_err;									\
})

#define BINARY_OP_FLOAT(res, type, lhs, op, rhs) ({				\
	struct drgn_error *_err;						\
	double lhs_fvalue, rhs_fvalue;						\
	_err = binary_operands_float((lhs), (rhs), &lhs_fvalue, &rhs_fvalue);	\
	if (!_err) {								\
		_err = drgn_object_set_float_internal((res), (type),		\
					              lhs_fvalue op rhs_fvalue);\
	}									\
	_err;									\
})

#define CMP(lhs, rhs) ({				\
	__auto_type _lhs = (lhs);			\
	__auto_type _rhs = (rhs);			\
							\
	(_lhs > _rhs ? 1 : _lhs < _rhs ? -1 : 0);	\
})

struct drgn_error *drgn_op_cmp_impl(const struct drgn_object *lhs,
				    const struct drgn_object *rhs,
				    const struct drgn_operand_type *op_type,
				    int *ret)
{
	struct drgn_error *err;

	struct drgn_object_type type;
	err = drgn_object_type_operand(op_type, &type);
	if (err)
		return err;

	switch (type.encoding) {
	case DRGN_OBJECT_ENCODING_SIGNED: {
		int64_t lhs_svalue, rhs_svalue;
		err = binary_operands_signed(lhs, rhs, type.bit_size,
					     &lhs_svalue, &rhs_svalue);
		if (err)
			return err;
		*ret = CMP(lhs_svalue, rhs_svalue);
		return NULL;
	}
	case DRGN_OBJECT_ENCODING_UNSIGNED: {
		uint64_t lhs_uvalue, rhs_uvalue;
		err = binary_operands_unsigned(lhs, rhs, type.bit_size,
					       &lhs_uvalue, &rhs_uvalue);
		if (err)
			return err;
		*ret = CMP(lhs_uvalue, rhs_uvalue);
		return NULL;
	}
	case DRGN_OBJECT_ENCODING_FLOAT: {
		double lhs_fvalue, rhs_fvalue;
		err = binary_operands_float(lhs, rhs, &lhs_fvalue, &rhs_fvalue);
		if (err)
			return err;
		*ret = CMP(lhs_fvalue, rhs_fvalue);
		return NULL;
	}
	default:
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "invalid operand type for cmp");
	}
}

struct drgn_error *drgn_op_cmp_pointers(const struct drgn_object *lhs,
					const struct drgn_object *rhs, int *ret)
{
	struct drgn_error *err;
	uint64_t lhs_value, rhs_value;

	err = pointer_operand(lhs, &lhs_value);
	if (err)
		return err;
	err = pointer_operand(rhs, &rhs_value);
	if (err)
		return err;

	*ret = CMP(lhs_value, rhs_value);
	return NULL;
}

#undef CMP

#define ARITHMETIC_BINARY_OP(op_name, op)					\
struct drgn_error *								\
drgn_op_##op_name##_impl(struct drgn_object *res,				\
			 const struct drgn_operand_type *op_type,		\
			 const struct drgn_object *lhs,				\
			 const struct drgn_object *rhs)				\
{										\
	struct drgn_error *err;							\
	struct drgn_object_type type;						\
	err = drgn_object_type_operand(op_type, &type);				\
	if (err)								\
		return err;							\
	switch (type.encoding) {						\
	case DRGN_OBJECT_ENCODING_SIGNED:					\
		return BINARY_OP_SIGNED_2C(res, &type, lhs, op, rhs);		\
	case DRGN_OBJECT_ENCODING_UNSIGNED:					\
		return BINARY_OP_UNSIGNED(res, &type, lhs, op, rhs);		\
	case DRGN_OBJECT_ENCODING_FLOAT:					\
		return BINARY_OP_FLOAT(res, &type, lhs, op, rhs);		\
	default:								\
		return drgn_error_create(DRGN_ERROR_TYPE,			\
					 "invalid result type for " #op_name);	\
	}									\
}
ARITHMETIC_BINARY_OP(add, +)
ARITHMETIC_BINARY_OP(sub, -)
#undef ARITHMETIC_BINARY_OP

struct drgn_error *
drgn_op_add_to_pointer(struct drgn_object *res,
		       const struct drgn_operand_type *op_type,
		       uint64_t referenced_size, bool negate,
		       const struct drgn_object *ptr,
		       const struct drgn_object *index)
{
	struct drgn_error *err;

	struct drgn_object_type type;
	err = drgn_object_type_operand(op_type, &type);
	if (err)
		return err;
	if (type.encoding != DRGN_OBJECT_ENCODING_UNSIGNED) {
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "invalid result type for pointer arithmetic");
	}

	uint64_t ptr_value;
	err = pointer_operand(ptr, &ptr_value);
	if (err)
		return err;

	uint64_t index_value;
	switch (index->encoding) {
	case DRGN_OBJECT_ENCODING_SIGNED: {
		int64_t svalue;
		err = drgn_object_value_signed(index, &svalue);
		if (err)
			return err;
		if (svalue >= 0) {
			index_value = svalue;
		} else {
			index_value = -svalue;
			negate = !negate;
		}
		break;
	}
	case DRGN_OBJECT_ENCODING_UNSIGNED:
		err = drgn_object_value_unsigned(index, &index_value);
		if (err)
			return err;
		break;
	case DRGN_OBJECT_ENCODING_SIGNED_BIG:
	case DRGN_OBJECT_ENCODING_UNSIGNED_BIG:
		return &drgn_integer_too_big;
	default:
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "invalid addend type for pointer arithmetic");
	}

	if (negate)
		ptr_value -= index_value * referenced_size;
	else
		ptr_value += index_value * referenced_size;
	return drgn_object_set_unsigned_internal(res, &type, ptr_value);
}

struct drgn_error *drgn_op_sub_pointers(struct drgn_object *res,
					const struct drgn_operand_type *op_type,
					uint64_t referenced_size,
					const struct drgn_object *lhs,
					const struct drgn_object *rhs)
{
	struct drgn_error *err;

	if (!referenced_size) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "object size must not be zero");
	}

	struct drgn_object_type type;
	err = drgn_object_type_operand(op_type, &type);
	if (err)
		return err;
	if (type.encoding != DRGN_OBJECT_ENCODING_SIGNED) {
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "invalid result type for pointer subtraction");
	}

	uint64_t lhs_value, rhs_value;
	err = pointer_operand(lhs, &lhs_value);
	if (err)
		return err;
	err = pointer_operand(rhs, &rhs_value);
	if (err)
		return err;

	int64_t diff;
	if (lhs_value >= rhs_value)
		diff = (lhs_value - rhs_value) / referenced_size;
	else
		diff = -((rhs_value - lhs_value) / referenced_size);
	return drgn_object_set_signed_internal(res, &type, diff);
}

struct drgn_error *drgn_op_mul_impl(struct drgn_object *res,
				    const struct drgn_operand_type *op_type,
				    const struct drgn_object *lhs,
				    const struct drgn_object *rhs)
{
	struct drgn_error *err;

	struct drgn_object_type type;
	err = drgn_object_type_operand(op_type, &type);
	if (err)
		return err;

	switch (type.encoding) {
	case DRGN_OBJECT_ENCODING_SIGNED: {
		int64_t lhs_svalue, rhs_svalue;
		err = binary_operands_signed(lhs, rhs, type.bit_size,
					     &lhs_svalue, &rhs_svalue);
		if (err)
			return err;

		/*
		 * Convert to sign and magnitude to avoid signed integer
		 * overflow.
		 */
		bool lhs_negative = lhs_svalue < 0;
		uint64_t lhs_uvalue = lhs_negative ? -lhs_svalue : lhs_svalue;
		bool rhs_negative = rhs_svalue < 0;
		uint64_t rhs_uvalue = rhs_negative ? -rhs_svalue : rhs_svalue;
		union {
			int64_t svalue;
			uint64_t uvalue;
		} tmp;
		tmp.uvalue = lhs_uvalue * rhs_uvalue;
		if (lhs_negative != rhs_negative)
			tmp.uvalue = -tmp.uvalue;
		return drgn_object_set_signed_internal(res, &type, tmp.svalue);
	}
	case DRGN_OBJECT_ENCODING_UNSIGNED:
		return BINARY_OP_UNSIGNED(res, &type, lhs, *, rhs);
	case DRGN_OBJECT_ENCODING_FLOAT:
		return BINARY_OP_FLOAT(res, &type, lhs, *, rhs);
	default:
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "invalid result type for mul");
	}
}

static struct drgn_error drgn_zero_division = {
	.code = DRGN_ERROR_ZERO_DIVISION,
	.message = "division by zero",
};

struct drgn_error *drgn_op_div_impl(struct drgn_object *res,
				    const struct drgn_operand_type *op_type,
				    const struct drgn_object *lhs,
				    const struct drgn_object *rhs)
{
	struct drgn_error *err;

	struct drgn_object_type type;
	err = drgn_object_type_operand(op_type, &type);
	if (err)
		return err;

	switch (type.encoding) {
	case DRGN_OBJECT_ENCODING_SIGNED: {
		int64_t lhs_svalue, rhs_svalue;
		err = binary_operands_signed(lhs, rhs, type.bit_size,
					     &lhs_svalue, &rhs_svalue);
		if (err)
			return err;
		if (!rhs_svalue)
			return &drgn_zero_division;
		return drgn_object_set_signed_internal(res, &type,
						       lhs_svalue / rhs_svalue);
	}
	case DRGN_OBJECT_ENCODING_UNSIGNED: {
		uint64_t lhs_uvalue, rhs_uvalue;
		err = binary_operands_unsigned(lhs, rhs, type.bit_size,
					       &lhs_uvalue, &rhs_uvalue);
		if (err)
			return err;
		if (!rhs_uvalue)
			return &drgn_zero_division;
		return drgn_object_set_unsigned_internal(res, &type,
							 lhs_uvalue / rhs_uvalue);
	}
	case DRGN_OBJECT_ENCODING_FLOAT: {
		double lhs_fvalue, rhs_fvalue;
		err = binary_operands_float(lhs, rhs, &lhs_fvalue, &rhs_fvalue);
		if (err)
			return err;
		if (!rhs_fvalue)
			return &drgn_zero_division;
		return drgn_object_set_float_internal(res, &type,
					              lhs_fvalue / rhs_fvalue);
	}
	default:
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "invalid result type for div");
	}
}

struct drgn_error *drgn_op_mod_impl(struct drgn_object *res,
				    const struct drgn_operand_type *op_type,
				    const struct drgn_object *lhs,
				    const struct drgn_object *rhs)
{
	struct drgn_error *err;

	struct drgn_object_type type;
	err = drgn_object_type_operand(op_type, &type);
	if (err)
		return err;

	switch (type.encoding) {
	case DRGN_OBJECT_ENCODING_SIGNED: {
		int64_t lhs_svalue, rhs_svalue;
		err = binary_operands_signed(lhs, rhs, type.bit_size,
					     &lhs_svalue, &rhs_svalue);
		if (err)
			return err;
		if (!rhs_svalue)
			return &drgn_zero_division;
		return drgn_object_set_signed_internal(res, &type,
						       lhs_svalue % rhs_svalue);
	}
	case DRGN_OBJECT_ENCODING_UNSIGNED: {
		uint64_t lhs_uvalue, rhs_uvalue;
		err = binary_operands_unsigned(lhs, rhs, type.bit_size,
					       &lhs_uvalue, &rhs_uvalue);
		if (err)
			return err;
		if (!rhs_uvalue)
			return &drgn_zero_division;
		return drgn_object_set_unsigned_internal(res, &type,
							 lhs_uvalue % rhs_uvalue);
	}
	default:
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "invalid result type for mod");
	}
}

static struct drgn_error *shift_operand(const struct drgn_object *rhs,
					const struct drgn_operand_type *rhs_type,
					uint64_t *ret)
{
	struct drgn_error *err;

	struct drgn_object_type type;
	err = drgn_object_type_operand(rhs_type, &type);
	if (err)
		return err;

	switch (type.encoding) {
	case DRGN_OBJECT_ENCODING_SIGNED: {
		int64_t rhs_svalue;
		err = drgn_object_convert_signed(rhs, type.bit_size,
						 &rhs_svalue);
		if (err)
			return err;
		if (rhs_svalue < 0) {
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "negative shift count");
		}
		*ret = rhs_svalue;
		return NULL;
	}
	case DRGN_OBJECT_ENCODING_UNSIGNED:
		return drgn_object_convert_unsigned(rhs, type.bit_size, ret);
	default:
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "invalid rhs type for shift");
	}
}

struct drgn_error *drgn_op_lshift_impl(struct drgn_object *res,
				       const struct drgn_object *lhs,
				       const struct drgn_operand_type *lhs_type,
				       const struct drgn_object *rhs,
				       const struct drgn_operand_type *rhs_type)
{
	struct drgn_error *err;

	struct drgn_object_type type;
	err = drgn_object_type_operand(lhs_type, &type);
	if (err)
		return err;

	uint64_t shift;
	err = shift_operand(rhs, rhs_type, &shift);
	if (err)
		return err;

	switch (type.encoding) {
	case DRGN_OBJECT_ENCODING_SIGNED: {
		union {
			int64_t svalue;
			uint64_t uvalue;
		} tmp;
		err = drgn_object_convert_signed(lhs, type.bit_size,
						 &tmp.svalue);
		if (err)
			return err;
		/* Left shift of a negative integer is undefined. */
		if (shift < type.bit_size)
			tmp.uvalue <<= shift;
		else
			tmp.uvalue = 0;
		return drgn_object_set_signed_internal(res, &type, tmp.svalue);
	}
	case DRGN_OBJECT_ENCODING_UNSIGNED: {
		uint64_t uvalue;
		err = drgn_object_convert_unsigned(lhs, type.bit_size,
						   &uvalue);
		if (err)
			return err;
		if (shift < type.bit_size)
			uvalue <<= shift;
		else
			uvalue = 0;
		return drgn_object_set_unsigned_internal(res, &type, uvalue);
	}
	default:
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "invalid result type for lshift");
	}
}

struct drgn_error *drgn_op_rshift_impl(struct drgn_object *res,
				       const struct drgn_object *lhs,
				       const struct drgn_operand_type *lhs_type,
				       const struct drgn_object *rhs,
				       const struct drgn_operand_type *rhs_type)
{
	struct drgn_error *err;

	struct drgn_object_type type;
	err = drgn_object_type_operand(lhs_type, &type);
	if (err)
		return err;

	uint64_t shift;
	err = shift_operand(rhs, rhs_type, &shift);
	if (err)
		return err;

	switch (type.encoding) {
	case DRGN_OBJECT_ENCODING_SIGNED: {
		int64_t svalue;
		err = drgn_object_convert_signed(lhs, type.bit_size, &svalue);
		if (err)
			return err;
		if (shift < type.bit_size)
			svalue >>= shift;
		else if (svalue >= 0)
			svalue = 0;
		else
			svalue = -1;
		return drgn_object_set_signed_internal(res, &type, svalue);
	}
	case DRGN_OBJECT_ENCODING_UNSIGNED: {
		uint64_t uvalue;
		err = drgn_object_convert_unsigned(lhs, type.bit_size, &uvalue);
		if (err)
			return err;
		if (shift < type.bit_size)
			uvalue >>= shift;
		else
			uvalue = 0;
		return drgn_object_set_unsigned_internal(res, &type, uvalue);
	}
	default:
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "invalid result type for lshift");
	}
}

#define INTEGER_BINARY_OP(op_name, op)						\
struct drgn_error *								\
drgn_op_##op_name##_impl(struct drgn_object *res,				\
			 const struct drgn_operand_type *op_type,		\
			 const struct drgn_object *lhs,				\
			 const struct drgn_object *rhs)				\
{										\
	struct drgn_error *err;							\
	struct drgn_object_type type;						\
	err = drgn_object_type_operand(op_type, &type);				\
	if (err)								\
		return err;							\
	switch (type.encoding) {						\
	case DRGN_OBJECT_ENCODING_SIGNED:					\
		return BINARY_OP_SIGNED_2C(res, &type, lhs, op, rhs);		\
	case DRGN_OBJECT_ENCODING_UNSIGNED:					\
		return BINARY_OP_UNSIGNED(res, &type, lhs, op, rhs);		\
	default:								\
		return drgn_error_create(DRGN_ERROR_TYPE,			\
					 "invalid result type for " #op_name);	\
	}									\
}
INTEGER_BINARY_OP(and, &)
INTEGER_BINARY_OP(or, |)
INTEGER_BINARY_OP(xor, ^)
#undef INTEGER_BINARY_OP

/* See BINARY_OP_SIGNED_2C. */
#define UNARY_OP_SIGNED_2C(res, type, op, obj) ({				\
	struct drgn_error *_err;						\
	const struct drgn_object_type *_type = (type);				\
	union {									\
		int64_t svalue;							\
		uint64_t uvalue;						\
	} tmp;									\
	_err = drgn_object_convert_signed((obj), _type->bit_size, &tmp.svalue);	\
	tmp.uvalue = op tmp.uvalue;						\
	if (!_err) {								\
		_err = drgn_object_set_signed_internal((res), _type,		\
						       tmp.svalue);		\
	}									\
	_err;									\
})

#define UNARY_OP_UNSIGNED(res, type, op, obj) ({				\
	struct drgn_error *_err;						\
	const struct drgn_object_type *_type = (type);				\
	uint64_t uvalue;							\
	_err = drgn_object_convert_unsigned((obj), _type->bit_size, &uvalue);	\
	if (!_err) {								\
		_err = drgn_object_set_unsigned_internal((res), _type,		\
							 op uvalue);		\
	}									\
	_err;									\
})

#define ARITHMETIC_UNARY_OP(op_name, op)					\
struct drgn_error *								\
drgn_op_##op_name##_impl(struct drgn_object *res,				\
			 const struct drgn_operand_type *op_type,		\
			 const struct drgn_object *obj)				\
{										\
	struct drgn_error *err;							\
	struct drgn_object_type type;						\
	err = drgn_object_type_operand(op_type, &type);				\
	if (err)								\
		return err;							\
	switch (type.encoding) {						\
	case DRGN_OBJECT_ENCODING_SIGNED:					\
		return UNARY_OP_SIGNED_2C(res, &type, op, obj);			\
	case DRGN_OBJECT_ENCODING_UNSIGNED:					\
		return UNARY_OP_UNSIGNED(res, &type, op, obj);			\
	case DRGN_OBJECT_ENCODING_FLOAT: {					\
		double fvalue;							\
		err = drgn_object_convert_float(obj, &fvalue);			\
		if (err)							\
			return err;						\
		return drgn_object_set_float_internal(res, &type, op fvalue);	\
										\
	}									\
	default:								\
		return drgn_error_create(DRGN_ERROR_TYPE,			\
					 "invalid result type for " #op_name);	\
	}									\
}
ARITHMETIC_UNARY_OP(pos, +)
ARITHMETIC_UNARY_OP(neg, -)
#undef ARITHMETIC_UNARY_OP

struct drgn_error *drgn_op_not_impl(struct drgn_object *res,
				    const struct drgn_operand_type *op_type,
				    const struct drgn_object *obj)
{
	struct drgn_error *err;
	struct drgn_object_type type;
	err = drgn_object_type_operand(op_type, &type);
	if (err)
		return err;
	switch (type.encoding) {
	case DRGN_OBJECT_ENCODING_SIGNED:
		return UNARY_OP_SIGNED_2C(res, &type, ~, obj);
	case DRGN_OBJECT_ENCODING_UNSIGNED:
		return UNARY_OP_UNSIGNED(res, &type, ~, obj);
	default:
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "invalid result type for not");
	}
}
