// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file
 *
 * Binary format parsing.
 *
 * See @ref BinaryBuffer.
 */

#ifndef DRGN_BINARY_BUFFER_H
#define DRGN_BINARY_BUFFER_H

#include <assert.h>
#include <byteswap.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "util.h"

/**
 * @ingroup Internals
 *
 * @defgroup BinaryBuffer Binary buffer
 *
 * Binary format parsing.
 *
 * A @ref binary_buffer is a buffer for parsing binary data safely. It has a
 * position (@ref binary_buffer::pos) and various functions to read from the
 * current position and advance it.
 *
 * The `binary_buffer_next*` functions read a value from the buffer and advance
 * the position past the read value. They return an error if the desired value
 * is out of bounds of the buffer. They also save the previous position for
 * error reporting (@ref binary_buffer::prev). On error, they do not advance the
 * position or change the previous position.
 *
 * The `binary_buffer_skip*` functions are similar, except that they skip past
 * unneeded data in the buffer and don't change the previous position.
 *
 * Errors are formatted through a callback (@ref binary_buffer_error_fn) which
 * can provide information about, e.g., what file contained the bad data. The
 * @ref binary_buffer can be embedded in a structure containing additional
 * context.
 *
 * @{
 */

struct binary_buffer;

/**
 * Binary buffer error formatting function.
 *
 * @param[in] bb Buffer.
 * @param[in] pos Position in the buffer where the error occurred.
 * @param[in] message Error message.
 */
typedef struct drgn_error *(*binary_buffer_error_fn)(struct binary_buffer *bb,
						     const char *pos,
						     const char *message);

/**
 * Buffer of binary data to parse.
 *
 * In addition to the functions defined here, `pos`, `prev`, and `end` may be
 * modified directly so long as `pos <= end && prev <= end` remains true.
 */
struct binary_buffer {
	/**
	 * Current position in the buffer.
	 *
	 * This is advanced by the `binary_buffer_next*` functions.
	 */
	const char *pos;
	/** Pointer to one byte after the last valid byte in the buffer. */
	const char *end;
	/**
	 * Position of the last accessed value.
	 *
	 * On success, the `binary_buffer_next*` functions set this to the
	 * position of the returned value (i.e., the position on entry). This is
	 * useful for reporting errors after validating a value that was just
	 * read.
	 *
	 * This is not updated by the `binary_buffer_skip*` functions.
	 */
	const char *prev;
	/** Whether the data is in the opposite byte order from the host. */
	bool bswap;
	/** Error formatting callback. */
	binary_buffer_error_fn error_fn;
};

/**
 * Initialize a @ref binary_buffer.
 *
 * @param[in] buf Pointer to data.
 * @param[in] len Length of data in bytes.
 * @param[in] little_endian Whether the data is little endian.
 * @param[in] error_fn Error formatting callback.
 */
static inline void binary_buffer_init(struct binary_buffer *bb, const void *buf,
				      size_t len, bool little_endian,
				      binary_buffer_error_fn error_fn)
{
	bb->pos = buf;
	bb->end = (const char *)buf + len;
	bb->prev = NULL;
	bb->bswap = little_endian != HOST_LITTLE_ENDIAN;
	bb->error_fn = error_fn;
}

/**
 * Report an error at the previous buffer position (@ref binary_buffer::prev).
 */
struct drgn_error *binary_buffer_error(struct binary_buffer *bb,
				       const char *format, ...)
	__attribute__((__returns_nonnull__, __format__(__printf__, 2, 3)));

/** Report an error at a given position in the buffer. */
struct drgn_error *binary_buffer_error_at(struct binary_buffer *bb,
					  const char *pos, const char *format,
					  ...)
	__attribute__((__returns_nonnull__, __format__(__printf__, 3, 4)));

/**
 * Return whether there are any bytes in the buffer after the current position.
 *
 * @return @c true if there bytes remaining, @c false if the position is at the
 * end of the buffer.
 */
static inline bool binary_buffer_has_next(struct binary_buffer *bb)
{
	return bb->pos < bb->end;
}

static inline struct drgn_error *
binary_buffer_check_bounds(struct binary_buffer *bb, uint64_t n)
{
	if (unlikely(bb->end - bb->pos < n)) {
		return binary_buffer_error_at(bb, bb->pos,
					      "expected at least %" PRIu64 " byte%s, have %td",
					      n, n == 1 ? "" : "s",
					      bb->end - bb->pos);
	}
	return NULL;
}

/** Advance the current buffer position by @p n bytes. */
static inline struct drgn_error *binary_buffer_skip(struct binary_buffer *bb,
						    uint64_t n)
{
	struct drgn_error *err;
	if ((err = binary_buffer_check_bounds(bb, n)))
		return err;
	bb->pos += n;
	return NULL;
}

#ifdef DOXYGEN
/**
 * Get an unsigned N-bit integer at the current buffer position and advance the
 * position.
 *
 * This is defined for N of 16, 32, and 64.
 *
 * The byte order is determined by the @p little_endian parameter that was
 * passed to @ref binary_buffer_init().
 *
 * @param[out] ret Returned value.
 */
struct drgn_error *binary_buffer_next_uN(struct binary_buffer *bb,
					 uintN_t *ret);

/** Like @ref binary_buffer_next_uN(), but return the value as a @c uint64_t. */
struct drgn_error *binary_buffer_next_uN_into_u64(struct binary_buffer *bb,
						  uint64_t *ret);

/**
 * Get a signed N-bit integer at the current buffer position and advance the
 * position.
 *
 * This is defined for N of 16, 32, and 64.
 *
 * The byte order is determined by the @p little_endian parameter that was
 * passed to @ref binary_buffer_init().
 *
 * @param[out] ret Returned value.
 */
struct drgn_error *binary_buffer_next_sN(struct binary_buffer *bb,
					 intN_t *ret);

/** Like @ref binary_buffer_next_sN(), but return the value as an @c int64_t. */
struct drgn_error *binary_buffer_next_sN_into_s64(struct binary_buffer *bb,
						  int64_t *ret);

/**
 * Like @ref binary_buffer_next_sN(), but return the value as a @c uint64_t.
 * Negative values are sign extended.
 */
struct drgn_error *binary_buffer_next_sN_into_u64(struct binary_buffer *bb,
						  unt64_t *ret);
#endif

#define DEFINE_NEXT_INT(bits)							\
static inline struct drgn_error *						\
binary_buffer_next_u##bits(struct binary_buffer *bb, uint##bits##_t *ret)	\
{										\
	struct drgn_error *err;							\
	uint##bits##_t tmp;							\
	if ((err = binary_buffer_check_bounds(bb, sizeof(tmp))))		\
		return err;							\
	bb->prev = bb->pos;							\
	memcpy(&tmp, bb->pos, sizeof(tmp));					\
	bb->pos += sizeof(tmp);							\
	*ret = bb->bswap ? bswap_##bits(tmp) : tmp;				\
	return NULL;								\
}										\
										\
static inline struct drgn_error *						\
binary_buffer_next_u##bits##_into_u64(struct binary_buffer *bb, uint64_t *ret)	\
{										\
	struct drgn_error *err;							\
	uint##bits##_t tmp;							\
	if ((err = binary_buffer_next_u##bits(bb, &tmp)))			\
		return err;							\
	*ret = tmp;								\
	return NULL;								\
}										\
										\
static inline struct drgn_error *						\
binary_buffer_next_s##bits(struct binary_buffer *bb, int##bits##_t *ret)	\
{										\
	struct drgn_error *err;							\
	uint##bits##_t tmp;							\
	if ((err = binary_buffer_next_u##bits(bb, &tmp)))			\
		return err;							\
	*ret = tmp;								\
	return NULL;								\
}										\
										\
static inline struct drgn_error *						\
binary_buffer_next_s##bits##_into_s64(struct binary_buffer *bb, int64_t *ret)	\
{										\
	struct drgn_error *err;							\
	int##bits##_t tmp;							\
	if ((err = binary_buffer_next_s##bits(bb, &tmp)))			\
		return err;							\
	*ret = tmp;								\
	return NULL;								\
}										\
										\
static inline struct drgn_error *						\
binary_buffer_next_s##bits##_into_u64(struct binary_buffer *bb, uint64_t *ret)	\
{										\
	struct drgn_error *err;							\
	int##bits##_t tmp;							\
	if ((err = binary_buffer_next_s##bits(bb, &tmp)))			\
		return err;							\
	*ret = tmp;								\
	return NULL;								\
}

#define bswap_8(x) (x)
DEFINE_NEXT_INT(8)
#undef bswap_8
DEFINE_NEXT_INT(16)
DEFINE_NEXT_INT(32)
DEFINE_NEXT_INT(64)

#undef DEFINE_NEXT_INT

/**
 * Get an unsigned integer of the given size at the current buffer position and
 * advance the position.
 *
 * The byte order is determined by the @p little_endian parameter that was
 * passed to @ref binary_buffer_init().
 *
 * @param[in] size Size in bytes. Must be no larger than 8.
 * @param[out] ret Returned value.
 */
static inline struct drgn_error *
binary_buffer_next_uint(struct binary_buffer *bb, size_t size, uint64_t *ret)
{
	assert(size <= 8);
	struct drgn_error *err;
	if ((err = binary_buffer_check_bounds(bb, size)))
		return err;
	*ret = 0;
	if (HOST_LITTLE_ENDIAN) {
		if (bb->bswap) {
			for (size_t i = 0; i < size; i++)
				((char *)ret)[i] = bb->pos[size - 1 - i];
		} else {
			memcpy(ret, bb->pos, size);
		}
	} else {
		if (bb->bswap) {
			for (size_t i = 0; i < size; i++)
				((char *)(ret + 1))[-i - 1] = bb->pos[i];
		} else {
			memcpy((char *)(ret + 1) - size, bb->pos, size);
		}
	}
	bb->prev = bb->pos;
	bb->pos += size;
	return NULL;
}

/**
 * Get a signed integer of the given size at the current buffer position and
 * advance the position.
 *
 * The byte order is determined by the @p little_endian parameter that was
 * passed to @ref binary_buffer_init().
 *
 * @param[in] size Size in bytes. Must be no larger than 8.
 * @param[out] ret Returned value.
 */
static inline struct drgn_error *
binary_buffer_next_sint(struct binary_buffer *bb, size_t size, int64_t *ret)
{
	struct drgn_error *err;
	uint64_t tmp;
	err = binary_buffer_next_uint(bb, size, &tmp);
	if (err)
		return err;
	if (size > 0)
		*ret = (int64_t)(tmp << (64 - 8 * size)) >> (64 - 8 * size);
	else
		*ret = tmp;
	return NULL;
}

/**
 * Decode an Unsigned Little-Endian Base 128 (ULEB128) number at the current
 * buffer position and advance the position.
 *
 * If the number does not fit in a @c uint64_t, an error is returned.
 *
 * @param[out] ret Returned value.
 */
static inline struct drgn_error *
binary_buffer_next_uleb128(struct binary_buffer *bb, uint64_t *ret)
{
	uint64_t value = 0;
	const char *pos = bb->pos;
	uint8_t byte;
	/* No overflow possible for the first 9 bytes. */
	for (int shift = 0; shift < 63; shift += 7) {
		if (unlikely(pos >= bb->end)) {
oob:
			return binary_buffer_error_at(bb, bb->pos,
						      "expected ULEB128 number");
		}
		byte = *(uint8_t *)(pos++);
		value |= (uint64_t)(byte & 0x7f) << shift;
		if (!(byte & 0x80)) {
done:
			bb->prev = bb->pos;
			bb->pos = pos;
			*ret = value;
			return NULL;
		}
	}
	/* The 10th byte must be 0 or 1. */
	if (unlikely(pos >= bb->end))
		goto oob;
	byte = *(uint8_t *)(pos++);
	if (byte & 0x7e) {
overflow:
		return binary_buffer_error_at(bb, bb->pos,
					      "ULEB128 number overflows unsigned 64-bit integer");
	}
	value |= (uint64_t)byte << 63;
	/* Any remaining bytes must be 0. */
	while (byte & 0x80) {
		if (unlikely(pos >= bb->end))
			goto oob;
		byte = *(uint8_t *)(pos++);
		if (byte & 0x7f)
			goto overflow;
	}
	goto done;
}

/**
 * Decode a Signed Little-Endian Base 128 (SLEB128) number at the current buffer
 * position and advance the position.
 *
 * If the number does not fit in an @c int64_t, an error is returned.
 *
 * @param[out] ret Returned value.
 */
static inline struct drgn_error *
binary_buffer_next_sleb128(struct binary_buffer *bb, int64_t *ret)
{
	uint64_t value = 0;
	const char *pos = bb->pos;
	uint8_t byte;
	/* No overflow possible for the first 9 bytes. */
	for (int shift = 0; shift < 63; shift += 7) {
		if (unlikely(pos >= bb->end)) {
oob:
			return binary_buffer_error_at(bb, bb->pos,
						      "expected SLEB128 number");
		}
		byte = *(uint8_t *)(pos++);
		value |= (uint64_t)(byte & 0x7f) << shift;
		if (!(byte & 0x80)) {
			if (byte & 0x40)
				value |= ~(UINT64_C(1) << (shift + 7)) + 1;
done:
			bb->prev = bb->pos;
			bb->pos = pos;
			*ret = value;
			return NULL;
		}
	}
	/*
	 * The least significant bit of the 10th byte must be the sign bit, and
	 * any other bits must match it (sign extension).
	 */
	if (unlikely(pos >= bb->end))
		goto oob;
	byte = *(uint8_t *)(pos++);
	uint8_t sign = byte & 0x7f;
	if (sign != 0 && sign != 0x7f) {
overflow:
		return binary_buffer_error_at(bb, bb->pos,
					      "SLEB128 number overflows signed 64-bit integer");
	}
	value |= (uint64_t)byte << 63;
	while (byte & 0x80) {
		if (unlikely(pos >= bb->end))
			goto oob;
		byte = *(uint8_t *)(pos++);
		if ((byte & 0x7f) != sign)
			goto overflow;
	}
	goto done;
}

/**
 * Like @ref binary_buffer_next_sleb128(), but return the value as a @c
 * uint64_t. Negative values are sign extended.
 */
static inline struct drgn_error *
binary_buffer_next_sleb128_into_u64(struct binary_buffer *bb, uint64_t *ret)
{
	struct drgn_error *err;
	int64_t tmp;
	if ((err = binary_buffer_next_sleb128(bb, &tmp)))
		return err;
	*ret = tmp;
	return NULL;
}

/** Skip past a LEB128 number at the current buffer position. */
static inline struct drgn_error *
binary_buffer_skip_leb128(struct binary_buffer *bb)
{
	const char *pos = bb->pos;
	while (likely(pos < bb->end)) {
		if (!(*(uint8_t *)(pos++) & 0x80)) {
			bb->pos = pos;
			return NULL;
		}
	}
	return binary_buffer_error_at(bb, bb->pos, "expected LEB128 number");
}

/**
 * Get a null-terminated string at the current buffer position and advance the
 * position.
 *
 * @param[out] str_ret Returned string (i.e., the buffer position on entry).
 * @param[out] len_ret Returned string length not including the null byte.
 */
static inline struct drgn_error *
binary_buffer_next_string(struct binary_buffer *bb, const char **str_ret,
			  size_t *len_ret)
{
	size_t len = strnlen(bb->pos, bb->end - bb->pos);
	if (unlikely(len == bb->end - bb->pos)) {
		return binary_buffer_error_at(bb, bb->pos,
					      "expected null-terminated string");
	}
	*str_ret = bb->prev = bb->pos;
	*len_ret = len;
	bb->pos += len + 1;
	return NULL;
}

/** Skip past a null-terminated string at the current buffer position. */
static inline struct drgn_error *
binary_buffer_skip_string(struct binary_buffer *bb)
{
	size_t len = strnlen(bb->pos, bb->end - bb->pos);
	if (unlikely(len == bb->end - bb->pos)) {
		return binary_buffer_error_at(bb, bb->pos,
					      "expected null-terminated string");
	}
	bb->pos += len + 1;
	return NULL;
}

/** @} */

#endif /* DRGN_BINARY_BUFFER_H */
