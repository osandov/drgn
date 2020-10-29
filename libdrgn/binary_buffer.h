// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * Binary format parsing.
 *
 * See @ref BinaryBuffer.
 */

#ifndef DRGN_BINARY_BUFFER_H
#define DRGN_BINARY_BUFFER_H

#include <byteswap.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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
	bb->bswap = little_endian != (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__);
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
binary_buffer_check_bounds(struct binary_buffer *bb, size_t n)
{
	if (unlikely(bb->end - bb->pos < n)) {
		return binary_buffer_error_at(bb, bb->pos,
					      "expected at least %zu byte%s, have %td",
					      n, n == 1 ? "" : "s",
					      bb->end - bb->pos);
	}
	return NULL;
}

/** Advance the current buffer position by @p n bytes. */
static inline struct drgn_error *binary_buffer_skip(struct binary_buffer *bb,
						    size_t n)
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
#endif

#define DEFINE_NEXT_UINT(bits)							\
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
}

#define bswap_8(x) (x)
DEFINE_NEXT_UINT(8)
#undef bswap_8
DEFINE_NEXT_UINT(16)
DEFINE_NEXT_UINT(32)
DEFINE_NEXT_UINT(64)

#undef DEFINE_NEXT_UINT

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
	int shift = 0;
	uint64_t value = 0;
	const char *pos = bb->pos;
	while (likely(pos < bb->end)) {
		uint8_t byte = *(uint8_t *)(pos++);
		if (unlikely(shift == 63 && byte > 1)) {
			return binary_buffer_error_at(bb, bb->pos,
						      "ULEB128 number overflows unsigned 64-bit integer");
		}
		value |= (uint64_t)(byte & 0x7f) << shift;
		shift += 7;
		if (!(byte & 0x80)) {
			bb->prev = bb->pos;
			bb->pos = pos;
			*ret = value;
			return NULL;
		}
	}
	return binary_buffer_error_at(bb, bb->pos, "expected ULEB128 number");
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
