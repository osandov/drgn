// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file
 *
 * Serialization and deserialization to and from memory.
 *
 * See @ref SerializationDeserialization.
 */

#ifndef DRGN_SERIALIZE_H
#define DRGN_SERIALIZE_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "minmax.h"

/**
 * @ingroup Internals
 *
 * @defgroup SerializationDeserialization Serialization/deserialization
 *
 * Serialization and deserialization of bits to and from memory.
 *
 * @{
 */

/** Truncate a signed integer to @p bit_size bits with sign extension. */
static inline int64_t truncate_signed(int64_t svalue, uint64_t bit_size)
{
	return (int64_t)((uint64_t)svalue << (64 - bit_size)) >> (64 - bit_size);
}

/** Truncate an unsigned integer to @p bit_size bits. */
static inline uint64_t truncate_unsigned(uint64_t uvalue, uint64_t bit_size)
{
	return uvalue << (64 - bit_size) >> (64 - bit_size);
}

/**
 * Copy the @p src_size least-significant bytes from @p src to the @p dst_size
 * least-significant bytes of @p dst.
 *
 * If `src_size > dst_size`, the extra bytes are discarded. If `src_size <
 * dst_size`, the extra bytes are zero-filled.
 */
static inline void copy_lsbytes(void *dst, size_t dst_size,
				bool dst_little_endian, const void *src,
				size_t src_size, bool src_little_endian)
{
	char *d = dst;
	const char *s = src;
	size_t size = min(dst_size, src_size);
	if (dst_little_endian) {
		if (src_little_endian) {
			memcpy(d, s, size);
		} else {
			for (size_t i = 0; i < size; i++)
				d[i] = s[src_size - 1 - i];
		}
		memset(d + size, 0, dst_size - size);
	} else {
		memset(d, 0, dst_size - size);
		if (src_little_endian) {
			for (size_t i = dst_size - size; i < dst_size; i++)
				d[i] = s[dst_size - 1 - i];
		} else {
			memcpy(d + dst_size - size, s + src_size - size, size);
		}
	}
}

/**
 * Return a bit mask with bits `[bit_offset, 7]` set.
 *
 * @param[in] lsb0 See @ref copy_bits().
 */
static inline uint8_t copy_bits_first_mask(unsigned int bit_offset, bool lsb0)
{
	return lsb0 ? 0xff << bit_offset : 0xff >> bit_offset;
}

/**
 * Return a bit mask with bits `[0, last_bit % 8]` set.
 *
 * @param[in] lsb0 See @ref copy_bits().
 */
static inline uint8_t copy_bits_last_mask(uint64_t last_bit, bool lsb0)
{
	return lsb0 ? 0xff >> (7 - last_bit % 8) : 0x7f80 >> (last_bit % 8);
}

/**
 * Copy @p bit_size bits from @p src at bit offset @p src_bit_offset to @p dst
 * at bit offset @p dst_bit_offset.
 *
 * @param[in] dst Destination buffer.
 * @param[in] dst_bit_offset Offset in bits from the beginning of @p dst to copy
 * to. Must be < 8.
 * @param[in] src Source buffer.
 * @param[in] src_bit_offset Offset in bits from the beginning of @p src to copy
 * from. Must be < 8.
 * @param[in] bit_size Number of bits to copy.
 * @param[in] lsb0 If @c true, bits within a byte are numbered from least
 * significant (0) to most significant (7); if @c false, they are numbered from
 * most significant (0) to least significant (7). This determines the
 * interpretation of @p dst_bit_offset and @p src_bit_offset.
 */
void copy_bits(void *dst, unsigned int dst_bit_offset, const void *src,
	       unsigned int src_bit_offset, uint64_t bit_size, bool lsb0);

/**
 * Serialize bits to a memory buffer.
 *
 * Note that this does not perform any bounds checking, so the caller must check
 * that <tt>bit_offset + bit_size</tt> is within the buffer.
 *
 * @param[in] buf Memory buffer to write to.
 * @param[in] bit_offset Offset in bits from the beginning of @p buf to where to
 * write. This is interpreted differently based on @p little_endian.
 * @param[in] uvalue Bits to write, in host order.
 * @param[in] bit_size Number of bits in @p uvalue. This must be greater than
 * zero and no more than 64. Note that this is not checked or truncated, so if
 * @p uvalue has more than this many bits, the results will likely be incorrect.
 * @param[in] little_endian Whether the bits should be written out in
 * little-endian order.
 */
void serialize_bits(void *buf, uint64_t bit_offset, uint64_t uvalue,
		    uint8_t bit_size, bool little_endian);

/**
 * Deserialize bits from a memory buffer.
 *
 * Note that this does not perform any bounds checking, so the caller must check
 * that <tt>bit_offset + bit_size</tt> is within the buffer.
 *
 * @param[in] buf Memory buffer to read from.
 * @param[in] bit_offset Offset in bits from the beginning of @p buf to where to
 * read from. This is interpreted differently based on @p little_endian.
 * @param[in] bit_size Number of bits to read. This must be greater than zero
 * and no more than 64.
 * @param[in] little_endian Whether the bits should be interpreted in
 * little-endian order.
 * @return The read bits in host order.
 */
uint64_t deserialize_bits(const void *buf, uint64_t bit_offset,
			  uint8_t bit_size, bool little_endian);

/** @} */

#endif /* DRGN_SERIALIZE_H */
