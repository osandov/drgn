// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

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
 * Serialize bits to a memory buffer.
 *
 * Note that this does not perform any bounds checking, so the caller must check
 * that <tt>bit_offset + bit_size</tt> is within the buffer.
 *
 * @param[in] buf Memory buffer to write to.
 * @param[in] bit_offset Offset in bits from the beginning of @p buf to where to
 * write. This is interpreted differently based on @p little_endian.
 * @param[in] uvalue Bits to write, in host order.
 * @param[in] bit_size Number of bits in @p uvalue. This must be grather than
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
 * @param[in] bit_size Number of bits to read. This must be grather than zero
 * and no more than 64.
 * @param[in] little_endian Whether the bits should be interpreted in
 * little-endian order.
 * @return The read bits in host order.
 */
uint64_t deserialize_bits(const void *buf, uint64_t bit_offset,
			  uint8_t bit_size, bool little_endian);

/** @} */

#endif /* DRGN_SERIALIZE_H */
