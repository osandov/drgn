// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * Helpers for parsing values in memory.
 *
 * See @ref MemoryParsing.
 */

#ifndef DRGN_READ_H
#define DRGN_READ_H

#include <byteswap.h>
#include <stdint.h>

/**
 * @ingroup Internals
 *
 * @defgroup MemoryParsing Memory parsing
 *
 * Helpers for parsing values in memory.
 *
 * This provides helpers for parsing values in memory (e.g., from an mmap'd
 * file) with safe bounds checking.
 *
 * These helpers take a cursor (@p ptr) which is read from and advanced. They
 * are bounds-checked against an end pointer (@p end). If desired, they will
 * swap the byte order of the read value. The @c readN helpers are defined for N
 * of 16, 32, and 64.
 *
 * @{
 */

/** Return whether <tt>ptr + size</tt> is within @p end. */
static inline bool read_in_bounds(const char *ptr, const char *end, size_t size)
{
	return ptr <= end && (size_t)(end - ptr) >= size;
}

/** Parse an unsigned 8-bit integer in memory. */
static inline bool read_u8(const char **ptr, const char *end, uint8_t *ret)
{
	if (!read_in_bounds(*ptr, end, sizeof(uint8_t)))
		return false;
	*ret = *(const uint8_t *)*ptr;
	*ptr += sizeof(uint8_t);
	return true;
}

/** Parse an unsigned 8-bit integer in memory into a @c size_t. */
static inline bool read_u8_into_size_t(const char **ptr, const char *end,
				       size_t *ret)
{
	uint8_t tmp;

	if (!read_u8(ptr, end, &tmp))
		return false;
	if (tmp > SIZE_MAX)
		return false;
	*ret = tmp;
	return true;
}

#ifdef DOXYGEN
/**
 * Parse an unsigned N-bit integer in memory.
 *
 * This does not perform any bounds checking, so it should only be used if
 * bounds checking was already done.
 *
 * This is defined for N of 16, 32, and 64.
 *
 * @param[in,out] ptr Pointer to read from and advance.
 * @param[in] bswap Whether to swap the byte order of the read value.
 * @param[out] ret Returned value.
 */
void read_uN_nocheck(const char **ptr, bool bswap, uintN_t *ret);

/**
 * Parse an unsigned N-bit integer in memory, checking bounds.
 *
 * @sa read_uN_nocheck().
 *
 * @param[in] end Pointer to one after the last valid address.
 * @return Whether the read was in bounds.
 */
bool read_uN(const char **ptr, const char *end, bool bswap, uintN_t *ret);

/**
 * Parse an unsigned N-bit integer in memory into a @c uint64_t.
 *
 * @sa read_uN_nocheck().
 */
void read_uN_into_u64_nocheck(const char **ptr, bool bswap, uint64_t *ret);

/**
 * Parse an unsigned N-bit integer in memory into a @c uint64_t, checking
 * bounds.
 *
 * @sa read_uN().
 */
bool read_uN_into_u64(const char **ptr, const char *end, bool bswap,
		      uint64_t *ret);

/**
 * Parse an unsigned N-bit integer in memory into a @c size_t, checking bounds.
 *
 * @sa read_uN().
 *
 * @return Whether the read was in bounds and the value was less than or equal
 * to @c SIZE_MAX.
 */
bool read_uN_into_u64(const char **ptr, const char *end, bool bswap,
		      uint64_t *ret);
#endif

#define DEFINE_READ(size)						\
static inline void read_u##size##_nocheck(const char **ptr, bool bswap,	\
					  uint##size##_t *ret)		\
{									\
	uint##size##_t tmp;						\
									\
	memcpy(&tmp, *ptr, sizeof(tmp));				\
	if (bswap)							\
		tmp = bswap_##size(tmp);				\
	*ret = tmp;							\
	*ptr += sizeof(uint##size##_t);					\
}									\
									\
static inline bool read_u##size(const char **ptr, const char *end,	\
				bool bswap, uint##size##_t *ret)	\
{									\
	if (!read_in_bounds(*ptr, end, sizeof(uint##size##_t)))		\
		return false;						\
	read_u##size##_nocheck(ptr, bswap, ret);			\
	return true;							\
}									\
									\
static inline void read_u##size##_into_u64_nocheck(const char **ptr,	\
						   bool bswap,		\
						   uint64_t *ret)	\
{									\
	uint##size##_t tmp;						\
									\
	read_u##size##_nocheck(ptr, bswap, &tmp);			\
	*ret = tmp;							\
}									\
									\
static inline bool read_u##size##_into_u64(const char **ptr,		\
					   const char *end, bool bswap,	\
					   uint64_t *ret)		\
{									\
	uint##size##_t tmp;						\
									\
	if (!read_u##size(ptr, end, bswap, &tmp))			\
		return false;						\
	*ret = tmp;							\
	return true;							\
}									\
									\
static inline bool read_u##size##_into_size_t(const char **ptr,		\
					      const char *end,		\
					      bool bswap, size_t *ret)	\
{									\
	uint##size##_t tmp;						\
									\
	if (!read_u##size(ptr, end, bswap, &tmp))			\
		return false;						\
	if (tmp > SIZE_MAX)						\
		return false;						\
	*ret = tmp;							\
	return true;							\
}

DEFINE_READ(16)
DEFINE_READ(32)
DEFINE_READ(64)

static inline bool read_be32(const char **ptr, const char *end, uint32_t *ret)
{
	return read_u32(ptr, end, __BYTE_ORDER__ != __ORDER_BIG_ENDIAN__,
			ret);
}

/** Advance @p ptr to the byte after the next null byte. */
static inline bool skip_string(const char **ptr, const char *end)
{
	const char *nul;

	if (*ptr >= end)
		return false;

	nul = memchr(*ptr, 0, end - *ptr);
	if (!nul)
		return false;

	*ptr = nul + 1;
	return true;
}

/**
 * Parse a null terminated string in memory.
 *
 * @param[in,out] ptr Pointer to read from and advance.
 * @param[in] end Pointer to one after the last valid address.
 * @param[out] str_ret Returned string. Equal to the initial value of
 * <tt>*ptr</tt>.
 * @param[out] len_ret Returned string length not including the null byte.
 */
static inline bool read_string(const char **ptr, const char *end,
			       const char **str_ret, size_t *len_ret)
{
	const char *nul;

	if (*ptr >= end)
		return false;

	nul = memchr(*ptr, 0, end - *ptr);
	if (!nul)
		return false;

	*str_ret = *ptr;
	*len_ret = nul - *ptr;
	*ptr = nul + 1;
	return true;
}

/** @} */

#endif /* DRGN_READ_H */
