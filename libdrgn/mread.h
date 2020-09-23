// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * Helpers for parsing values in memory.
 *
 * See @ref MemoryParsing.
 */

#ifndef DRGN_MREAD_H
#define DRGN_MREAD_H

#include <byteswap.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @ingroup Internals
 *
 * @defgroup MemoryParsing Memory parsing
 *
 * Helpers for reading values in memory.
 *
 * This provides helpers for reading values in memory (e.g., from an mmap'd
 * file) with safe bounds checking.
 *
 * @{
 */

/**
 * Return whether <tt>ptr + offset</tt> is within @p end.
 *
 * @param[in] ptr Pointer to check.
 * @param[in] end Pointer to one byte after the last valid byte.
 * @param[in] offset Offset to check.
 * @return @c true if the result would be in bounds, @c false if not.
 */
static inline bool mread_in_bounds(const char *ptr, const char *end,
				   size_t offset)
{
	return end - ptr >= offset;
}

/**
 * Return <tt>start + offset</tt>, checking bounds.
 *
 * @param[in] start Pointer to first valid byte.
 * @param[in] end Pointer to one byte after the last valid byte.
 * @param[in] offset Offset from @p start.
 * @return <tt>start + offset</tt> if it is within @p end, @c NULL if not.
 */
static inline const char *mread_begin(const char *start, const char *end,
				      size_t offset)
{
	return mread_in_bounds(start, end, offset) ? start + offset : NULL;
}

/**
 * Advance @p ptr by @p offset, checking bounds.
 *
 * @param[in,out] ptr Pointer to check and advance.
 * @param[in] end Pointer to one byte after the last valid byte.
 * @param[in] offset Offset to advance by.
 * @return @c true if the pointer was advanced, @c false if it was not advanced
 * because the result would be out of bounds.
 */
static inline bool mread_skip(const char **ptr, const char *end, size_t offset)
{
	if (!mread_in_bounds(*ptr, end, offset))
		return false;
	*ptr += offset;
	return true;
}

/**
 * Read an unsigned 8-bit integer in memory and advance @p ptr.
 *
 * @param[in,out] ptr Pointer to read from and advance.
 * @param[in] end Pointer to one byte after the last valid byte.
 * @param[out] ret Returned value.
 * @return @c true on success, @c false if the read was out of bounds.
 */
static inline bool mread_u8(const char **ptr, const char *end, uint8_t *ret)
{
	if (!mread_in_bounds(*ptr, end, sizeof(uint8_t)))
		return false;
	*ret = *(const uint8_t *)*ptr;
	*ptr += sizeof(uint8_t);
	return true;
}

/**
 * Read an unsigned 8-bit integer in memory into a @c size_t and advance @p ptr.
 *
 * @sa mread_u8()
 */
static inline bool mread_u8_into_size_t(const char **ptr, const char *end,
					size_t *ret)
{
	uint8_t tmp;
	if (!mread_u8(ptr, end, &tmp))
		return false;
	/* SIZE_MAX is required to be at least 65535, so this won't overflow. */
	*ret = tmp;
	return true;
}

#ifdef DOXYGEN
/**
 * Read an unsigned N-bit integer in memory and advance @p ptr.
 *
 * This is defined for N of 16, 32, and 64.
 *
 * @param[in,out] ptr Pointer to read from and advance.
 * @param[in] end Pointer to one byte after the last valid byte.
 * @param[in] bswap Whether to swap the byte order of the read value.
 * @param[out] ret Returned value.
 * @return @c true on success, @c false if the read was out of bounds.
 */
bool mread_uN(const char **ptr, const char *end, bool bswap, uintN_t *ret);

/**
 * Read an unsigned N-bit little-endian integer in memory and advance @p ptr.
 *
 * @sa mread_uN()
 */
bool mread_leN(const char **ptr, const char *end, uintN_t *ret);

/**
 * Read an unsigned N-bit big-endian integer in memory and advance @p ptr.
 *
 * @sa mread_uN()
 */
bool mread_beN(const char **ptr, const char *end, uintN_t *ret);

/**
 * Read an unsigned N-bit integer in memory into a @c uint64_t and advance @p
 * ptr.
 *
 * @sa mread_uN()
 */
bool mread_uN_into_u64(const char **ptr, const char *end, bool bswap,
		       uint64_t *ret);

/**
 * Read an unsigned N-bit integer in memory into a @c size_t and advance @p
 * ptr.
 *
 * @sa mread_uN()
 *
 * @return @c true on success, @c false if the read was out of bounds or the
 * result is too large for a @c size_t
 */
bool mread_uN_into_size_t(const char **ptr, const char *end, bool bswap,
			  uint64_t *ret);
#endif

#define DEFINE_READ(size)							\
static inline bool mread_u##size(const char **ptr, const char *end, bool bswap,	\
				 uint##size##_t *ret)				\
{										\
	if (!mread_in_bounds(*ptr, end, sizeof(uint##size##_t)))		\
		return false;							\
	uint##size##_t tmp;							\
	memcpy(&tmp, *ptr, sizeof(tmp));					\
	if (bswap)								\
		tmp = bswap_##size(tmp);					\
	*ret = tmp;								\
	*ptr += sizeof(uint##size##_t);						\
	return true;								\
}										\
										\
static inline bool mread_le##size(const char **ptr, const char *end,		\
				  uint##size##_t *ret)				\
{										\
	return mread_u##size(ptr, end,						\
			     __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__, ret);	\
}										\
										\
static inline bool mread_be##size(const char **ptr, const char *end,		\
				  uint##size##_t *ret)				\
{										\
	return mread_u##size(ptr, end, __BYTE_ORDER__ != __ORDER_BIG_ENDIAN__,	\
			     ret);						\
}										\
										\
static inline bool mread_u##size##_into_u64(const char **ptr, const char *end,	\
					    bool bswap, uint64_t *ret)		\
{										\
	uint##size##_t tmp;							\
	if (!mread_u##size(ptr, end, bswap, &tmp))				\
		return false;							\
	*ret = tmp;								\
	return true;								\
}										\
										\
static inline bool mread_u##size##_into_size_t(const char **ptr,		\
					       const char *end, bool bswap,	\
					       size_t *ret)			\
{										\
	uint##size##_t tmp;							\
	if (!mread_u##size(ptr, end, bswap, &tmp))				\
		return false;							\
	if (tmp > SIZE_MAX)							\
		return false;							\
	*ret = tmp;								\
	return true;								\
}

DEFINE_READ(16)
DEFINE_READ(32)
DEFINE_READ(64)

/**
 * Advance @p ptr to the byte after the next null byte.
 *
 * @param[in,out] ptr Pointer to advance.
 * @param[in] end Pointer to one byte after the last valid byte.
 * @return @c true if the pointer was advanced, @c false if no null byte was
 * found.
 */
static inline bool mread_skip_string(const char **ptr, const char *end)
{
	const char *nul = memchr(*ptr, 0, end - *ptr);
	if (!nul)
		return false;
	*ptr = nul + 1;
	return true;
}

/**
 * Read a null-terminated string in memory and advance @p ptr.
 *
 * @param[in,out] ptr Pointer to read from and advance.
 * @param[in] end Pointer to one byte after the last valid byte.
 * @param[out] str_ret Returned string. Equal to the initial value of
 * <tt>*ptr</tt>.
 * @param[out] len_ret Returned string length not including the null byte.
 * @return @c true on success, @c false if no null byte was found.
 */
static inline bool mread_string(const char **ptr, const char *end,
				const char **str_ret, size_t *len_ret)
{
	const char *nul = memchr(*ptr, 0, end - *ptr);
	if (!nul)
		return false;
	*str_ret = *ptr;
	*len_ret = nul - *ptr;
	*ptr = nul + 1;
	return true;
}

/** @} */

#endif /* DRGN_MREAD_H */
