// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * Hexadecimal encoding/decoding.
 *
 * See @ref Hexlify.
 */

#ifndef DRGN_HEXLIFY_H
#define DRGN_HEXLIFY_H

#include <stdbool.h>
#include <stddef.h>

/**
 * @ingroup Internals
 *
 * @defgroup Hexlify Hexlify
 *
 * Hexadecimal encoding/decoding.
 *
 * @{
 */

/**
 * Encode binary data to a hexadecimal string.
 *
 * The output string is an even number of lowercase hexadecimal characters with
 * no separators. It is not null-terminated.
 *
 * @param[in] in Input binary data.
 * @param[in] in_len Size of @p in in bytes.
 * @param[out] out Output hexadecimal string of size `2 * in_len` characters.
 * Not null-terminated.
 */
void hexlify(const void *in, size_t in_len, char *out);

/**
 * Allocate and encode binary data to a hexadecimal string.
 *
 * This is like @ref hexlify(), but it allocates the output string, including a
 * terminating null byte.
 *
 * @param[in] in Input binary data.
 * @param[in] in_len Size of @p in in bytes.
 * @return Output hexadecimal string, or `NULL` on failure to allocate memory.
 * Unlike @ref hexlify(), this *is* null-terminated. On success, it must be
 * freed with `free()`.
 */
char *ahexlify(const void *in, size_t in_len);

/**
 * Decode hexadecimal string to binary data.
 *
 * The input string must be an even number of hexadecimal characters (either
 * lowercase or uppercase) with no separators.
 *
 * @param[in] in Input hexadecimal string. Does not need to be null-terminated.
 * @param[in] in_len Number of characters in @p in.
 * @param[out] out Returned binary data of size `in_len / 2` bytes.
 * @return `true` if data was successfully decoded, `false` if not (either
 * because @p in_len was odd or @p in contained non-hexadecimal characters).
 */
bool unhexlify(const char *in, size_t in_len, void *out);

/** @} */

#endif /* DRGN_HEXLIFY_H */
