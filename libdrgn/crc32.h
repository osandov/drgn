// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * CRC-32 checksums.
 *
 * See @ref CRC32.
 */

#ifndef DRGN_CRC32_H
#define DRGN_CRC32_H

#include <stddef.h>
#include <stdint.h>

/**
 * @ingroup Internals
 *
 * @defgroup CRC32 CRC-32
 *
 * CRC-32 checksums.
 *
 * @{
 */

/**
 * Update a CRC-32 checksum with additional data.
 *
 * This uses the IEEE CRC-32 polynomial (<EM>x</EM><SUP>32</SUP> +
 * <EM>x</EM><SUP>26</SUP> + <EM>x</EM><SUP>23</SUP> + <EM>x</EM><SUP>22</SUP> +
 * <EM>x</EM><SUP>16</SUP> + <EM>x</EM><SUP>12</SUP> + <EM>x</EM><SUP>11</SUP> +
 * <EM>x</EM><SUP>10</SUP> + <EM>x</EM><SUP>8</SUP> + <EM>x</EM><SUP>7</SUP> +
 * <EM>x</EM><SUP>5</SUP> + <EM>x</EM><SUP>4</SUP> + <EM>x</EM><SUP>2</SUP> +
 * <EM>x</EM> + 1).
 *
 * @param[in] crc Checksum to update. For the first call, this is the initial
 * checksum value (often `0xffffffff`).
 * @param[in] buf Data to checksum.
 * @param[in] len Size of @p buf in bytes.
 * @return Updated checksum. This is not bitwise negated as is often required
 * for the final result.
 */
uint32_t crc32_update(uint32_t crc, const void *buf, size_t len);

/** @} */

#endif /* DRGN_CRC32_H */
