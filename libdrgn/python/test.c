// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/*
 * Wrapper functions for testing.
 *
 * In order to test a few internal interfaces that don't have Python bindings,
 * we export some wrappers for those interfaces. These wrappers are accessed via
 * ctypes.
 *
 * The extra declarations are needed to silence -Wmissing-prototypes.
 */

#include "drgnpy.h"
#include "../serialize.h"

typeof(serialize_bits) drgn_test_serialize_bits;
DRGNPY_PUBLIC void drgn_test_serialize_bits(void *buf, uint64_t bit_offset,
					    uint64_t uvalue, uint8_t bit_size,
					    bool little_endian)
{
	return serialize_bits(buf, bit_offset, uvalue, bit_size, little_endian);
}

typeof(deserialize_bits) drgn_test_deserialize_bits;
DRGNPY_PUBLIC uint64_t drgn_test_deserialize_bits(const void *buf,
						  uint64_t bit_offset,
						  uint8_t bit_size,
						  bool little_endian)
{
	return deserialize_bits(buf, bit_offset, bit_size, little_endian);
}
