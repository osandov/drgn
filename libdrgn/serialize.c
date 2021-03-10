// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

#include <assert.h>
#include <endian.h>

#include "serialize.h"

void serialize_bits(void *buf, uint64_t bit_offset, uint64_t uvalue,
		    uint8_t bit_size, bool little_endian)
{
	uint8_t *p;
	size_t bits, size;
	unsigned char tmp[9];
	uint8_t first_mask, last_mask;

	assert(bit_size > 0);
	assert(bit_size <= 64);

	p = (uint8_t *)buf + bit_offset / 8;
	bit_offset %= 8;
	bits = bit_offset + bit_size;
	size = (bits + 7) / 8;
	if (little_endian) {
		if (size > sizeof(uvalue))
			tmp[8] = uvalue >> (64 - bit_offset);
		uvalue = htole64(uvalue << bit_offset);
		memcpy(tmp, &uvalue, sizeof(uvalue));

		/* bit_offset least significant bits. */
		first_mask = (1 << bit_offset) - 1;
		/* 8 - (bit_offset + bit_size) % 8 most significant bits. */
		last_mask = 0xff00 >> -bits % 8;
	} else {
		unsigned int shift;

		shift = -bits % 8;
		if (size > sizeof(uvalue)) {
			tmp[0] = uvalue >> (64 - shift);
			uvalue = htobe64(uvalue << shift);
			memcpy(&tmp[1], &uvalue, sizeof(uvalue));
		} else {
			uvalue = htobe64(uvalue << (64 - bits));
			memcpy(&tmp[0], &uvalue, sizeof(uvalue));
		}

		/* bit_offset most significant bits. */
		first_mask = 0xff00 >> bit_offset;
		/* 8 - (bit_offset + bit_size) % 8 least significant bits. */
		last_mask = (1 << shift) - 1;
	}

	if (size == 1) {
		p[0] = (p[0] & (first_mask | last_mask)) | tmp[0];
	} else {
		p[0] = (p[0] & first_mask) | tmp[0];
		memcpy(p + 1, tmp + 1, size - 2);
		p[size - 1] = (p[size - 1] & last_mask) | tmp[size - 1];
	}
}

uint64_t deserialize_bits(const void *buf, uint64_t bit_offset,
			  uint8_t bit_size, bool little_endian)
{
	const uint8_t *p;
	size_t bits, size;
	uint64_t ret = 0;

	assert(bit_size > 0);
	assert(bit_size <= 64);

	p = (const uint8_t *)buf + bit_offset / 8;
	bit_offset %= 8;
	bits = bit_offset + bit_size;
	size = (bits + 7) / 8;
	if (little_endian) {
		memcpy(&ret, p, min(size, sizeof(ret)));
		ret = le64toh(ret) >> bit_offset;
		if (size > sizeof(ret))
			ret |= (uint64_t)p[8] << (64 - bit_offset);
	} else {
		unsigned int shift;

		if (size > sizeof(ret))
			memcpy(&ret, &p[1], sizeof(ret));
		else
			memcpy((char *)(&ret + 1) - size, p, size);
		shift = -bits % 8;
		ret = be64toh(ret) >> shift;
		if (size > sizeof(ret))
			ret |= (uint64_t)p[0] << (64 - shift);
	}
	return truncate_unsigned(ret, bit_size);
}
