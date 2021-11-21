// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <assert.h>
#include <endian.h>

#include "serialize.h"

static inline uint8_t copy_bits_step(const uint8_t *s, unsigned int src_bit_offset,
				     unsigned int bit_size,
				     unsigned int dst_bit_offset, bool lsb0)
{
	uint8_t result;
	if (lsb0) {
		result = s[0] >> src_bit_offset;
		if (bit_size > 8 - src_bit_offset)
			result |= s[1] << (8 - src_bit_offset);
		result <<= dst_bit_offset;
	} else {
		result = s[0] << src_bit_offset;
		if (bit_size > 8 - src_bit_offset)
			result |= s[1] >> (8 - src_bit_offset);
		result >>= dst_bit_offset;
	}
	return result;
}

void copy_bits(void *dst, unsigned int dst_bit_offset, const void *src,
	       unsigned int src_bit_offset, uint64_t bit_size, bool lsb0)
{
	assert(dst_bit_offset < 8);
	assert(src_bit_offset < 8);

	if (bit_size == 0)
		return;

	uint8_t *d = dst;
	const uint8_t *s = src;
	uint64_t dst_last_bit = dst_bit_offset + bit_size - 1;
	uint8_t dst_first_mask = copy_bits_first_mask(dst_bit_offset, lsb0);
	uint8_t dst_last_mask = copy_bits_last_mask(dst_last_bit, lsb0);

	if (dst_bit_offset == src_bit_offset) {
		/*
		 * In the common case that the source and destination have the
		 * same offset, we can use memcpy(), preserving bits at the
		 * start and/or end if necessary.
		 */
		uint8_t first_byte = d[0];
		uint8_t last_byte = d[dst_last_bit / 8];
		memcpy(d, s, dst_last_bit / 8 + 1);
		if (dst_bit_offset != 0) {
			d[0] = ((first_byte & ~dst_first_mask)
				| (d[0] & dst_first_mask));
		}
		if (dst_last_bit % 8 != 7) {
			d[dst_last_bit / 8] = ((last_byte & ~dst_last_mask)
					       | (d[dst_last_bit / 8] & dst_last_mask));
		}
	} else if (bit_size <= 8 - dst_bit_offset) {
		/* Destination is only one byte. */
		uint8_t dst_mask = dst_first_mask & dst_last_mask;
		d[0] = ((d[0] & ~dst_mask)
			| (copy_bits_step(&s[0], src_bit_offset, bit_size,
					  dst_bit_offset, lsb0) & dst_mask));
	} else {
		/* Destination is two or more bytes. */
		d[0] = ((d[0] & ~dst_first_mask)
			 | (copy_bits_step(&s[0], src_bit_offset,
					   8 - dst_bit_offset, dst_bit_offset,
					   lsb0) & dst_first_mask));
		src_bit_offset += 8 - dst_bit_offset;
		size_t si = src_bit_offset / 8;
		src_bit_offset %= 8;
		size_t di = 1;
		while (di < dst_last_bit / 8) {
			d[di] = copy_bits_step(&s[si], src_bit_offset, 8, 0,
					       lsb0);
			di++;
			si++;
		}
		d[di] = ((d[di] & ~dst_last_mask)
			 | (copy_bits_step(&s[si], src_bit_offset,
					   dst_last_bit % 8 + 1, 0, lsb0)
			    & dst_last_mask));
	}
}

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
