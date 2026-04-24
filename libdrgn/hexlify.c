// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <stdint.h>
#include <stdlib.h>

#include "hexlify.h"

static const char nibble_to_hex_digit[] = "0123456789abcdef";

void hexlify(const void *in, size_t in_len, char *out)
{
	for (size_t i = 0; i < in_len; i++) {
		uint8_t byte = ((uint8_t *)in)[i];
		out[2 * i] = nibble_to_hex_digit[byte >> 4];
		out[2 * i + 1] = nibble_to_hex_digit[byte & 0xf];
	}
}

void hexlify_reversed(const void *in, size_t in_len, char *out)
{
	for (size_t i = 0; i < in_len; i++) {
		uint8_t byte = ((uint8_t *)in)[i];
		out[2 * (in_len - i) - 2] = nibble_to_hex_digit[byte >> 4];
		out[2 * (in_len - i) - 1] = nibble_to_hex_digit[byte & 0xf];
	}
}

char *ahexlify(const void *in, size_t in_len)
{
	size_t out_size;
	if (__builtin_mul_overflow(in_len, 2U, &out_size) ||
	    __builtin_add_overflow(out_size, 1U, &out_size))
		return NULL;
	char *out = malloc(out_size);
	if (!out)
		return NULL;
	hexlify(in, in_len, out);
	out[out_size - 1] = '\0';
	return out;
}

bool unhexlify(const char *in, size_t in_len, void *out)
{
	if (in_len % 2)
		return false;
	for (size_t i = 0; i < in_len; i += 2) {
		uint8_t lo, hi;
		if (!hex_digit_to_nibble(in[i], &hi) ||
		    !hex_digit_to_nibble(in[i + 1], &lo))
			return false;
		((uint8_t *)out)[i / 2] = (hi << 4) | lo;
	}
	return true;
}
