// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DRGN_CITYHASH_H
#define DRGN_CITYHASH_H

#include <byteswap.h>
#include <stddef.h>
#include <stdint.h>

static inline uint32_t cityhash_fetch32(const uint8_t *p)
{
	return ((uint32_t)p[0] |
		((uint32_t)p[1] <<  8) |
		((uint32_t)p[2] << 16) |
		((uint32_t)p[3] << 24));
}

static inline uint64_t cityhash_fetch64(const uint8_t *p)
{
	return ((uint64_t)p[0] |
		((uint64_t)p[1] <<  8) |
		((uint64_t)p[2] << 16) |
		((uint64_t)p[3] << 24) |
		((uint64_t)p[4] << 32) |
		((uint64_t)p[5] << 40) |
		((uint64_t)p[6] << 48) |
		((uint64_t)p[7] << 56));
}

#define cityhash_c1 UINT32_C(0xcc9e2d51)
#define cityhash_c2 UINT32_C(0x1b873593)
#define cityhash_c3 UINT32_C(0xe6546b64)

static uint32_t cityhash_fmix(uint32_t h)
{
	h ^= h >> 16;
	h *= UINT32_C(0x85ebca6b);
	h ^= h >> 13;
	h *= UINT32_C(0xc2b2ae35);
	h ^= h >> 16;
	return h;
}

static uint32_t cityhash_rotate32(uint32_t x, int b) {
	return b == 0 ? x : (x >> b) | (x << (32 - b));
}

static uint32_t cityhash_mur(uint32_t a, uint32_t h) {
	a *= cityhash_c1;
	a = cityhash_rotate32(a, 17);
	a *= cityhash_c2;
	h ^= a;
	h = cityhash_rotate32(h, 19);
	return h * 5 + cityhash_c3;
}

static uint32_t cityhash32_len_13to24(const uint8_t *s, size_t len) {
	uint32_t a = cityhash_fetch32(s - 4 + (len >> 1));
	uint32_t b = cityhash_fetch32(s + 4);
	uint32_t c = cityhash_fetch32(s + len - 8);
	uint32_t d = cityhash_fetch32(s + (len >> 1));
	uint32_t e = cityhash_fetch32(s);
	uint32_t f = cityhash_fetch32(s + len - 4);
	uint32_t h = len;

	return cityhash_fmix(cityhash_mur(f, cityhash_mur(e, cityhash_mur(d, cityhash_mur(c, cityhash_mur(b, cityhash_mur(a, h)))))));
}

static uint32_t cityhash32_len_0to4(const uint8_t *s, size_t len) {
	uint32_t b = 0;
	uint32_t c = 9;
	for (size_t i = 0; i < len; i++) {
		signed char v = s[i];
		b = b * cityhash_c1 + v;
		c ^= b;
	}
	return cityhash_fmix(cityhash_mur(b, cityhash_mur(len, c)));
}

static uint32_t cityhash32_len_5to12(const uint8_t *s, size_t len) {
	uint32_t a = len, b = len * 5, c = 9, d = b;
	a += cityhash_fetch32(s);
	b += cityhash_fetch32(s + len - 4);
	c += cityhash_fetch32(s + ((len >> 1) & 4));
	return cityhash_fmix(cityhash_mur(c, cityhash_mur(b, cityhash_mur(a, d))));
}

__attribute__((__unused__))
static uint32_t cityhash32(const void *data, size_t len) {
	const uint8_t *s = data;

	if (len <= 4)
		return cityhash32_len_0to4(s, len);
	else if (len <= 12)
		return cityhash32_len_5to12(s, len);
	else if (len <= 24)
		return cityhash32_len_13to24(s, len);

	uint32_t h = len, g = cityhash_c1 * len, f = g;
	uint32_t a0 = cityhash_rotate32(cityhash_fetch32(s + len - 4) * cityhash_c1, 17) * cityhash_c2;
	uint32_t a1 = cityhash_rotate32(cityhash_fetch32(s + len - 8) * cityhash_c1, 17) * cityhash_c2;
	uint32_t a2 = cityhash_rotate32(cityhash_fetch32(s + len - 16) * cityhash_c1, 17) * cityhash_c2;
	uint32_t a3 = cityhash_rotate32(cityhash_fetch32(s + len - 12) * cityhash_c1, 17) * cityhash_c2;
	uint32_t a4 = cityhash_rotate32(cityhash_fetch32(s + len - 20) * cityhash_c1, 17) * cityhash_c2;
	h ^= a0;
	h = cityhash_rotate32(h, 19);
	h = h * 5 + cityhash_c3;
	h ^= a2;
	h = cityhash_rotate32(h, 19);
	h = h * 5 + cityhash_c3;
	g ^= a1;
	g = cityhash_rotate32(g, 19);
	g = g * 5 + cityhash_c3;
	g ^= a3;
	g = cityhash_rotate32(g, 19);
	g = g * 5 + cityhash_c3;
	f += a4;
	f = cityhash_rotate32(f, 19);
	f = f * 5 + cityhash_c3;
	size_t iters = (len - 1) / 20;
	do {
		uint32_t a0 = cityhash_rotate32(cityhash_fetch32(s) * cityhash_c1, 17) * cityhash_c2;
		uint32_t a1 = cityhash_fetch32(s + 4);
		uint32_t a2 = cityhash_rotate32(cityhash_fetch32(s + 8) * cityhash_c1, 17) * cityhash_c2;
		uint32_t a3 = cityhash_rotate32(cityhash_fetch32(s + 12) * cityhash_c1, 17) * cityhash_c2;
		uint32_t a4 = cityhash_fetch32(s + 16);
		h ^= a0;
		h = cityhash_rotate32(h, 18);
		h = h * 5 + cityhash_c3;
		f += a1;
		f = cityhash_rotate32(f, 19);
		f = f * cityhash_c1;
		g += a2;
		g = cityhash_rotate32(g, 18);
		g = g * 5 + cityhash_c3;
		h ^= a3 + a1;
		h = cityhash_rotate32(h, 19);
		h = h * 5 + cityhash_c3;
		g ^= a4;
		g = bswap_32(g) * 5;
		h += a4 * 5;
		h = bswap_32(h);
		f += a0;
		uint32_t tmp;
		tmp = f;
		f = g;
		g = h;
		h = tmp;
		s += 20;
	} while (--iters != 0);
	g = cityhash_rotate32(g, 11) * cityhash_c1;
	g = cityhash_rotate32(g, 17) * cityhash_c1;
	f = cityhash_rotate32(f, 11) * cityhash_c1;
	f = cityhash_rotate32(f, 17) * cityhash_c1;
	h = cityhash_rotate32(h + g, 19);
	h = h * 5 + cityhash_c3;
	h = cityhash_rotate32(h, 17) * cityhash_c1;
	h = cityhash_rotate32(h + f, 19);
	h = h * 5 + cityhash_c3;
	h = cityhash_rotate32(h, 17) * cityhash_c1;
	return h;
}

struct cityhash_pair {
	uint64_t first;
	uint64_t second;
};

#define cityhash_k0 UINT64_C(0xc3a5c85c97cb3127)
#define cityhash_k1 UINT64_C(0xb492b66fbe98f273)
#define cityhash_k2 UINT64_C(0x9ae16a3b2f90404f)

static inline uint64_t cityhash_rotate(uint64_t x, int b)
{
	return b == 0 ? x : (x >> b) | (x << (64 - b));
}

static inline uint64_t cityhash_shiftmix(uint64_t val)
{
	return val ^ (val >> 47);
}

static inline uint64_t cityhash_128_to_64(uint64_t lo, uint64_t hi) {
	static const uint64_t mul = UINT64_C(0x9ddfea08eb382d69);
	uint64_t a = (lo ^ hi) * mul;
	a ^= (a >> 47);
	uint64_t b = (hi ^ a) * mul;
	b ^= (b >> 47);
	b *= mul;
	return b;
}

static inline uint64_t cityhash_len_16(uint64_t u, uint64_t v, uint64_t mul)
{
	uint64_t a = (u ^ v) * mul;
	a ^= (a >> 47);
	uint64_t b = (v ^ a) * mul;
	b ^= (b >> 47);
	b *= mul;
	return b;
}

static uint64_t cityhash_len_0to16(const uint8_t *s, size_t len)
{
	if (len == 0) {
		return cityhash_k2;
	} else if (len < 4) {
		uint8_t a = s[0];
		uint8_t b = s[len >> 1];
		uint8_t c = s[len - 1];
		uint32_t y = (uint32_t)a + ((uint32_t)b << 8);
		uint32_t z = len + ((uint32_t)c << 2);
		return cityhash_shiftmix(y * cityhash_k2 ^ z * cityhash_k0) * cityhash_k2;
	} else if (len < 8) {
		uint64_t mul = cityhash_k2 + len * 2;
		uint64_t a = cityhash_fetch32(s);
		return cityhash_len_16(len + (a << 3),
				       cityhash_fetch32(s + len - 4), mul);
	} else {
		uint64_t mul = cityhash_k2 + len * 2;
		uint64_t a = cityhash_fetch64(s) + cityhash_k2;
		uint64_t b = cityhash_fetch64(s + len - 8);
		uint64_t c = cityhash_rotate(b, 37) * mul + a;
		uint64_t d = (cityhash_rotate(a, 25) + b) * mul;
		return cityhash_len_16(c, d, mul);
	}
}

static uint64_t cityhash_len_17to32(const uint8_t *s, size_t len)
{
	uint64_t mul = cityhash_k2 + len * 2;
	uint64_t a = cityhash_fetch64(s) * cityhash_k1;
	uint64_t b = cityhash_fetch64(s + 8);
	uint64_t c = cityhash_fetch64(s + len - 8) * mul;
	uint64_t d = cityhash_fetch64(s + len - 16) * cityhash_k2;
	return cityhash_len_16(cityhash_rotate(a + b, 43) +
			       cityhash_rotate(c, 30) + d,
			       a + cityhash_rotate(b + cityhash_k2, 18) + c,
			       mul);
}

static struct cityhash_pair cityhash_weak_len_32_with_seeds(const uint8_t *s,
							    uint64_t a,
							    uint64_t b)
{
	uint64_t w = cityhash_fetch64(s);
	uint64_t x = cityhash_fetch64(s + 8);
	uint64_t y = cityhash_fetch64(s + 16);
	uint64_t z = cityhash_fetch64(s + 24);
	a += w;
	b = cityhash_rotate(b + a + z, 21);
	uint64_t c = a;
	a += x;
	a += y;
	b += cityhash_rotate(a, 44);
	return (struct cityhash_pair){a + z, b + c};
}

static uint64_t cityhash_len_33to64(const uint8_t *s, size_t len)
{
	uint64_t mul = cityhash_k2 + len * 2;
	uint64_t a = cityhash_fetch64(s) * cityhash_k2;
	uint64_t b = cityhash_fetch64(s + 8);
	uint64_t c = cityhash_fetch64(s + len - 24);
	uint64_t d = cityhash_fetch64(s + len - 32);
	uint64_t e = cityhash_fetch64(s + 16) * cityhash_k2;
	uint64_t f = cityhash_fetch64(s + 24) * 9;
	uint64_t g = cityhash_fetch64(s + len - 8);
	uint64_t h = cityhash_fetch64(s + len - 16) * mul;
	uint64_t u = cityhash_rotate(a + g, 43) + (cityhash_rotate(b, 30) + c) * 9;
	uint64_t v = ((a + g) ^ d) + f + 1;
	uint64_t w = bswap_64((u + v) * mul) + h;
	uint64_t x = cityhash_rotate(e + f, 42) + c;
	uint64_t y = (bswap_64((v + w) * mul) + g) * mul;
	uint64_t z = e + f + c;
	a = bswap_64((x + z) * mul + y) + b;
	b = cityhash_shiftmix((z + a) * mul + d + h) * mul;
	return b + x;
}

__attribute__((__unused__))
static uint64_t cityhash64(const void *data, size_t len)
{
	const uint8_t *s = data;

	if (len <= 16)
		return cityhash_len_0to16(s, len);
	else if (len <= 32)
		return cityhash_len_17to32(s, len);
	else if (len <= 64)
		return cityhash_len_33to64(s, len);

	uint64_t x = cityhash_fetch64(s + len - 40);
	uint64_t y = (cityhash_fetch64(s + len - 16) +
		      cityhash_fetch64(s + len - 56));
	uint64_t z = cityhash_128_to_64(cityhash_fetch64(s + len - 48) + len,
					cityhash_fetch64(s + len - 24));
	struct cityhash_pair v =
		cityhash_weak_len_32_with_seeds(s + len - 64, len, z);
	struct cityhash_pair w =
		cityhash_weak_len_32_with_seeds(s + len - 32, y + cityhash_k1,
						x);
	x = x * cityhash_k1 + cityhash_fetch64(s);

	len = (len - 1) & ~(size_t)63;
	do {
		x = (cityhash_rotate(x + y + v.first +
				     cityhash_fetch64(s + 8), 37) *
		     cityhash_k1);
		y = (cityhash_rotate(y + v.second +
				     cityhash_fetch64(s + 48), 42) *
		     cityhash_k1);
		x ^= w.second;
		y += v.first + cityhash_fetch64(s + 40);
		z = cityhash_rotate(z + w.first, 33) * cityhash_k1;
		v = cityhash_weak_len_32_with_seeds(s, v.second * cityhash_k1,
						    x + w.first);
		w = cityhash_weak_len_32_with_seeds(s + 32, z + w.second,
						    y + cityhash_fetch64(s + 16));
		uint64_t tmp = z;
		z = x;
		x = tmp;
		s += 64;
		len -= 64;
	} while (len != 0);
	return cityhash_128_to_64(cityhash_128_to_64(v.first, w.first) + cityhash_shiftmix(y) * cityhash_k1 + z,
				  cityhash_128_to_64(v.second, w.second) + x);
}

static inline size_t cityhash_size_t(const void *data, size_t len)
{
	if (sizeof(size_t) == sizeof(uint32_t))
		return cityhash32(data, len);
	else
		return cityhash64(data, len);
}

#endif /* DRGN_CITYHASH_H */
