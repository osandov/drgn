// Copyright 2018 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <stdint.h>
#include <string.h>

/* SipHash-1-3 by default */
#ifndef cROUNDS
#define cROUNDS 1
#endif
#ifndef dROUNDS
#define dROUNDS 3
#endif

struct siphash {
	uint64_t v0, v1, v2, v3;
	uint8_t buf[8];
	size_t len;
};

static inline uint64_t siphash_rotl(uint64_t x, int b)
{
	return (x << b) | (x >> (64 - b));
}

static inline uint64_t siphash_u8_to_le64(const uint8_t *p)
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

/*
 * Normally, SipHash takes a 128-bit key which is mixed into the initial state.
 * We don't care about hash flooding attacks, so we don't bother.
 */
static inline void siphash_init(struct siphash *hash)
{
	hash->v0 = 0x736f6d6570736575ULL;
	hash->v1 = 0x646f72616e646f6dULL;
	hash->v2 = 0x6c7967656e657261ULL;
	hash->v3 = 0x7465646279746573ULL;
	hash->len = 0;
}

static inline void siphash_round(struct siphash *hash, int rounds) {
	int i;

	for (i = 0; i < rounds; i++) {
		hash->v0 += hash->v1;
		hash->v1 = siphash_rotl(hash->v1, 13);
		hash->v1 ^= hash->v0;
		hash->v0 = siphash_rotl(hash->v0, 32);

		hash->v2 += hash->v3;
		hash->v3 = siphash_rotl(hash->v3, 16);
		hash->v3 ^= hash->v2;

		hash->v0 += hash->v3;
		hash->v3 = siphash_rotl(hash->v3, 21);
		hash->v3 ^= hash->v0;

		hash->v2 += hash->v1;
		hash->v1 = siphash_rotl(hash->v1, 17);
		hash->v1 ^= hash->v2;
		hash->v2 = siphash_rotl(hash->v2, 32);
	}
}

static inline void siphash_update(struct siphash *hash, const void *src, size_t len)
{
	const uint8_t *p = src, *end = p + len;
	uint64_t m;

	if (hash->len % 8) {
		size_t fill = 8 - hash->len % 8;

		if (fill > len)
			fill = len;

		memcpy(&hash->buf[hash->len % 8], p, fill);
		p += fill;
		hash->len += fill;

		if (hash->len % 8)
			return;

		m = siphash_u8_to_le64(hash->buf);
		hash->v3 ^= m;
		siphash_round(hash, cROUNDS);
		hash->v0 ^= m;
	}

	hash->len += end - p;

	while (end - p >= 8) {
		m = siphash_u8_to_le64(p);
		hash->v3 ^= m;
		siphash_round(hash, cROUNDS);
		hash->v0 ^= m;
		p += 8;
	}

	if (p < end)
		memcpy(hash->buf, p, end - p);
}

static inline uint64_t siphash_final(struct siphash *hash)
{
	uint64_t b = (uint64_t)hash->len << 56;

	switch (hash->len % 8) {
	case 7:
		b |= (uint64_t)hash->buf[6] << 48;
	case 6:
		b |= (uint64_t)hash->buf[5] << 40;
	case 5:
		b |= (uint64_t)hash->buf[4] << 32;
	case 4:
		b |= (uint64_t)hash->buf[3] << 24;
	case 3:
		b |= (uint64_t)hash->buf[2] << 16;
	case 2:
		b |= (uint64_t)hash->buf[1] << 8;
	case 1:
		b |= (uint64_t)hash->buf[0];
	case 0:
		break;
	}

	hash->v3 ^= b;
	siphash_round(hash, cROUNDS);
	hash->v0 ^= b;
	hash->v2 ^= 0xff;
	siphash_round(hash, dROUNDS);

	return hash->v0 ^ hash->v1 ^ hash->v2  ^ hash->v3;
}
