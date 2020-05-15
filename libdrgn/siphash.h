// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

#ifndef DRGN_SIPHASH_H
#define DRGN_SIPHASH_H

#include <stdint.h>
#include <string.h>

/* SipHash-2-4 by default */
#ifndef cROUNDS
#define cROUNDS 2
#endif
#ifndef dROUNDS
#define dROUNDS 4
#endif

struct siphash {
	uint64_t v0, v1, v2, v3;
	uint8_t buf[8];
	size_t len;
};

struct siphash128 {
	struct siphash hash;
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

static inline void siphash_init(struct siphash *hash, const uint64_t key[2])
{
	hash->v0 = UINT64_C(0x736f6d6570736575) ^ key[0];
	hash->v1 = UINT64_C(0x646f72616e646f6d) ^ key[1];
	hash->v2 = UINT64_C(0x6c7967656e657261) ^ key[0];
	hash->v3 = UINT64_C(0x7465646279746573) ^ key[1];
	hash->len = 0;
}

static inline void siphash128_init(struct siphash128 *hash128,
				   const uint64_t key[2])
{
	struct siphash *hash = &hash128->hash;

	siphash_init(hash, key);
	hash->v1 ^= 0xee;
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

static inline void siphash_update(struct siphash *hash, const void *src,
				  size_t len)
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

static inline void siphash128_update(struct siphash128 *hash128,
				     const void *src, size_t len)
{
	siphash_update(&hash128->hash, src, len);
}

static inline void siphash_final_common(struct siphash *hash)
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
}

static inline uint64_t siphash_final(struct siphash *hash)
{
	siphash_final_common(hash);
	hash->v2 ^= 0xff;
	siphash_round(hash, dROUNDS);
	return hash->v0 ^ hash->v1 ^ hash->v2  ^ hash->v3;
}

static inline void siphash128_final(struct siphash128 *hash128,
				    uint64_t output[2])
{
	struct siphash *hash = &hash128->hash;

	siphash_final_common(hash);
	hash->v2 ^= 0xee;
	siphash_round(hash, dROUNDS);
	output[0] = hash->v0 ^ hash->v1 ^ hash->v2  ^ hash->v3;

	hash->v1 ^= 0xdd;
	siphash_round(hash, dROUNDS);
	output[1] = hash->v0 ^ hash->v1 ^ hash->v2  ^ hash->v3;
}

#endif /* DRGN_SIPHASH_H */
