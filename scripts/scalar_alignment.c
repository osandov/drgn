// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: MIT

// This file can be used to figure out a platform's alignment requirements. Try
// compiling it with `clang $FLAGS scripts/scalar_alignment.c` and get the
// alignment requirements from the error diagnostic. For example:
//
// ```
// $ clang --target=aarch64 scripts/scalar_alignment.c
// scripts/scalar_alignment.c:64:5: error: cannot initialize array of type 'int[1][2][4][8][16]' with array of type 'max_align_t[16]'
//    64 | int scalar_alignment[alignof_size1][alignof_size2][alignof_size4][alignof_size8][alignof_size16] = (max_align_t[_Alignof(max_align_t)]){};
//       |     ^                                                                                              ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// 1 error generated.
// ```
//
// The array lengths in `int[1][2][4][8][16]` are the alignment requirements for
// 1-, 2-, 4-, 8-, and 16-byte scalar types, respectively. The array length in
// `max_align_t[16]` is the maximum fundamental alignment.
//
// `clang --target=...` can be used to check a non-native platform; see
// `clang -print-targets`.

#include <stddef.h>

#ifdef __SIZEOF_INT128__
#define INT128_TYPE(size) X(__int128, size)
#else
#define INT128_TYPE(size)
#endif

#ifdef __SIZEOF_FLOAT128__
#define FLOAT128_TYPE(size) X(__float128, size)
#else
#define FLOAT128_TYPE(size)
#endif

#define TYPES(size)		\
	X(void *, size)		\
	X(void (*)(void), size)	\
	X(char, size)		\
	X(short, size)		\
	X(int, size)		\
	X(long, size)		\
	X(long long, size)	\
	INT128_TYPE(size)	\
	X(float, size)		\
	X(double, size)		\
	X(long double, size)	\
	FLOAT128_TYPE(size)

#define X(type, size) sizeof(type) == size ? _Alignof(type) :
enum {
	alignof_size1 = TYPES(1) 0,
	alignof_size2 = TYPES(2) 0,
	alignof_size4 = TYPES(4) 0,
	alignof_size8 = TYPES(8) 0,
	alignof_size16 = TYPES(16) 0,
};
#undef X

// Clang diagnoses the following with error: cannot initialize array of type
// 'int[... scalar alignments ...]' with array of type
// 'max_align_t[max alignment]'.
int scalar_alignment[alignof_size1][alignof_size2][alignof_size4][alignof_size8][alignof_size16] = (max_align_t[_Alignof(max_align_t)]){};

// Check that every type with the same size, rounded down to the nearest power
// of 2, has the same alignment.
#define X(type, size)						\
	_Static_assert(sizeof(type) < size			\
		       || sizeof(type) >= size * 2		\
		       || _Alignof(type) == alignof_size##size,	\
		       "alignment mismatch");
TYPES(1)
TYPES(2)
TYPES(4)
TYPES(8)
TYPES(16)
#undef X
