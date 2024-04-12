// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef DRGN_TEST_UTIL_H
#define DRGN_TEST_UTIL_H

#include <check.h>

#include "../drgn.h"
#include "../pp.h"

#define drgn_ck_no_err(err) drgn_ck_no_err_impl(err, PP_UNIQUE(_err))
#define drgn_ck_no_err_impl(err, unique_err) do {				\
	struct drgn_error *unique_err = (err);					\
	ck_assert_msg(!unique_err, "Assertion '!(%s)' failed: error: %s", #err,	\
		      unique_err ? unique_err->message : "");			\
} while (0)

// Copies of assert macros added in check 0.11.0.

#ifndef ck_assert_ptr_null
#ifndef _ck_assert_ptr_null
#define _ck_assert_ptr_null(X, OP) do { \
  const void* _ck_x = (X); \
  ck_assert_msg(_ck_x OP NULL, \
  "Assertion '%s' failed: %s == %#lx", \
  #X" "#OP" NULL", \
  #X, (unsigned long)(uintptr_t)_ck_x); \
} while (0)
#endif

#define ck_assert_ptr_null(X) _ck_assert_ptr_null(X, ==)
#endif

#ifndef ck_assert_ptr_nonnull
#define ck_assert_ptr_nonnull(X) _ck_assert_ptr_null(X, !=)
#endif

#ifndef ck_assert_mem_eq
#ifndef CK_MAX_ASSERT_MEM_PRINT_SIZE
#define CK_MAX_ASSERT_MEM_PRINT_SIZE 64
#endif

#ifndef _ck_assert_mem
#define _ck_assert_mem(X, OP, Y, L) do { \
  const uint8_t* _ck_x = (const uint8_t*)(X); \
  const uint8_t* _ck_y = (const uint8_t*)(Y); \
  size_t _ck_l = (L); \
  char _ck_x_str[CK_MAX_ASSERT_MEM_PRINT_SIZE * 2 + 1]; \
  char _ck_y_str[CK_MAX_ASSERT_MEM_PRINT_SIZE * 2 + 1]; \
  static const char _ck_hexdigits[] = "0123456789abcdef"; \
  size_t _ck_i; \
  size_t _ck_maxl = (_ck_l > CK_MAX_ASSERT_MEM_PRINT_SIZE) ? CK_MAX_ASSERT_MEM_PRINT_SIZE : _ck_l; \
  for (_ck_i = 0; _ck_i < _ck_maxl; _ck_i++) { \
    _ck_x_str[_ck_i * 2  ]   = _ck_hexdigits[(_ck_x[_ck_i] >> 4) & 0xF]; \
    _ck_y_str[_ck_i * 2  ]   = _ck_hexdigits[(_ck_y[_ck_i] >> 4) & 0xF]; \
    _ck_x_str[_ck_i * 2 + 1] = _ck_hexdigits[_ck_x[_ck_i] & 0xF]; \
    _ck_y_str[_ck_i * 2 + 1] = _ck_hexdigits[_ck_y[_ck_i] & 0xF]; \
  } \
  _ck_x_str[_ck_i * 2] = 0; \
  _ck_y_str[_ck_i * 2] = 0; \
  if (_ck_maxl != _ck_l) { \
    _ck_x_str[_ck_i * 2 - 2] = '.'; \
    _ck_y_str[_ck_i * 2 - 2] = '.'; \
    _ck_x_str[_ck_i * 2 - 1] = '.'; \
    _ck_y_str[_ck_i * 2 - 1] = '.'; \
  } \
  ck_assert_msg(0 OP memcmp(_ck_y, _ck_x, _ck_l), \
    "Assertion '%s' failed: %s == \"%s\", %s == \"%s\"", #X" "#OP" "#Y, #X, _ck_x_str, #Y, _ck_y_str); \
} while (0)
#endif

#define ck_assert_mem_eq(X, Y, L) _ck_assert_mem(X, ==, Y, L)
#endif

#ifndef ck_assert_mem_ne
#define ck_assert_mem_ne(X, Y, L) _ck_assert_mem(X, !=, Y, L)
#endif

#ifndef ck_assert_mem_lt
#define ck_assert_mem_lt(X, Y, L) _ck_assert_mem(X, <, Y, L)
#endif

#ifndef ck_assert_mem_le
#define ck_assert_mem_le(X, Y, L) _ck_assert_mem(X, <=, Y, L)
#endif

#ifndef ck_assert_mem_gt
#define ck_assert_mem_gt(X, Y, L) _ck_assert_mem(X, >, Y, L)
#endif

#ifndef ck_assert_mem_ge
#define ck_assert_mem_ge(X, Y, L) _ck_assert_mem(X, >=, Y, L)
#endif

#endif /* DRGN_TEST_UTIL_H */
