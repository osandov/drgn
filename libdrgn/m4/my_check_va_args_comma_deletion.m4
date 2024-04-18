# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

# Check that when ', ##__VA_ARGS__' is used in a macro taking variable
# arguments, the comma is deleted if no variable arguments were passed. This is
# a GNU C extension: https://gcc.gnu.org/onlinedocs/cpp/Variadic-Macros.html.
AC_DEFUN([MY_CHECK_VA_ARGS_COMMA_DELETION],
[AC_CACHE_CHECK([for __VA_ARGS__ comma deletion extension],
		[my_cv_va_args_comma_deletion],
		[AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
#define mandatory(_, ...) mandatory2(, ##__VA_ARGS__, 0, 1)
#define mandatory2(_0, _1, N, ...) N
_Static_assert(mandatory(_), "no comma deletion with mandatory argument");

#define empty(...) empty2(, ##__VA_ARGS__, 0, 1)
#define empty2(_0, _1, N, ...) N
_Static_assert(empty(), "no comma deletion with empty argument");
]])],
				   [my_cv_va_args_comma_deletion=yes],
				   [my_cv_va_args_comma_deletion=no])])
if test "x$my_cv_va_args_comma_deletion" != xyes; then
	AC_MSG_FAILURE([no __VA_ARGS__ comma deletion extension])
fi
])
