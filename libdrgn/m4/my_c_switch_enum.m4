# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

# Check whether our SWITCH_ENUM macro works with the current compiler. There
# are a few known limitations:
#
# - Before GCC 12.1, GCC can't parse it. This was fixed by GCC commit
#   1bf976a5de69 ("openmp: Actually ignore pragma_stmt pragmas for which
#   c_parser_pragma returns false").
# - Before GCC 12.2, GCC doesn't actually apply the warnings. This was fixed by
#   GCC commit 98e2676558f6 ("c: Fix location for _Pragma tokens [PR97498]").
# - Before Clang 18.1, Clang ignores -Wswitch-default. It was implemented in
#   llvm-project commit c28178298513 ("[clang][Sema] Add -Wswitch-default
#   warning option (#73077)").
#
# Keep this in sync with util.h.
AC_DEFUN([MY_C_SWITCH_ENUM],
[AC_CACHE_CHECK([whether SWITCH_ENUM compiles], [my_cv_c_switch_enum_compiles],
		[AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
#define SWITCH_ENUM(expr)					\
	_Pragma("GCC diagnostic push")				\
	_Pragma("GCC diagnostic error \"-Wswitch-enum\"")	\
	_Pragma("GCC diagnostic error \"-Wswitch-default\"")	\
	switch (expr)						\
	_Pragma("GCC diagnostic pop")

int main(void)
{
	enum { FOO, BAR } x;
	SWITCH_ENUM(x) {
	case FOO:
	case BAR:
	default:
		break;
	}
	return 0;
}
]])], [my_cv_c_switch_enum_compiles=yes], [my_cv_c_switch_enum_compiles=no])])

if test "x$my_cv_c_switch_enum_compiles" = xyes; then
	dnl Now we know that the macro compiles. Check whether it actually
	dnl works. We don't do anything with this beyond logging it.
	AC_CACHE_CHECK([whether SWITCH_ENUM catches missing enumeration values],
		       [my_cv_c_switch_enum_works],
		       [AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
#define SWITCH_ENUM(expr)					\
	_Pragma("GCC diagnostic push")				\
	_Pragma("GCC diagnostic error \"-Wswitch-enum\"")	\
	_Pragma("GCC diagnostic error \"-Wswitch-default\"")	\
	switch (expr)						\
	_Pragma("GCC diagnostic pop")

int main(void)
{
	enum { FOO, BAR } x;
	SWITCH_ENUM(x) {
	case FOO:
	default:
		break;
	}
	return 0;
}
]])], [my_cv_c_switch_enum_works=no], [my_cv_c_switch_enum_works=yes])])
	AC_CACHE_CHECK([whether SWITCH_ENUM catches missing default case],
		       [my_cv_c_switch_enum_default_works],
		       [AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
#define SWITCH_ENUM(expr)					\
	_Pragma("GCC diagnostic push")				\
	_Pragma("GCC diagnostic error \"-Wswitch-enum\"")	\
	_Pragma("GCC diagnostic error \"-Wswitch-default\"")	\
	switch (expr)						\
	_Pragma("GCC diagnostic pop")

int main(void)
{
	enum { FOO, BAR } x;
	SWITCH_ENUM(x) {
	case FOO:
	case BAR:
		break;
	}
	return 0;
}
]])], [my_cv_c_switch_enum_default_works=no], [my_cv_c_switch_enum_default_works=yes])])
else
	AC_DEFINE([SWITCH_ENUM(expr)], [switch (expr)])
fi
])
