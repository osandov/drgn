# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

# Check whether our SWITCH_ENUM macro works with the current compiler.
AC_DEFUN([MY_C_SWITCH_ENUM],
[save_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS -iquote $srcdir"

AC_CACHE_CHECK([whether SWITCH_ENUM compiles], [my_cv_c_switch_enum_compiles],
		[AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
#include "switch_enum.h"

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
#include "switch_enum.h"

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
#include "switch_enum.h"

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

CPPFLAGS="$save_CPPFLAGS"
])
