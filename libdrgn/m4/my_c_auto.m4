# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

# Check whether C23 auto is supported by the current compiler and compilation
# flags. If not, but the GNU __auto_type extension is supported, define auto to
# __auto_type. Otherwise, fail.
AC_DEFUN([MY_C_AUTO],
[AC_CACHE_CHECK([for auto], [my_cv_c_auto],
		[AC_COMPILE_IFELSE([AC_LANG_SOURCE([[auto x = 1;]])],
				   [my_cv_c_auto=yes], [my_cv_c_auto=no])])
if test "x$my_cv_c_auto" != xyes; then
	AC_CACHE_CHECK([for __auto_type], [my_cv_c___auto_type],
		       [AC_COMPILE_IFELSE([AC_LANG_SOURCE([[__auto_type x = 1;]])],
					  [my_cv_c___auto_type=yes], [my_cv_c___auto_type=no])])
	if test "x$my_cv_c___auto_type" == xyes; then
		AC_DEFINE([auto], [__auto_type])
	else
		AC_MSG_ERROR([no auto or __auto_type])
	fi
fi
])
