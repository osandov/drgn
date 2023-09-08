dnl Copyright (c) Meta Platforms, Inc. and affiliates.
dnl SPDX-License-Identifier: LGPL-2.1-or-later

AC_INIT([libdrgn], [0.0.24],
	[https://github.com/osandov/drgn/issues],,
	[https://github.com/osandov/drgn])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC

AM_INIT_AUTOMAKE([-Wall -Wno-portability foreign subdir-objects])
AM_SILENT_RULES([yes])
AM_PROG_AR

LT_INIT

AC_SYS_LARGEFILE

MY_C_AUTO

AC_ARG_ENABLE([openmp],
	      [AS_HELP_STRING([--enable-openmp@<:@=ARG@:>@],
			      [use OpenMP. ARG may be yes, no, or the name of
			       the OpenMP runtime library to use (e.g., gomp or
			       omp)
			       @<:@default=yes@:>@])],
	      [], [enable_openmp=yes])

OPENMP_CFLAGS=
OPENMP_LIBS=
AS_CASE(["x$enable_openmp"],
	[xyes], [OPENMP_CFLAGS=-fopenmp],
	[xno], [],
	dnl Use -Wc so that -fopenmp only gets passed when compiling, not
	dnl linking, otherwise the linker will add the default runtime library.
	[OPENMP_CFLAGS=-Wc,-fopenmp
	 OPENMP_LIBS=-l$enable_openmp])
AC_SUBST(OPENMP_CFLAGS)
AC_SUBST(OPENMP_LIBS)

dnl We need Python for code generation even if we're not building the bindings.
AM_PATH_PYTHON([3.6])

AC_ARG_ENABLE([python],
	      [AS_HELP_STRING([--enable-python],
			      [build Python bindings @<:@default=no@:>@])],
	      [], [enable_python=no])

AM_CONDITIONAL([ENABLE_PYTHON], [test "x$enable_python" != xno])
AM_COND_IF([ENABLE_PYTHON],
	   [AS_IF([test -z "$PYTHON_CPPFLAGS"],
		  [prog="import sysconfig
include = sysconfig.get_path('include')
platinclude = sysconfig.get_path('platinclude')
include_paths = [[include]]
if platinclude != include:
    include_paths.append(plat_include)
print(' '.join('-I' + path for path in include_paths))"
		   PYTHON_CPPFLAGS=`"$PYTHON" -c "$prog"`])
	    AC_SUBST(PYTHON_CPPFLAGS)
	    AC_MSG_CHECKING([for $PYTHON development headers])
	    save_CPPFLAGS="$CPPFLAGS"
	    CPPFLAGS="$CPPFLAGS $PYTHON_CPPFLAGS"
	    AC_COMPILE_IFELSE([AC_LANG_SOURCE([[#include <Python.h>]])],
			      [AC_MSG_RESULT([yes])],
			      [AC_MSG_RESULT([no])
			       AC_MSG_ERROR(
[Could not compile test program with Python headers.

You may need to install your distribution's Python development package (e.g.,
python3-devel or python3-dev) or specify the location of the Python development
headers by setting the PYTHON_CPPFLAGS environment variable.])])
	    CPPFLAGS="$save_CPPFLAGS"])

PKG_PROG_PKG_CONFIG

PKG_CHECK_MODULES(elfutils, [libelf >= 0.165 libdw >= 0.165])

AC_ARG_WITH([libkdumpfile],
	    [AS_HELP_STRING([--with-libkdumpfile],
			    [build with support for the makedumpfile kernel
			     core dump format using libkdumpfile
			     @<:@default=auto@:>@])],
			     [], [with_libkdumpfile=auto])
AS_CASE(["x$with_libkdumpfile"],
	[xyes], [PKG_CHECK_MODULES(libkdumpfile, [libkdumpfile])],
	[xauto], [PKG_CHECK_MODULES(libkdumpfile, [libkdumpfile],
				    [with_libkdumpfile=yes],
				    [with_libkdumpfile=no])])
AM_CONDITIONAL([WITH_LIBKDUMPFILE], [test "x$with_libkdumpfile" = xyes])
AM_COND_IF([WITH_LIBKDUMPFILE], [AC_DEFINE(WITH_LIBKDUMPFILE)])

AC_ARG_ENABLE([compiler-warnings],
	      [AS_HELP_STRING([--enable-compiler-warnings@<:@=no|yes|error@:>@],
			      [enable compiler warnings. If no, then only the
			       default compiler warnings are enabled. If yes,
			       then additional warnings required by the package
			       are enabled. If error, then warnings are treated
			       as errors (this is only intended for
			       developers). @<:@default=yes@:>@])],
	      [], [enable_compiler_warnings=no])

dnl Make Clang error instead of warn for unknown warning options.
AX_CHECK_COMPILE_FLAG([-Werror=unknown-warning-option],
		      [compiler_flags_test="-Werror=unknown-warning-option"],
		      [compiler_flags_test=""])
AS_IF([test "x$enable_compiler_warnings" != xno],
      [AX_APPEND_COMPILE_FLAGS([ dnl
       -Wall dnl
       -Wformat-overflow=2 dnl
       -Wformat-truncation=2 dnl
       -Wimplicit-fallthrough dnl
       ], [WARN_CFLAGS], [$compiler_flags_test])])
AS_IF([test "x$enable_compiler_warnings" = xerror],
      [AX_APPEND_FLAG([-Werror], [WARN_CFLAGS])])
AC_SUBST(WARN_CFLAGS)

AC_ARG_ENABLE([asan],
	      [AS_HELP_STRING([--enable-asan], [enable AddressSanitizer])],
	      [], [enable_asan=no])

AS_IF([test "x$enable_asan" != xno],
      [AX_APPEND_FLAG([-fsanitize=address], [SANITIZER_CFLAGS])
       AX_APPEND_FLAG([-fno-omit-frame-pointer], [SANITIZER_CFLAGS])
       AX_APPEND_FLAG([-fsanitize=address], [SANITIZER_LDFLAGS])])

AC_ARG_ENABLE([ubsan],
	      [AS_HELP_STRING([--enable-ubsan],
			      [enable UndefinedBehaviorSanitizer])],
	      [], [enable_ubsan=no])

AS_IF([test "x$enable_ubsan" != xno],
      [AX_APPEND_FLAG([-fsanitize=undefined], [SANITIZER_CFLAGS])
       AX_APPEND_FLAG([-fno-omit-frame-pointer], [SANITIZER_CFLAGS])
       AX_APPEND_FLAG([-fsanitize=undefined], [SANITIZER_LDFLAGS])])

AC_SUBST(SANITIZER_CFLAGS)
AC_SUBST(SANITIZER_LDFLAGS)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
