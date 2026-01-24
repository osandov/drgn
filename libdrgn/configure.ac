dnl Copyright (c) Meta Platforms, Inc. and affiliates.
dnl SPDX-License-Identifier: LGPL-2.1-or-later

AC_INIT([libdrgn], [0.0.33],
	[https://github.com/osandov/drgn/issues],,
	[https://github.com/osandov/drgn])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC

AM_INIT_AUTOMAKE([-Wall -Wno-portability foreign nostdinc subdir-objects])
AM_SILENT_RULES([yes])
AM_PROG_AR

LT_INIT

AC_SYS_LARGEFILE

AC_REQUIRE_AUX_FILE([tap-driver.sh])

MY_C_AUTO
MY_C_SWITCH_ENUM
MY_CHECK_VA_ARGS_COMMA_DELETION

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
AM_PATH_PYTHON([3.8])

AC_ARG_ENABLE([libdrgn],
	      [AS_HELP_STRING([--disable-libdrgn],
			      [don't build the libdrgn C library. Note that
			       libdrgn's API and ABI are unstable])],
	      [], [enable_libdrgn=yes])

AC_ARG_ENABLE([python],
	      [AS_HELP_STRING([--enable-python],
			      [enable Python support in libdrgn, which allows
			       it to use Python plugins and double as the
			       Python extension module])],
	      [], [enable_python=no])

AC_ARG_ENABLE([python-extension],
	      [AS_HELP_STRING([--enable-python-extension],
			      [build the drgn Python extension module separate
			       from libdrgn])],
	      [], [enable_python_extension=no])

AM_CONDITIONAL([ENABLE_LIBDRGN], [test "x$enable_libdrgn" != xno])
AM_CONDITIONAL([ENABLE_PYTHON],
	       [test "x$enable_python" != xno || test "x$enable_python_extension" != xno])
AM_CONDITIONAL([ENABLE_PYTHON_EXTENSION],
	       [test "x$enable_python_extension" != xno])

AM_COND_IF([ENABLE_PYTHON],
	   [AS_IF([test "x$enable_libdrgn" != xno],
		  [find_libpython=yes], [find_libpython=no])
	    MY_PYTHON_DEVEL([$find_libpython])])

PKG_PROG_PKG_CONFIG

PKG_CHECK_MODULES(elfutils, [libelf >= 0.165 libdw >= 0.165])

AC_ARG_WITH([debuginfod],
	    [AS_HELP_STRING([--with-debuginfod],
			    [build with support for debuginfod
			     @<:@default=auto@:>@])],
			     [], [with_debuginfod=auto])
AS_CASE(["x$with_debuginfod"],
	[xyes], [PKG_CHECK_MODULES(libdebuginfod, [libdebuginfod])],
	[xauto], [PKG_CHECK_MODULES(libdebuginfod, [libdebuginfod],
				    [with_debuginfod=yes],
				    [with_debuginfod=no])])
AM_CONDITIONAL([WITH_DEBUGINFOD], [test "x$with_debuginfod" != xno])
AM_COND_IF([WITH_DEBUGINFOD], [AC_DEFINE(WITH_DEBUGINFOD)])

AC_ARG_ENABLE([dlopen-debuginfod],
	      [AS_HELP_STRING([--disable-dlopen-debuginfod],
			      [if building with support for debuginfod, link
			       against libdebuginfod instead of loading it with
			       dlopen(3)])],
	      [], [enable_dlopen_debuginfod=yes])
AM_CONDITIONAL([ENABLE_DLOPEN_DEBUGINFOD],
	       [test "x$enable_dlopen_debuginfod" != xno])
AM_COND_IF([ENABLE_DLOPEN_DEBUGINFOD], [AC_DEFINE(ENABLE_DLOPEN_DEBUGINFOD)])

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

AC_ARG_WITH([lzma],
	    [AS_HELP_STRING([--with-lzma],
			    [build with support for lzma decompression of ELF sections
			     @<:@default=auto@:>@])],
			     [], [with_lzma=auto])
AS_CASE(["x$with_lzma"],
	[xyes], [PKG_CHECK_MODULES(lzma, [liblzma])],
	[xauto], [PKG_CHECK_MODULES(lzma, [liblzma],
				    [with_lzma=yes],
				    [with_lzma=no])])
AM_CONDITIONAL([WITH_LZMA], [test "x$with_lzma" != xno])
AM_COND_IF([WITH_LZMA], [AC_DEFINE(WITH_LZMA)])

AC_ARG_WITH([pcre2],
	    [AS_HELP_STRING([--with-pcre2],
			    [build with support for searching memory with
			     regular expressions using PCRE2
			     @<:@default=auto@:>@])],
			     [], [with_pcre2=auto])
AS_CASE(["x$with_pcre2"],
	[xyes], [PKG_CHECK_MODULES(pcre2, [libpcre2-8])],
	[xauto], [PKG_CHECK_MODULES(pcre2, [libpcre2-8],
				    [with_pcre2=yes],
				    [with_pcre2=no])])
AM_CONDITIONAL([WITH_PCRE2], [test "x$with_pcre2" = xyes])
AM_COND_IF([WITH_PCRE2], [AC_DEFINE(WITH_PCRE2)])

dnl We need check for running tests, but we don't want to fail the build over
dnl it. Instead, if it's not found, set variables so that only `make check`
dnl fails.
PKG_CHECK_MODULES(check, [check >= 0.10.0],,
		  [check_CFLAGS="\$(error Test requires 'check' ('check-devel') >= 0.10.0)"
		   check_LIBS="\$(error Test requires 'check' ('check-devel') >= 0.10.0)"])

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
       -Wformat-security dnl
       -Wformat-truncation=2 dnl
       -Wimplicit-fallthrough dnl
       -Wmissing-prototypes dnl
       -Wpointer-arith dnl
       -Wshadow dnl
       -Wvla dnl
       -Wno-format-zero-length dnl
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
