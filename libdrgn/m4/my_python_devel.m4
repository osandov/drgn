# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

# MY_PYTHON_DEVEL([find-libpython=no])
# Check for Python development files and define PYTHON_CPPFLAGS and PYTHON_LIBS
# accordingly.
AC_DEFUN([MY_PYTHON_DEVEL],
[
AS_IF([test -z "$PYTHON_CPPFLAGS"],
      [prog="import sysconfig
include = sysconfig.get_path('include')
platinclude = sysconfig.get_path('platinclude')
include_paths = [[include]]
if platinclude != include:
    include_paths.append(plat_include)
print(' '.join('-I' + path for path in include_paths))"
       PYTHON_CPPFLAGS=`"$PYTHON" -c "$prog"`])

save_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $PYTHON_CPPFLAGS"

AS_IF([test "x$1" = xyes],
      [AS_IF([test -z "$PYTHON_LIBS"]
	     [prog="import sysconfig
print('-L' + sysconfig.get_config_var('LIBDIR') +
      ' -lpython' + sysconfig.get_config_var('LDVERSION'))"
       PYTHON_LIBS=`"$PYTHON" -c "$prog"`])

       save_LIBS="$LIBS"
       LIBS="$LIBS $PYTHON_LIBS"

       AC_MSG_CHECKING([for $PYTHON development headers and library])
       AC_LINK_IFELSE([AC_LANG_SOURCE([[
#include <Python.h>

int main(void)
{
	Py_Initialize();
}
]])],
		      [AC_MSG_RESULT([yes])],
		      [AC_MSG_RESULT([no])
		       AC_MSG_ERROR(
[Could not compile and link test program with Python headers and library.

You may need to install your distribution's Python development package (e.g.,
python3-devel or python3-dev) or specify the location of the Python development
headers and/or library by setting the PYTHON_CPPFLAGS and PYTHON_LIBS
environment variables.])])

       LIBS="$save_LIBS"],
      [AC_MSG_CHECKING([for $PYTHON development headers])
       AC_COMPILE_IFELSE([AC_LANG_SOURCE([[#include <Python.h>]])],
			 [AC_MSG_RESULT([yes])],
			 [AC_MSG_RESULT([no])
			  AC_MSG_ERROR(
[Could not compile test program with Python headers.

You may need to install your distribution's Python development package (e.g.,
python3-devel or python3-dev) or specify the location of the Python development
headers by setting the PYTHON_CPPFLAGS environment variable.])])])

CPPFLAGS="$save_CPPFLAGS"

AC_SUBST(PYTHON_CPPFLAGS)
AC_SUBST(PYTHON_LIBS)
])
