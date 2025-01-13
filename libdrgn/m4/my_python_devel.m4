# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

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
AC_SUBST(PYTHON_CPPFLAGS)
AS_IF([test -z "$PYTHON_LIBS"],
      [prog="import sysconfig
print('-L' + sysconfig.get_config_var('LIBDIR') +
      ' -lpython' + sysconfig.get_config_var('LDVERSION'))"
       PYTHON_LIBS=`"$PYTHON" -c "$prog"`])
AC_SUBST(PYTHON_LIBS)
AC_MSG_CHECKING([for $PYTHON development files])
save_CPPFLAGS="$CPPFLAGS"
save_LIBS="$LIBS"
CPPFLAGS="$CPPFLAGS $PYTHON_CPPFLAGS"
LIBS="$LIBS $PYTHON_LIBS"
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
[Could not compile Python development test program.

You may need to install your distribution's Python development package (e.g.,
python3-devel or python3-dev) or set the PYTHON_CPPFLAGS and PYTHON_LIBS
environment variables.])])
CPPFLAGS="$save_CPPFLAGS"
LIBS="$save_LIBS"
])
