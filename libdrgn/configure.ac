AC_INIT([drgn], m4_esyscmd_s([build-aux/version.sh]),
	[https://github.com/osandov/drgn/issues],,
	[https://github.com/osandov/drgn])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC

AM_INIT_AUTOMAKE([-Wall foreign])
AM_PROG_AR

LT_INIT

PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES(libelf, [libelf])
AC_SUBST([libelf_CFLAGS])
AC_SUBST([libelf_LIBS])
dnl We need dwarf_cu_getdwarf() which was added in elfutils 0.160.
PKG_CHECK_MODULES(libdw, [libdw >= 0.160])
AC_SUBST([libdw_CFLAGS])
AC_SUBST([libdw_LIBS])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
