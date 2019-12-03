## Process this file with automake to create Makefile.in
## Configure input file for elfutils.
##
## Copyright (C) 1996-2006, 2008, 2009, 2015 Red Hat, Inc.
##
## This file is part of elfutils.
##
## This file is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 3 of the License, or
## (at your option) any later version.
##
## elfutils is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program.  If not, see <http://www.gnu.org/licenses/>.
##
ACLOCAL_AMFLAGS = -I m4

# automake already tells which subdir is being entered.
# Don't make make repeat.
AM_MAKEFLAGS = --no-print-directory

pkginclude_HEADERS = version.h

SUBDIRS = config m4 lib libelf libcpu backends libebl libdwelf libdwfl libdw \
	  libasm
if ENABLE_PROGRAMS
SUBDIRS += src
endif
SUBDIRS += po doc tests

if DEBUGINFOD
SUBDIRS += debuginfod
endif

EXTRA_DIST = elfutils.spec GPG-KEY NOTES CONTRIBUTING \
	     COPYING COPYING-GPLV2 COPYING-LGPLV3

# Make sure the test install uses lib64 when $LIB will yield lib64.
# Make sure the test build uses the same compiler, which on e.g. ppc64
# determines which platform we are actually testing.
# Run all tests under valgrind.
AM_DISTCHECK_CONFIGURE_FLAGS = \
	--libdir=`echo $(libdir) | sed "s,^$(exec_prefix),$$dc_install_base,"`\
	--enable-valgrind --enable-sanitize-undefined \
	CC="$(CC)"

distcheck-hook:
	chmod -R u+w $(distdir)

rpm: dist
	rpmbuild -ts --sign elfutils-@PACKAGE_VERSION@.tar.bz2

# Tell version 3.79 and up of GNU make to not build goals in this
# directory in parallel.
.NOTPARALLEL:
