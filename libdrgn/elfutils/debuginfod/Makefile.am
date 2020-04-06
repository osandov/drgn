## Makefile.am for libdebuginfod library subdirectory in elfutils.
##
## Process this file with automake to create Makefile.in
##
## Copyright (C) 2019 Red Hat, Inc.
## This file is part of elfutils.
##
## This file is free software; you can redistribute it and/or modify
## it under the terms of either
##
##   * the GNU Lesser General Public License as published by the Free
##     Software Foundation; either version 3 of the License, or (at
##     your option) any later version
##
## or
##
##   * the GNU General Public License as published by the Free
##     Software Foundation; either version 2 of the License, or (at
##     your option) any later version
##
## or both in parallel, as here.
##
## elfutils is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License for more details.
##
## You should have received copies of the GNU General Public License and
## the GNU Lesser General Public License along with this program.  If
## not, see <http://www.gnu.org/licenses/>.
##
include $(top_srcdir)/config/eu.am
AM_CPPFLAGS += -I$(srcdir) -I$(srcdir)/../libelf -I$(srcdir)/../libebl \
	   -I$(srcdir)/../libdw -I$(srcdir)/../libdwelf \
	   $(libmicrohttpd_CFLAGS) $(libcurl_CFLAGS) $(sqlite3_CFLAGS) \
	   $(libarchive_CFLAGS)
VERSION = 1

# Disable eu- prefixing for artifacts (binaries & man pages) in this
# directory, since they do not conflict with binutils tools.
program_prefix=
program_transform_name = s,x,x,

if BUILD_STATIC
libasm = ../libasm/libasm.a
libdw = ../libdw/libdw.a -lz $(zip_LIBS) $(libelf) $(libebl) -ldl -lpthread
libelf = ../libelf/libelf.a -lz
libdebuginfod = ./libdebuginfod.a $(libcurl_LIBS)
else
libasm = ../libasm/libasm.so
libdw = ../libdw/libdw.so
libelf = ../libelf/libelf.so
libdebuginfod = ./libdebuginfod.so
endif
libebl = ../libebl/libebl.a
libeu = ../lib/libeu.a

AM_LDFLAGS = -Wl,-rpath-link,../libelf:../libdw:.

if ENABLE_PROGRAMS
bin_PROGRAMS = debuginfod debuginfod-find
endif
debuginfod_SOURCES = debuginfod.cxx
debuginfod_LDADD = $(libdw) $(libelf) $(libeu) $(libdebuginfod) $(libmicrohttpd_LIBS) $(libcurl_LIBS) $(sqlite3_LIBS) $(libarchive_LIBS) -lpthread -ldl

debuginfod_find_SOURCES = debuginfod-find.c
debuginfod_find_LDADD = $(libdw) $(libelf) $(libeu) $(libdebuginfod)

noinst_LIBRARIES = libdebuginfod.a
noinst_LIBRARIES += libdebuginfod_pic.a

libdebuginfod_a_SOURCES = debuginfod-client.c
libdebuginfod_pic_a_SOURCES = debuginfod-client.c
am_libdebuginfod_pic_a_OBJECTS = $(libdebuginfod_a_SOURCES:.c=.os)

pkginclude_HEADERS = debuginfod.h

libdebuginfod_so_LIBS = libdebuginfod_pic.a
libdebuginfod_so_LDLIBS = $(libcurl_LIBS)
libdebuginfod.so$(EXEEXT): $(srcdir)/libdebuginfod.map $(libdebuginfod_so_LIBS)
	$(AM_V_CCLD)$(LINK) $(dso_LDFLAGS) -o $@ \
		-Wl,--soname,$@.$(VERSION) \
		-Wl,--version-script,$<,--no-undefined \
		-Wl,--whole-archive $(libdebuginfod_so_LIBS) -Wl,--no-whole-archive \
		$(libdebuginfod_so_LDLIBS)
	@$(textrel_check)
	$(AM_V_at)ln -fs $@ $@.$(VERSION)

if ENABLE_SHARED
install: install-am libdebuginfod.so
	$(mkinstalldirs) $(DESTDIR)$(libdir)
	$(INSTALL_PROGRAM) libdebuginfod.so $(DESTDIR)$(libdir)/libdebuginfod-$(PACKAGE_VERSION).so
	ln -fs libdebuginfod-$(PACKAGE_VERSION).so $(DESTDIR)$(libdir)/libdebuginfod.so.$(VERSION)
	ln -fs libdebuginfod.so.$(VERSION) $(DESTDIR)$(libdir)/libdebuginfod.so
endif

uninstall: uninstall-am
if ENABLE_SHARED
	rm -f $(DESTDIR)$(libdir)/libdebuginfod-$(PACKAGE_VERSION).so
	rm -f $(DESTDIR)$(libdir)/libdebuginfod.so.$(VERSION)
	rm -f $(DESTDIR)$(libdir)/libdebuginfod.so
endif
	rmdir --ignore-fail-on-non-empty $(DESTDIR)$(includedir)/elfutils

EXTRA_DIST = libdebuginfod.map
MOSTLYCLEANFILES = $(am_libdebuginfod_pic_a_OBJECTS) libdebuginfod.so.$(VERSION)
CLEANFILES += $(am_libdebuginfod_pic_a_OBJECTS) libdebuginfod.so

# automake std-options override: arrange to pass LD_LIBRARY_PATH
installcheck-binPROGRAMS: $(bin_PROGRAMS)
	bad=0; pid=$$$$; list="$(bin_PROGRAMS)"; for p in $$list; do \
	  case ' $(AM_INSTALLCHECK_STD_OPTIONS_EXEMPT) ' in \
	   *" $$p "* | *" $(srcdir)/$$p "*) continue;; \
	  esac; \
	  f=`echo "$$p" | \
	     sed 's,^.*/,,;s/$(EXEEXT)$$//;$(transform);s/$$/$(EXEEXT)/'`; \
	  for opt in --help --version; do \
	    if LD_LIBRARY_PATH=$(DESTDIR)$(libdir) \
	       $(DESTDIR)$(bindir)/$$f $$opt > c$${pid}_.out 2> c$${pid}_.err \
		 && test -n "`cat c$${pid}_.out`" \
		 && test -z "`cat c$${pid}_.err`"; then :; \
	    else echo "$$f does not support $$opt" 1>&2; bad=1; fi; \
	  done; \
	done; rm -f c$${pid}_.???; exit $$bad
