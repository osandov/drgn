ACLOCAL_AMFLAGS = -I m4

SUBDIRS = elfutils include

AM_CPPFLAGS = -Iinclude -D_GNU_SOURCE

include_HEADERS = drgn.h

noinst_LTLIBRARIES = libdrgnimpl.la

libdrgnimpl_la_SOURCES = arch_x86_64.c \
			 binary_search_tree.h \
			 cityhash.h \
			 dwarf_index.c \
			 dwarf_index.h \
			 dwarf_info_cache.c \
			 dwarf_info_cache.h \
			 error.c \
			 error.h \
			 hash_table.c \
			 hash_table.h \
			 internal.c \
			 internal.h \
			 language.h \
			 language_c.c \
			 lexer.c \
			 lexer.h \
			 linux_kernel.c \
			 linux_kernel.h \
			 memory_reader.c \
			 memory_reader.h \
			 object.c \
			 object.h \
			 object_index.c \
			 object_index.h \
			 path.c \
			 platform.c \
			 platform.h \
			 program.c \
			 program.h \
			 read.h \
			 serialize.c \
			 serialize.h \
			 siphash.h \
			 splay_tree.c \
			 stack_trace.c \
			 string_builder.c \
			 string_builder.h \
			 symbol.c \
			 symbol.h \
			 type.c \
			 type.h \
			 type_index.c \
			 type_index.h \
			 vector.c \
			 vector.h

libdrgnimpl_la_CFLAGS = -fvisibility=hidden -fopenmp

if WITH_LIBKDUMPFILE
libdrgnimpl_la_SOURCES += kdump.c
libdrgnimpl_la_CFLAGS += $(libkdumpfile_CFLAGS)
libdrgnimpl_la_LIBADD = $(libkdumpfile_LIBS)
endif

elfutils_LIBS = elfutils/libdw/libdw.a elfutils/libelf/libelf.a -lz -llzma -lbz2

lib_LTLIBRARIES = libdrgn.la

libdrgn_la_SOURCES =
libdrgn_la_LDFLAGS = -version-info 0:0:0
libdrgn_la_LIBADD = libdrgnimpl.la $(elfutils_LIBS)

if WITH_PYTHON
BUILT_SOURCES = python/docstrings.h

noinst_LTLIBRARIES += _drgn.la
endif

CLEANFILES = python/constants.c python/docstrings.c python/docstrings.h

_drgn_la_SOURCES = python/docstrings.h \
		   python/drgnpy.h \
		   python/error.c \
		   python/module.c \
		   python/object.c \
		   python/platform.c \
		   python/program.c \
		   python/stack_trace.c \
		   python/symbol.c \
		   python/test.c \
		   python/type.c \
		   python/util.c

nodist__drgn_la_SOURCES = python/constants.c python/docstrings.c

_drgn_la_CFLAGS = -fvisibility=hidden
_drgn_la_CPPFLAGS = $(AM_CPPFLAGS) $(PYTHON_CPPFLAGS) -iquote $(srcdir)/python \
		    -iquote python
_drgn_la_LDFLAGS = -Wl,--exclude-libs,ALL -avoid-version -module -shared \
		   -rpath $(pkgpyexecdir)
_drgn_la_LIBADD = libdrgnimpl.la $(elfutils_LIBS)

if WITH_LIBKDUMPFILE
_drgn_la_CFLAGS += $(libkdumpfile_CFLAGS)
endif

GEN_CONSTANTS = $(top_srcdir)/build-aux/gen_constants.py
GEN_DOCSTRINGS = $(top_srcdir)/build-aux/gen_docstrings.py

python/constants.c: drgn.h $(GEN_CONSTANTS)
	$(PYTHON) $(GEN_CONSTANTS) < $< > $@

python/docstrings.c: ../docs/api_reference.rst $(GEN_DOCSTRINGS)
	$(PYTHON) $(GEN_DOCSTRINGS) < $< > $@

python/docstrings.h: ../docs/api_reference.rst $(GEN_DOCSTRINGS)
	$(PYTHON) $(GEN_DOCSTRINGS) -H < $< > $@

EXTRA_DIST = $(GEN_CONSTANTS) $(GEN_DOCSTRINGS)
