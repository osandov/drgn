ACLOCAL_AMFLAGS = -I m4

include_HEADERS = drgn.h

noinst_LTLIBRARIES = libdrgnimpl.la

libdrgnimpl_la_SOURCES = arch_x86_64.c \
			 binary_search_tree.h \
			 cityhash.h \
			 dwarf_index.c \
			 dwarf_index.h \
			 dwarf_info_cache.c \
			 dwarf_info_cache.h \
			 elf_relocator.c \
			 elf_relocator.h \
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

libdrgnimpl_la_CFLAGS = -fvisibility=hidden -fopenmp $(libelf_CFLAGS) \
			$(libdw_CFLAGS)
libdrgnimpl_la_CPPFLAGS = -D_GNU_SOURCE
libdrgnimpl_la_LIBADD = $(libelf_LIBS) $(libdw_LIBS)

lib_LTLIBRARIES = libdrgn.la

libdrgn_la_SOURCES =
libdrgn_la_LDFLAGS = -version-info 0:0:0
libdrgn_la_LIBADD = libdrgnimpl.la

if WITH_PYTHON
noinst_LTLIBRARIES += _drgn.la
endif

CLEANFILES = python/constants.c python/docstrings.c

_drgn_la_SOURCES = python/docstrings.h \
		   python/drgnpy.h \
		   python/error.c \
		   python/module.c \
		   python/object.c \
		   python/platform.c \
		   python/program.c \
		   python/symbol.c \
		   python/test.c \
		   python/type.c \
		   python/util.c

nodist__drgn_la_SOURCES = python/constants.c python/docstrings.c

_drgn_la_CFLAGS = -fvisibility=hidden
_drgn_la_CPPFLAGS = $(PYTHON_CPPFLAGS) -D_GNU_SOURCE
_drgn_la_LDFLAGS = -Wl,--exclude-libs,ALL -avoid-version -module -shared \
		   -rpath $(pkgpyexecdir)
_drgn_la_LIBADD = libdrgnimpl.la

GEN_CONSTANTS = $(top_srcdir)/build-aux/gen_constants.py
GEN_DOCSTRINGS = $(top_srcdir)/build-aux/gen_docstrings.py

$(top_builddir)/python/constants.c: $(top_srcdir)/drgn.h $(GEN_CONSTANTS)
	$(PYTHON) $(GEN_CONSTANTS) $(top_srcdir)/python < $< > $@

$(top_builddir)/python/docstrings.c: $(top_srcdir)/../docs/api_reference.rst $(GEN_DOCSTRINGS)
	$(PYTHON) $(GEN_DOCSTRINGS) < $< > $@

EXTRA_DIST = $(GEN_CONSTANTS) $(GEN_DOCSTRINGS)

# This target lists all of the files that need to be distributed for setup.py
# sdist. It is based on the automake distdir target.
.PHONY: distfiles
distfiles:
	@srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	topsrcdirstrip=`echo "$(top_srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	list='$(DISTFILES)'; \
	  dist_files=`for file in $$list; do echo $$file; done | \
	  sed -e "s|^$$srcdirstrip/||;t" \
	      -e "s|^$$topsrcdirstrip/|$(top_builddir)/|;t"`; \
	for file in $$dist_files; do \
	  if test -f $(srcdir)/$$file || test -d $(srcdir)/$$file; then \
	    echo $(srcdir)/$$file; \
	  else \
	    echo "ERROR: $$file is not in source directory" >&2; \
	    exit 1; \
	  fi; \
	done
