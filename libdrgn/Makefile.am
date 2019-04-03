ACLOCAL_AMFLAGS = -I m4

include_HEADERS = drgn.h

noinst_LTLIBRARIES = libdrgnimpl.la

libdrgnimpl_la_SOURCES = cityhash.h \
			 dwarf_index.c \
			 dwarf_index.h \
			 dwarf_object_index.c \
			 dwarf_type_index.c \
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
			 memory_file_reader.c \
			 memory_reader.h \
			 mock.c \
			 object.c \
			 object.h \
			 object_index.c \
			 object_index.h \
			 path.c \
			 program.c \
			 program.h \
			 read.h \
			 serialize.c \
			 serialize.h \
			 siphash.h \
			 string_builder.c \
			 string_builder.h \
			 type.c \
			 type.h \
			 type_index.c \
			 type_index.h

libdrgnimpl_la_CFLAGS = -D_GNU_SOURCE -fvisibility=hidden -fopenmp \
			$(libelf_CFLAGS) $(libdw_CFLAGS)
libdrgnimpl_la_LDFLAGS = -fvisibility=hidden -fopenmp
libdrgnimpl_la_LIBADD = $(libelf_LIBS) $(libdw_LIBS)

lib_LTLIBRARIES = libdrgn.la

libdrgn_la_SOURCES =
libdrgn_la_LDFLAGS = -fvisibility=hidden -version-info 0:0:0
libdrgn_la_LIBADD = libdrgnimpl.la

if WITH_PYTHON
noinst_LTLIBRARIES += _drgn.la
endif

_drgn_la_SOURCES = python/drgnpy.h \
		   python/module.c \
		   python/object.c \
		   python/program.c \
		   python/test.c \
		   python/type.c \
		   python/util.c

nodist__drgn_la_SOURCES = python/constants.c

_drgn_la_CFLAGS = $(PYTHON_CFLAGS) -D_GNU_SOURCE -fvisibility=hidden
_drgn_la_LDFLAGS = -avoid-version -module -shared -rpath $(pkgpyexecdir) \
		   -Wl,--exclude-libs,ALL
_drgn_la_LIBADD = libdrgnimpl.la

$(top_builddir)/python/constants.c: $(top_srcdir)/drgn.h $(top_srcdir)/build-aux/gen_constants.py
	$(PYTHON) $(top_srcdir)/build-aux/gen_constants.py $(top_srcdir)/python < $< > $@

EXTRA_DIST = $(top_srcdir)/build-aux/gen_constants.py

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
