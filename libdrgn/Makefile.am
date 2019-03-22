ACLOCAL_AMFLAGS = -I m4

include_HEADERS = drgn.h

lib_LTLIBRARIES = libdrgn.la

libdrgn_la_SOURCES = cityhash.h \
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

libdrgn_la_CFLAGS = -D_GNU_SOURCE -fvisibility=hidden -fopenmp \
		    @libelf_CFLAGS@ @libdw_CFLAGS@
libdrgn_la_LDFLAGS = -fvisibility=hidden -version-info 0:0:0
libdrgn_la_LIBADD = @libelf_LIBS@ @libdw_LIBS@
