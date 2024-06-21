# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

ACLOCAL_AMFLAGS = -I m4

.DELETE_ON_ERROR:

AM_CPPFLAGS = -I $(top_srcdir)/include -D_GNU_SOURCE
AM_CFLAGS = $(WARN_CFLAGS) $(SANITIZER_CFLAGS)
AM_LDFLAGS= $(SANITIZER_LDFLAGS)

noinst_HEADERS = include/elf.h \
		 tests/test_util.h

include_HEADERS = drgn.h

ARCH_DEFS_PYS = arch_aarch64_defs.py \
		arch_ppc64_defs.py \
		arch_s390x_defs.py \
		arch_x86_64_defs.py

ARCH_DEFS_INCS = $(ARCH_DEFS_PYS:_defs.py=_defs.inc)

STRSWITCH_INCS = drgn_program_parse_vmcoreinfo.inc \
		 linux_kernel_object_find.inc

BUILT_SOURCES = $(ARCH_DEFS_INCS) \
		$(STRSWITCH_INCS) \
		c_keywords.inc \
		drgn.h \
		drgn_section_name_to_index.inc \
		elf_sections.h

noinst_LTLIBRARIES = libdrgnimpl.la

libdrgnimpl_la_SOURCES = $(ARCH_DEFS_PYS:_defs.py=.c) \
			 $(ARCH_DEFS_INCS) \
			 $(STRSWITCH_INCS) \
			 arch_arm.c \
			 arch_i386.c \
			 arch_riscv.c \
			 array.h \
			 binary_buffer.c \
			 binary_buffer.h \
			 binary_search_tree.h \
			 bitops.h \
			 c_keywords.inc \
			 c_lexer.h \
			 cfi.c \
			 cfi.h \
			 cityhash.h \
			 cleanup.h \
			 debug_info.c \
			 debug_info.h \
			 drgn_section_name_to_index.inc \
			 dwarf_constants.c \
			 dwarf_constants.h \
			 dwarf_info.c \
			 dwarf_info.h \
			 elf_file.c \
			 elf_file.h \
			 elf_sections.h \
			 error.c \
			 error.h \
			 generics.h \
			 handler.c \
			 handler.h \
			 hash_table.c \
			 hash_table.h \
			 helpers.h \
			 io.c \
			 io.h \
			 language.c \
			 language.h \
			 language_c.c \
			 lazy_object.c \
			 lazy_object.h \
			 lexer.c \
			 lexer.h \
			 linux_kernel.c \
			 linux_kernel.h \
			 linux_kernel_helpers.c \
			 log.c \
			 log.h \
			 memory_reader.c \
			 memory_reader.h \
			 minmax.h \
			 nstring.h \
			 object.c \
			 object.h \
			 openmp.c \
			 openmp.h \
			 orc.h \
			 orc_info.c \
			 orc_info.h \
			 path.c \
			 path.h \
			 platform.c \
			 platform.h \
			 pp.h \
			 program.c \
			 program.h \
			 register_state.c \
			 register_state.h \
			 serialize.c \
			 serialize.h \
			 splay_tree.c \
			 stack_trace.c \
			 stack_trace.h \
			 string_builder.c \
			 string_builder.h \
			 symbol.c \
			 symbol.h \
			 type.c \
			 type.h \
			 util.h \
			 vector.h

libdrgnimpl_la_CFLAGS = $(AM_CFLAGS) -fvisibility=hidden $(OPENMP_CFLAGS) \
			$(elfutils_CFLAGS)
libdrgnimpl_la_CPPFLAGS = $(AM_CPPFLAGS) -iquote .
libdrgnimpl_la_LIBADD = $(OPENMP_LIBS) $(elfutils_LIBS) -lm

if WITH_LIBKDUMPFILE
libdrgnimpl_la_SOURCES += kdump.c
libdrgnimpl_la_CFLAGS += $(libkdumpfile_CFLAGS)
libdrgnimpl_la_LIBADD += $(libkdumpfile_LIBS)
endif

%: %.strswitch build-aux/gen_strswitch.py build-aux/codegen_utils.py
	$(AM_V_GEN)$(PYTHON) $(word 2, $^) -o $@ $<

arch_%_defs.inc: arch_%_defs.py build-aux/gen_arch_inc_strswitch.py build-aux/gen_strswitch.py build-aux/codegen_utils.py
	$(AM_V_GEN)$(PYTHON) $(word 2, $^) $< | $(PYTHON) $(word 3, $^) -o $@ -

c_keywords.inc: build-aux/gen_c_keywords_inc_strswitch.py build-aux/gen_strswitch.py build-aux/codegen_utils.py
	$(AM_V_GEN)$(PYTHON) $< | $(PYTHON) $(word 2, $^) -o $@ -

drgn_section_name_to_index.inc: build-aux/gen_elf_sections.py build-aux/gen_strswitch.py build-aux/codegen_utils.py
	$(AM_V_GEN)$(PYTHON) $< | $(PYTHON) $(word 2, $^) -o $@ -

elf_sections.h: build-aux/gen_elf_sections.py build-aux/codegen_utils.py
	$(AM_V_GEN)$(PYTHON) $< -H > $@

lib_LTLIBRARIES = libdrgn.la

libdrgn_la_SOURCES =
libdrgn_la_LDFLAGS = $(AM_LDFLAGS) -version-info 0:0:0
libdrgn_la_LIBADD = libdrgnimpl.la

if ENABLE_PYTHON
BUILT_SOURCES += python/docstrings.h

noinst_LTLIBRARIES += _drgn.la
endif

_drgn_la_SOURCES = python/constants.c \
		   python/docstrings.c \
		   python/docstrings.h \
		   python/drgnpy.h \
		   python/error.c \
		   python/helpers.c \
		   python/language.c \
		   python/main.c \
		   python/object.c \
		   python/platform.c \
		   python/program.c \
		   python/stack_trace.c \
		   python/symbol.c \
		   python/test.c \
		   python/thread.c \
		   python/type.c \
		   python/type_kind_set.c \
		   python/util.c

_drgn_la_CFLAGS = $(AM_CFLAGS) -fvisibility=hidden
_drgn_la_CPPFLAGS = $(AM_CPPFLAGS) $(PYTHON_CPPFLAGS) -iquote $(srcdir)/python \
		    -iquote python
_drgn_la_LDFLAGS = $(AM_LDFLAGS) -Wl,--exclude-libs,ALL -avoid-version -module \
		   -shared -rpath $(pkgpyexecdir)
_drgn_la_LIBADD = libdrgnimpl.la

if WITH_LIBKDUMPFILE
_drgn_la_CFLAGS += $(libkdumpfile_CFLAGS)
endif

python/constants.c: drgn.h build-aux/gen_constants.py
	$(AM_V_GEN)$(PYTHON) $(word 2, $^) < $< > $@

drgndoc_docstrings_deps = $(wildcard $(srcdir)/../docs/exts/drgndoc/*.py)
drgndoc_docstrings = PYTHONPATH="$(srcdir)/../docs/exts:$$PYTHONPATH" $(PYTHON) -m drgndoc.docstrings

python/docstrings.c: ../_drgn.pyi $(drgndoc_docstrings_deps)
	$(AM_V_GEN)$(drgndoc_docstrings) -m _drgn:drgn $< > $@

python/docstrings.h: ../_drgn.pyi $(drgndoc_docstrings_deps)
	$(AM_V_GEN)$(drgndoc_docstrings) -H -m _drgn:drgn $< > $@

EXTRA_DIST = $(ARCH_DEFS_PYS) \
	     $(STRSWITCH_INCS:.inc=.inc.strswitch) \
	     Doxyfile \
	     build-aux/checkmk \
	     build-aux/codegen_utils.py \
	     build-aux/gen_arch_inc_strswitch.py \
	     build-aux/gen_c_keywords_inc_strswitch.py \
	     build-aux/gen_constants.py \
	     build-aux/gen_elf_sections.py \
	     build-aux/gen_strswitch.py

EXTRA_PROGRAMS = examples/load_debug_info

examples_load_debug_info_SOURCES = examples/load_debug_info.c
examples_load_debug_info_LDADD = libdrgnimpl.la

# Only test internals here. Anything exposed via Python should be tested in
# Python unit tests instead.
TESTS = $(check_PROGRAMS)

check_PROGRAMS = tests/cityhash \
		 tests/language_c \
		 tests/lexer \
		 tests/path

EXTRA_DIST += $(addsuffix .c.in,$(check_PROGRAMS))

AM_TESTS_ENVIRONMENT = export CK_TAP_LOG_FILE_NAME=-;

LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
	     $(top_srcdir)/build-aux/tap-driver.sh

tests/%.c: build-aux/checkmk tests/%.c.in
	$(AWK) -f $^ > $@

test_cflags = $(AM_CFLAGS) $(check_CFLAGS)
test_cppflags = $(AM_CPPFLAGS) -iquote $(srcdir)/tests
test_ldadd = $(check_LIBS) libdrgnimpl.la

tests_cityhash_CFLAGS = $(test_cflags)
tests_cityhash_CPPFLAGS = $(test_cppflags)
tests_cityhash_LDADD = $(test_ldadd)
tests_language_c_CFLAGS = $(test_cflags)
tests_language_c_CPPFLAGS = $(test_cppflags)
tests_language_c_LDADD = $(test_ldadd)
tests_lexer_CFLAGS = $(test_cflags)
tests_lexer_CPPFLAGS = $(test_cppflags)
tests_lexer_LDADD = $(test_ldadd)
tests_path_CFLAGS = $(test_cflags)
tests_path_CPPFLAGS = $(test_cppflags)
tests_path_LDADD = $(test_ldadd)

# Don't delete test-suite.log on failure.
.PRECIOUS: $(TEST_SUITE_LOG)
