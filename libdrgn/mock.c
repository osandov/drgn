// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <inttypes.h>
#include <stdlib.h>

#include "internal.h"
#include "program.h"

static struct drgn_error *drgn_mock_memory_read(void *buf, uint64_t address,
						size_t count, bool physical,
						uint64_t offset, void *arg)
{
	memcpy(buf, (char *)arg + offset, count);
	return NULL;
}

static bool filename_matches(const char *entry_filename, const char *filename)
{
	struct path_iterator haystack = {
		.components = (struct path_iterator_component [1]){},
		.num_components = 1,
	};
	struct path_iterator needle = {
		.components = (struct path_iterator_component [1]){},
		.num_components = 1,
	};

	if (!filename || !filename[0])
		return true;
	if (!entry_filename)
		return true;

	haystack.components[0].path = entry_filename;
	haystack.components[0].len = strlen(entry_filename);
	needle.components[1].path = filename;
	needle.components[1].len = strlen(filename);
	return path_ends_with(&haystack, &needle);
}

static struct drgn_error *drgn_mock_type_find(enum drgn_type_kind kind,
					      const char *name, size_t name_len,
					      const char *filename, void *arg,
					      struct drgn_qualified_type *ret)
{
	struct drgn_mock_type *types = arg;
	size_t i;

	if (!types) {
		ret->type = NULL;
		return NULL;
	}
	for (i = 0; types[i].type; i++) {
		struct drgn_type *type = types[i].type;
		const char *type_filename = types[i].filename;
		const char *type_name;

		if (drgn_type_kind(type) != kind)
			continue;

		if (drgn_type_has_name(type))
			type_name = drgn_type_name(type);
		else
			type_name = drgn_type_tag(type);
		if (!type_name || strncmp(type_name, name, name_len) != 0 ||
		    type_name[name_len] ||
		    !filename_matches(type_filename, filename))
			continue;

		ret->type = type;
		ret->qualifiers = 0;
		return NULL;
	}
	ret->type = NULL;
	return NULL;
}

static struct drgn_error *
drgn_mock_symbol_find(const char *name, size_t name_len, const char *filename,
		      enum drgn_find_object_flags flags, void *arg,
		      struct drgn_symbol *ret)
{
	struct drgn_mock_symbol *symbols = arg;
	size_t i;

	if (!symbols) {
		ret->type = NULL;
		return NULL;
	}
	for (i = 0; symbols[i].name; i++) {
		const struct drgn_mock_symbol *sym = &symbols[i];
		struct drgn_type *underlying_type;
		bool is_function;

		underlying_type = drgn_underlying_type(sym->qualified_type.type);
		is_function = (drgn_type_kind(underlying_type) ==
			       DRGN_TYPE_FUNCTION);
		if (sym->is_enumerator) {
		    if (!(flags & DRGN_FIND_OBJECT_CONSTANT))
			    continue;
		} else if (is_function) {
		    if (!(flags & DRGN_FIND_OBJECT_FUNCTION))
			    continue;
		} else if (!(flags & DRGN_FIND_OBJECT_VARIABLE)) {
			    continue;
		}

		if (strncmp(sym->name, name, name_len) != 0 ||
		    sym->name[name_len] ||
		    !filename_matches(sym->filename, filename))
			continue;

		ret->type = sym->qualified_type.type;
		ret->qualifiers = sym->qualified_type.qualifiers;
		if (sym->is_enumerator) {
			ret->kind = DRGN_SYMBOL_ENUMERATOR;
		} else {
			ret->kind = DRGN_SYMBOL_ADDRESS;
			ret->little_endian = sym->little_endian;
			ret->address = sym->address;
		}
		return NULL;
	}
	ret->type = NULL;
	return NULL;
}

struct drgn_error *
drgn_program_init_mock(struct drgn_program *prog, uint8_t word_size,
		       bool little_endian,
		       struct drgn_mock_memory_segment *segments,
		       size_t num_segments, struct drgn_mock_type *types,
		       struct drgn_mock_symbol *symbols)
{
	struct drgn_error *err;
	struct drgn_memory_reader *reader;
	struct drgn_type_index *tindex;
	struct drgn_symbol_index *sindex;
	size_t i;

	err = drgn_memory_reader_create(&reader);
	if (err)
		return err;

	for (i = 0; i < num_segments; i++) {
		struct drgn_mock_memory_segment *segment = &segments[i];

		err = drgn_memory_reader_add_segment(reader, segment->virt_addr,
						     segment->phys_addr,
						     segment->size,
						     drgn_mock_memory_read,
						     (void *)segment->buf);
		if (err)
			goto err_reader;
	}

	err = drgn_type_index_create(word_size, &tindex);
	if (err)
		goto err_reader;

	err = drgn_type_index_add_finder(tindex, drgn_mock_type_find, types);
	if (err)
		goto err_tindex;

	err = drgn_symbol_index_create(&sindex);
	if (err)
		goto err_tindex;

	err = drgn_symbol_index_add_finder(sindex, drgn_mock_symbol_find,
					   symbols);
	if (err)
		goto err_sindex;

	drgn_program_init(prog, reader, tindex, sindex);
	prog->little_endian = little_endian;
	return NULL;

err_sindex:
	drgn_symbol_index_destroy(sindex);
err_tindex:
	drgn_type_index_destroy(tindex);
err_reader:
	drgn_memory_reader_destroy(reader);
	return err;
}
