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

static struct drgn_error *
drgn_mock_type_index_find(struct drgn_type_index *tindex,
			  enum drgn_type_kind kind, const char *name,
			  size_t name_len, const char *filename,
			  struct drgn_qualified_type *ret)
{
	struct drgn_mock_type_index *mtindex;
	size_t i;

	mtindex = container_of(tindex, struct drgn_mock_type_index, tindex);
	if (!mtindex->types)
		goto not_found;
	for (i = 0; mtindex->types[i].type; i++) {
		struct drgn_type *type = mtindex->types[i].type;
		const char *type_filename = mtindex->types[i].filename;
		const char *type_name;

		if (drgn_type_kind(type) != kind)
			continue;

		if (kind == DRGN_TYPE_TYPEDEF)
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
not_found:
	return drgn_type_index_not_found_error(kind, name, name_len, filename);
}

static void drgn_mock_type_index_destroy(struct drgn_type_index *tindex)
{
	struct drgn_mock_type_index *mtindex;

	mtindex = container_of(tindex, struct drgn_mock_type_index, tindex);
	drgn_type_index_deinit(tindex);
	free(mtindex);
}

static const struct drgn_type_index_ops drgn_mock_type_index_ops = {
	.find = drgn_mock_type_index_find,
	.destroy = drgn_mock_type_index_destroy,
};

struct drgn_error *
drgn_mock_type_index_create(uint8_t word_size, bool little_endian,
			    struct drgn_mock_type *types,
			    struct drgn_mock_type_index **ret)
{
	struct drgn_mock_type_index *mtindex;

	if (word_size != 4 && word_size != 8) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "type index word size must be 4 or 8");
	}

	mtindex = malloc(sizeof(*mtindex));
	if (!mtindex)
		return &drgn_enomem;

	drgn_type_index_init(&mtindex->tindex, &drgn_mock_type_index_ops,
			     word_size, little_endian);
	mtindex->types = types;

	*ret = mtindex;
	return NULL;
}

static struct drgn_error *
drgn_mock_symbol_index_find(struct drgn_symbol_index *sindex,
			    const char *name, const char *filename,
			    enum drgn_find_object_flags flags,
			    struct drgn_symbol *ret)
{
	struct drgn_mock_symbol_index *msindex;
	size_t i;

	msindex = container_of(sindex, struct drgn_mock_symbol_index, sindex);
	if (!msindex->symbols)
		goto not_found;
	for (i = 0; msindex->symbols[i].name; i++) {
		const struct drgn_mock_symbol *obj = &msindex->symbols[i];
		struct drgn_type *underlying_type;
		bool is_function;

		underlying_type = drgn_underlying_type(obj->qualified_type.type);
		is_function = (drgn_type_kind(underlying_type) ==
			       DRGN_TYPE_FUNCTION);
		if (obj->is_enumerator) {
		    if (!(flags & DRGN_FIND_OBJECT_CONSTANT))
			    continue;
		} else if (is_function) {
		    if (!(flags & DRGN_FIND_OBJECT_FUNCTION))
			    continue;
		} else if (!(flags & DRGN_FIND_OBJECT_VARIABLE)) {
			    continue;
		}

		if (strcmp(obj->name, name) != 0 ||
		    !filename_matches(obj->filename, filename))
			continue;

		ret->qualified_type = obj->qualified_type;
		if (obj->is_enumerator) {
			return drgn_symbol_from_enumerator(ret, obj->name);
		} else {
			ret->is_enumerator = false;
			ret->little_endian = obj->little_endian;
			ret->address = obj->address;
			return NULL;
		}
	}
not_found:
	return drgn_symbol_index_not_found_error(name, filename, flags);
}

static void drgn_mock_symbol_index_destroy(struct drgn_symbol_index *sindex)
{
	struct drgn_mock_symbol_index *msindex;

	msindex = container_of(sindex, struct drgn_mock_symbol_index, sindex);
	free(msindex);
}

static const struct drgn_symbol_index_ops drgn_mock_symbol_index_ops = {
	.destroy = drgn_mock_symbol_index_destroy,
	.find = drgn_mock_symbol_index_find,
};

struct drgn_error *
drgn_mock_symbol_index_create(struct drgn_mock_symbol *symbols,
			      struct drgn_mock_symbol_index **ret)
{
	struct drgn_mock_symbol_index *msindex;

	msindex = malloc(sizeof(*msindex));
	if (!msindex)
		return &drgn_enomem;

	msindex->sindex.ops = &drgn_mock_symbol_index_ops;
	msindex->symbols = symbols;

	*ret = msindex;
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
	struct drgn_mock_type_index *mtindex;
	struct drgn_mock_symbol_index *msindex;
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

	err = drgn_mock_type_index_create(word_size, little_endian, types,
					  &mtindex);
	if (err)
		goto err_reader;

	err = drgn_mock_symbol_index_create(symbols, &msindex);
	if (err)
		goto err_tindex;

	drgn_program_init(prog, reader, &mtindex->tindex, &msindex->sindex);
	return NULL;

err_tindex:
	drgn_type_index_destroy(&mtindex->tindex);
err_reader:
	drgn_memory_reader_destroy(reader);
	return err;
}
