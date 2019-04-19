// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <inttypes.h>
#include <stdlib.h>

#include "internal.h"
#include "program.h"

static struct drgn_error *
drgn_mock_memory_reader_read(struct drgn_memory_reader *reader, void *buf,
			     uint64_t address, size_t count, bool physical)
{
	struct drgn_mock_memory_reader *mreader;
	char *p = buf;

	mreader = container_of(reader, struct drgn_mock_memory_reader, reader);
	while (count) {
		struct drgn_mock_memory_segment *segment;
		uint64_t segment_address;
		uint64_t segment_offset;
		size_t copy_count;
		size_t i;

		for (i = 0; i < mreader->num_segments; i++) {
			segment = &mreader->segments[i];
			segment_address = (physical ? segment->phys_addr :
					   segment->virt_addr);
			if (segment_address <= address &&
			    address < segment_address + segment->size)
				break;
		}
		if (i >= mreader->num_segments) {
			return drgn_error_format(DRGN_ERROR_FAULT,
						 "could not find memory segment containing 0x%" PRIx64,
						 address);
		}

		segment_offset = address - segment_address;
		copy_count = min(segment->size - segment_offset,
				 (uint64_t)count);
		memcpy(p, (const char *)segment->buf + segment_offset,
		       copy_count);

		p += copy_count;
		count -= copy_count;
		address += copy_count;
	}
	return NULL;
}

static void drgn_mock_memory_reader_destroy(struct drgn_memory_reader *reader)
{
	struct drgn_mock_memory_reader *mreader;

	mreader = container_of(reader, struct drgn_mock_memory_reader, reader);
	free(mreader);
}

static const struct drgn_memory_reader_ops drgn_mock_memory_reader_ops = {
	.destroy = drgn_mock_memory_reader_destroy,
	.read = drgn_mock_memory_reader_read,
};

struct drgn_error *
drgn_mock_memory_reader_create(struct drgn_mock_memory_segment *segments,
			       size_t num_segments,
			       struct drgn_mock_memory_reader **ret)
{
	struct drgn_mock_memory_reader *mreader;

	mreader = malloc(sizeof(*mreader));
	if (!mreader)
		return &drgn_enomem;

	mreader->reader.ops = &drgn_mock_memory_reader_ops;
	mreader->segments = segments;
	mreader->num_segments = num_segments;

	*ret = mreader;
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
	for (i = 0; i < mtindex->num_types; i++) {
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
			    struct drgn_mock_type *types, size_t num_types,
			    struct drgn_mock_type_index **ret)
{
	struct drgn_mock_type_index *mtindex;
	size_t i;

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
	mtindex->num_types = num_types;

	for (i = 0; i < mtindex->num_types; i++) {
		struct drgn_type *type = mtindex->types[i].type;
		enum drgn_primitive_type primitive;

		primitive = drgn_type_primitive(type);
		if (primitive != DRGN_NOT_PRIMITIVE_TYPE)
			mtindex->tindex.primitive_types[primitive] = type;
	}

	*ret = mtindex;
	return NULL;
}

static struct drgn_error *
drgn_mock_object_index_find(struct drgn_object_index *oindex,
			    const char *name, const char *filename,
			    enum drgn_find_object_flags flags,
			    struct drgn_partial_object *ret)
{
	struct drgn_mock_object_index *moindex;
	size_t i;

	moindex = container_of(oindex, struct drgn_mock_object_index, oindex);

	for (i = 0; i < moindex->num_objects; i++) {
		const struct drgn_mock_object *obj = &moindex->objects[i];
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
			return drgn_partial_object_from_enumerator(ret,
								   obj->name);
		} else {
			ret->is_enumerator = false;
			ret->little_endian = obj->little_endian;
			ret->address = obj->address;
			return NULL;
		}
	}
	return drgn_object_index_not_found_error(name, filename, flags);
}

static void drgn_mock_object_index_destroy(struct drgn_object_index *oindex)
{
	struct drgn_mock_object_index *moindex;

	moindex = container_of(oindex, struct drgn_mock_object_index, oindex);
	free(moindex);
}

static const struct drgn_object_index_ops drgn_mock_object_index_ops = {
	.destroy = drgn_mock_object_index_destroy,
	.find = drgn_mock_object_index_find,
};

struct drgn_error *
drgn_mock_object_index_create(struct drgn_mock_object *objects,
			      size_t num_objects,
			      struct drgn_mock_object_index **ret)
{
	struct drgn_mock_object_index *moindex;

	moindex = malloc(sizeof(*moindex));
	if (!moindex)
		return &drgn_enomem;

	moindex->oindex.ops = &drgn_mock_object_index_ops;
	moindex->objects = objects;
	moindex->num_objects = num_objects;

	*ret = moindex;
	return NULL;
}

struct drgn_error *
drgn_program_init_mock(struct drgn_program *prog, uint8_t word_size,
		       bool little_endian,
		       struct drgn_mock_memory_segment *segments,
		       size_t num_segments, struct drgn_mock_type *types,
		       size_t num_types, struct drgn_mock_object *objects,
		       size_t num_objects,
		       void (*deinit_fn)(struct drgn_program *))
{
	struct drgn_error *err;
	struct drgn_mock_memory_reader *mreader;
	struct drgn_mock_type_index *mtindex;
	struct drgn_mock_object_index *moindex;

	err = drgn_mock_memory_reader_create(segments, num_segments, &mreader);
	if (err)
		return err;

	err = drgn_mock_type_index_create(word_size, little_endian, types,
					  num_types, &mtindex);
	if (err)
		goto err_reader;

	err = drgn_mock_object_index_create(objects, num_objects, &moindex);
	if (err)
		goto err_tindex;

	drgn_program_init(prog, &mreader->reader, &mtindex->tindex,
			  &moindex->oindex, deinit_fn);
	return NULL;

err_tindex:
	drgn_type_index_destroy(&mtindex->tindex);
err_reader:
	drgn_memory_reader_destroy(&mreader->reader);
	return err;
}
