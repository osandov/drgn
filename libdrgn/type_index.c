// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <limits.h>
#include <string.h>

#include "internal.h"
#include "language.h"
#include "type_index.h"

/* These functions compare the underlying type by reference, not by value. */

static struct hash_pair
drgn_pointer_type_hash(struct drgn_type * const *key)
{
	struct drgn_type *type = *key;
	struct drgn_qualified_type referenced_type;
	size_t hash;

	referenced_type = drgn_type_type(type);
	hash = hash_combine(hash_combine((uintptr_t)referenced_type.type,
					 referenced_type.qualifiers),
			    drgn_type_size(type));
	return hash_pair_from_avalanching_hash(hash);
}

static bool drgn_pointer_type_eq(struct drgn_type * const *ap,
				 struct drgn_type * const *bp)
{
	struct drgn_type *a = *ap, *b = *bp;
	struct drgn_qualified_type referenced_a, referenced_b;

	referenced_a = drgn_type_type(a);
	referenced_b = drgn_type_type(b);
	return (referenced_a.type == referenced_b.type &&
		referenced_a.qualifiers == referenced_b.qualifiers &&
		drgn_type_size(a) == drgn_type_size(b));
}

DEFINE_HASH_SET_FUNCTIONS(drgn_pointer_type_set, struct drgn_type *,
			  drgn_pointer_type_hash, drgn_pointer_type_eq)

static struct hash_pair
drgn_array_type_hash(struct drgn_type * const *key)
{
	struct drgn_type *type = *key;
	struct drgn_qualified_type referenced_type;
	size_t hash;

	referenced_type = drgn_type_type(type);
	hash = hash_combine((uintptr_t)referenced_type.type,
			    referenced_type.qualifiers);
	hash = hash_combine(hash, drgn_type_is_complete(type));
	hash = hash_combine(hash, drgn_type_length(type));
	return hash_pair_from_avalanching_hash(hash);
}

static bool drgn_array_type_eq(struct drgn_type * const *ap,
			       struct drgn_type * const *bp)
{
	struct drgn_type *a = *ap, *b = *bp;
	struct drgn_qualified_type referenced_a, referenced_b;

	referenced_a = drgn_type_type(a);
	referenced_b = drgn_type_type(b);
	return (referenced_a.type == referenced_b.type &&
		referenced_a.qualifiers == referenced_b.qualifiers &&
		drgn_type_is_complete(a) == drgn_type_is_complete(b) &&
		drgn_type_length(a) == drgn_type_length(b));
}

DEFINE_HASH_SET_FUNCTIONS(drgn_array_type_set, struct drgn_type *,
			  drgn_array_type_hash, drgn_array_type_eq)

void drgn_type_index_init(struct drgn_type_index *tindex,
			  const struct drgn_type_index_ops *ops,
			  uint8_t word_size, bool little_endian)
{
	memset(tindex, 0, sizeof(*tindex));
	tindex->ops = ops;
	drgn_pointer_type_set_init(&tindex->pointer_types);
	drgn_array_type_set_init(&tindex->array_types);
	tindex->word_size = word_size;
	tindex->little_endian = little_endian;
}

static void free_pointer_types(struct drgn_type_index *tindex)
{
	struct drgn_pointer_type_set_pos pos;

	pos = drgn_pointer_type_set_first_pos(&tindex->pointer_types);
	while (pos.item) {
		free(*pos.item);
		drgn_pointer_type_set_next_pos(&pos);
	}
	drgn_pointer_type_set_deinit(&tindex->pointer_types);
}

static void free_array_types(struct drgn_type_index *tindex)
{
	struct drgn_array_type_set_pos pos;

	pos = drgn_array_type_set_first_pos(&tindex->array_types);
	while (pos.item) {
		free(*pos.item);
		drgn_array_type_set_next_pos(&pos);
	}
	drgn_array_type_set_deinit(&tindex->array_types);
}

void drgn_type_index_deinit(struct drgn_type_index *tindex)
{
	free_array_types(tindex);
	free_pointer_types(tindex);
}

/* Default long, unsigned long, size_t, and ptrdiff_t are 64 bits. */
static struct drgn_type default_primitive_types[DRGN_PRIMITIVE_TYPE_NUM];
/* 32-bit version of long, unsigned long, size_t, and ptrdiff_t. */
static struct drgn_type default_primitive_types_32bit[4];

__attribute__((constructor(200)))
static void default_primitive_types_init(void)
{
	struct drgn_qualified_type qualified_type;
	size_t i;

	drgn_int_type_init(&default_primitive_types[DRGN_C_TYPE_CHAR],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_CHAR][0],
			   1, true);
	drgn_int_type_init(&default_primitive_types[DRGN_C_TYPE_SIGNED_CHAR],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_SIGNED_CHAR][0],
			   1, true);
	drgn_int_type_init(&default_primitive_types[DRGN_C_TYPE_UNSIGNED_CHAR],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_UNSIGNED_CHAR][0],
			   1, false);
	drgn_int_type_init(&default_primitive_types[DRGN_C_TYPE_SHORT],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_SHORT][0],
			   2, true);
	drgn_int_type_init(&default_primitive_types[DRGN_C_TYPE_UNSIGNED_SHORT],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_UNSIGNED_SHORT][0],
			   2, false);
	drgn_int_type_init(&default_primitive_types[DRGN_C_TYPE_INT],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_INT][0], 4,
			   true);
	drgn_int_type_init(&default_primitive_types[DRGN_C_TYPE_UNSIGNED_INT],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_UNSIGNED_INT][0],
			   4, false);
	drgn_int_type_init(&default_primitive_types[DRGN_C_TYPE_LONG],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_LONG][0],
			   8, true);
	drgn_int_type_init(&default_primitive_types[DRGN_C_TYPE_UNSIGNED_LONG],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_UNSIGNED_LONG][0],
			   8, false);
	drgn_int_type_init(&default_primitive_types[DRGN_C_TYPE_LONG_LONG],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_LONG_LONG][0],
			   8, true);
	drgn_int_type_init(&default_primitive_types[DRGN_C_TYPE_UNSIGNED_LONG_LONG],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_UNSIGNED_LONG_LONG][0],
			   8, false);
	drgn_bool_type_init(&default_primitive_types[DRGN_C_TYPE_BOOL],
			    drgn_primitive_type_spellings[DRGN_C_TYPE_BOOL][0],
			    1);
	drgn_float_type_init(&default_primitive_types[DRGN_C_TYPE_FLOAT],
			     drgn_primitive_type_spellings[DRGN_C_TYPE_FLOAT][0],
			     4);
	drgn_float_type_init(&default_primitive_types[DRGN_C_TYPE_DOUBLE],
			     drgn_primitive_type_spellings[DRGN_C_TYPE_DOUBLE][0],
			     8);
	drgn_float_type_init(&default_primitive_types[DRGN_C_TYPE_LONG_DOUBLE],
			     drgn_primitive_type_spellings[DRGN_C_TYPE_LONG_DOUBLE][0],
			     16);
	qualified_type.type = &default_primitive_types[DRGN_C_TYPE_UNSIGNED_LONG];
	qualified_type.qualifiers = 0;
	drgn_typedef_type_init(&default_primitive_types[DRGN_C_TYPE_SIZE_T],
			       drgn_primitive_type_spellings[DRGN_C_TYPE_SIZE_T][0],
			       qualified_type);
	qualified_type.type = &default_primitive_types[DRGN_C_TYPE_LONG];
	drgn_typedef_type_init(&default_primitive_types[DRGN_C_TYPE_PTRDIFF_T],
			       drgn_primitive_type_spellings[DRGN_C_TYPE_PTRDIFF_T][0],
			       qualified_type);
	for (i = 0; i < ARRAY_SIZE(default_primitive_types); i++) {
		if (drgn_primitive_type_kind[i] == DRGN_TYPE_VOID)
			continue;
		assert(drgn_type_primitive(&default_primitive_types[i]) == i);
	}

	drgn_int_type_init(&default_primitive_types_32bit[0],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_LONG][0],
			   4, true);
	drgn_int_type_init(&default_primitive_types_32bit[1],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_UNSIGNED_LONG][0],
			   4, false);
	qualified_type.type = &default_primitive_types_32bit[1];
	drgn_typedef_type_init(&default_primitive_types_32bit[2],
			       drgn_primitive_type_spellings[DRGN_C_TYPE_SIZE_T][0],
			       qualified_type);
	qualified_type.type = &default_primitive_types_32bit[0];
	drgn_typedef_type_init(&default_primitive_types_32bit[3],
			       drgn_primitive_type_spellings[DRGN_C_TYPE_PTRDIFF_T][0],
			       qualified_type);
	assert(drgn_type_primitive(&default_primitive_types_32bit[0]) ==
	       DRGN_C_TYPE_LONG);
	assert(drgn_type_primitive(&default_primitive_types_32bit[1]) ==
	       DRGN_C_TYPE_UNSIGNED_LONG);
	assert(drgn_type_primitive(&default_primitive_types_32bit[2]) ==
	       DRGN_C_TYPE_SIZE_T);
	assert(drgn_type_primitive(&default_primitive_types_32bit[3]) ==
	       DRGN_C_TYPE_PTRDIFF_T);
}

struct drgn_error *
drgn_type_index_find_primitive(struct drgn_type_index *tindex,
			       enum drgn_primitive_type type,
			       struct drgn_type **ret)
{
	struct drgn_error *err;
	struct drgn_qualified_type qualified_type;
	enum drgn_type_kind kind;
	const char * const *spellings;
	size_t i;

	if (tindex->primitive_types[type]) {
		*ret = tindex->primitive_types[type];
		return NULL;
	}

	kind = drgn_primitive_type_kind[type];
	if (kind == DRGN_TYPE_VOID) {
		*ret = &drgn_void_type;
		goto out;
	}

	spellings = drgn_primitive_type_spellings[type];
	for (i = 0; spellings[i]; i++) {
		err = drgn_type_index_find_internal(tindex, kind, spellings[i],
						    strlen(spellings[i]), NULL,
						    &qualified_type);
		if (err && err->code == DRGN_ERROR_LOOKUP) {
			drgn_error_destroy(err);
		} else if (err) {
			return err;
		} else if (drgn_type_primitive(qualified_type.type) == type) {
			*ret = qualified_type.type;
			goto out;
		}
	}

	if (tindex->word_size == 4 && type == DRGN_C_TYPE_LONG)
		*ret = &default_primitive_types_32bit[0];
	else if (tindex->word_size == 4 && type == DRGN_C_TYPE_UNSIGNED_LONG)
		*ret = &default_primitive_types_32bit[1];
	else if (tindex->word_size == 4 && type == DRGN_C_TYPE_SIZE_T)
		*ret = &default_primitive_types_32bit[2];
	else if (tindex->word_size == 4 && type == DRGN_C_TYPE_PTRDIFF_T)
		*ret = &default_primitive_types_32bit[3];
	else
		*ret = &default_primitive_types[type];
out:
	tindex->primitive_types[type] = *ret;
	return NULL;
}

struct drgn_error *
drgn_type_index_pointer_type(struct drgn_type_index *tindex, uint64_t size,
			     struct drgn_qualified_type referenced_type,
			     struct drgn_type **ret)
{
	struct drgn_type key, *type = &key;
	struct drgn_pointer_type_set_pos pos;
	struct hash_pair hp;

	drgn_pointer_type_init(type, size, referenced_type);
	hp = drgn_pointer_type_set_hash(&type);
	pos = drgn_pointer_type_set_search_pos(&tindex->pointer_types, &type,
					       hp);
	if (pos.item) {
		*ret = *pos.item;
		return NULL;
	}

	type = malloc(sizeof(*type));
	if (!type)
		return &drgn_enomem;
	*type = key;

	if (!drgn_pointer_type_set_insert_searched(&tindex->pointer_types,
						   &type, hp)) {
		free(type);
		return &drgn_enomem;
	}
	*ret = type;
	return NULL;
}

static struct drgn_error *
drgn_type_index_array_type_internal(struct drgn_type_index *tindex,
				    struct drgn_type *key,
				    struct drgn_type **ret)
{
	struct drgn_type *type;
	struct drgn_array_type_set_pos pos;
	struct hash_pair hp;

	hp = drgn_array_type_set_hash(&key);
	pos = drgn_array_type_set_search_pos(&tindex->array_types, &key, hp);
	if (pos.item) {
		*ret = *pos.item;
		return NULL;
	}

	type = malloc(sizeof(*type));
	if (!type)
		return &drgn_enomem;
	*type = *key;

	if (!drgn_array_type_set_insert_searched(&tindex->array_types, &type,
						 hp)) {
		free(type);
		return &drgn_enomem;
	}
	*ret = type;
	return NULL;
}

struct drgn_error *
drgn_type_index_array_type(struct drgn_type_index *tindex, uint64_t length,
			   struct drgn_qualified_type element_type,
			   struct drgn_type **ret)
{
	struct drgn_type key;

	drgn_array_type_init(&key, length, element_type);
	return drgn_type_index_array_type_internal(tindex, &key, ret);
}

struct drgn_error *
drgn_type_index_incomplete_array_type(struct drgn_type_index *tindex,
				      struct drgn_qualified_type element_type,
				      struct drgn_type **ret)
{
	struct drgn_type key;

	drgn_array_type_init_incomplete(&key, element_type);
	return drgn_type_index_array_type_internal(tindex, &key, ret);
}

struct drgn_error *
drgn_type_index_not_found_error(enum drgn_type_kind kind,
				const char *name, size_t name_len,
				const char *filename)
{
	static const char *type_kind_spelling[] = {
		[DRGN_TYPE_STRUCT] = "struct",
		[DRGN_TYPE_UNION] = "union",
		[DRGN_TYPE_ENUM] = "enum",
		[DRGN_TYPE_TYPEDEF] = "typedef",
	};
	int precision = name_len < INT_MAX ? (int)name_len : INT_MAX;

	if (filename) {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find '%s %.*s' in '%s'",
					 type_kind_spelling[kind], precision, name,
					 filename);
	} else {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find '%s %.*s'",
					 type_kind_spelling[kind], precision, name);
	}
}
