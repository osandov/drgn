// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

#include <limits.h>
#include <string.h>

#include "internal.h"
#include "language.h"
#include "type_index.h"

/* These functions compare the underlying type by reference, not by value. */

static struct hash_pair
drgn_pointer_type_key_hash(const struct drgn_pointer_type_key *key)
{
	size_t hash;

	hash = hash_combine((uintptr_t)key->type, key->qualifiers);
	hash = hash_combine(hash, (uintptr_t)key->lang);
	return hash_pair_from_avalanching_hash(hash);
}

static bool drgn_pointer_type_key_eq(const struct drgn_pointer_type_key *a,
				     const struct drgn_pointer_type_key *b)
{
	return (a->type == b->type && a->qualifiers == b->qualifiers &&
		a->lang == b->lang);
}

DEFINE_HASH_TABLE_FUNCTIONS(drgn_pointer_type_table, drgn_pointer_type_key_hash,
			    drgn_pointer_type_key_eq)

static struct hash_pair
drgn_array_type_key_hash(const struct drgn_array_type_key *key)
{
	size_t hash;

	hash = hash_combine((uintptr_t)key->type, key->qualifiers);
	hash = hash_combine(hash, key->is_complete);
	hash = hash_combine(hash, key->length);
	hash = hash_combine(hash, (uintptr_t)key->lang);
	return hash_pair_from_avalanching_hash(hash);
}

static bool drgn_array_type_key_eq(const struct drgn_array_type_key *a,
				   const struct drgn_array_type_key *b)
{
	return (a->type == b->type && a->qualifiers == b->qualifiers &&
		a->is_complete == b->is_complete && a->length == b->length &&
		a->lang == b->lang);
}

DEFINE_HASH_TABLE_FUNCTIONS(drgn_array_type_table, drgn_array_type_key_hash,
			    drgn_array_type_key_eq)

static struct hash_pair drgn_member_hash_pair(const struct drgn_member_key *key)
{
	size_t hash;

	if (key->name)
		hash = cityhash_size_t(key->name, key->name_len);
	else
		hash = 0;
	hash = hash_combine((uintptr_t)key->type, hash);
	return hash_pair_from_avalanching_hash(hash);
}

static bool drgn_member_eq(const struct drgn_member_key *a,
			   const struct drgn_member_key *b)
{
	return (a->type == b->type && a->name_len == b->name_len &&
		(!a->name_len || memcmp(a->name, b->name, a->name_len) == 0));
}

DEFINE_HASH_TABLE_FUNCTIONS(drgn_member_map, drgn_member_hash_pair,
			    drgn_member_eq)

DEFINE_HASH_TABLE_FUNCTIONS(drgn_type_set, hash_pair_ptr_type,
			    hash_table_scalar_eq)

void drgn_type_index_init(struct drgn_type_index *tindex)
{
	tindex->finders = NULL;
	memset(tindex->primitive_types, 0, sizeof(tindex->primitive_types));
	drgn_pointer_type_table_init(&tindex->pointer_types);
	drgn_array_type_table_init(&tindex->array_types);
	drgn_member_map_init(&tindex->members);
	drgn_type_set_init(&tindex->members_cached);
	tindex->word_size = 0;
}

static void free_pointer_types(struct drgn_type_index *tindex)
{
	struct drgn_pointer_type_table_iterator it;

	for (it = drgn_pointer_type_table_first(&tindex->pointer_types);
	     it.entry; it = drgn_pointer_type_table_next(it))
		free(*it.entry);
	drgn_pointer_type_table_deinit(&tindex->pointer_types);
}

static void free_array_types(struct drgn_type_index *tindex)
{
	struct drgn_array_type_table_iterator it;

	for (it = drgn_array_type_table_first(&tindex->array_types); it.entry;
	     it = drgn_array_type_table_next(it))
		free(*it.entry);
	drgn_array_type_table_deinit(&tindex->array_types);
}

void drgn_type_index_deinit(struct drgn_type_index *tindex)
{
	struct drgn_type_finder *finder;

	drgn_member_map_deinit(&tindex->members);
	drgn_type_set_deinit(&tindex->members_cached);
	free_array_types(tindex);
	free_pointer_types(tindex);

	finder = tindex->finders;
	while (finder) {
		struct drgn_type_finder *next = finder->next;

		free(finder);
		finder = next;
	}
}

struct drgn_error *drgn_type_index_add_finder(struct drgn_type_index *tindex,
					      drgn_type_find_fn fn, void *arg)
{
	struct drgn_type_finder *finder;

	finder = malloc(sizeof(*finder));
	if (!finder)
		return &drgn_enomem;
	finder->fn = fn;
	finder->arg = arg;
	finder->next = tindex->finders;
	tindex->finders = finder;
	return NULL;
}

void drgn_type_index_remove_finder(struct drgn_type_index *tindex)
{
	struct drgn_type_finder *finder;

	finder = tindex->finders->next;
	free(tindex->finders);
	tindex->finders = finder;
}

/* Default long and unsigned long are 64 bits. */
static struct drgn_type default_primitive_types[DRGN_PRIMITIVE_TYPE_NUM];
/* 32-bit versions of long and unsigned long. */
static struct drgn_type default_long_32bit;
static struct drgn_type default_unsigned_long_32bit;

__attribute__((constructor(200)))
static void default_primitive_types_init(void)
{
	size_t i;

	drgn_int_type_init(&default_primitive_types[DRGN_C_TYPE_CHAR],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_CHAR][0],
			   1, true, &drgn_language_c);
	drgn_int_type_init(&default_primitive_types[DRGN_C_TYPE_SIGNED_CHAR],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_SIGNED_CHAR][0],
			   1, true, &drgn_language_c);
	drgn_int_type_init(&default_primitive_types[DRGN_C_TYPE_UNSIGNED_CHAR],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_UNSIGNED_CHAR][0],
			   1, false, &drgn_language_c);
	drgn_int_type_init(&default_primitive_types[DRGN_C_TYPE_SHORT],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_SHORT][0],
			   2, true, &drgn_language_c);
	drgn_int_type_init(&default_primitive_types[DRGN_C_TYPE_UNSIGNED_SHORT],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_UNSIGNED_SHORT][0],
			   2, false, &drgn_language_c);
	drgn_int_type_init(&default_primitive_types[DRGN_C_TYPE_INT],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_INT][0], 4,
			   true, &drgn_language_c);
	drgn_int_type_init(&default_primitive_types[DRGN_C_TYPE_UNSIGNED_INT],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_UNSIGNED_INT][0],
			   4, false, &drgn_language_c);
	drgn_int_type_init(&default_primitive_types[DRGN_C_TYPE_LONG],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_LONG][0],
			   8, true, &drgn_language_c);
	drgn_int_type_init(&default_primitive_types[DRGN_C_TYPE_UNSIGNED_LONG],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_UNSIGNED_LONG][0],
			   8, false, &drgn_language_c);
	drgn_int_type_init(&default_primitive_types[DRGN_C_TYPE_LONG_LONG],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_LONG_LONG][0],
			   8, true, &drgn_language_c);
	drgn_int_type_init(&default_primitive_types[DRGN_C_TYPE_UNSIGNED_LONG_LONG],
			   drgn_primitive_type_spellings[DRGN_C_TYPE_UNSIGNED_LONG_LONG][0],
			   8, false, &drgn_language_c);
	drgn_bool_type_init(&default_primitive_types[DRGN_C_TYPE_BOOL],
			    drgn_primitive_type_spellings[DRGN_C_TYPE_BOOL][0],
			    1, &drgn_language_c);
	drgn_float_type_init(&default_primitive_types[DRGN_C_TYPE_FLOAT],
			     drgn_primitive_type_spellings[DRGN_C_TYPE_FLOAT][0],
			     4, &drgn_language_c);
	drgn_float_type_init(&default_primitive_types[DRGN_C_TYPE_DOUBLE],
			     drgn_primitive_type_spellings[DRGN_C_TYPE_DOUBLE][0],
			     8, &drgn_language_c);
	drgn_float_type_init(&default_primitive_types[DRGN_C_TYPE_LONG_DOUBLE],
			     drgn_primitive_type_spellings[DRGN_C_TYPE_LONG_DOUBLE][0],
			     16, &drgn_language_c);
	for (i = 0; i < ARRAY_SIZE(default_primitive_types); i++) {
		if (drgn_primitive_type_kind[i] == DRGN_TYPE_VOID ||
		    i == DRGN_C_TYPE_SIZE_T || i == DRGN_C_TYPE_PTRDIFF_T)
			continue;
		assert(drgn_type_primitive(&default_primitive_types[i]) == i);
	}

	drgn_int_type_init(&default_long_32bit,
			   drgn_primitive_type_spellings[DRGN_C_TYPE_LONG][0],
			   4, true, &drgn_language_c);
	assert(drgn_type_primitive(&default_long_32bit) ==
	       DRGN_C_TYPE_LONG);

	drgn_int_type_init(&default_unsigned_long_32bit,
			   drgn_primitive_type_spellings[DRGN_C_TYPE_UNSIGNED_LONG][0],
			   4, false, &drgn_language_c);
	assert(drgn_type_primitive(&default_unsigned_long_32bit) ==
	       DRGN_C_TYPE_UNSIGNED_LONG);
}

/*
 * Like @ref drgn_type_index_find_parsed(), but returns
 * <tt>&drgn_error_not_found</tt> instead of a more informative error message.
 */
static struct drgn_error *
drgn_type_index_find_parsed_internal(struct drgn_type_index *tindex,
				     enum drgn_type_kind kind, const char *name,
				     size_t name_len, const char *filename,
				     struct drgn_qualified_type *ret)
{
	struct drgn_error *err;
	struct drgn_type_finder *finder;

	finder = tindex->finders;
	while (finder) {
		err = finder->fn(kind, name, name_len, filename, finder->arg,
				 ret);
		if (!err) {
			if (drgn_type_kind(ret->type) != kind) {
				return drgn_error_create(DRGN_ERROR_TYPE,
							 "type find callback returned wrong kind of type");
			}
			return NULL;
		}
		if (err != &drgn_not_found)
			return err;
		finder = finder->next;
	}
	return &drgn_not_found;
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
		*ret = drgn_void_type(&drgn_language_c);
		goto out;
	}

	spellings = drgn_primitive_type_spellings[type];
	for (i = 0; spellings[i]; i++) {
		err = drgn_type_index_find_parsed_internal(tindex, kind,
							   spellings[i],
							   strlen(spellings[i]),
							   NULL,
							   &qualified_type);
		if (!err && drgn_type_primitive(qualified_type.type) == type) {
			*ret = qualified_type.type;
			goto out;
		} else if (err && err != &drgn_not_found) {
			return err;
		}
	}

	/* long and unsigned long default to the word size. */
	if (type == DRGN_C_TYPE_LONG || type == DRGN_C_TYPE_UNSIGNED_LONG) {
		if (!tindex->word_size) {
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "word size has not been set");
		}
		if (tindex->word_size == 4) {
			*ret = (type == DRGN_C_TYPE_LONG ?
				&default_long_32bit :
				&default_unsigned_long_32bit);
			goto out;
		}
	}
	/*
	 * size_t and ptrdiff_t default to typedefs of whatever integer type
	 * matches the word size.
	 */
	if (type == DRGN_C_TYPE_SIZE_T || type == DRGN_C_TYPE_PTRDIFF_T) {
		static enum drgn_primitive_type integer_types[2][3] = {
			{
				DRGN_C_TYPE_UNSIGNED_LONG,
				DRGN_C_TYPE_UNSIGNED_LONG_LONG,
				DRGN_C_TYPE_UNSIGNED_INT,
			},
			{
				DRGN_C_TYPE_LONG,
				DRGN_C_TYPE_LONG_LONG,
				DRGN_C_TYPE_INT,
			},
		};

		if (!tindex->word_size) {
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "word size has not been set");
		}
		for (i = 0; i < 3; i++) {
			enum drgn_primitive_type integer_type;

			integer_type = integer_types[type == DRGN_C_TYPE_PTRDIFF_T][i];
			err = drgn_type_index_find_primitive(tindex,
							     integer_type,
							     &qualified_type.type);
			if (err)
				return err;
			if (drgn_type_size(qualified_type.type) ==
			    tindex->word_size) {
				qualified_type.qualifiers = 0;
				*ret = (type == DRGN_C_TYPE_SIZE_T ?
					&tindex->default_size_t :
					&tindex->default_ptrdiff_t);
				drgn_typedef_type_init(*ret, spellings[0],
						       qualified_type, &drgn_language_c);
				goto out;
			}
		}
		return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
					 "no suitable integer type for %s",
					 spellings[0]);
	}

	*ret = &default_primitive_types[type];

out:
	tindex->primitive_types[type] = *ret;
	return NULL;
}

struct drgn_error *
drgn_type_index_find_parsed(struct drgn_type_index *tindex,
			    enum drgn_type_kind kind, const char *name,
			    size_t name_len, const char *filename,
			    struct drgn_qualified_type *ret)
{
	struct drgn_error *err;
	int precision;

	err = drgn_type_index_find_parsed_internal(tindex, kind, name, name_len,
						   filename, ret);
	if (err != &drgn_not_found)
		return err;

	precision = name_len < INT_MAX ? (int)name_len : INT_MAX;
	if (filename) {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find '%s %.*s' in '%s'",
					 drgn_type_kind_spelling[kind], precision, name,
					 filename);
	} else {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find '%s %.*s'",
					 drgn_type_kind_spelling[kind], precision, name);
	}
}

struct drgn_error *
drgn_type_index_pointer_type(struct drgn_type_index *tindex,
			     struct drgn_qualified_type referenced_type,
			     const struct drgn_language *lang,
			     struct drgn_type **ret)
{
	const struct drgn_pointer_type_key key = {
		.type = referenced_type.type,
		.qualifiers = referenced_type.qualifiers,
		.lang = lang ? lang : drgn_type_language(referenced_type.type),
	};
	struct drgn_pointer_type_table_iterator it;
	struct drgn_type *type;
	struct hash_pair hp;

	if (!tindex->word_size) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "word size has not been set");
	}

	hp = drgn_pointer_type_table_hash(&key);
	it = drgn_pointer_type_table_search_hashed(&tindex->pointer_types, &key,
						   hp);
	if (it.entry) {
		type = *it.entry;
		goto out;
	}

	type = malloc(sizeof(*type));
	if (!type)
		return &drgn_enomem;
	drgn_pointer_type_init(type, tindex->word_size, referenced_type,
			       key.lang);
	if (drgn_pointer_type_table_insert_searched(&tindex->pointer_types,
						    &type, hp, NULL) == -1) {
		free(type);
		return &drgn_enomem;
	}
out:
	*ret = type;
	return NULL;
}

struct drgn_error *
drgn_type_index_array_type(struct drgn_type_index *tindex, uint64_t length,
			   struct drgn_qualified_type element_type,
			   const struct drgn_language *lang,
			   struct drgn_type **ret)
{
	const struct drgn_array_type_key key = {
		.type = element_type.type,
		.qualifiers = element_type.qualifiers,
		.is_complete = true,
		.length = length,
		.lang = lang ? lang : drgn_type_language(element_type.type),
	};
	struct drgn_array_type_table_iterator it;
	struct drgn_type *type;
	struct hash_pair hp;

	hp = drgn_array_type_table_hash(&key);
	it = drgn_array_type_table_search_hashed(&tindex->array_types, &key,
						 hp);
	if (it.entry) {
		type = *it.entry;
		goto out;
	}

	type = malloc(sizeof(*type));
	if (!type)
		return &drgn_enomem;
	drgn_array_type_init(type, length, element_type, key.lang);
	if (drgn_array_type_table_insert_searched(&tindex->array_types, &type,
						  hp, NULL) == -1) {
		free(type);
		return &drgn_enomem;
	}
out:
	*ret = type;
	return NULL;
}

struct drgn_error *
drgn_type_index_incomplete_array_type(struct drgn_type_index *tindex,
				      struct drgn_qualified_type element_type,
				      const struct drgn_language *lang,
				      struct drgn_type **ret)
{
	const struct drgn_array_type_key key = {
		.type = element_type.type,
		.qualifiers = element_type.qualifiers,
		.is_complete = false,
		.lang = lang ? lang : drgn_type_language(element_type.type),
	};
	struct drgn_array_type_table_iterator it;
	struct drgn_type *type;
	struct hash_pair hp;

	hp = drgn_array_type_table_hash(&key);
	it = drgn_array_type_table_search_hashed(&tindex->array_types, &key,
						 hp);
	if (it.entry) {
		type = *it.entry;
		goto out;
	}

	type = malloc(sizeof(*type));
	if (!type)
		return &drgn_enomem;
	drgn_array_type_init_incomplete(type, element_type, key.lang);
	if (drgn_array_type_table_insert_searched(&tindex->array_types, &type,
						  hp, NULL) == -1) {
		free(type);
		return &drgn_enomem;
	}
out:
	*ret = type;
	return NULL;
}

static struct drgn_error *
drgn_type_index_cache_members(struct drgn_type_index *tindex,
			      struct drgn_type *outer_type,
			      struct drgn_type *type, uint64_t bit_offset)
{
	struct drgn_error *err;
	struct drgn_type_member *members;
	size_t num_members, i;

	if (!drgn_type_has_members(type))
		return NULL;

	members = drgn_type_members(type);
	num_members = drgn_type_num_members(type);
	for (i = 0; i < num_members; i++) {
		struct drgn_type_member *member;

		member = &members[i];
		if (member->name) {
			struct drgn_member_map_entry entry = {
				.key = {
					.type = outer_type,
					.name = member->name,
					.name_len = strlen(member->name),
				},
				.value = {
					.type = &member->type,
					.bit_offset =
						bit_offset + member->bit_offset,
					.bit_field_size =
						member->bit_field_size,
				},
			};

			if (drgn_member_map_insert(&tindex->members, &entry,
						   NULL) == -1)
				return &drgn_enomem;
		} else {
			struct drgn_qualified_type member_type;

			err = drgn_member_type(member, &member_type);
			if (err)
				return err;
			err = drgn_type_index_cache_members(tindex, outer_type,
							    member_type.type,
							    bit_offset +
							    member->bit_offset);
			if (err)
				return err;
		}
	}
	return NULL;
}

struct drgn_error *drgn_type_index_find_member(struct drgn_type_index *tindex,
					       struct drgn_type *type,
					       const char *member_name,
					       size_t member_name_len,
					       struct drgn_member_value **ret)
{
	struct drgn_error *err;
	const struct drgn_member_key key = {
		.type = drgn_underlying_type(type),
		.name = member_name,
		.name_len = member_name_len,
	};
	struct hash_pair hp, cached_hp;
	struct drgn_member_map_iterator it;

	hp = drgn_member_map_hash(&key);
	it = drgn_member_map_search_hashed(&tindex->members, &key, hp);
	if (it.entry) {
		*ret = &it.entry->value;
		return NULL;
	}

	/*
	 * Cache miss. One of the following is true:
	 *
	 * 1. The type isn't a structure, union, or class, which is a type
	 *    error.
	 * 2. The type hasn't been cached, which means we need to cache it and
	 *    check again.
	 * 3. The type has already been cached, which means the member doesn't
	 *    exist.
	 */
	if (!drgn_type_has_members(key.type)) {
		return drgn_type_error("'%s' is not a structure, union, or class",
				       type);
	}
	cached_hp = drgn_type_set_hash(&key.type);
	if (drgn_type_set_search_hashed(&tindex->members_cached, &key.type,
					cached_hp).entry)
		return drgn_error_member_not_found(type, member_name);

	err = drgn_type_index_cache_members(tindex, key.type, key.type, 0);
	if (err)
		return err;

	if (drgn_type_set_insert_searched(&tindex->members_cached, &key.type,
					  cached_hp, NULL) == -1)
		return &drgn_enomem;

	it = drgn_member_map_search_hashed(&tindex->members, &key, hp);
	if (it.entry) {
		*ret = &it.entry->value;
		return NULL;
	}

	return drgn_error_member_not_found(type, member_name);
}
