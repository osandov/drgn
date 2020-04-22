// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

#include <string.h>

#include "internal.h"
#include "hash_table.h"
#include "language.h"
#include "program.h"
#include "type.h"

const char * const drgn_type_kind_spelling[] = {
	[DRGN_TYPE_VOID] = "void",
	[DRGN_TYPE_INT] = "int",
	[DRGN_TYPE_BOOL] = "bool",
	[DRGN_TYPE_FLOAT] = "float",
	[DRGN_TYPE_COMPLEX] = "complex",
	[DRGN_TYPE_STRUCT] = "struct",
	[DRGN_TYPE_UNION] = "union",
	[DRGN_TYPE_CLASS] = "class",
	[DRGN_TYPE_ENUM] = "enum",
	[DRGN_TYPE_TYPEDEF] = "typedef",
	[DRGN_TYPE_POINTER] = "pointer",
	[DRGN_TYPE_ARRAY] = "array",
	[DRGN_TYPE_FUNCTION] = "function",
};

/**
 * Names of primitive types.
 *
 * In some languages, like C, the same primitive type can be spelled in multiple
 * ways. For example, "int" can also be spelled "signed int" or "int signed".
 *
 * This maps each @ref drgn_primitive_type to a ``NULL``-terminated array of the
 * different ways to spell that type. The spelling at index zero is the
 * preferred spelling.
 */
static const char * const * const
drgn_primitive_type_spellings[DRGN_PRIMITIVE_TYPE_NUM] = {
	[DRGN_C_TYPE_VOID] = (const char * []){ "void", NULL, },
	[DRGN_C_TYPE_CHAR] = (const char * []){ "char", NULL, },
	[DRGN_C_TYPE_SIGNED_CHAR] = (const char * []){
		"signed char", "char signed", NULL,
	},
	[DRGN_C_TYPE_UNSIGNED_CHAR] = (const char * []){
		"unsigned char", "char unsigned", NULL,
	},
	[DRGN_C_TYPE_SHORT] = (const char * []){
		"short", "signed short", "short signed", "short int",
		"int short", "signed short int", "signed int short",
		"short signed int", "short int signed", "int signed short",
		"int short signed", NULL,
	},
	[DRGN_C_TYPE_UNSIGNED_SHORT] = (const char * []){
		"unsigned short", "short unsigned", "unsigned short int",
		"unsigned int short", "short unsigned int",
		"short int unsigned", "int unsigned short",
		"int short unsigned", NULL,
	},
	[DRGN_C_TYPE_INT] = (const char * []){
		"int", "signed", "signed int", "int signed", NULL,
	},
	[DRGN_C_TYPE_UNSIGNED_INT] = (const char * []){
		"unsigned int", "int unsigned", "unsigned", NULL,
	},
	[DRGN_C_TYPE_LONG] = (const char * []){
		"long", "signed long", "long signed", "long int", "int long",
		"signed long int", "signed int long", "long signed int",
		"long int signed", "int signed long", "int long signed", NULL,
	},
	[DRGN_C_TYPE_UNSIGNED_LONG] = (const char * []){
		"unsigned long", "long unsigned", "unsigned long int",
		"unsigned int long", "long unsigned int", "long int unsigned",
		"int unsigned long", "int long unsigned", NULL,
	},
	[DRGN_C_TYPE_LONG_LONG] = (const char * []){
		"long long", "signed long long", "long signed long",
		"long long signed", "long long int", "long int long",
		"int long long", "signed long long int", "signed long int long",
		"signed int long long", "long signed long int",
		"long signed int long", "long long signed int",
		"long long int signed", "long int signed long",
		"long int long signed", "int signed long long",
		"int long signed long", "int long long signed", NULL,
	},
	[DRGN_C_TYPE_UNSIGNED_LONG_LONG] = (const char * []){
		"unsigned long long", "long unsigned long",
		"long long unsigned", "unsigned long long int",
		"unsigned long int long", "unsigned int long long",
		"long unsigned long int", "long unsigned int long",
		"long long unsigned int", "long long int unsigned",
		"long int unsigned long", "long int long unsigned",
		"int unsigned long long", "int long unsigned long",
		"int long long unsigned", NULL,
	},
	[DRGN_C_TYPE_BOOL] = (const char * []){ "_Bool", NULL, },
	[DRGN_C_TYPE_FLOAT] = (const char * []){ "float", NULL, },
	[DRGN_C_TYPE_DOUBLE] = (const char * []){ "double", NULL, },
	[DRGN_C_TYPE_LONG_DOUBLE] = (const char * []){
		"long double", "double long", NULL,
	},
	[DRGN_C_TYPE_SIZE_T] = (const char * []){ "size_t", NULL, },
	[DRGN_C_TYPE_PTRDIFF_T] = (const char * []){ "ptrdiff_t", NULL, },
};

/**
 * Mapping from a @ref drgn_type_primitive to the corresponding @ref
 * drgn_type_kind.
 */
static const enum drgn_type_kind
drgn_primitive_type_kind[DRGN_PRIMITIVE_TYPE_NUM + 1] = {
	[DRGN_C_TYPE_CHAR] = DRGN_TYPE_INT,
	[DRGN_C_TYPE_SIGNED_CHAR] = DRGN_TYPE_INT,
	[DRGN_C_TYPE_UNSIGNED_CHAR] = DRGN_TYPE_INT,
	[DRGN_C_TYPE_SHORT] = DRGN_TYPE_INT,
	[DRGN_C_TYPE_UNSIGNED_SHORT] = DRGN_TYPE_INT,
	[DRGN_C_TYPE_INT] = DRGN_TYPE_INT,
	[DRGN_C_TYPE_UNSIGNED_INT] = DRGN_TYPE_INT,
	[DRGN_C_TYPE_LONG] = DRGN_TYPE_INT,
	[DRGN_C_TYPE_UNSIGNED_LONG] = DRGN_TYPE_INT,
	[DRGN_C_TYPE_LONG_LONG] = DRGN_TYPE_INT,
	[DRGN_C_TYPE_UNSIGNED_LONG_LONG] = DRGN_TYPE_INT,
	[DRGN_C_TYPE_BOOL] = DRGN_TYPE_BOOL,
	[DRGN_C_TYPE_FLOAT] = DRGN_TYPE_FLOAT,
	[DRGN_C_TYPE_DOUBLE] = DRGN_TYPE_FLOAT,
	[DRGN_C_TYPE_LONG_DOUBLE] = DRGN_TYPE_FLOAT,
	[DRGN_C_TYPE_SIZE_T] = DRGN_TYPE_TYPEDEF,
	[DRGN_C_TYPE_PTRDIFF_T] = DRGN_TYPE_TYPEDEF,
	[DRGN_C_TYPE_VOID] = DRGN_TYPE_VOID,
	[DRGN_NOT_PRIMITIVE_TYPE] = -1,
};

/** Return whether a primitive type is always a signed integer type. */
static inline bool
drgn_primitive_type_is_signed(enum drgn_primitive_type primitive)
{
	switch (primitive) {
	case DRGN_C_TYPE_SIGNED_CHAR:
	case DRGN_C_TYPE_SHORT:
	case DRGN_C_TYPE_INT:
	case DRGN_C_TYPE_LONG:
	case DRGN_C_TYPE_LONG_LONG:
	case DRGN_C_TYPE_PTRDIFF_T:
		return true;
	default:
		return false;
	}
}

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

void drgn_type_thunk_free(struct drgn_type_thunk *thunk)
{
	thunk->free_fn(thunk);
}

struct drgn_error *drgn_lazy_type_evaluate(struct drgn_lazy_type *lazy_type,
					   struct drgn_qualified_type *qualified_type)
{
	if (drgn_lazy_type_is_evaluated(lazy_type)) {
		qualified_type->type = lazy_type->type;
		qualified_type->qualifiers = lazy_type->qualifiers;
	} else {
		struct drgn_error *err;
		struct drgn_type_thunk *thunk_ptr = lazy_type->thunk;
		struct drgn_type_thunk thunk = *thunk_ptr;

		err = thunk.evaluate_fn(thunk_ptr, qualified_type);
		if (err)
			return err;
		drgn_lazy_type_init_evaluated(lazy_type, qualified_type->type,
					      qualified_type->qualifiers);
		thunk.free_fn(thunk_ptr);
	}
	return NULL;
}

void drgn_lazy_type_deinit(struct drgn_lazy_type *lazy_type)
{
	if (!drgn_lazy_type_is_evaluated(lazy_type))
		drgn_type_thunk_free(lazy_type->thunk);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_member_type(struct drgn_type_member *member,
		 struct drgn_qualified_type *ret)
{
	return drgn_lazy_type_evaluate(&member->type, ret);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_parameter_type(struct drgn_type_parameter *parameter,
		    struct drgn_qualified_type *ret)
{
	return drgn_lazy_type_evaluate(&parameter->type, ret);
}

void drgn_int_type_init(struct drgn_type *type, const char *name, uint64_t size,
			bool is_signed, const struct drgn_language *lang)
{
	enum drgn_primitive_type primitive;

	assert(name);
	type->_private.kind = DRGN_TYPE_INT;
	type->_private.is_complete = true;
	primitive = c_parse_specifier_list(name);
	if (drgn_primitive_type_kind[primitive] == DRGN_TYPE_INT &&
	    (primitive == DRGN_C_TYPE_CHAR ||
	     is_signed == drgn_primitive_type_is_signed(primitive))) {
		type->_private.primitive = primitive;
		type->_private.name =
			drgn_primitive_type_spellings[primitive][0];
	} else {
		type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
		type->_private.name = name;
	}
	type->_private.size = size;
	type->_private.is_signed = is_signed;
	type->_private.language = drgn_language_or_default(lang);
}

void drgn_bool_type_init(struct drgn_type *type, const char *name,
			 uint64_t size, const struct drgn_language *lang)
{
	assert(name);
	type->_private.kind = DRGN_TYPE_BOOL;
	type->_private.is_complete = true;
	if (c_parse_specifier_list(name) == DRGN_C_TYPE_BOOL) {
		type->_private.primitive = DRGN_C_TYPE_BOOL;
		type->_private.name =
			drgn_primitive_type_spellings[DRGN_C_TYPE_BOOL][0];
	} else {
		type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
		type->_private.name = name;
	}
	type->_private.size = size;
	type->_private.language = drgn_language_or_default(lang);
}

void drgn_float_type_init(struct drgn_type *type, const char *name,
			  uint64_t size, const struct drgn_language *lang)
{
	enum drgn_primitive_type primitive;

	assert(name);
	type->_private.kind = DRGN_TYPE_FLOAT;
	type->_private.is_complete = true;
	primitive = c_parse_specifier_list(name);
	if (drgn_primitive_type_kind[primitive] == DRGN_TYPE_FLOAT) {
		type->_private.primitive = primitive;
		type->_private.name =
			drgn_primitive_type_spellings[primitive][0];
	} else {
		type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
		type->_private.name = name;
	}
	type->_private.size = size;
	type->_private.language = drgn_language_or_default(lang);
}

void drgn_complex_type_init(struct drgn_type *type, const char *name,
			    uint64_t size, struct drgn_type *real_type,
			    const struct drgn_language *lang)
{
	assert(name);
	assert(real_type);
	assert(drgn_type_kind(real_type) == DRGN_TYPE_FLOAT ||
	       drgn_type_kind(real_type) == DRGN_TYPE_INT);
	type->_private.kind = DRGN_TYPE_COMPLEX;
	type->_private.is_complete = true;
	type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
	type->_private.name = name;
	type->_private.size = size;
	type->_private.type = real_type;
	type->_private.qualifiers = 0;
	type->_private.language = drgn_language_or_default(lang);
}

void drgn_struct_type_init(struct drgn_type *type, const char *tag,
			   uint64_t size, struct drgn_type_member *members,
			   size_t num_members, const struct drgn_language *lang)
{
	type->_private.kind = DRGN_TYPE_STRUCT;
	type->_private.is_complete = true;
	type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
	type->_private.tag = tag;
	type->_private.size = size;
	type->_private.members = members;
	type->_private.num_members = num_members;
	type->_private.language = drgn_language_or_default(lang);
}

void drgn_struct_type_init_incomplete(struct drgn_type *type, const char *tag,
				      const struct drgn_language *lang)
{
	type->_private.kind = DRGN_TYPE_STRUCT;
	type->_private.is_complete = false;
	type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
	type->_private.tag = tag;
	type->_private.size = 0;
	type->_private.members = NULL;
	type->_private.num_members = 0;
	type->_private.language = drgn_language_or_default(lang);
}

void drgn_union_type_init(struct drgn_type *type, const char *tag,
			  uint64_t size, struct drgn_type_member *members,
			  size_t num_members, const struct drgn_language *lang)
{
	type->_private.kind = DRGN_TYPE_UNION;
	type->_private.is_complete = true;
	type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
	type->_private.tag = tag;
	type->_private.size = size;
	type->_private.members = members;
	type->_private.num_members = num_members;
	type->_private.language = drgn_language_or_default(lang);
}

void drgn_union_type_init_incomplete(struct drgn_type *type, const char *tag,
				     const struct drgn_language *lang)
{
	type->_private.kind = DRGN_TYPE_UNION;
	type->_private.is_complete = false;
	type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
	type->_private.tag = tag;
	type->_private.size = 0;
	type->_private.members = NULL;
	type->_private.num_members = 0;
	type->_private.language = drgn_language_or_default(lang);
}

void drgn_class_type_init(struct drgn_type *type, const char *tag,
			  uint64_t size, struct drgn_type_member *members,
			  size_t num_members, const struct drgn_language *lang)
{
	type->_private.kind = DRGN_TYPE_CLASS;
	type->_private.is_complete = true;
	type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
	type->_private.tag = tag;
	type->_private.size = size;
	type->_private.members = members;
	type->_private.num_members = num_members;
	type->_private.language = drgn_language_or_default(lang);
}

void drgn_class_type_init_incomplete(struct drgn_type *type, const char *tag,
				     const struct drgn_language *lang)
{
	type->_private.kind = DRGN_TYPE_CLASS;
	type->_private.is_complete = false;
	type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
	type->_private.tag = tag;
	type->_private.size = 0;
	type->_private.members = NULL;
	type->_private.num_members = 0;
	type->_private.language = drgn_language_or_default(lang);
}

void drgn_enum_type_init(struct drgn_type *type, const char *tag,
			 struct drgn_type *compatible_type,
			 struct drgn_type_enumerator *enumerators,
			 size_t num_enumerators,
			 const struct drgn_language *lang)
{
	assert(drgn_type_kind(compatible_type) == DRGN_TYPE_INT);
	type->_private.kind = DRGN_TYPE_ENUM;
	type->_private.is_complete = true;
	type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
	type->_private.tag = tag;
	type->_private.type = compatible_type;
	type->_private.qualifiers = 0;
	type->_private.enumerators = enumerators;
	type->_private.num_enumerators = num_enumerators;
	type->_private.language = drgn_language_or_default(lang);
}

void drgn_enum_type_init_incomplete(struct drgn_type *type, const char *tag,
				    const struct drgn_language *lang)
{
	type->_private.kind = DRGN_TYPE_ENUM;
	type->_private.is_complete = false;
	type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
	type->_private.tag = tag;
	type->_private.type = NULL;
	type->_private.qualifiers = 0;
	type->_private.enumerators = NULL;
	type->_private.num_enumerators = 0;
	type->_private.language = drgn_language_or_default(lang);
}

void drgn_typedef_type_init(struct drgn_type *type, const char *name,
			    struct drgn_qualified_type aliased_type,
			    const struct drgn_language *lang)
{
	type->_private.kind = DRGN_TYPE_TYPEDEF;
	type->_private.is_complete = drgn_type_is_complete(aliased_type.type);
	if (strcmp(name, "size_t") == 0)
		type->_private.primitive = DRGN_C_TYPE_SIZE_T;
	else if (strcmp(name, "ptrdiff_t") == 0)
		type->_private.primitive = DRGN_C_TYPE_PTRDIFF_T;
	else
		type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
	type->_private.name = name;
	type->_private.type = aliased_type.type;
	type->_private.qualifiers = aliased_type.qualifiers;
	type->_private.language = drgn_language_or_default(lang);
}

void drgn_pointer_type_init(struct drgn_type *type, uint64_t size,
			    struct drgn_qualified_type referenced_type,
			    const struct drgn_language *lang)
{
	type->_private.kind = DRGN_TYPE_POINTER;
	type->_private.is_complete = true;
	type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
	type->_private.size = size;
	type->_private.type = referenced_type.type;
	type->_private.qualifiers = referenced_type.qualifiers;
	type->_private.language = drgn_language_or_default(lang);
}

void drgn_array_type_init(struct drgn_type *type, uint64_t length,
			  struct drgn_qualified_type element_type,
			  const struct drgn_language *lang)
{
	type->_private.kind = DRGN_TYPE_ARRAY;
	type->_private.is_complete = true;
	type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
	type->_private.length = length;
	type->_private.type = element_type.type;
	type->_private.qualifiers = element_type.qualifiers;
	type->_private.language = drgn_language_or_default(lang);
}

void drgn_array_type_init_incomplete(struct drgn_type *type,
				     struct drgn_qualified_type element_type,
				     const struct drgn_language *lang)
{
	type->_private.kind = DRGN_TYPE_ARRAY;
	type->_private.is_complete = false;
	type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
	type->_private.length = 0;
	type->_private.type = element_type.type;
	type->_private.qualifiers = element_type.qualifiers;
	type->_private.language = drgn_language_or_default(lang);
}

void drgn_function_type_init(struct drgn_type *type,
			     struct drgn_qualified_type return_type,
			     struct drgn_type_parameter *parameters,
			     size_t num_parameters, bool is_variadic,
			     const struct drgn_language *lang)
{
	type->_private.kind = DRGN_TYPE_FUNCTION;
	type->_private.is_complete = true;
	type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
	type->_private.type = return_type.type;
	type->_private.qualifiers = return_type.qualifiers;
	type->_private.parameters = parameters;
	type->_private.num_parameters = num_parameters;
	type->_private.is_variadic = is_variadic;
	type->_private.language = drgn_language_or_default(lang);
}

struct drgn_type_pair {
	struct drgn_type *a;
	struct drgn_type *b;
};

static struct hash_pair
hash_pair_drgn_type_pair(const struct drgn_type_pair *pair)
{
	return hash_pair_from_avalanching_hash(hash_combine((uintptr_t)pair->a,
							    (uintptr_t)pair->b));
}

static bool drgn_type_pair_eq(const struct drgn_type_pair *a,
			      const struct drgn_type_pair *b)
{
	return a->a == b->a && a->b == b->b;
}

DEFINE_HASH_SET(drgn_type_pair_set, struct drgn_type_pair,
		hash_pair_drgn_type_pair, drgn_type_pair_eq)

static struct drgn_error *drgn_type_eq_impl(struct drgn_type *a,
					    struct drgn_type *b,
					    struct drgn_type_pair_set *cache,
					    int *depth, bool *ret);

static struct drgn_error *
drgn_qualified_type_eq_impl(struct drgn_qualified_type *a,
			    struct drgn_qualified_type *b,
			    struct drgn_type_pair_set *cache, int *depth,
			    bool *ret)
{
	if (a->qualifiers != b->qualifiers) {
		*ret = false;
		return NULL;
	}
	return drgn_type_eq_impl(a->type, b->type, cache, depth, ret);
}

static struct drgn_error *drgn_type_members_eq(struct drgn_type *a,
					       struct drgn_type *b,
					       struct drgn_type_pair_set *cache,
					       int *depth, bool *ret)
{
	struct drgn_type_member *members_a, *members_b;
	size_t num_a, num_b, i;

	num_a = drgn_type_num_members(a);
	num_b = drgn_type_num_members(b);
	if (num_a != num_b)
		goto out_false;

	members_a = drgn_type_members(a);
	members_b = drgn_type_members(b);
	for (i = 0; i < num_a; i++) {
		struct drgn_qualified_type type_a, type_b;
		struct drgn_error *err;

		if (members_a[i].bit_offset != members_b[i].bit_offset ||
		    members_a[i].bit_field_size != members_b[i].bit_field_size)
			goto out_false;
		if (!members_a[i].name && !members_b[i].name)
			continue;
		if (!members_a[i].name || !members_b[i].name ||
		    strcmp(members_a[i].name, members_b[i].name) != 0)
			goto out_false;

		err = drgn_member_type(&members_a[i], &type_a);
		if (err)
			return err;
		err = drgn_member_type(&members_b[i], &type_b);
		if (err)
			return err;
		err = drgn_qualified_type_eq_impl(&type_a, &type_b, cache,
						  depth, ret);
		if (err)
			return err;
		if (!*ret)
			return NULL;
	}

	*ret = true;
	return NULL;

out_false:
	*ret = false;
	return NULL;
}

static bool drgn_type_enumerators_eq(struct drgn_type *a, struct drgn_type *b)
{
	const struct drgn_type_enumerator *enumerators_a, *enumerators_b;
	size_t num_a, num_b, i;

	num_a = drgn_type_num_enumerators(a);
	num_b = drgn_type_num_enumerators(b);
	if (num_a != num_b)
		return false;

	enumerators_a = drgn_type_enumerators(a);
	enumerators_b = drgn_type_enumerators(b);
	for (i = 0; i < num_a; i++) {
		if (strcmp(enumerators_a[i].name, enumerators_b[i].name) != 0)
			return false;
		if (enumerators_a[i].uvalue != enumerators_b[i].uvalue)
			return false;
	}
	return true;
}

static struct drgn_error *
drgn_type_parameters_eq(struct drgn_type *a, struct drgn_type *b,
			struct drgn_type_pair_set *cache, int *depth, bool *ret)
{
	struct drgn_type_parameter *parameters_a, *parameters_b;
	size_t num_a, num_b, i;

	num_a = drgn_type_num_parameters(a);
	num_b = drgn_type_num_parameters(b);
	if (num_a != num_b)
		goto out_false;

	parameters_a = drgn_type_parameters(a);
	parameters_b = drgn_type_parameters(b);
	for (i = 0; i < num_a; i++) {
		struct drgn_qualified_type type_a, type_b;
		struct drgn_error *err;

		if (!parameters_a[i].name && !parameters_b[i].name)
			continue;
		if (!parameters_a[i].name || !parameters_b[i].name ||
		    strcmp(parameters_a[i].name, parameters_b[i].name) != 0)
			goto out_false;

		err = drgn_parameter_type(&parameters_a[i], &type_a);
		if (err)
			return err;
		err = drgn_parameter_type(&parameters_b[i], &type_b);
		if (err)
			return err;
		err = drgn_qualified_type_eq_impl(&type_a, &type_b, cache,
						  depth, ret);
		if (err)
			return err;
		if (!*ret)
			return NULL;
	}

	*ret = true;
	return NULL;

out_false:
	*ret = false;
	return NULL;
}

static struct drgn_error *drgn_type_eq_impl(struct drgn_type *a,
					    struct drgn_type *b,
					    struct drgn_type_pair_set *cache,
					    int *depth, bool *ret)
{
	struct drgn_error *err;
	struct drgn_type_pair pair = { a, b };
	struct hash_pair hp;

	if (*depth >= 1000) {
		return drgn_error_create(DRGN_ERROR_RECURSION,
					 "maximum type comparison depth exceeded");
	}

	if (a == b) {
		*ret = true;
		return NULL;
	}
	if (!a || !b) {
		*ret = false;
		return NULL;
	}

	/*
	 * Cache this comparison so that we don't do it again. We insert the
	 * cache entry before doing the comparison in order to break cycles.
	 */
	hp = drgn_type_pair_set_hash(&pair);
	switch (drgn_type_pair_set_insert_hashed(cache, &pair, hp, NULL)) {
	case 1:
		/* These types haven't been compared yet. */
		break;
	case 0:
		/*
		 * These types have either already been compared, in which case
		 * they must be equal (otherwise we would've returned false
		 * immediately), or they are currently being compared, in which
		 * case they are equal as long as everything we compare after
		 * this is equal.
		 */
		*ret = true;
		return NULL;
	case -1:
		return &drgn_enomem;
	}
	(*depth)++;

	if (drgn_type_kind(a) != drgn_type_kind(b) ||
	    drgn_type_language(a) != drgn_type_language(b) ||
	    drgn_type_is_complete(a) != drgn_type_is_complete(b))
		goto out_false;

	if (drgn_type_has_name(a) &&
	    strcmp(drgn_type_name(a), drgn_type_name(b)) != 0)
		goto out_false;
	if (drgn_type_has_tag(a)) {
		const char *tag_a, *tag_b;

		tag_a = drgn_type_tag(a);
		tag_b = drgn_type_tag(b);
		if ((!tag_a != !tag_b) || (tag_a && strcmp(tag_a, tag_b) != 0))
			goto out_false;
	}
	if (drgn_type_has_size(a) && drgn_type_size(a) != drgn_type_size(b))
		goto out_false;
	if (drgn_type_has_length(a) &&
	    drgn_type_length(a) != drgn_type_length(b))
		goto out_false;
	if (drgn_type_has_is_signed(a) &&
	    drgn_type_is_signed(a) != drgn_type_is_signed(b))
		goto out_false;
	if (drgn_type_has_type(a)) {
		struct drgn_qualified_type type_a, type_b;

		type_a = drgn_type_type(a);
		type_b = drgn_type_type(b);
		err = drgn_qualified_type_eq_impl(&type_a, &type_b, cache,
						  depth, ret);
		if (err || !*ret)
			goto out;
	}
	if (drgn_type_has_members(a)) {
		err = drgn_type_members_eq(a, b, cache, depth, ret);
		if (err || !*ret)
			goto out;
	}
	if (drgn_type_has_enumerators(a) && !drgn_type_enumerators_eq(a, b))
		goto out_false;
	if (drgn_type_has_parameters(a)) {
		err = drgn_type_parameters_eq(a, b, cache, depth, ret);
		if (err || !*ret)
			goto out;
	}
	if (drgn_type_has_is_variadic(a) &&
	    drgn_type_is_variadic(a) != drgn_type_is_variadic(b))
		goto out_false;

	*ret = true;
	err = NULL;
	goto out;
out_false:
	*ret = false;
	err = NULL;
out:
	(*depth)--;
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *drgn_type_eq(struct drgn_type *a,
					       struct drgn_type *b, bool *ret)
{
	struct drgn_type_pair_set cache = HASH_TABLE_INIT;
	int depth = 0;
	struct drgn_error *err = drgn_type_eq_impl(a, b, &cache, &depth, ret);
	drgn_type_pair_set_deinit(&cache);
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_qualified_type_eq(struct drgn_qualified_type a,
		       struct drgn_qualified_type b, bool *ret)
{
	if (a.qualifiers != b.qualifiers) {
		*ret = false;
		return NULL;
	}
	return drgn_type_eq(a.type, b.type, ret);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_format_type_name(struct drgn_qualified_type qualified_type, char **ret)
{
	const struct drgn_language *lang = drgn_type_language(qualified_type.type);
	return lang->format_type_name(qualified_type, ret);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_format_type(struct drgn_qualified_type qualified_type, char **ret)
{
	const struct drgn_language *lang = drgn_type_language(qualified_type.type);
	return lang->format_type(qualified_type, ret);
}

bool drgn_type_is_integer(struct drgn_type *type)
{
	switch (drgn_type_kind(type)) {
	case DRGN_TYPE_INT:
	case DRGN_TYPE_BOOL:
	case DRGN_TYPE_ENUM:
		return true;
	case DRGN_TYPE_TYPEDEF:
		return drgn_type_is_integer(drgn_type_type(type).type);
	default:
		return false;
	}
}

bool drgn_type_is_arithmetic(struct drgn_type *type)
{
	switch (drgn_type_kind(type)) {
	case DRGN_TYPE_INT:
	case DRGN_TYPE_BOOL:
	case DRGN_TYPE_FLOAT:
	case DRGN_TYPE_ENUM:
		return true;
	case DRGN_TYPE_TYPEDEF:
		return drgn_type_is_arithmetic(drgn_type_type(type).type);
	default:
		return false;
	}
}

bool drgn_type_is_scalar(struct drgn_type *type)
{
	switch (drgn_type_kind(type)) {
	case DRGN_TYPE_INT:
	case DRGN_TYPE_BOOL:
	case DRGN_TYPE_FLOAT:
	case DRGN_TYPE_ENUM:
	case DRGN_TYPE_POINTER:
		return true;
	case DRGN_TYPE_TYPEDEF:
		return drgn_type_is_scalar(drgn_type_type(type).type);
	default:
		return false;
	}
}

LIBDRGN_PUBLIC struct drgn_error *drgn_type_sizeof(struct drgn_type *type,
						   uint64_t *ret)
{
	struct drgn_error *err;
	enum drgn_type_kind kind = drgn_type_kind(type);

	if (!drgn_type_is_complete(type)) {
		return drgn_error_format(DRGN_ERROR_TYPE,
					 "cannot get size of incomplete %s type",
					 drgn_type_kind_spelling[kind]);
	}
	switch (kind) {
	case DRGN_TYPE_INT:
	case DRGN_TYPE_BOOL:
	case DRGN_TYPE_FLOAT:
	case DRGN_TYPE_COMPLEX:
	case DRGN_TYPE_POINTER:
		*ret = drgn_type_size(type);
		return NULL;
	case DRGN_TYPE_STRUCT:
	case DRGN_TYPE_UNION:
	case DRGN_TYPE_CLASS:
		*ret = drgn_type_size(type);
		return NULL;
	case DRGN_TYPE_ENUM:
	case DRGN_TYPE_TYPEDEF:
		return drgn_type_sizeof(drgn_type_type(type).type, ret);
	case DRGN_TYPE_ARRAY:
		err = drgn_type_sizeof(drgn_type_type(type).type, ret);
		if (err)
			return err;
		if (__builtin_mul_overflow(*ret, drgn_type_length(type), ret)) {
			return drgn_error_create(DRGN_ERROR_OVERFLOW,
						 "type size is too large");
		}
		return NULL;
	case DRGN_TYPE_VOID:
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "cannot get size of void type");
	case DRGN_TYPE_FUNCTION:
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "cannot get size of function type");
	}
	UNREACHABLE();
}

struct drgn_error *drgn_type_bit_size(struct drgn_type *type, uint64_t *ret)
{
	struct drgn_error *err;

	err = drgn_type_sizeof(type, ret);
	if (err)
		return err;
	if (__builtin_mul_overflow(*ret, 8U, ret)) {
		return drgn_error_create(DRGN_ERROR_OVERFLOW,
					 "type bit size is too large");
	}
	return NULL;
}

enum drgn_object_kind drgn_type_object_kind(struct drgn_type *type)
{
	switch (drgn_type_kind(type)) {
	case DRGN_TYPE_INT:
		return (drgn_type_is_signed(type) ? DRGN_OBJECT_SIGNED :
			DRGN_OBJECT_UNSIGNED);
	case DRGN_TYPE_BOOL:
	case DRGN_TYPE_POINTER:
		return DRGN_OBJECT_UNSIGNED;
	case DRGN_TYPE_FLOAT:
		return DRGN_OBJECT_FLOAT;
	case DRGN_TYPE_COMPLEX:
		return DRGN_OBJECT_BUFFER;
	case DRGN_TYPE_STRUCT:
	case DRGN_TYPE_UNION:
	case DRGN_TYPE_CLASS:
	case DRGN_TYPE_ARRAY:
		return (drgn_type_is_complete(type) ? DRGN_OBJECT_BUFFER :
			DRGN_OBJECT_INCOMPLETE_BUFFER);
	case DRGN_TYPE_ENUM:
		if (!drgn_type_is_complete(type))
			return DRGN_OBJECT_INCOMPLETE_INTEGER;
		/* fallthrough */
	case DRGN_TYPE_TYPEDEF:
		return drgn_type_object_kind(drgn_type_type(type).type);
	case DRGN_TYPE_VOID:
	case DRGN_TYPE_FUNCTION:
		return DRGN_OBJECT_NONE;
	}
	UNREACHABLE();
}

struct drgn_error *drgn_type_error(const char *format, struct drgn_type *type)
{
	struct drgn_qualified_type qualified_type = { type };

	return drgn_qualified_type_error(format, qualified_type);
}

struct drgn_error *
drgn_qualified_type_error(const char *format,
			  struct drgn_qualified_type qualified_type)
{
	struct drgn_error *err;
	char *name;

	err = drgn_format_type_name(qualified_type, &name);
	if (err)
		return err;
	err = drgn_error_format(DRGN_ERROR_TYPE, format, name);
	free(name);
	return err;
}

struct drgn_error *drgn_error_incomplete_type(const char *format,
					      struct drgn_type *type)
{
	switch (drgn_type_kind(drgn_underlying_type(type))) {
	case DRGN_TYPE_STRUCT:
		return drgn_error_format(DRGN_ERROR_TYPE, format,
					 "incomplete structure");
	case DRGN_TYPE_UNION:
		return drgn_error_format(DRGN_ERROR_TYPE, format,
					 "incomplete union");
	case DRGN_TYPE_CLASS:
		return drgn_error_format(DRGN_ERROR_TYPE, format,
					 "incomplete class");
	case DRGN_TYPE_ENUM:
		return drgn_error_format(DRGN_ERROR_TYPE, format,
					 "incomplete enumerated");
	case DRGN_TYPE_ARRAY:
		return drgn_error_format(DRGN_ERROR_TYPE, format,
					 "incomplete array");
	case DRGN_TYPE_FUNCTION:
		return drgn_error_format(DRGN_ERROR_TYPE, format, "function");
	case DRGN_TYPE_VOID:
		return drgn_error_format(DRGN_ERROR_TYPE, format, "void");
	default:
		UNREACHABLE();
	}
}

struct drgn_error *drgn_error_member_not_found(struct drgn_type *type,
					       const char *member_name)
{
	struct drgn_error *err;
	struct drgn_qualified_type qualified_type = { type };
	char *name;

	err = drgn_format_type_name(qualified_type, &name);
	if (err)
		return err;
	err = drgn_error_format(DRGN_ERROR_LOOKUP, "'%s' has no member '%s'",
				name, member_name);
	free(name);
	return err;
}

void drgn_program_init_types(struct drgn_program *prog)
{
	drgn_pointer_type_table_init(&prog->pointer_types);
	drgn_array_type_table_init(&prog->array_types);
	drgn_member_map_init(&prog->members);
	drgn_type_set_init(&prog->members_cached);
}

static void free_pointer_types(struct drgn_program *prog)
{
	struct drgn_pointer_type_table_iterator it;

	for (it = drgn_pointer_type_table_first(&prog->pointer_types);
	     it.entry; it = drgn_pointer_type_table_next(it))
		free(*it.entry);
	drgn_pointer_type_table_deinit(&prog->pointer_types);
}

static void free_array_types(struct drgn_program *prog)
{
	struct drgn_array_type_table_iterator it;
	for (it = drgn_array_type_table_first(&prog->array_types); it.entry;
	     it = drgn_array_type_table_next(it))
		free(*it.entry);
	drgn_array_type_table_deinit(&prog->array_types);
}

void drgn_program_deinit_types(struct drgn_program *prog)
{
	drgn_member_map_deinit(&prog->members);
	drgn_type_set_deinit(&prog->members_cached);
	free_array_types(prog);
	free_pointer_types(prog);

	struct drgn_type_finder *finder = prog->type_finders;
	while (finder) {
		struct drgn_type_finder *next = finder->next;
		free(finder);
		finder = next;
	}
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_add_type_finder(struct drgn_program *prog, drgn_type_find_fn fn,
			     void *arg)
{
	struct drgn_type_finder *finder = malloc(sizeof(*finder));
	if (!finder)
		return &drgn_enomem;
	finder->fn = fn;
	finder->arg = arg;
	finder->next = prog->type_finders;
	prog->type_finders = finder;
	return NULL;
}

struct drgn_error *
drgn_program_find_type_impl(struct drgn_program *prog,
			    enum drgn_type_kind kind, const char *name,
			    size_t name_len, const char *filename,
			    struct drgn_qualified_type *ret)
{
	struct drgn_type_finder *finder = prog->type_finders;
	while (finder) {
		struct drgn_error *err =
			finder->fn(kind, name, name_len, filename, finder->arg,
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

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_find_type(struct drgn_program *prog, const char *name,
		       const char *filename, struct drgn_qualified_type *ret)
{
	struct drgn_error *err;
	err = drgn_program_language(prog)->find_type(prog, name, filename, ret);
	if (err != &drgn_not_found)
		return err;

	if (filename) {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find '%s' in '%s'", name,
					 filename);
	} else {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find '%s'", name);
	}
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

struct drgn_error *
drgn_program_find_primitive_type(struct drgn_program *prog,
				 enum drgn_primitive_type type,
				 struct drgn_type **ret)
{
	struct drgn_error *err;
	struct drgn_qualified_type qualified_type;
	enum drgn_type_kind kind;
	const char * const *spellings;
	uint8_t word_size;
	size_t i;

	if (prog->primitive_types[type]) {
		*ret = prog->primitive_types[type];
		return NULL;
	}

	kind = drgn_primitive_type_kind[type];
	if (kind == DRGN_TYPE_VOID) {
		*ret = drgn_void_type(&drgn_language_c);
		goto out;
	}

	spellings = drgn_primitive_type_spellings[type];
	for (i = 0; spellings[i]; i++) {
		err = drgn_program_find_type_impl(prog, kind, spellings[i],
						  strlen(spellings[i]), NULL,
						  &qualified_type);
		if (!err && drgn_type_primitive(qualified_type.type) == type) {
			*ret = qualified_type.type;
			goto out;
		} else if (err && err != &drgn_not_found) {
			return err;
		}
	}

	if (!prog->has_platform) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "program word size is not known");
	}
	word_size = drgn_program_is_64_bit(prog) ? 8 : 4;

	/* long and unsigned long default to the word size. */
	if (type == DRGN_C_TYPE_LONG || type == DRGN_C_TYPE_UNSIGNED_LONG) {
		if (word_size == 4) {
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

		for (i = 0; i < 3; i++) {
			enum drgn_primitive_type integer_type;

			integer_type = integer_types[type == DRGN_C_TYPE_PTRDIFF_T][i];
			err = drgn_program_find_primitive_type(prog,
							       integer_type,
							       &qualified_type.type);
			if (err)
				return err;
			if (drgn_type_size(qualified_type.type) == word_size) {
				qualified_type.qualifiers = 0;
				*ret = (type == DRGN_C_TYPE_SIZE_T ?
					&prog->default_size_t :
					&prog->default_ptrdiff_t);
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
	prog->primitive_types[type] = *ret;
	return NULL;
}

struct drgn_error *
drgn_program_pointer_type(struct drgn_program *prog,
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

	if (!prog->has_platform) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "program word size is not known");
	}

	hp = drgn_pointer_type_table_hash(&key);
	it = drgn_pointer_type_table_search_hashed(&prog->pointer_types, &key,
						   hp);
	if (it.entry) {
		type = *it.entry;
		goto out;
	}

	type = malloc(sizeof(*type));
	if (!type)
		return &drgn_enomem;
	drgn_pointer_type_init(type, drgn_program_is_64_bit(prog) ? 8 : 4,
			       referenced_type, key.lang);
	if (drgn_pointer_type_table_insert_searched(&prog->pointer_types, &type,
						    hp, NULL) == -1) {
		free(type);
		return &drgn_enomem;
	}
out:
	*ret = type;
	return NULL;
}

struct drgn_error *
drgn_program_array_type(struct drgn_program *prog, uint64_t length,
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
	it = drgn_array_type_table_search_hashed(&prog->array_types, &key, hp);
	if (it.entry) {
		type = *it.entry;
		goto out;
	}

	type = malloc(sizeof(*type));
	if (!type)
		return &drgn_enomem;
	drgn_array_type_init(type, length, element_type, key.lang);
	if (drgn_array_type_table_insert_searched(&prog->array_types, &type, hp,
						  NULL) == -1) {
		free(type);
		return &drgn_enomem;
	}
out:
	*ret = type;
	return NULL;
}

struct drgn_error *
drgn_program_incomplete_array_type(struct drgn_program *prog,
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
	it = drgn_array_type_table_search_hashed(&prog->array_types, &key, hp);
	if (it.entry) {
		type = *it.entry;
		goto out;
	}

	type = malloc(sizeof(*type));
	if (!type)
		return &drgn_enomem;
	drgn_array_type_init_incomplete(type, element_type, key.lang);
	if (drgn_array_type_table_insert_searched(&prog->array_types, &type, hp,
						  NULL) == -1) {
		free(type);
		return &drgn_enomem;
	}
out:
	*ret = type;
	return NULL;
}

static struct drgn_error *
drgn_program_cache_members(struct drgn_program *prog,
			   struct drgn_type *outer_type,
			   struct drgn_type *type, uint64_t bit_offset)
{
	if (!drgn_type_has_members(type))
		return NULL;

	struct drgn_type_member *members = drgn_type_members(type);
	size_t num_members = drgn_type_num_members(type);
	for (size_t i = 0; i < num_members; i++) {
		struct drgn_type_member *member = &members[i];
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
			if (drgn_member_map_insert(&prog->members, &entry,
						   NULL) == -1)
				return &drgn_enomem;
		} else {
			struct drgn_qualified_type member_type;
			struct drgn_error *err = drgn_member_type(member,
								  &member_type);
			if (err)
				return err;
			err = drgn_program_cache_members(prog, outer_type,
							 member_type.type,
							 bit_offset +
							 member->bit_offset);
			if (err)
				return err;
		}
	}
	return NULL;
}

struct drgn_error *drgn_program_find_member(struct drgn_program *prog,
					    struct drgn_type *type,
					    const char *member_name,
					    size_t member_name_len,
					    struct drgn_member_value **ret)
{
	const struct drgn_member_key key = {
		.type = drgn_underlying_type(type),
		.name = member_name,
		.name_len = member_name_len,
	};
	struct hash_pair hp = drgn_member_map_hash(&key);
	struct drgn_member_map_iterator it =
		drgn_member_map_search_hashed(&prog->members, &key, hp);
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
	struct hash_pair cached_hp = drgn_type_set_hash(&key.type);
	if (drgn_type_set_search_hashed(&prog->members_cached, &key.type,
					cached_hp).entry)
		return drgn_error_member_not_found(type, member_name);

	struct drgn_error *err = drgn_program_cache_members(prog, key.type,
							    key.type, 0);
	if (err)
		return err;

	if (drgn_type_set_insert_searched(&prog->members_cached, &key.type,
					  cached_hp, NULL) == -1)
		return &drgn_enomem;

	it = drgn_member_map_search_hashed(&prog->members, &key, hp);
	if (it.entry) {
		*ret = &it.entry->value;
		return NULL;
	}

	return drgn_error_member_not_found(type, member_name);
}
