// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

#include <stdlib.h>
#include <string.h>

#include "cityhash.h"
#include "error.h"
#include "hash_table.h"
#include "language.h"
#include "program.h"
#include "type.h"
#include "util.h"

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

struct drgn_error *drgn_lazy_type_evaluate(struct drgn_lazy_type *lazy_type,
					   struct drgn_qualified_type *ret)
{
	if (drgn_lazy_type_is_evaluated(lazy_type)) {
		ret->type = lazy_type->type;
		ret->qualifiers = lazy_type->qualifiers;
	} else {
		struct drgn_type_thunk *thunk_ptr = lazy_type->thunk;
		struct drgn_type_thunk thunk = *thunk_ptr;
		struct drgn_error *err = thunk.evaluate_fn(thunk_ptr, ret);
		if (err)
			return err;
		if (drgn_type_program(ret->type) != thunk.prog) {
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "type is from different program");
		}
		drgn_lazy_type_init_evaluated(lazy_type, ret->type,
					      ret->qualifiers);
		thunk.free_fn(thunk_ptr);
	}
	return NULL;
}

void drgn_lazy_type_deinit(struct drgn_lazy_type *lazy_type)
{
	if (!drgn_lazy_type_is_evaluated(lazy_type))
		drgn_type_thunk_free(lazy_type->thunk);
}

static inline struct drgn_error *
drgn_lazy_type_check_prog(struct drgn_lazy_type *lazy_type,
			  struct drgn_program *prog)
{
	if ((drgn_lazy_type_is_evaluated(lazy_type) ?
	     drgn_type_program(lazy_type->type) :
	     lazy_type->thunk->prog) != prog) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "type is from different program");
	}
	return NULL;
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

static struct hash_pair drgn_type_dedupe_hash(struct drgn_type * const *entry)
{
	struct drgn_type *type = *entry;
	size_t hash = hash_combine(drgn_type_kind(type),
				   (uintptr_t)drgn_type_language(type));
	/*
	 * We don't dedupe complete compound or enumerated types, and typedefs
	 * inherit is_complete from the aliased type, so is_complete can only
	 * differ for otherwise equal array types. We implicitly include that in
	 * the hash with the is_complete check below, so we don't need to hash
	 * it explicitly.
	 */
	if (drgn_type_has_name(type)) {
		const char *name = drgn_type_name(type);
		hash = hash_combine(hash, cityhash_size_t(name, strlen(name)));
	}
	if (drgn_type_has_size(type))
		hash = hash_combine(hash, drgn_type_size(type));
	if (drgn_type_has_is_signed(type))
		hash = hash_combine(hash, drgn_type_is_signed(type));
	const char *tag;
	if (drgn_type_has_tag(type) && (tag = drgn_type_tag(type)))
		hash = hash_combine(hash, cityhash_size_t(tag, strlen(tag)));
	if (drgn_type_has_type(type)) {
		struct drgn_qualified_type qualified_type =
			drgn_type_type(type);
		hash = hash_combine(hash, (uintptr_t)qualified_type.type);
		hash = hash_combine(hash, qualified_type.qualifiers);
	}
	if (drgn_type_has_length(type) && drgn_type_is_complete(type))
		hash = hash_combine(hash, drgn_type_length(type));
	return hash_pair_from_avalanching_hash(hash);
}

static bool drgn_type_dedupe_eq(struct drgn_type * const *entry_a,
				struct drgn_type * const *entry_b)
{
	struct drgn_type *a = *entry_a;
	struct drgn_type *b = *entry_b;

	if (drgn_type_kind(a) != drgn_type_kind(b) ||
	    drgn_type_language(a) != drgn_type_language(b) ||
	    drgn_type_is_complete(a) != drgn_type_is_complete(b))
		return false;
	if (drgn_type_has_name(a) &&
	    strcmp(drgn_type_name(a), drgn_type_name(b)) != 0)
		return false;
	if (drgn_type_has_size(a) && drgn_type_size(a) != drgn_type_size(b))
		return false;
	if (drgn_type_has_is_signed(a) &&
	    drgn_type_is_signed(a) != drgn_type_is_signed(b))
		return false;
	if (drgn_type_has_tag(a)) {
		const char *tag_a = drgn_type_tag(a);
		const char *tag_b = drgn_type_tag(b);
		if ((!tag_a != !tag_b) || (tag_a && strcmp(tag_a, tag_b) != 0))
			return false;
	}
	if (drgn_type_has_type(a)) {
		struct drgn_qualified_type type_a = drgn_type_type(a);
		struct drgn_qualified_type type_b = drgn_type_type(b);
		if (type_a.type != type_b.type ||
		    type_a.qualifiers != type_b.qualifiers)
			return false;
	}
	if (drgn_type_has_length(a) &&
	    drgn_type_length(a) != drgn_type_length(b))
		return false;
	return true;
}

/*
 * We don't deduplicate complete compound types, complete enumerated types, or
 * function types, so the hash and comparison functions ignore members,
 * enumerators, parameters, and is_variadic.
 */
DEFINE_HASH_TABLE_FUNCTIONS(drgn_dedupe_type_set, drgn_type_dedupe_hash,
			    drgn_type_dedupe_eq)

DEFINE_VECTOR_FUNCTIONS(drgn_typep_vector)

static struct drgn_error *find_or_create_type(struct drgn_type *key,
					      struct drgn_type **ret)
{
	struct drgn_program *prog = key->_private.program;
	struct hash_pair hp = drgn_dedupe_type_set_hash(&key);
	struct drgn_dedupe_type_set_iterator it =
		drgn_dedupe_type_set_search_hashed(&prog->dedupe_types, &key,
						   hp);
	if (it.entry) {
		*ret = *it.entry;
		return NULL;
	}

	struct drgn_type *type = malloc(sizeof(*type));
	if (!type)
		return &drgn_enomem;

	*type = *key;
	if (!drgn_dedupe_type_set_insert_searched(&prog->dedupe_types, &type,
						  hp, NULL)) {
		free(type);
		return &drgn_enomem;
	}
	*ret = type;
	return NULL;
}

struct drgn_type *drgn_void_type(struct drgn_program *prog,
				 const struct drgn_language *lang)
{
	if (!lang)
		lang = drgn_program_language(prog);
	return &prog->void_types[lang - drgn_languages];
}

struct drgn_error *drgn_int_type_create(struct drgn_program *prog,
					const char *name, uint64_t size,
					bool is_signed,
					const struct drgn_language *lang,
					struct drgn_type **ret)
{
	enum drgn_primitive_type primitive = c_parse_specifier_list(name);
	if (drgn_primitive_type_kind[primitive] == DRGN_TYPE_INT &&
	    (primitive == DRGN_C_TYPE_CHAR ||
	     is_signed == drgn_primitive_type_is_signed(primitive)))
		name = drgn_primitive_type_spellings[primitive][0];
	else
		primitive = DRGN_NOT_PRIMITIVE_TYPE;

	struct drgn_type key = {
		{
			.kind = DRGN_TYPE_INT,
			.is_complete = true,
			.primitive = primitive,
			.name = name,
			.size = size,
			.is_signed = is_signed,
			.program = prog,
			.language = lang ? lang : drgn_program_language(prog),
		}
	};
	return find_or_create_type(&key, ret);
}

struct drgn_error *drgn_bool_type_create(struct drgn_program *prog,
					 const char *name, uint64_t size,
					 const struct drgn_language *lang,
					 struct drgn_type **ret)
{
	enum drgn_primitive_type primitive = c_parse_specifier_list(name);
	if (primitive == DRGN_C_TYPE_BOOL)
		name = drgn_primitive_type_spellings[DRGN_C_TYPE_BOOL][0];
	else
		primitive = DRGN_NOT_PRIMITIVE_TYPE;

	struct drgn_type key = {
		{
			.kind = DRGN_TYPE_BOOL,
			.is_complete = true,
			.primitive = primitive,
			.name = name,
			.size = size,
			.program = prog,
			.language = lang ? lang : drgn_program_language(prog),
		}
	};
	return find_or_create_type(&key, ret);
}

struct drgn_error *drgn_float_type_create(struct drgn_program *prog,
					  const char *name, uint64_t size,
					  const struct drgn_language *lang,
					  struct drgn_type **ret)
{
	enum drgn_primitive_type primitive = c_parse_specifier_list(name);
	if (drgn_primitive_type_kind[primitive] == DRGN_TYPE_FLOAT)
		name = drgn_primitive_type_spellings[primitive][0];
	else
		primitive = DRGN_NOT_PRIMITIVE_TYPE;

	struct drgn_type key = {
		{
			.kind = DRGN_TYPE_FLOAT,
			.is_complete = true,
			.primitive = primitive,
			.name = name,
			.size = size,
			.program = prog,
			.language = lang ? lang : drgn_program_language(prog),
		}
	};
	return find_or_create_type(&key, ret);
}

struct drgn_error *drgn_complex_type_create(struct drgn_program *prog,
					    const char *name, uint64_t size,
					    struct drgn_type *real_type,
					    const struct drgn_language *lang,
					    struct drgn_type **ret)
{
	if (drgn_type_program(real_type) != prog) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "type is from different program");
	}
	if (drgn_type_kind(real_type) != DRGN_TYPE_FLOAT &&
	    drgn_type_kind(real_type) != DRGN_TYPE_INT) {
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "real type of complex type must be floating-point or integer type");
	}

	struct drgn_type key = {
		{
			.kind = DRGN_TYPE_COMPLEX,
			.is_complete = true,
			.primitive = DRGN_NOT_PRIMITIVE_TYPE,
			.name = name,
			.size = size,
			.type = real_type,
			.program = prog,
			.language = lang ? lang : drgn_program_language(prog),
		}
	};
	return find_or_create_type(&key, ret);
}

DEFINE_VECTOR_FUNCTIONS(drgn_type_member_vector)

void drgn_compound_type_builder_init(struct drgn_compound_type_builder *builder,
				     struct drgn_program *prog,
				     enum drgn_type_kind kind)
{
	assert(kind == DRGN_TYPE_STRUCT ||
	       kind == DRGN_TYPE_UNION ||
	       kind == DRGN_TYPE_CLASS);
	builder->prog = prog;
	builder->kind = kind;
	drgn_type_member_vector_init(&builder->members);
}

void
drgn_compound_type_builder_deinit(struct drgn_compound_type_builder *builder)
{
	for (size_t i = 0; i < builder->members.size; i++)
		drgn_lazy_type_deinit(&builder->members.data[i].type);
	drgn_type_member_vector_deinit(&builder->members);
}

struct drgn_error *
drgn_compound_type_builder_add_member(struct drgn_compound_type_builder *builder,
				      struct drgn_lazy_type type,
				      const char *name, uint64_t bit_offset,
				      uint64_t bit_field_size)
{
	struct drgn_error *err = drgn_lazy_type_check_prog(&type,
							   builder->prog);
	if (err)
		return err;
	struct drgn_type_member *member =
		drgn_type_member_vector_append_entry(&builder->members);
	if (!member)
		return &drgn_enomem;
	member->type = type;
	member->name = name;
	member->bit_offset = bit_offset;
	member->bit_field_size = bit_field_size;
	return NULL;
}

struct drgn_error *
drgn_compound_type_create(struct drgn_compound_type_builder *builder,
			  const char *tag, uint64_t size,
			  const struct drgn_language *lang,
			  struct drgn_type **ret)
{
	struct drgn_type *type = malloc(sizeof(*type));
	if (!type)
		return &drgn_enomem;
	if (!drgn_typep_vector_append(&builder->prog->created_types, &type)) {
		free(type);
		return &drgn_enomem;
	}

	drgn_type_member_vector_shrink_to_fit(&builder->members);

	type->_private.kind = builder->kind;
	type->_private.is_complete = true;
	type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
	type->_private.tag = tag;
	type->_private.size = size;
	type->_private.members = builder->members.data;
	type->_private.num_members = builder->members.size;
	type->_private.program = builder->prog;
	type->_private.language =
		lang ? lang : drgn_program_language(builder->prog);
	*ret = type;
	return NULL;
}

struct drgn_error *
drgn_incomplete_compound_type_create(struct drgn_program *prog,
				     enum drgn_type_kind kind, const char *tag,
				     const struct drgn_language *lang,
				     struct drgn_type **ret)
{
	assert(kind == DRGN_TYPE_STRUCT ||
	       kind == DRGN_TYPE_UNION ||
	       kind == DRGN_TYPE_CLASS);
	struct drgn_type key = {
		{
			.kind = kind,
			.is_complete = false,
			.primitive = DRGN_NOT_PRIMITIVE_TYPE,
			.tag = tag,
			.program = prog,
			.language = lang ? lang : drgn_program_language(prog),
		}
	};
	return find_or_create_type(&key, ret);
}

DEFINE_VECTOR_FUNCTIONS(drgn_type_enumerator_vector)

void drgn_enum_type_builder_init(struct drgn_enum_type_builder *builder,
				 struct drgn_program *prog)
{
	builder->prog = prog;
	drgn_type_enumerator_vector_init(&builder->enumerators);
}

void drgn_enum_type_builder_deinit(struct drgn_enum_type_builder *builder)
{
	drgn_type_enumerator_vector_deinit(&builder->enumerators);
}

struct drgn_error *
drgn_enum_type_builder_add_signed(struct drgn_enum_type_builder *builder,
				  const char *name, int64_t svalue)
{
	struct drgn_type_enumerator *enumerator =
		drgn_type_enumerator_vector_append_entry(&builder->enumerators);
	if (!enumerator)
		return &drgn_enomem;
	enumerator->name = name;
	enumerator->svalue = svalue;
	return NULL;
}

struct drgn_error *
drgn_enum_type_builder_add_unsigned(struct drgn_enum_type_builder *builder,
				    const char *name, uint64_t uvalue)
{
	struct drgn_type_enumerator *enumerator =
		drgn_type_enumerator_vector_append_entry(&builder->enumerators);
	if (!enumerator)
		return &drgn_enomem;
	enumerator->name = name;
	enumerator->uvalue = uvalue;
	return NULL;
}

struct drgn_error *drgn_enum_type_create(struct drgn_enum_type_builder *builder,
					 const char *tag,
					 struct drgn_type *compatible_type,
					 const struct drgn_language *lang,
					 struct drgn_type **ret)
{
	if (drgn_type_program(compatible_type) != builder->prog) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "type is from different program");
	}
	if (drgn_type_kind(compatible_type) != DRGN_TYPE_INT) {
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "compatible type of enum type must be integer type");
	}

	struct drgn_type *type = malloc(sizeof(*type));
	if (!type)
		return &drgn_enomem;
	if (!drgn_typep_vector_append(&builder->prog->created_types, &type)) {
		free(type);
		return &drgn_enomem;
	}

	drgn_type_enumerator_vector_shrink_to_fit(&builder->enumerators);

	type->_private.kind = DRGN_TYPE_ENUM;
	type->_private.is_complete = true;
	type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
	type->_private.tag = tag;
	type->_private.type = compatible_type;
	type->_private.qualifiers = 0;
	type->_private.enumerators = builder->enumerators.data;
	type->_private.num_enumerators = builder->enumerators.size;
	type->_private.program = builder->prog;
	type->_private.language =
		lang ? lang : drgn_program_language(builder->prog);
	*ret = type;
	return NULL;
}

struct drgn_error *
drgn_incomplete_enum_type_create(struct drgn_program *prog, const char *tag,
				 const struct drgn_language *lang,
				 struct drgn_type **ret)
{
	struct drgn_type key = {
		{
			.kind = DRGN_TYPE_ENUM,
			.is_complete = false,
			.primitive = DRGN_NOT_PRIMITIVE_TYPE,
			.tag = tag,
			.program = prog,
			.language = lang ? lang : drgn_program_language(prog),
		}
	};
	return find_or_create_type(&key, ret);
}

struct drgn_error *
drgn_typedef_type_create(struct drgn_program *prog, const char *name,
			 struct drgn_qualified_type aliased_type,
			 const struct drgn_language *lang,
			 struct drgn_type **ret)
{
	if (drgn_type_program(aliased_type.type) != prog) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "type is from different program");
	}

	enum drgn_primitive_type primitive;
	if (strcmp(name, "size_t") == 0)
		primitive = DRGN_C_TYPE_SIZE_T;
	else if (strcmp(name, "ptrdiff_t") == 0)
		primitive = DRGN_C_TYPE_PTRDIFF_T;
	else
		primitive = DRGN_NOT_PRIMITIVE_TYPE;

	struct drgn_type key = {
		{
			.kind = DRGN_TYPE_TYPEDEF,
			.is_complete = drgn_type_is_complete(aliased_type.type),
			.primitive = primitive,
			.name = name,
			.type = aliased_type.type,
			.qualifiers = aliased_type.qualifiers,
			.program = prog,
			.language = lang ? lang : drgn_program_language(prog),
		}
	};
	return find_or_create_type(&key, ret);
}

struct drgn_error *
drgn_pointer_type_create(struct drgn_program *prog,
			 struct drgn_qualified_type referenced_type,
			 uint64_t size, const struct drgn_language *lang,
			 struct drgn_type **ret)
{
	if (drgn_type_program(referenced_type.type) != prog) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "type is from different program");
	}

	struct drgn_type key = {
		{
			.kind = DRGN_TYPE_POINTER,
			.is_complete = true,
			.primitive = DRGN_NOT_PRIMITIVE_TYPE,
			.size = size,
			.type = referenced_type.type,
			.qualifiers = referenced_type.qualifiers,
			.program = prog,
			.language = lang ? lang : drgn_program_language(prog),
		}
	};
	return find_or_create_type(&key, ret);
}

struct drgn_error *
drgn_array_type_create(struct drgn_program *prog,
		       struct drgn_qualified_type element_type,
		       uint64_t length, const struct drgn_language *lang,
		       struct drgn_type **ret)
{
	if (drgn_type_program(element_type.type) != prog) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "type is from different program");
	}

	struct drgn_type key = {
		{
			.kind = DRGN_TYPE_ARRAY,
			.is_complete = true,
			.primitive = DRGN_NOT_PRIMITIVE_TYPE,
			.length = length,
			.type = element_type.type,
			.qualifiers = element_type.qualifiers,
			.program = prog,
			.language = lang ? lang : drgn_program_language(prog),
		}
	};
	return find_or_create_type(&key, ret);
}

struct drgn_error *
drgn_incomplete_array_type_create(struct drgn_program *prog,
				  struct drgn_qualified_type element_type,
				  const struct drgn_language *lang,
				  struct drgn_type **ret)
{
	if (drgn_type_program(element_type.type) != prog) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "type is from different program");
	}

	struct drgn_type key = {
		{
			.kind = DRGN_TYPE_ARRAY,
			.is_complete = false,
			.primitive = DRGN_NOT_PRIMITIVE_TYPE,
			.type = element_type.type,
			.qualifiers = element_type.qualifiers,
			.program = prog,
			.language = lang ? lang : drgn_program_language(prog),
		}
	};
	return find_or_create_type(&key, ret);
}

DEFINE_VECTOR_FUNCTIONS(drgn_type_parameter_vector)

void drgn_function_type_builder_init(struct drgn_function_type_builder *builder,
				     struct drgn_program *prog)
{
	builder->prog = prog;
	drgn_type_parameter_vector_init(&builder->parameters);
}

void
drgn_function_type_builder_deinit(struct drgn_function_type_builder *builder)
{
	for (size_t i = 0; i < builder->parameters.size; i++)
		drgn_lazy_type_deinit(&builder->parameters.data[i].type);
	drgn_type_parameter_vector_deinit(&builder->parameters);
}

struct drgn_error *
drgn_function_type_builder_add_parameter(struct drgn_function_type_builder *builder,
					 struct drgn_lazy_type type,
					 const char *name)
{
	struct drgn_error *err = drgn_lazy_type_check_prog(&type,
							   builder->prog);
	if (err)
		return err;
	struct drgn_type_parameter *parameter =
		drgn_type_parameter_vector_append_entry(&builder->parameters);
	if (!parameter)
		return &drgn_enomem;
	parameter->type = type;
	parameter->name = name;
	return NULL;
}

struct drgn_error *
drgn_function_type_create(struct drgn_function_type_builder *builder,
			  struct drgn_qualified_type return_type,
			  bool is_variadic, const struct drgn_language *lang,
			  struct drgn_type **ret)
{
	if (drgn_type_program(return_type.type) != builder->prog) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "type is from different program");
	}

	struct drgn_type *type = malloc(sizeof(*type));
	if (!type)
		return &drgn_enomem;
	if (!drgn_typep_vector_append(&builder->prog->created_types, &type)) {
		free(type);
		return &drgn_enomem;
	}

	drgn_type_parameter_vector_shrink_to_fit(&builder->parameters);

	type->_private.kind = DRGN_TYPE_FUNCTION;
	type->_private.is_complete = true;
	type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
	type->_private.type = return_type.type;
	type->_private.qualifiers = return_type.qualifiers;
	type->_private.parameters = builder->parameters.data;
	type->_private.num_parameters = builder->parameters.size;
	type->_private.is_variadic = is_variadic;
	type->_private.program = builder->prog;
	type->_private.language =
		lang ? lang : drgn_program_language(builder->prog);
	*ret = type;
	return NULL;
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
	struct drgn_type_pair pair = { a, b };
	struct hash_pair hp = drgn_type_pair_set_hash(&pair);
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
	    drgn_type_is_complete(a) != drgn_type_is_complete(b))
		goto out_false;

	switch (drgn_type_kind(a)) {
	/*
	 * This types are uniquely deduplicated, so if their pointers did not
	 * compare equal then they are not equal.
	 */
	case DRGN_TYPE_VOID:
	case DRGN_TYPE_INT:
	case DRGN_TYPE_BOOL:
	case DRGN_TYPE_FLOAT:
	case DRGN_TYPE_COMPLEX:
		goto out_false;
	/* These types are uniquely deduplicated only if incomplete. */
	case DRGN_TYPE_STRUCT:
	case DRGN_TYPE_UNION:
	case DRGN_TYPE_CLASS:
	case DRGN_TYPE_ENUM:
		if (!drgn_type_is_complete(a))
			goto out_false;
		break;
	/*
	 * These types are not uniquely deduplicated because they can refer to
	 * types that are not deduplicated.
	 */
	case DRGN_TYPE_TYPEDEF:
	case DRGN_TYPE_POINTER:
	case DRGN_TYPE_ARRAY:
	case DRGN_TYPE_FUNCTION:
		break;
	}

	if (drgn_type_language(a) != drgn_type_language(b))
		goto out_false;

	if (drgn_type_has_name(a) &&
	    strcmp(drgn_type_name(a), drgn_type_name(b)) != 0)
		goto out_false;
	if (drgn_type_has_tag(a)) {
		const char *tag_a = drgn_type_tag(a);
		const char *tag_b = drgn_type_tag(b);
		if ((!tag_a != !tag_b) || (tag_a && strcmp(tag_a, tag_b) != 0))
			goto out_false;
	}
	if (drgn_type_has_size(a) && drgn_type_size(a) != drgn_type_size(b))
		goto out_false;
	if (drgn_type_has_length(a) &&
	    drgn_type_length(a) != drgn_type_length(b))
		goto out_false;
	assert(!drgn_type_has_is_signed(a));
	if (drgn_type_has_type(a)) {
		struct drgn_qualified_type type_a = drgn_type_type(a);
		struct drgn_qualified_type type_b = drgn_type_type(b);
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
	if (drgn_type_program(a) != drgn_type_program(b)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "types are from different programs");
	}
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
	for (size_t i = 0; i < ARRAY_SIZE(prog->void_types); i++) {
		struct drgn_type *type = &prog->void_types[i];
		type->_private.kind = DRGN_TYPE_VOID;
		type->_private.is_complete = false;
		type->_private.primitive = DRGN_C_TYPE_VOID;
		type->_private.program = prog;
		type->_private.language = &drgn_languages[i];
	}
	drgn_dedupe_type_set_init(&prog->dedupe_types);
	drgn_typep_vector_init(&prog->created_types);
	drgn_member_map_init(&prog->members);
	drgn_type_set_init(&prog->members_cached);
}

void drgn_program_deinit_types(struct drgn_program *prog)
{
	drgn_member_map_deinit(&prog->members);
	drgn_type_set_deinit(&prog->members_cached);

	for (size_t i = 0; i < prog->created_types.size; i++) {
		struct drgn_type *type = prog->created_types.data[i];
		if (drgn_type_has_members(type)) {
			struct drgn_type_member *members =
				drgn_type_members(type);
			size_t num_members = drgn_type_num_members(type);
			for (size_t j = 0; j < num_members; j++)
				drgn_lazy_type_deinit(&members[j].type);
			free(members);
		}
		if (drgn_type_has_enumerators(type))
			free(drgn_type_enumerators(type));
		if (drgn_type_has_parameters(type)) {
			struct drgn_type_parameter *parameters =
				drgn_type_parameters(type);
			size_t num_parameters = drgn_type_num_parameters(type);
			for (size_t j = 0; j < num_parameters; j++)
				drgn_lazy_type_deinit(&parameters[j].type);
			free(parameters);
		}
		free(type);
	}
	drgn_typep_vector_deinit(&prog->created_types);

	for (struct drgn_dedupe_type_set_iterator it =
	     drgn_dedupe_type_set_first(&prog->dedupe_types);
	     it.entry; it = drgn_dedupe_type_set_next(it))
		free(*it.entry);
	drgn_dedupe_type_set_deinit(&prog->dedupe_types);

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
			if (drgn_type_program(ret->type) != prog) {
				return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
							 "type find callback returned type from wrong program");
			}
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

/*
 * size_t and ptrdiff_t default to typedefs of whatever integer type matches the
 * word size.
 */
static struct drgn_error *
default_size_t_or_ptrdiff_t(struct drgn_program *prog,
			    enum drgn_primitive_type type,
			    struct drgn_type **ret)
{
	static const enum drgn_primitive_type integer_types[2][3] = {
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
	struct drgn_error *err;
	uint8_t word_size;

	err = drgn_program_word_size(prog, &word_size);
	if (err)
		return err;
	for (size_t i = 0; i < ARRAY_SIZE(integer_types[0]); i++) {
		enum drgn_primitive_type integer_type;
		struct drgn_qualified_type qualified_type;

		integer_type = integer_types[type == DRGN_C_TYPE_PTRDIFF_T][i];
		err = drgn_program_find_primitive_type(prog, integer_type,
						       &qualified_type.type);
		if (err)
			return err;
		if (drgn_type_size(qualified_type.type) == word_size) {
			qualified_type.qualifiers = 0;
			return drgn_typedef_type_create(prog,
							drgn_primitive_type_spellings[type][0],
							qualified_type,
							&drgn_language_c, ret);
		}
	}
	return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
				 "no suitable integer type for %s",
				 drgn_primitive_type_spellings[type][0]);
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
	size_t i;

	if (prog->primitive_types[type]) {
		*ret = prog->primitive_types[type];
		return NULL;
	}

	kind = drgn_primitive_type_kind[type];
	if (kind == DRGN_TYPE_VOID) {
		*ret = drgn_void_type(prog, &drgn_language_c);
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

	switch (type) {
	case DRGN_C_TYPE_CHAR:
	case DRGN_C_TYPE_SIGNED_CHAR:
		err = drgn_int_type_create(prog, spellings[0], 1, true,
					   &drgn_language_c, ret);
		break;
	case DRGN_C_TYPE_UNSIGNED_CHAR:
		err = drgn_int_type_create(prog, spellings[0], 1, false,
					   &drgn_language_c, ret);
		break;
	case DRGN_C_TYPE_SHORT:
		err = drgn_int_type_create(prog, spellings[0], 2, true,
					   &drgn_language_c, ret);
		break;
	case DRGN_C_TYPE_UNSIGNED_SHORT:
		err = drgn_int_type_create(prog, spellings[0], 2, false,
					   &drgn_language_c, ret);
		break;
	case DRGN_C_TYPE_INT:
		err = drgn_int_type_create(prog, spellings[0], 4, true,
					   &drgn_language_c, ret);
		break;
	case DRGN_C_TYPE_UNSIGNED_INT:
		err = drgn_int_type_create(prog, spellings[0], 4, false,
					   &drgn_language_c, ret);
		break;
	/* long and unsigned long default to the word size. */
	case DRGN_C_TYPE_LONG:
	case DRGN_C_TYPE_UNSIGNED_LONG: {
		uint8_t word_size;

		err = drgn_program_word_size(prog, &word_size);
		if (err)
			break;
		err = drgn_int_type_create(prog, spellings[0], word_size,
					   type == DRGN_C_TYPE_LONG,
					   &drgn_language_c, ret);
		break;
	}
	case DRGN_C_TYPE_LONG_LONG:
		err = drgn_int_type_create(prog, spellings[0], 8, true,
					   &drgn_language_c, ret);
		break;
	case DRGN_C_TYPE_UNSIGNED_LONG_LONG:
		err = drgn_int_type_create(prog, spellings[0], 8, false,
					   &drgn_language_c, ret);
		break;
	case DRGN_C_TYPE_BOOL:
		err = drgn_bool_type_create(prog, spellings[0], 1,
					    &drgn_language_c, ret);
		break;
	case DRGN_C_TYPE_FLOAT:
		err = drgn_float_type_create(prog, spellings[0], 4,
					     &drgn_language_c, ret);
		break;
	case DRGN_C_TYPE_DOUBLE:
		err = drgn_float_type_create(prog, spellings[0], 8,
					     &drgn_language_c, ret);
		break;
	case DRGN_C_TYPE_LONG_DOUBLE:
		err = drgn_float_type_create(prog, spellings[0], 16,
					     &drgn_language_c, ret);
		break;
	case DRGN_C_TYPE_SIZE_T:
	case DRGN_C_TYPE_PTRDIFF_T:
		err = default_size_t_or_ptrdiff_t(prog, type, ret);
		break;
	default:
		UNREACHABLE();
	}
	if (err)
		return err;
	assert(drgn_type_primitive(*ret) == type);

out:
	prog->primitive_types[type] = *ret;
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
