// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "array.h"
#include "error.h"
#include "hash_table.h"
#include "language.h"
#include "lazy_object.h"
#include "program.h"
#include "type.h"
#include "util.h"

const char * const drgn_type_kind_spelling[] = {
	[DRGN_TYPE_VOID] = "void",
	[DRGN_TYPE_INT] = "int",
	[DRGN_TYPE_BOOL] = "bool",
	[DRGN_TYPE_FLOAT] = "float",
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

static struct hash_pair
drgn_member_key_hash_pair(const struct drgn_member_key *key)
{
	size_t hash;
	if (key->name)
		hash = hash_bytes(key->name, key->name_len);
	else
		hash = 0;
	hash = hash_combine((uintptr_t)key->type, hash);
	return hash_pair_from_avalanching_hash(hash);
}

static bool drgn_member_key_eq(const struct drgn_member_key *a,
			       const struct drgn_member_key *b)
{
	return (a->type == b->type && a->name_len == b->name_len &&
		(!a->name_len || memcmp(a->name, b->name, a->name_len) == 0));
}

DEFINE_HASH_MAP_FUNCTIONS(drgn_member_map, drgn_member_key_hash_pair,
			  drgn_member_key_eq)

DEFINE_HASH_SET_FUNCTIONS(drgn_type_set, ptr_key_hash_pair, scalar_key_eq)

LIBDRGN_PUBLIC struct drgn_error *
drgn_member_object(struct drgn_type_member *member,
		   const struct drgn_object **ret)
{
	struct drgn_error *err = drgn_lazy_object_evaluate(&member->object);
	if (!err)
		*ret = &member->object.obj;
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_member_type(struct drgn_type_member *member,
		 struct drgn_qualified_type *type_ret,
		 uint64_t *bit_field_size_ret)
{
	struct drgn_error *err = drgn_lazy_object_evaluate(&member->object);
	if (err)
		return err;
	*type_ret = drgn_object_qualified_type(&member->object.obj);
	if (bit_field_size_ret) {
		if (member->object.obj.is_bit_field)
			*bit_field_size_ret = member->object.obj.bit_size;
		else
			*bit_field_size_ret = 0;
	}
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_parameter_default_argument(struct drgn_type_parameter *parameter,
				const struct drgn_object **ret)
{
	struct drgn_error *err =
		drgn_lazy_object_evaluate(&parameter->default_argument);
	if (!err)
		*ret = &parameter->default_argument.obj;
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_parameter_type(struct drgn_type_parameter *parameter,
		    struct drgn_qualified_type *ret)
{
	struct drgn_error *err =
		drgn_lazy_object_evaluate(&parameter->default_argument);
	if (!err)
		*ret = drgn_object_qualified_type(&parameter->default_argument.obj);
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_template_parameter_type(struct drgn_type_template_parameter *parameter,
			     struct drgn_qualified_type *ret)
{
	struct drgn_error *err =
		drgn_lazy_object_evaluate(&parameter->argument);
	if (!err)
		*ret = drgn_object_qualified_type(&parameter->argument.obj);
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_template_parameter_object(struct drgn_type_template_parameter *parameter,
			       const struct drgn_object **ret)
{
	struct drgn_error *err =
		drgn_lazy_object_evaluate(&parameter->argument);
	if (err)
		return err;
	if (parameter->argument.obj.kind == DRGN_OBJECT_ABSENT)
		*ret = NULL;
	else
		*ret = &parameter->argument.obj;
	return NULL;
}

static struct hash_pair
drgn_type_dedupe_hash_pair(struct drgn_type * const *entry)
{
	struct drgn_type *type = *entry;
	size_t hash = hash_combine(drgn_type_kind(type),
				   drgn_type_is_complete(type));
	hash = hash_combine(hash, (uintptr_t)drgn_type_language(type));
	if (drgn_type_has_name(type))
		hash = hash_combine(hash, hash_c_string(drgn_type_name(type)));
	if (drgn_type_has_size(type))
		hash = hash_combine(hash, drgn_type_size(type));
	if (drgn_type_has_is_signed(type))
		hash = hash_combine(hash, drgn_type_is_signed(type));
	if (drgn_type_has_little_endian(type))
		hash = hash_combine(hash, drgn_type_little_endian(type));
	const char *tag;
	if (drgn_type_has_tag(type) && (tag = drgn_type_tag(type)))
		hash = hash_combine(hash, hash_c_string(tag));
	if (drgn_type_has_type(type)) {
		struct drgn_qualified_type qualified_type =
			drgn_type_type(type);
		hash = hash_combine(hash, (uintptr_t)qualified_type.type);
		hash = hash_combine(hash, qualified_type.qualifiers);
	}
	if (drgn_type_has_length(type))
		hash = hash_combine(hash, drgn_type_length(type));
	if (drgn_type_has_is_variadic(type))
		hash = hash_combine(hash, drgn_type_is_variadic(type));
	return hash_pair_from_avalanching_hash(hash);
}

static bool drgn_type_dedupe_eq(struct drgn_type * const *entry_a,
				struct drgn_type * const *entry_b)
{
	struct drgn_type *a = *entry_a;
	struct drgn_type *b = *entry_b;

	if (drgn_type_kind(a) != drgn_type_kind(b) ||
	    drgn_type_is_complete(a) != drgn_type_is_complete(b) ||
	    drgn_type_language(a) != drgn_type_language(b))
		return false;
	if (drgn_type_has_name(a) &&
	    strcmp(drgn_type_name(a), drgn_type_name(b)) != 0)
		return false;
	if (drgn_type_has_size(a) && drgn_type_size(a) != drgn_type_size(b))
		return false;
	if (drgn_type_has_is_signed(a) &&
	    drgn_type_is_signed(a) != drgn_type_is_signed(b))
		return false;
	if (drgn_type_has_little_endian(a) &&
	    drgn_type_little_endian(a) != drgn_type_little_endian(b))
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
	if (drgn_type_has_is_variadic(a) &&
	    drgn_type_is_variadic(a) != drgn_type_is_variadic(b))
		return false;
	return true;
}

/*
 * We don't deduplicate types with members, parameters, template parameters, or
 * enumerators, so the hash and comparison functions ignore those.
 */
DEFINE_HASH_SET_FUNCTIONS(drgn_dedupe_type_set, drgn_type_dedupe_hash_pair,
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
	if (drgn_dedupe_type_set_insert_searched(&prog->dedupe_types, &type, hp,
						 NULL) < 0) {
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

static struct drgn_error *
drgn_byte_order_to_little_endian(struct drgn_program *prog,
				 enum drgn_byte_order byte_order, bool *ret)
{
	SWITCH_ENUM_DEFAULT(byte_order,
	case DRGN_BIG_ENDIAN:
		*ret = false;
		return NULL;
	case DRGN_LITTLE_ENDIAN:
		*ret = true;
		return NULL;
	case DRGN_PROGRAM_ENDIAN:
		return drgn_program_is_little_endian(prog, ret);
	default:
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "invalid byte order");
	)
}

struct drgn_error *drgn_int_type_create(struct drgn_program *prog,
					const char *name, uint64_t size,
					bool is_signed,
					enum drgn_byte_order byte_order,
					const struct drgn_language *lang,
					struct drgn_type **ret)
{
	struct drgn_error *err;

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
	err = drgn_byte_order_to_little_endian(prog, byte_order,
					       &key._private.little_endian);
	if (err)
		return err;
	return find_or_create_type(&key, ret);
}

struct drgn_error *drgn_bool_type_create(struct drgn_program *prog,
					 const char *name, uint64_t size,
					 enum drgn_byte_order byte_order,
					 const struct drgn_language *lang,
					 struct drgn_type **ret)
{
	struct drgn_error *err;

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
	err = drgn_byte_order_to_little_endian(prog, byte_order,
					       &key._private.little_endian);
	if (err)
		return err;
	return find_or_create_type(&key, ret);
}

struct drgn_error *drgn_float_type_create(struct drgn_program *prog,
					  const char *name, uint64_t size,
					  enum drgn_byte_order byte_order,
					  const struct drgn_language *lang,
					  struct drgn_type **ret)
{
	struct drgn_error *err;

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
	err = drgn_byte_order_to_little_endian(prog, byte_order,
					       &key._private.little_endian);
	if (err)
		return err;
	return find_or_create_type(&key, ret);
}

DEFINE_VECTOR_FUNCTIONS(drgn_type_template_parameter_vector)

static void
drgn_template_parameters_builder_init(struct drgn_template_parameters_builder *builder,
				      struct drgn_program *prog)
{
	builder->prog = prog;
	drgn_type_template_parameter_vector_init(&builder->parameters);
}

static void
drgn_template_parameters_builder_deinit(struct drgn_template_parameters_builder *builder)
{
	for (size_t i = 0; i < builder->parameters.size; i++)
		drgn_lazy_object_deinit(&builder->parameters.data[i].argument);
	drgn_type_template_parameter_vector_deinit(&builder->parameters);
}

struct drgn_error *
drgn_template_parameters_builder_add(struct drgn_template_parameters_builder *builder,
				     const union drgn_lazy_object *argument,
				     const char *name, bool is_default)
{
	struct drgn_error *err = drgn_lazy_object_check_prog(argument,
							     builder->prog);
	if (err)
		return err;
	struct drgn_type_template_parameter *parameter =
		drgn_type_template_parameter_vector_append_entry(&builder->parameters);
	if (!parameter)
		return &drgn_enomem;
	parameter->argument = *argument;
	parameter->name = name;
	parameter->is_default = is_default;
	return NULL;
}

DEFINE_VECTOR_FUNCTIONS(drgn_type_member_vector)

void drgn_compound_type_builder_init(struct drgn_compound_type_builder *builder,
				     struct drgn_program *prog,
				     enum drgn_type_kind kind)
{
	assert(kind == DRGN_TYPE_STRUCT ||
	       kind == DRGN_TYPE_UNION ||
	       kind == DRGN_TYPE_CLASS);
	drgn_template_parameters_builder_init(&builder->template_builder, prog);
	builder->kind = kind;
	drgn_type_member_vector_init(&builder->members);
}

void
drgn_compound_type_builder_deinit(struct drgn_compound_type_builder *builder)
{
	for (size_t i = 0; i < builder->members.size; i++)
		drgn_lazy_object_deinit(&builder->members.data[i].object);
	drgn_type_member_vector_deinit(&builder->members);
	drgn_template_parameters_builder_deinit(&builder->template_builder);
}

struct drgn_error *
drgn_compound_type_builder_add_member(struct drgn_compound_type_builder *builder,
				      const union drgn_lazy_object *object,
				      const char *name, uint64_t bit_offset)
{
	struct drgn_error *err =
		drgn_lazy_object_check_prog(object,
					    builder->template_builder.prog);
	if (err)
		return err;
	struct drgn_type_member *member =
		drgn_type_member_vector_append_entry(&builder->members);
	if (!member)
		return &drgn_enomem;
	member->object = *object;
	member->name = name;
	member->bit_offset = bit_offset;
	return NULL;
}

struct drgn_error *
drgn_compound_type_create(struct drgn_compound_type_builder *builder,
			  const char *tag, uint64_t size, bool is_complete,
			  const struct drgn_language *lang,
			  struct drgn_type **ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = builder->template_builder.prog;

	if (!is_complete) {
		if (builder->members.size) {
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "incomplete type must not have members");
		}
		if (size != 0) {
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "size of incomplete type must be zero");
		}
	}

	if (!builder->members.size &&
	    !builder->template_builder.parameters.size) {
		struct drgn_type key = {
			{
				.kind = builder->kind,
				.is_complete = is_complete,
				.primitive = DRGN_NOT_PRIMITIVE_TYPE,
				.tag = tag,
				.size = size,
				.program = prog,
				.language =
					lang ? lang : drgn_program_language(prog),
			}
		};
		err = find_or_create_type(&key, ret);
		if (!err)
			drgn_type_member_vector_deinit(&builder->members);
		return err;
	}

	struct drgn_type *type = malloc(sizeof(*type));
	if (!type)
		return &drgn_enomem;
	if (!drgn_typep_vector_append(&prog->created_types, &type)) {
		free(type);
		return &drgn_enomem;
	}

	drgn_type_member_vector_shrink_to_fit(&builder->members);
	drgn_type_template_parameter_vector_shrink_to_fit(&builder->template_builder.parameters);

	type->_private.kind = builder->kind;
	type->_private.is_complete = is_complete;
	type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
	type->_private.tag = tag;
	type->_private.size = size;
	type->_private.members = builder->members.data;
	type->_private.num_members = builder->members.size;
	type->_private.template_parameters =
		builder->template_builder.parameters.data;
	type->_private.num_template_parameters =
		builder->template_builder.parameters.size;
	type->_private.program = prog;
	type->_private.language = lang ? lang : drgn_program_language(prog);
	*ret = type;
	return NULL;
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
	struct drgn_error *err;

	if (drgn_type_program(compatible_type) != builder->prog) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "type is from different program");
	}
	if (drgn_type_kind(compatible_type) != DRGN_TYPE_INT) {
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "compatible type of enum type must be integer type");
	}

	if (!builder->enumerators.size) {
		struct drgn_type key = {
			{
				.kind = DRGN_TYPE_ENUM,
				.is_complete = true,
				.primitive = DRGN_NOT_PRIMITIVE_TYPE,
				.tag = tag,
				.type = compatible_type,
				.program = builder->prog,
				.language =
					lang ? lang : drgn_program_language(builder->prog),
			}
		};
		err = find_or_create_type(&key, ret);
		if (!err)
			drgn_type_enumerator_vector_deinit(&builder->enumerators);
		return err;
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
			 uint64_t size, enum drgn_byte_order byte_order,
			 const struct drgn_language *lang,
			 struct drgn_type **ret)
{
	struct drgn_error *err;

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
	err = drgn_byte_order_to_little_endian(prog, byte_order,
					       &key._private.little_endian);
	if (err)
		return err;
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
	drgn_template_parameters_builder_init(&builder->template_builder, prog);
	drgn_type_parameter_vector_init(&builder->parameters);
}

void
drgn_function_type_builder_deinit(struct drgn_function_type_builder *builder)
{
	for (size_t i = 0; i < builder->parameters.size; i++)
		drgn_lazy_object_deinit(&builder->parameters.data[i].default_argument);
	drgn_type_parameter_vector_deinit(&builder->parameters);
	drgn_template_parameters_builder_deinit(&builder->template_builder);
}

struct drgn_error *
drgn_function_type_builder_add_parameter(struct drgn_function_type_builder *builder,
					 const union drgn_lazy_object *default_argument,
					 const char *name)
{
	struct drgn_error *err =
		drgn_lazy_object_check_prog(default_argument,
					    builder->template_builder.prog);
	if (err)
		return err;
	struct drgn_type_parameter *parameter =
		drgn_type_parameter_vector_append_entry(&builder->parameters);
	if (!parameter)
		return &drgn_enomem;
	parameter->default_argument = *default_argument;
	parameter->name = name;
	return NULL;
}

struct drgn_error *
drgn_function_type_create(struct drgn_function_type_builder *builder,
			  struct drgn_qualified_type return_type,
			  bool is_variadic, const struct drgn_language *lang,
			  struct drgn_type **ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = builder->template_builder.prog;

	if (drgn_type_program(return_type.type) != prog) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "type is from different program");
	}

	if (!builder->parameters.size &&
	    !builder->template_builder.parameters.size) {
		struct drgn_type key = {
			{
				.kind = DRGN_TYPE_FUNCTION,
				.is_complete = true,
				.primitive = DRGN_NOT_PRIMITIVE_TYPE,
				.type = return_type.type,
				.qualifiers = return_type.qualifiers,
				.is_variadic = is_variadic,
				.program = prog,
				.language =
					lang ? lang : drgn_program_language(prog),
			}
		};
		err = find_or_create_type(&key, ret);
		if (!err)
			drgn_type_parameter_vector_deinit(&builder->parameters);
		return err;
	}

	struct drgn_type *type = malloc(sizeof(*type));
	if (!type)
		return &drgn_enomem;
	if (!drgn_typep_vector_append(&prog->created_types, &type)) {
		free(type);
		return &drgn_enomem;
	}

	drgn_type_parameter_vector_shrink_to_fit(&builder->parameters);
	drgn_type_template_parameter_vector_shrink_to_fit(&builder->template_builder.parameters);

	type->_private.kind = DRGN_TYPE_FUNCTION;
	type->_private.is_complete = true;
	type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
	type->_private.type = return_type.type;
	type->_private.qualifiers = return_type.qualifiers;
	type->_private.parameters = builder->parameters.data;
	type->_private.num_parameters = builder->parameters.size;
	type->_private.is_variadic = is_variadic;
	type->_private.template_parameters =
		builder->template_builder.parameters.data;
	type->_private.num_template_parameters =
		builder->template_builder.parameters.size;
	type->_private.program = prog;
	type->_private.language = lang ? lang : drgn_program_language(prog);
	*ret = type;
	return NULL;
}

static struct drgn_error *
drgn_type_with_byte_order_impl(struct drgn_type **type,
			       struct drgn_type **underlying_type,
			       enum drgn_byte_order byte_order)
{
	struct drgn_error *err;
	switch (drgn_type_kind(*type)) {
	case DRGN_TYPE_INT:
		err = drgn_int_type_create(drgn_type_program(*type),
					   drgn_type_name(*type),
					   drgn_type_size(*type),
					   drgn_type_is_signed(*type),
					   byte_order,
					   drgn_type_language(*type), type);
		if (!err)
			*underlying_type = *type;
		return err;
	case DRGN_TYPE_BOOL:
		err = drgn_bool_type_create(drgn_type_program(*type),
					    drgn_type_name(*type),
					    drgn_type_size(*type), byte_order,
					    drgn_type_language(*type), type);
		if (!err)
			*underlying_type = *type;
		return err;
	case DRGN_TYPE_FLOAT:
		err = drgn_float_type_create(drgn_type_program(*type),
					     drgn_type_name(*type),
					     drgn_type_size(*type), byte_order,
					     drgn_type_language(*type), type);
		if (!err)
			*underlying_type = *type;
		return err;
	case DRGN_TYPE_POINTER:
		err = drgn_pointer_type_create(drgn_type_program(*type),
					       drgn_type_type(*type),
					       drgn_type_size(*type),
					       byte_order,
					       drgn_type_language(*type), type);
		if (!err)
			*underlying_type = *type;
		return err;
	case DRGN_TYPE_TYPEDEF: {
		struct drgn_qualified_type aliased_type = drgn_type_type(*type);
		err = drgn_type_with_byte_order_impl(&aliased_type.type,
						     underlying_type,
						     byte_order);
		if (err)
			return err;
		return drgn_typedef_type_create(drgn_type_program(*type),
						drgn_type_name(*type),
						aliased_type,
						drgn_type_language(*type),
						type);
	}
	case DRGN_TYPE_ENUM: {
		assert(drgn_type_is_complete(*type));
		struct drgn_type *compatible_type = drgn_type_type(*type).type;
		struct drgn_type *unused;
		err = drgn_type_with_byte_order_impl(&compatible_type, &unused,
						     byte_order);
		if (err)
			return err;
		struct drgn_enum_type_builder builder;
		drgn_enum_type_builder_init(&builder,
					    drgn_type_program(*type));
		size_t num_enumerators =
			drgn_type_num_enumerators(*type);
		if (num_enumerators) {
			if (!drgn_type_enumerator_vector_reserve(&builder.enumerators,
								 num_enumerators)) {
				drgn_enum_type_builder_deinit(&builder);
				return &drgn_enomem;
			}
			memcpy(&builder.enumerators.data,
			       drgn_type_enumerators(*type),
			       num_enumerators * sizeof(struct drgn_type_enumerator));
		}
		err = drgn_enum_type_create(&builder, drgn_type_tag(*type),
					    compatible_type,
					    drgn_type_language(*type), type);
		if (err) {
			drgn_enum_type_builder_deinit(&builder);
			return err;
		}
		*underlying_type = *type;
		return err;
	}
	default:
		return NULL;
	}
}

struct drgn_error *
drgn_type_with_byte_order(struct drgn_type **type,
			  struct drgn_type **underlying_type,
			  enum drgn_byte_order byte_order)
{
	struct drgn_error *err;
	bool type_little_endian;
	if (drgn_type_has_little_endian(*underlying_type)) {
		type_little_endian =
			drgn_type_little_endian(*underlying_type);
	} else if (drgn_type_kind(*underlying_type) == DRGN_TYPE_ENUM &&
		   drgn_type_is_complete(*underlying_type)) {
		type_little_endian =
			drgn_type_little_endian(drgn_type_type(*underlying_type).type);
	} else {
		return NULL;
	}
	bool little_endian;
	err = drgn_byte_order_to_little_endian(drgn_type_program(*underlying_type),
					       byte_order, &little_endian);
	if (err)
		return err;
	if (type_little_endian == little_endian)
		return NULL;
	return drgn_type_with_byte_order_impl(type, underlying_type,
					      drgn_byte_order_from_little_endian(little_endian));
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
	SWITCH_ENUM(kind,
	case DRGN_TYPE_INT:
	case DRGN_TYPE_BOOL:
	case DRGN_TYPE_FLOAT:
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
	)
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

enum drgn_object_encoding drgn_type_object_encoding(struct drgn_type *type)
{
	SWITCH_ENUM(drgn_type_kind(type),
	case DRGN_TYPE_INT:
		return (drgn_type_is_signed(type) ?
			DRGN_OBJECT_ENCODING_SIGNED :
			DRGN_OBJECT_ENCODING_UNSIGNED);
	case DRGN_TYPE_BOOL:
	case DRGN_TYPE_POINTER:
		return DRGN_OBJECT_ENCODING_UNSIGNED;
	case DRGN_TYPE_FLOAT:
		return DRGN_OBJECT_ENCODING_FLOAT;
	case DRGN_TYPE_STRUCT:
	case DRGN_TYPE_UNION:
	case DRGN_TYPE_CLASS:
	case DRGN_TYPE_ARRAY:
		return (drgn_type_is_complete(type) ?
			DRGN_OBJECT_ENCODING_BUFFER :
			DRGN_OBJECT_ENCODING_INCOMPLETE_BUFFER);
	case DRGN_TYPE_ENUM:
		if (!drgn_type_is_complete(type))
			return DRGN_OBJECT_ENCODING_INCOMPLETE_INTEGER;
		/* fallthrough */
	case DRGN_TYPE_TYPEDEF:
		return drgn_type_object_encoding(drgn_type_type(type).type);
	case DRGN_TYPE_VOID:
	case DRGN_TYPE_FUNCTION:
		return DRGN_OBJECT_ENCODING_NONE;
	)
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

void drgn_program_init_types(struct drgn_program *prog)
{
	for (size_t i = 0; i < array_size(prog->void_types); i++) {
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
				drgn_lazy_object_deinit(&members[j].object);
			free(members);
		}
		if (drgn_type_has_enumerators(type))
			free(drgn_type_enumerators(type));
		if (drgn_type_has_parameters(type)) {
			struct drgn_type_parameter *parameters =
				drgn_type_parameters(type);
			size_t num_parameters = drgn_type_num_parameters(type);
			for (size_t j = 0; j < num_parameters; j++)
				drgn_lazy_object_deinit(&parameters[j].default_argument);
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
	uint8_t address_size;
	err = drgn_program_address_size(prog, &address_size);
	if (err)
		return err;
	array_for_each(integer_type,
		       integer_types[type == DRGN_C_TYPE_PTRDIFF_T]) {
		struct drgn_qualified_type qualified_type;
		err = drgn_program_find_primitive_type(prog, *integer_type,
						       &qualified_type.type);
		if (err)
			return err;
		if (drgn_type_size(qualified_type.type) == address_size) {
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
					   DRGN_PROGRAM_ENDIAN,
					   &drgn_language_c, ret);
		break;
	case DRGN_C_TYPE_UNSIGNED_CHAR:
		err = drgn_int_type_create(prog, spellings[0], 1, false,
					   DRGN_PROGRAM_ENDIAN,
					   &drgn_language_c, ret);
		break;
	case DRGN_C_TYPE_SHORT:
		err = drgn_int_type_create(prog, spellings[0], 2, true,
					   DRGN_PROGRAM_ENDIAN,
					   &drgn_language_c, ret);
		break;
	case DRGN_C_TYPE_UNSIGNED_SHORT:
		err = drgn_int_type_create(prog, spellings[0], 2, false,
					   DRGN_PROGRAM_ENDIAN,
					   &drgn_language_c, ret);
		break;
	case DRGN_C_TYPE_INT:
		err = drgn_int_type_create(prog, spellings[0], 4, true,
					   DRGN_PROGRAM_ENDIAN,
					   &drgn_language_c, ret);
		break;
	case DRGN_C_TYPE_UNSIGNED_INT:
		err = drgn_int_type_create(prog, spellings[0], 4, false,
					   DRGN_PROGRAM_ENDIAN,
					   &drgn_language_c, ret);
		break;
	/* long and unsigned long default to the word size. */
	case DRGN_C_TYPE_LONG:
	case DRGN_C_TYPE_UNSIGNED_LONG: {
		uint8_t address_size;
		err = drgn_program_address_size(prog, &address_size);
		if (err)
			break;
		err = drgn_int_type_create(prog, spellings[0], address_size,
					   type == DRGN_C_TYPE_LONG,
					   DRGN_PROGRAM_ENDIAN,
					   &drgn_language_c, ret);
		break;
	}
	case DRGN_C_TYPE_LONG_LONG:
		err = drgn_int_type_create(prog, spellings[0], 8, true,
					   DRGN_PROGRAM_ENDIAN,
					   &drgn_language_c, ret);
		break;
	case DRGN_C_TYPE_UNSIGNED_LONG_LONG:
		err = drgn_int_type_create(prog, spellings[0], 8, false,
					   DRGN_PROGRAM_ENDIAN,
					   &drgn_language_c, ret);
		break;
	case DRGN_C_TYPE_BOOL:
		err = drgn_bool_type_create(prog, spellings[0], 1,
					    DRGN_PROGRAM_ENDIAN,
					    &drgn_language_c, ret);
		break;
	case DRGN_C_TYPE_FLOAT:
		err = drgn_float_type_create(prog, spellings[0], 4,
					     DRGN_PROGRAM_ENDIAN,
					     &drgn_language_c, ret);
		break;
	case DRGN_C_TYPE_DOUBLE:
		err = drgn_float_type_create(prog, spellings[0], 8,
					     DRGN_PROGRAM_ENDIAN,
					     &drgn_language_c, ret);
		break;
	case DRGN_C_TYPE_LONG_DOUBLE:
		err = drgn_float_type_create(prog, spellings[0], 16,
					     DRGN_PROGRAM_ENDIAN,
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
drgn_type_cache_members(struct drgn_type *outer_type,
			struct drgn_type *type, uint64_t bit_offset)
{
	struct drgn_program *prog = drgn_type_program(outer_type);

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
					.member = member,
					.bit_offset =
						bit_offset + member->bit_offset,
				},
			};
			if (drgn_member_map_insert(&prog->members, &entry,
						   NULL) == -1)
				return &drgn_enomem;
		} else {
			struct drgn_qualified_type member_type;
			struct drgn_error *err = drgn_member_type(member,
								  &member_type,
								  NULL);
			if (err)
				return err;
			err = drgn_type_cache_members(outer_type,
						      member_type.type,
						      bit_offset +
						      member->bit_offset);
			if (err)
				return err;
		}
	}
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_type_offsetof(struct drgn_type *type, const char *member_designator,
		   uint64_t *ret)
{

	struct drgn_error *err;
	const struct drgn_language *lang = drgn_type_language(type);
	uint64_t bit_offset;
	err = lang->bit_offset(drgn_type_program(type), type, member_designator,
			       &bit_offset);
	if (err)
		return err;
	if (bit_offset % 8) {
		return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
					 "member is not byte-aligned");
	}
	*ret = bit_offset / 8;
	return NULL;
}

static struct drgn_error *
drgn_type_find_member_impl(struct drgn_type *type, const char *member_name,
			   size_t member_name_len,
			   struct drgn_member_value **ret)
{
	struct drgn_program *prog = drgn_type_program(type);
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
					cached_hp).entry) {
		*ret = NULL;
		return NULL;
	}

	struct drgn_error *err = drgn_type_cache_members(key.type, key.type, 0);
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

	*ret = NULL;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_type_find_member_len(struct drgn_type *type, const char *member_name,
			  size_t member_name_len,
			  struct drgn_type_member **member_ret,
			  uint64_t *bit_offset_ret)
{
	struct drgn_error *err;
	struct drgn_member_value *member;
	err = drgn_type_find_member_impl(type, member_name, member_name_len,
					 &member);
	if (err)
		return err;
	if (!member) {
		struct drgn_qualified_type qualified_type = { type };
		char *type_name;
		err = drgn_format_type_name(qualified_type, &type_name);
		if (err)
			return err;
		err = drgn_error_format(DRGN_ERROR_LOOKUP,
					"'%s' has no member '%.*s'",
					type_name,
					member_name_len > INT_MAX ?
					INT_MAX : (int)member_name_len,
					member_name);
		free(type_name);
		return err;
	}
	*member_ret = member->member;
	*bit_offset_ret = member->bit_offset;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_type_has_member_len(struct drgn_type *type, const char *member_name,
			 size_t member_name_len, bool *ret)
{
	struct drgn_error *err;
	struct drgn_member_value *member;
	err = drgn_type_find_member_impl(type, member_name, member_name_len,
					 &member);
	if (err)
		return err;
	*ret = member != NULL;
	return NULL;
}
