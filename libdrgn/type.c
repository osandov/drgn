#include <string.h>

#include "internal.h"
#include "hash_table.h"
#include "language.h"
#include "type.h"
#include "type_index.h"

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

const char * const * const
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

const enum drgn_type_kind
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
			   uint64_t size, size_t num_members,
			   const struct drgn_language *lang)
{
	type->_private.kind = DRGN_TYPE_STRUCT;
	type->_private.is_complete = true;
	type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
	type->_private.tag = tag;
	type->_private.size = size;
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
	type->_private.num_members = 0;
	type->_private.language = drgn_language_or_default(lang);
}

void drgn_union_type_init(struct drgn_type *type, const char *tag,
			  uint64_t size, size_t num_members,
			  const struct drgn_language *lang)
{
	type->_private.kind = DRGN_TYPE_UNION;
	type->_private.is_complete = true;
	type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
	type->_private.tag = tag;
	type->_private.size = size;
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
	type->_private.num_members = 0;
	type->_private.language = drgn_language_or_default(lang);
}

void drgn_class_type_init(struct drgn_type *type, const char *tag,
			  uint64_t size, size_t num_members,
			  const struct drgn_language *lang)
{
	type->_private.kind = DRGN_TYPE_CLASS;
	type->_private.is_complete = true;
	type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
	type->_private.tag = tag;
	type->_private.size = size;
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
	type->_private.num_members = 0;
	type->_private.language = drgn_language_or_default(lang);
}

void drgn_enum_type_init(struct drgn_type *type, const char *tag,
			 struct drgn_type *compatible_type,
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
			     size_t num_parameters, bool is_variadic,
			     const struct drgn_language *lang)
{
	type->_private.kind = DRGN_TYPE_FUNCTION;
	type->_private.is_complete = true;
	type->_private.primitive = DRGN_NOT_PRIMITIVE_TYPE;
	type->_private.type = return_type.type;
	type->_private.qualifiers = return_type.qualifiers;
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
	struct drgn_error *err;
	struct drgn_type_pair_set cache;
	int depth = 0;

	drgn_type_pair_set_init(&cache);
	err = drgn_type_eq_impl(a, b, &cache, &depth, ret);
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
	DRGN_UNREACHABLE();
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
	DRGN_UNREACHABLE();
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
		DRGN_UNREACHABLE();
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
