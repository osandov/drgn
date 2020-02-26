// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * Type internals.
 *
 * See @ref TypeInternals.
 */

#ifndef DRGN_TYPE_H
#define DRGN_TYPE_H

#include "drgn.h"
#include "language.h"

/**
 * @ingroup Internals
 *
 * @defgroup TypeInternals Types
 *
 * Type internals.
 *
 * This provides internal helpers for creating and accessing types.
 * Additionally, standard C types need special handling for C's various operator
 * conversion rules, so this provides helpers for working with standard C types.
 *
 * @{
 */

/**
 * @defgroup LazyTypes Lazy types
 *
 * Lazily-evaluated types.
 *
 * The graph of types in a program can be very deep (and often cyclical), so
 * drgn lazily evaluates the types of compound type members and function
 * parameters.
 *
 * @{
 */

/**
 * Thunk which evaluates to a @ref drgn_qualified_type.
 *
 * This is used for @ref drgn_lazy_type.
 *
 * Note that the thunk callbacks take no additional arguments. A "closure" can
 * be created by embedding this structure in a structure containing the
 * necessary arguments; the closure type can then be accessed through a macro
 * like @c container_of().
 */
struct drgn_type_thunk {
	/**
	 * Callback to evaluate this thunk to a @ref drgn_qualified_type.
	 *
	 * This should initialize the passed qualified type. If this succeeds,
	 * the thunk will then be freed with @ref drgn_type_thunk::free_fn().
	 * Otherwise, this may be called again.
	 */
	struct drgn_error *(*evaluate_fn)(struct drgn_type_thunk *,
					  struct drgn_qualified_type *);
	/**
	 * Callback to free this thunk.
	 *
	 * @ref drgn_type_thunk::evaluate_fn() may or may not have been called.
	 */
	void (*free_fn)(struct drgn_type_thunk *);
};

/**
 * Free a @ref drgn_type_thunk.
 *
 * @param[in] thunk Thunk to free.
 */
void drgn_type_thunk_free(struct drgn_type_thunk *thunk);

/**
 * Create a @ref drgn_lazy_type from a @ref drgn_type_thunk.
 *
 * @param[out] lazy_type Lazy type to initialize.
 * @param[in] thunk Thunk to wrap.
 */
static inline void drgn_lazy_type_init_thunk(struct drgn_lazy_type *lazy_type,
					     struct drgn_type_thunk *thunk)
{
	lazy_type->thunk = thunk;
	lazy_type->qualifiers = -1;
}

/**
 * Create a @ref drgn_lazy_type from a @ref drgn_type and qualifiers.
 *
 * @param[out] lazy_type Lazy type to initialize.
 * @param[in] type Type to wrap. May be @c NULL.
 * @param[in] qualifiers Type qualifiers. Must be 0 if type is @c NULL. Must not
 * be -1.
 */
static inline void
drgn_lazy_type_init_evaluated(struct drgn_lazy_type *lazy_type,
			      struct drgn_type *type,
			      enum drgn_qualifiers qualifiers)
{
	if (!type)
		assert(!qualifiers);
	assert(qualifiers != (enum drgn_qualifiers)-1);
	lazy_type->type = type;
	lazy_type->qualifiers = qualifiers;
}

/**
 * Get whether a @ref drgn_lazy_type has been evaluated.
 *
 * @param[in] lazy_type Lazy type to check.
 * @return Whether the lazy type is evaluated.
 */
static inline bool drgn_lazy_type_is_evaluated(struct drgn_lazy_type *lazy_type)
{
	return lazy_type->qualifiers != (enum drgn_qualifiers)-1;
}

/**
 * Evaluate a @ref drgn_lazy_type to a @ref drgn_qualified_type.
 *
 * If this succeeds, the lazy type is considered evaluated and future calls will
 * always succeed and return the cached result. If this fails, the lazy type
 * remains in a valid, unevaluated state.
 *
 * @param[in] lazy_type Lazy type to evaluate.
 * @param[out] qualified_type Evaluated type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_lazy_type_evaluate(struct drgn_lazy_type *lazy_type,
					   struct drgn_qualified_type *qualified_type);

/**
 * Free a @ref drgn_lazy_type.
 *
 * If the type has not been evaluted, this frees the @ref drgn_type_thunk.
 * Otherwise, this is a no-op.
 *
 * @param[in] lazy_type Lazy type to free.
 */
void drgn_lazy_type_deinit(struct drgn_lazy_type *lazy_type);

/** @} */

/**
 * @defgroup TypeCreation Type creation
 *
 * Creating type descriptors.
 *
 * libdrgn does not provide a way to allocate a @ref drgn_type. Instead, a type
 * can be allocated in any way deemed appropriate (e.g., with @c malloc(), on
 * the stack, embedded in another structure). These helpers initialize an
 * allocated type.
 *
 * Note that structure, union, enumerated, and function types end with a
 * variable-length array. The caller must allocate the necessary number of
 * elements.
 *
 * @{
 */

/**
 * Get the void type for the given @ref drgn_language.
 *
 * The void type does not have any fields, so there is a single type
 * descriptor per language to represent it.
 */
static inline struct drgn_type *
drgn_void_type(const struct drgn_language *lang)
{
	return (struct drgn_type *)&drgn_language_or_default(lang)->void_type;
}

/**
 * Initialize an integer type.
 *
 * @param[out] type Type to initialize.
 * @param[in] name Name of the type. This string is not copied. It must not be
 * @c NULL.
 * @param[in] size Size of the type in bytes.
 * @param[in] is_signed Whether the type is signed.
 * @param[in] lang Language of this type.
 */
void drgn_int_type_init(struct drgn_type *type, const char *name, uint64_t size,
			bool is_signed, const struct drgn_language *lang);

/**
 * Initialize a boolean type.
 *
 * @param[out] type Type to initialize.
 * @param[in] name Name of the type. This string is not copied. It must not be
 * @c NULL.
 * @param[in] size Size of the type in bytes.
 * @param[in] lang Language of this type.
 */
void drgn_bool_type_init(struct drgn_type *type, const char *name,
			 uint64_t size, const struct drgn_language *lang);

/**
 * Initialize a floating-point type.
 *
 * @param[out] type Type to initialize.
 * @param[in] name Name of the type. This string is not copied. It must not be
 * @c NULL.
 * @param[in] size Size of the type in bytes.
 * @param[in] lang Language of this type.
 */
void drgn_float_type_init(struct drgn_type *type, const char *name,
			  uint64_t size, const struct drgn_language *lang);

/**
 * Initialize a complex type.
 *
 * @param[out] type Type to initialize.
 * @param[in] name Name of the type. This string is not copied. It must not be
 * @c NULL.
 * @param[in] size Size of the type in bytes.
 * @param[in] real_type The corresponding real type. It must not be @c NULL and
 * must be a floating-point or integer type.
 * @param[in] lang Language of this type.
 */
void drgn_complex_type_init(struct drgn_type *type, const char *name,
			    uint64_t size, struct drgn_type *real_type,
			    const struct drgn_language *lang);

/**
 * Initialize a member of a type.
 *
 * @param[out] type Type containing member to initialize.
 * @param[in] i Index of member to initialize.
 * @param[in] member_type See @ref drgn_type_member::type.
 * @param[in] name See @ref drgn_type_member::name.
 * @param[in] bit_offset See @ref drgn_type_member::bit_offset.
 * @param[in] bit_field_size See @ref drgn_type_member::bit_field_size.
 */
static inline void drgn_type_member_init(struct drgn_type *type, size_t i,
					 struct drgn_lazy_type member_type,
					 const char *name, uint64_t bit_offset,
					 uint64_t bit_field_size)
{
	struct drgn_type_member *members = drgn_type_payload(type);

	members[i].type = member_type;
	members[i].name = name;
	members[i].bit_offset = bit_offset;
	members[i].bit_field_size = bit_field_size;
}

/**
 * Free a member of a type.
 *
 * This only frees @ref drgn_type_member::type.
 *
 * @param[out] type Type containing member to free.
 * @param[in] i Index of member to free.
 */
static inline void drgn_type_member_deinit(struct drgn_type *type, size_t i)
{
	struct drgn_type_member *members = drgn_type_payload(type);

	drgn_lazy_type_deinit(&members[i].type);
}

/**
 * Initialize a structure type.
 *
 * @param[out] type Type to initialize. This must have @c num_members @ref
 * drgn_type_member%s allocated after it. The members must be initialized with
 * @ref drgn_type_member_init() (either before or after this function is
 * called).
 * @param[in] tag Name of the type. This string is not copied. It may be @c NULL
 * if the type is anonymous.
 * @param[in] size Size of the type in bytes.
 * @param[in] num_members The number of members in the type.
 * @param[in] lang Language of this type.
 */
void drgn_struct_type_init(struct drgn_type *type, const char *tag,
			   uint64_t size, size_t num_members,
			   const struct drgn_language *lang);

/**
 * Initialize an incomplete structure type.
 *
 * @c size and @c num_members are set to zero and @c is_complete is set to @c
 * false.
 *
 * @param[out] type Type to initialize.
 * @param[in] tag Name of the type. This string is not copied. It may be @c NULL
 * if the type is anonymous.
 * @param[in] lang Language of this type.
 */
void drgn_struct_type_init_incomplete(struct drgn_type *type, const char *tag,
				      const struct drgn_language *lang);

/**
 * Initialize a union type.
 *
 * @sa drgn_struct_type_init().
 */
void drgn_union_type_init(struct drgn_type *type, const char *tag,
			  uint64_t size, size_t num_members,
			  const struct drgn_language *lang);

/**
 * Initialize an incomplete union type.
 *
 * @sa drgn_struct_type_init_incomplete().
 * @param[in] lang Language of this type.
 */
void drgn_union_type_init_incomplete(struct drgn_type *type, const char *tag,
				     const struct drgn_language *lang);

/**
 * Initialize a class type.
 * @param[out] type Type to initialize. This must have @c num_members @ref
 * drgn_type_memer%s allocated after it. Similar to struct type, the members
 * must be initialized with @ref drgn_type_member_init() (either before or after
 * this function is called).
 * @param[in] tag Name of the type.
 * @param[in] size Size of the type in bytes.
 * @param[in] num_members The number of members in the type.
 * @param[in] lang Language of this type.
 */
void drgn_class_type_init(struct drgn_type *type, const char *tag,
			  uint64_t size, size_t num_members,
			  const struct drgn_language *lang);

/**
 * Initialize an incomplete class type.
 *
 * @c size and @c num_members are set to zero and @c is_complete is set to @c
 * false.
 *
 * @param[out] type Type to initialize.
 * @param[int] tag Name of the type.
 * @param[in] lang Language of this type.
 */
void drgn_class_type_init_incomplete(struct drgn_type *type, const char *tag,
				     const struct drgn_language *lang);

/**
 * Initialize a signed enumerator of a type.
 *
 * @param[out] type Type containing enumerator to initialize.
 * @param[in] i Index of enumerator to initialize.
 * @param[in] name See @ref drgn_type_enumerator::name.
 * @param[in] svalue See @ref drgn_type_enumerator::svalue.
 */
static inline void drgn_type_enumerator_init_signed(struct drgn_type *type,
						    size_t i,
						    const char *name,
						    int64_t svalue)
{
	struct drgn_type_enumerator *enumerators = drgn_type_payload(type);

	enumerators[i].name = name;
	enumerators[i].svalue = svalue;
}

/**
 * Initialize an unsigned enumerator of a type.
 *
 * @param[out] type Type containing enumerator to initialize.
 * @param[in] i Index of enumerator to initialize.
 * @param[in] name See @ref drgn_type_enumerator::name.
 * @param[in] uvalue See @ref drgn_type_enumerator::uvalue.
 */
static inline void drgn_type_enumerator_init_unsigned(struct drgn_type *type,
						      size_t i,
						      const char *name,
						      uint64_t uvalue)
{
	struct drgn_type_enumerator *enumerators = drgn_type_payload(type);

	enumerators[i].name = name;
	enumerators[i].uvalue = uvalue;
}

/**
 * Initialize an enumerated type.
 *
 * @param[out] type Type to initialize. This must have @c num_enumerators @ref
 * drgn_type_enumerator%s allocated after it. The enumerators must be
 * initialized with @ref drgn_type_enumerator_init() (either before or after
 * this function is called).
 * @param[in] tag Name of the type. This string is not copied. It may be @c NULL
 * if the type is anonymous.
 * @param[in] compatible_type Type compatible with this enumerated type. It must
 * be an integer type.
 * @param[in] num_enumerators The number of enumerators in the type.
 * @param[in] lang Language of this type.
 */
void drgn_enum_type_init(struct drgn_type *type, const char *tag,
			 struct drgn_type *compatible_type,
			 size_t num_enumerators,
			 const struct drgn_language *lang);

/**
 * Initialize an incomplete enumerated type.
 *
 * @c compatible_type is set to @c NULL and @c num_enumerators is set to zero.
 *
 * @param[out] type Type to initialize.
 * @param[in] tag Name of the type. This string is not copied. It may be @c NULL
 * if the type is anonymous.
 * @param[in] lang Language of this type.
 */
void drgn_enum_type_init_incomplete(struct drgn_type *type, const char *tag,
				    const struct drgn_language *lang);

/**
 * Initialize a typedef type.
 *
 * @param[out] type Type to initialize.
 * @param[in] name Name of the type. This string is not copied. It must not be
 * @c NULL.
 * @param[in] aliased_type Type aliased by the typedef.
 * @param[in] lang Language of this type.
 */
void drgn_typedef_type_init(struct drgn_type *type, const char *name,
			    struct drgn_qualified_type aliased_type,
			    const struct drgn_language *lang);

/**
 * Initialize a pointer type.
 *
 * @param[out] type Type to initialize.
 * @param[in] size Size of the type in bytes.
 * @param[in] referenced_type Type referenced by the pointer type.
 * @param[in] lang Language of this type.
 */
void drgn_pointer_type_init(struct drgn_type *type, uint64_t size,
			    struct drgn_qualified_type referenced_type,
			    const struct drgn_language *lang);

/**
 * Initialize an array type.
 *
 * @param[out] type Type to initialize.
 * @param[in] length Number of elements in the array type.
 * @param[in] element_type Type of an element in the array type.
 * @param[in] lang Language of this type.
 */
void drgn_array_type_init(struct drgn_type *type, uint64_t length,
			  struct drgn_qualified_type element_type,
			  const struct drgn_language *lang);

/**
 * Initialize an incomplete array type.
 *
 * @c length is set to zero.
 *
 * @param[out] type Type to initialize.
 * @param[in] element_type Type of an element in the array type.
 * @param[in] lang Language of this type.
 */
void drgn_array_type_init_incomplete(struct drgn_type *type,
				     struct drgn_qualified_type element_type,
				     const struct drgn_language *lang);

/**
 * Initialize a parameter of a type.
 *
 * @param[out] type Type containing parameter to initialize.
 * @param[in] i Index of parameter to initialize.
 * @param[in] parameter_type See @ref drgn_type_parameter::type.
 * @param[in] name See @ref drgn_type_parameter::name.
 */
static inline void
drgn_type_parameter_init(struct drgn_type *type, size_t i,
			 struct drgn_lazy_type parameter_type, const char *name)
{
	struct drgn_type_parameter *parameters = drgn_type_payload(type);

	parameters[i].type = parameter_type;
	parameters[i].name = name;
}

/**
 * Free a parameter of a type.
 *
 * This only frees @ref drgn_type_parameter::type.
 *
 * @param[out] type Type containing parameter to free.
 * @param[in] i Index of parameter to free.
 */
static inline void drgn_type_parameter_deinit(struct drgn_type *type, size_t i)
{
	struct drgn_type_parameter *parameters = drgn_type_payload(type);

	drgn_lazy_type_deinit(&parameters[i].type);
}

/**
 * Initialize a function type.
 *
 * @param[out] type Type to initialize. This must have @c num_parameters @ref
 * drgn_type_parameter%s allocated after it. The parameters must be initialized
 * separately (either before or after this function is called).
 * @param[in] return_type Type returned by the function type.
 * @param[in] num_parameters The number of parameters accepted by the function
 * type.
 * @param[in] is_variadic Whether the function type is variadic.
 * @param[in] lang Language of this type.
 */
void drgn_function_type_init(struct drgn_type *type,
			     struct drgn_qualified_type return_type,
			     size_t num_parameters, bool is_variadic,
			     const struct drgn_language *lang);

/** @} */

/** Mapping from @ref drgn_type_kind to the spelling of that kind. */
extern const char * const drgn_type_kind_spelling[];

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
extern const char * const * const
drgn_primitive_type_spellings[DRGN_PRIMITIVE_TYPE_NUM];

/**
 * Mapping from a @ref drgn_type_primitive to the corresponding @ref
 * drgn_type_kind.
 */
extern const enum drgn_type_kind
drgn_primitive_type_kind[DRGN_PRIMITIVE_TYPE_NUM + 1];

/**
 * Parse the name of an unqualified primitive C type.
 *
 * @return The type, or @ref DRGN_NOT_PRIMITIVE_TYPE if @p s is not the name of
 * a primitive C type.
 */
enum drgn_primitive_type c_parse_specifier_list(const char *s);

/**
 * Get the type of a @ref drgn_type with all typedefs removed.
 *
 * I.e., the underlying type is the aliased type of the type if it is a typedef,
 * recursively.
 */
static inline struct drgn_type *drgn_underlying_type(struct drgn_type *type)
{
	struct drgn_type *underlying_type;

	underlying_type = type;
	while (drgn_type_kind(underlying_type) == DRGN_TYPE_TYPEDEF)
		underlying_type = drgn_type_type(underlying_type).type;
	return underlying_type;
}

/**
 * Get whether an enumerated type is signed.
 *
 * This is true if and only if the compatible integer type is signed.
 *
 * @param[in] type Enumerated type. It must be complete.
 */
static inline bool drgn_enum_type_is_signed(struct drgn_type *type)
{
	assert(type->_private.type);
	return drgn_type_is_signed(type->_private.type);
}

/**
 * Get whether a type is anonymous (i.e., the type has no name).
 *
 * This may be @c false for structure, union, class, and enum types. Otherwise,
 * it is always true.
 */
static inline bool drgn_type_is_anonymous(struct drgn_type *type)
{
	switch (drgn_type_kind(type)) {
	case DRGN_TYPE_STRUCT:
	case DRGN_TYPE_UNION:
	case DRGN_TYPE_CLASS:
	case DRGN_TYPE_ENUM:
		return !drgn_type_tag(type);
	default:
		return false;
	}
}

/**
 * Returned whether a @ref drgn_type is an integer type.
 *
 * This is true for integer, boolean, and enumerated types, as well typedefs
 * with an underlying type of one of those.
 */
bool drgn_type_is_integer(struct drgn_type *type);

/**
 * Return whether a @ref drgn_type is an arithmetic type.
 *
 * This is true for integer types (see @ref drgn_type_is_integer()) as well as
 * floating-point types and equivalent typedefs.
 */
bool drgn_type_is_arithmetic(struct drgn_type *type);

/**
 * Return whether a @ref drgn_type is a scalar type.
 *
 * This is true for arithmetic types (see @ref drgn_type_is_arithmetic()) as
 * well as pointer types and equivalent typedefs.
 */
bool drgn_type_is_scalar(struct drgn_type *type);

/**
 * Get the size of a type in bits.
 *
 * This is the same as multplying the result of @ref drgn_type_sizeof() by 8
 * except that it handles overflow.
 */
struct drgn_error *drgn_type_bit_size(struct drgn_type *type,
				      uint64_t *ret);

/** Get the appropriate @ref drgn_object_kind for a @ref drgn_type. */
enum drgn_object_kind drgn_type_object_kind(struct drgn_type *type);

/** @} */

#endif /* DRGN_TYPE_H */
