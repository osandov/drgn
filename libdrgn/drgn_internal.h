// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * Wrapper around drgn.h with internal-only definitions.
 */

#ifndef DRGN_INTERNAL_H
#define DRGN_INTERNAL_H

#include <assert.h>

// Used for functions that are inline inside of libdrgn and also have an
// external definition.
#ifndef DRGN_ACCESSOR_LINKAGE
#define DRGN_ACCESSOR_LINKAGE static inline
#endif

#include "drgn.h" // IWYU pragma: export

enum drgn_type_flags {
	DRGN_TYPE_FLAG_IS_COMPLETE = 1 << 0,
	DRGN_TYPE_FLAG_IS_SIGNED = 1 << 1,
	DRGN_TYPE_FLAG_LITTLE_ENDIAN = 1 << 2,
	DRGN_TYPE_FLAG_IS_VARIADIC = 1 << 3,
};

// Common part of all types. In order to keep it as compact as possible, it uses
// a few unions and can be embedded in one of the structs below for types that
// need more.
//
// Don't access this directly. Use the getter functions.
struct drgn_type {
	/** @privatesection */
	enum drgn_type_kind _kind;
	enum drgn_primitive_type _primitive;
	// These are the qualifiers for the wrapped type, not this type.
	enum drgn_qualifiers _qualifiers;
	enum drgn_type_flags _flags;
	struct drgn_program *_program;
	const struct drgn_language *_language;
	union {
		const char *_name;
		const char *_tag;
		struct drgn_type_parameter *_parameters;
	};
	union {
		uint64_t _size;
		uint64_t _length;
		struct drgn_type_enumerator *_enumerators;
		size_t _num_parameters;
	};
	union {
		struct drgn_type *_type;
		struct drgn_type_member *_members;
	};
};

struct drgn_extended_type {
	struct drgn_type type;
	// This is a layer violation; it'd be cleaner to have an opaque context
	// and callback table that could be passed when constructing a type. But
	// for now, we're only supporting this for DWARF.
	uintptr_t _die_addr;
};

struct drgn_templated_type {
	struct drgn_extended_type extended;
	struct drgn_type_template_parameter *_template_parameters;
	size_t _num_template_parameters;
};

struct drgn_compound_type {
	struct drgn_templated_type templated;
	size_t _num_members;
};

struct drgn_enum_type {
	struct drgn_extended_type extended;
	size_t _num_enumerators;
};

DRGN_ACCESSOR_LINKAGE
enum drgn_type_kind drgn_type_kind(struct drgn_type *type)
{
	return type->_kind;
}

DRGN_ACCESSOR_LINKAGE
enum drgn_primitive_type drgn_type_primitive(struct drgn_type *type)
{
	return type->_primitive;
}

DRGN_ACCESSOR_LINKAGE
bool drgn_type_is_complete(struct drgn_type *type)
{
	return type->_flags & DRGN_TYPE_FLAG_IS_COMPLETE;
}

DRGN_ACCESSOR_LINKAGE
struct drgn_program *drgn_type_program(struct drgn_type *type)
{
	return type->_program;
}

DRGN_ACCESSOR_LINKAGE
const struct drgn_language *drgn_type_language(struct drgn_type *type)
{
	return type->_language;
}

DRGN_ACCESSOR_LINKAGE
const char *drgn_type_name(struct drgn_type *type)
{
	assert(drgn_type_has_name(type));
	return type->_name;
}

DRGN_ACCESSOR_LINKAGE
uint64_t drgn_type_size(struct drgn_type *type)
{
	assert(drgn_type_has_size(type));
	return type->_size;
}

DRGN_ACCESSOR_LINKAGE
bool drgn_type_is_signed(struct drgn_type *type)
{
	assert(drgn_type_has_is_signed(type));
	return type->_flags & DRGN_TYPE_FLAG_IS_SIGNED;
}

DRGN_ACCESSOR_LINKAGE
bool drgn_type_little_endian(struct drgn_type *type)
{
	assert(drgn_type_has_little_endian(type));
	return type->_flags & DRGN_TYPE_FLAG_LITTLE_ENDIAN;
}

DRGN_ACCESSOR_LINKAGE
const char *drgn_type_tag(struct drgn_type *type)
{
	assert(drgn_type_has_tag(type));
	return type->_tag;
}

DRGN_ACCESSOR_LINKAGE
struct drgn_type_member *drgn_type_members(struct drgn_type *type)
{
	assert(drgn_type_has_members(type));
	return type->_members;
}

DRGN_ACCESSOR_LINKAGE
size_t drgn_type_num_members(struct drgn_type *type)
{
	assert(drgn_type_has_members(type));
	return ((struct drgn_compound_type *)type)->_num_members;
}

DRGN_ACCESSOR_LINKAGE
struct drgn_qualified_type drgn_type_type(struct drgn_type *type)
{
	assert(drgn_type_has_type(type));
	return (struct drgn_qualified_type){
		.type = type->_type,
		.qualifiers = type->_qualifiers,
	};
}

DRGN_ACCESSOR_LINKAGE
struct drgn_type_enumerator *drgn_type_enumerators(struct drgn_type *type)
{
	assert(drgn_type_has_enumerators(type));
	return type->_enumerators;
}

DRGN_ACCESSOR_LINKAGE
size_t drgn_type_num_enumerators(struct drgn_type *type)
{
	assert(drgn_type_has_enumerators(type));
	return ((struct drgn_enum_type *)type)->_num_enumerators;
}

DRGN_ACCESSOR_LINKAGE
uint64_t drgn_type_length(struct drgn_type *type)
{
	assert(drgn_type_has_length(type));
	return type->_length;
}

DRGN_ACCESSOR_LINKAGE
struct drgn_type_parameter *drgn_type_parameters(struct drgn_type *type)
{
	assert(drgn_type_has_parameters(type));
	return type->_parameters;
}

DRGN_ACCESSOR_LINKAGE
size_t drgn_type_num_parameters(struct drgn_type *type)
{
	assert(drgn_type_has_parameters(type));
	return type->_num_parameters;
}

DRGN_ACCESSOR_LINKAGE
bool drgn_type_is_variadic(struct drgn_type *type)
{
	assert(drgn_type_has_is_variadic(type));
	return type->_flags & DRGN_TYPE_FLAG_IS_VARIADIC;
}

DRGN_ACCESSOR_LINKAGE
struct drgn_type_template_parameter *
drgn_type_template_parameters(struct drgn_type *type)
{
	assert(drgn_type_has_template_parameters(type));
	return ((struct drgn_templated_type *)type)->_template_parameters;
}

DRGN_ACCESSOR_LINKAGE
size_t drgn_type_num_template_parameters(struct drgn_type *type)
{
	assert(drgn_type_has_template_parameters(type));
	return ((struct drgn_templated_type *)type)->_num_template_parameters;
}

static inline bool drgn_type_kind_has_die_addr(enum drgn_type_kind kind)
{
	return (kind == DRGN_TYPE_STRUCT ||
		kind == DRGN_TYPE_UNION ||
		kind == DRGN_TYPE_CLASS ||
		kind == DRGN_TYPE_ENUM ||
		kind == DRGN_TYPE_FUNCTION);
}

static inline bool drgn_type_has_die_addr(struct drgn_type *type)
{
	return drgn_type_kind_has_die_addr(drgn_type_kind(type));
}

static inline uintptr_t drgn_type_die_addr(struct drgn_type *type)
{
	assert(drgn_type_has_die_addr(type));
	return ((struct drgn_extended_type *)type)->_die_addr;
}

static inline void drgn_type_init_die_addr(struct drgn_type *type,
					   uintptr_t die_addr)
{
	assert(drgn_type_has_die_addr(type));
	((struct drgn_extended_type *)type)->_die_addr = die_addr;
}

#endif /* DRGN_INTERNAL_H */
