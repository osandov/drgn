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

// Don't access this directly. Use the getter functions.
struct drgn_type {
	/** @privatesection */
	struct {
		enum drgn_type_kind kind;
		bool is_complete;
		enum drgn_primitive_type primitive;
		// These are the qualifiers for the wrapped type, not this type.
		enum drgn_qualifiers qualifiers;
		struct drgn_program *program;
		const struct drgn_language *language;
		// This mess of unions is used to make this as compact as
		// possible. Use the provided helpers and don't think about it.
		union {
			const char *name;
			const char *tag;
			size_t num_parameters;
		};
		union {
			uint64_t size;
			uint64_t length;
			size_t num_enumerators;
			bool is_variadic;
		};
		union {
			bool is_signed;
			size_t num_members;
			struct drgn_type *type;
		};
		union {
			bool little_endian;
			struct drgn_type_member *members;
			struct drgn_type_enumerator *enumerators;
			struct drgn_type_parameter *parameters;
		};
		struct drgn_type_template_parameter *template_parameters;
		size_t num_template_parameters;
	} _private;
};

DRGN_ACCESSOR_LINKAGE
enum drgn_type_kind drgn_type_kind(struct drgn_type *type)
{
	return type->_private.kind;
}

DRGN_ACCESSOR_LINKAGE
enum drgn_primitive_type drgn_type_primitive(struct drgn_type *type)
{
	return type->_private.primitive;
}

DRGN_ACCESSOR_LINKAGE
bool drgn_type_is_complete(struct drgn_type *type)
{
	return type->_private.is_complete;
}

DRGN_ACCESSOR_LINKAGE
struct drgn_program *drgn_type_program(struct drgn_type *type)
{
	return type->_private.program;
}

DRGN_ACCESSOR_LINKAGE
const struct drgn_language *drgn_type_language(struct drgn_type *type)
{
	return type->_private.language;
}

DRGN_ACCESSOR_LINKAGE
const char *drgn_type_name(struct drgn_type *type)
{
	assert(drgn_type_has_name(type));
	return type->_private.name;
}

DRGN_ACCESSOR_LINKAGE
uint64_t drgn_type_size(struct drgn_type *type)
{
	assert(drgn_type_has_size(type));
	return type->_private.size;
}

DRGN_ACCESSOR_LINKAGE
bool drgn_type_is_signed(struct drgn_type *type)
{
	assert(drgn_type_has_is_signed(type));
	return type->_private.is_signed;
}

DRGN_ACCESSOR_LINKAGE
bool drgn_type_little_endian(struct drgn_type *type)
{
	assert(drgn_type_has_little_endian(type));
	return type->_private.little_endian;
}

DRGN_ACCESSOR_LINKAGE
const char *drgn_type_tag(struct drgn_type *type)
{
	assert(drgn_type_has_tag(type));
	return type->_private.tag;
}

DRGN_ACCESSOR_LINKAGE
struct drgn_type_member *drgn_type_members(struct drgn_type *type)
{
	assert(drgn_type_has_members(type));
	return type->_private.members;
}

DRGN_ACCESSOR_LINKAGE
size_t drgn_type_num_members(struct drgn_type *type)
{
	assert(drgn_type_has_members(type));
	return type->_private.num_members;
}

DRGN_ACCESSOR_LINKAGE
struct drgn_qualified_type drgn_type_type(struct drgn_type *type)
{
	assert(drgn_type_has_type(type));
	return (struct drgn_qualified_type){
		.type = type->_private.type,
		.qualifiers = type->_private.qualifiers,
	};
}

DRGN_ACCESSOR_LINKAGE
struct drgn_type_enumerator *drgn_type_enumerators(struct drgn_type *type)
{
	assert(drgn_type_has_enumerators(type));
	return type->_private.enumerators;
}

DRGN_ACCESSOR_LINKAGE
size_t drgn_type_num_enumerators(struct drgn_type *type)
{
	assert(drgn_type_has_enumerators(type));
	return type->_private.num_enumerators;
}

DRGN_ACCESSOR_LINKAGE
uint64_t drgn_type_length(struct drgn_type *type)
{
	assert(drgn_type_has_length(type));
	return type->_private.length;
}

DRGN_ACCESSOR_LINKAGE
struct drgn_type_parameter *drgn_type_parameters(struct drgn_type *type)
{
	assert(drgn_type_has_parameters(type));
	return type->_private.parameters;
}

DRGN_ACCESSOR_LINKAGE
size_t drgn_type_num_parameters(struct drgn_type *type)
{
	assert(drgn_type_has_parameters(type));
	return type->_private.num_parameters;
}

DRGN_ACCESSOR_LINKAGE
bool drgn_type_is_variadic(struct drgn_type *type)
{
	assert(drgn_type_has_is_variadic(type));
	return type->_private.is_variadic;
}

DRGN_ACCESSOR_LINKAGE
struct drgn_type_template_parameter *
drgn_type_template_parameters(struct drgn_type *type)
{
	assert(drgn_type_has_template_parameters(type));
	return type->_private.template_parameters;
}

DRGN_ACCESSOR_LINKAGE
size_t drgn_type_num_template_parameters(struct drgn_type *type)
{
	assert(drgn_type_has_template_parameters(type));
	return type->_private.num_template_parameters;
}

#endif /* DRGN_INTERNAL_H */
