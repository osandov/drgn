// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file
 *
 * Error helpers.
 *
 * See @ref Errors.
 */

#ifndef DRGN_ERROR_H
#define DRGN_ERROR_H

#include "drgn.h"

/**
 * @ingroup Internals
 *
 * @defgroup Errors Errors
 *
 * Common errors.
 *
 * @{
 */

struct drgn_operand_type;

/** Global stop iteration error. */
extern struct drgn_error drgn_stop;

/** Global @ref DRGN_ERROR_OBJECT_ABSENT error. */
extern struct drgn_error drgn_error_object_absent;

struct string_builder;

/**
 * Create a @ref drgn_error with a message from a @ref string_builder.
 *
 * This finalizes the string builder.
 */
struct drgn_error *drgn_error_from_string_builder(enum drgn_error_code code,
						  struct string_builder *sb);

/**
 * Append a formatted @ref drgn_error to a @ref string_builder.
 *
 * @return @c true on success, @c false on error (if we couldn't allocate
 * memory).
 */
bool string_builder_append_error(struct string_builder *sb,
				 struct drgn_error *err);

/** Create a @ref drgn_error from the libelf error indicator. */
struct drgn_error *drgn_error_libelf(void)
	__attribute__((__returns_nonnull__));

/** Create a @ref drgn_error from the libdw error indicator. */
struct drgn_error *drgn_error_libdw(void)
	__attribute__((__returns_nonnull__));

/** Create a @ref drgn_error from the libdwfl error indicator. */
struct drgn_error *drgn_error_libdwfl(void)
	__attribute__((__returns_nonnull__));

/**
 * Create a @ref drgn_error with a type name.
 *
 * The error code will be @ref DRGN_ERROR_TYPE.
 *
 * @param[in] format Format string for the type error. Must contain %s, which
 * will be replaced with the type name, and no other conversion specifications.
 */
struct drgn_error *drgn_type_error(const char *format, struct drgn_type *type)
	__attribute__((__returns_nonnull__));

/**
 * Create a @ref drgn_error with a qualified type name.
 *
 * @sa drgn_type_error().
 */
struct drgn_error *
drgn_qualified_type_error(const char *format,
			  struct drgn_qualified_type qualified_type)
	__attribute__((__returns_nonnull__));

/**
 * Create a @ref drgn_error for an incomplete type.
 *
 * @sa drgn_type_error().
 */
struct drgn_error *drgn_error_incomplete_type(const char *format,
					      struct drgn_type *type);

/** Create a @ref drgn_error for invalid types to a binary operator. */
struct drgn_error *drgn_error_binary_op(const char *op_name,
					struct drgn_operand_type *type1,
					struct drgn_operand_type *type2)
	__attribute__((__returns_nonnull__));

/** Create a @ref drgn_error for an invalid type to a unary operator. */
struct drgn_error *drgn_error_unary_op(const char *op_name,
				       struct drgn_operand_type *type)
	__attribute__((__returns_nonnull__));

/** Create a @ref drgn_error for a failed symbol lookup. */
struct drgn_error *drgn_error_symbol_not_found(uint64_t address)
	__attribute__((__returns_nonnull__));

/** @} */

#endif /* DRGN_ERROR_H */
