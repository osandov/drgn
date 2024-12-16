// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * Error helpers.
 *
 * See @ref Errors.
 */

#ifndef DRGN_ERROR_H
#define DRGN_ERROR_H

#include "drgn_internal.h"
#include "pp.h"

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
 * This deinitializes the string builder.
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
 * Create a @ref drgn_error with two qualified type names.
 *
 * @param[in] format Format string for the type error. Must contain two `%s`,
 * which will be replaced with the two type names, and no other conversion
 * specifications.
 */
struct drgn_error *
drgn_2_qualified_types_error(const char *format,
			     struct drgn_qualified_type qualified_type1,
			     struct drgn_qualified_type qualified_type2)
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

/**
 * Scope guard that counts recursive calls and returns with a @ref
 * DRGN_ERROR_RECURSION error if the recursion depth exceeds a limit.
 *
 * ```
 * struct drgn_error *my_recursive_function(int n)
 * {
 *         drgn_recursion_guard(1000, "maximum recursion depth exceeded");
 *         if (n <= 0)
 *                 return NULL;
 *         return my_recursive_function(n - 1);
 * }
 * ```
 *
 * @param[in] limit Maximum recursion depth. For example, 0 means that the
 * function may be called but may not make any recursive calls.
 * @param[in] message Error message if limit is exceeded.
 */
#define drgn_recursion_guard(limit, message)	\
	drgn_recursion_guard_impl(limit, message, PP_UNIQUE(recursion_count))

static inline void drgn_recursion_guard_cleanup(int **guard)
{
	(**guard)--;
}

#define drgn_recursion_guard_impl(limit, message, unique_recursion_count)	\
	static _Thread_local int unique_recursion_count = 0;			\
	if (unique_recursion_count > (limit))					\
		return drgn_error_create(DRGN_ERROR_RECURSION, (message));	\
	unique_recursion_count++;						\
	__attribute__((__cleanup__(drgn_recursion_guard_cleanup), __unused__))	\
	int *PP_UNIQUE(recursion_count_ptr) = &unique_recursion_count

/**
 * Catch a certain kind of @ref drgn_error and free it
 *
 * If @a errp points to a non-@c NULL error whose code matches @a code, then the
 * free the error (if necessary), replace the pointer value with @c NULL, and
 * return @c true. Otherwise, return @c false, and @a err is not modified.
 */
static inline bool drgn_error_catch(struct drgn_error **errp,
				    enum drgn_error_code code)
{
	if (*errp && (*errp)->code == code) {
		drgn_error_destroy(*errp);
		*errp = NULL;
		return true;
	}
	return false;
}

/** @} */

#endif /* DRGN_ERROR_H */
