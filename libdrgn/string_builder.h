// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file
 *
 * String builder interface.
 *
 * See @ref StringBuilding.
 */

#ifndef DRGN_STRING_BUILDER_H
#define DRGN_STRING_BUILDER_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/**
 * @ingroup Internals
 *
 * @defgroup StringBuilding String building
 *
 * String builder interface.
 *
 * @ref string_builder provides an append-only way to build a string piece by
 * piece. @ref string_callback provides an alternative to prepending pieces.
 *
 * @{
 */

/**
 * String builder.
 *
 * A string builder consists of a buffer and a length. The buffer is resized as
 * needed. The buffer can only be appended to; see @ref string_callback for an
 * alternative to insertion.
 */
struct string_builder {
	/**
	 * Current string buffer.
	 *
	 * This may be reallocated when appending. It must be freed with @c
	 * free() when it will no longer be used. It should be initialized to @c
	 * NULL.
	 */
	char *str;
	/**
	 * Length of @c str.
	 *
	 * It should be initialized to zero.
	 */
	size_t len;
	/**
	 * Allocated size of @c str.
	 *
	 * It should be initialized to zero.
	 */
	size_t capacity;
};

/**
 * Null-terminate and return a string from a @ref string_builder.
 *
 * On success, the string builder must be reinitialized before being reused.
 *
 * @param[out] ret Returned string.
 * @return @c true on success, @c false on error (if we couldn't allocate
 * memory).
 */
bool string_builder_finalize(struct string_builder *sb, char **ret);

/**
 * Resize the buffer of a @ref string_builder.
 *
 * On success, the allocated size of the string buffer is at least @p capacity.
 *
 * @param[in] sb String builder.
 * @param[in] capacity New minimum size of the string buffer.
 * @return @c true on success, @c false on error (if we couldn't allocate
 * memory).
 */
bool string_builder_reserve(struct string_builder *sb, size_t capacity);

/**
 * Append a character to a @ref string_builder.
 *
 * @param[in] sb String builder.
 * @param[in] c Character to append.
 * @return @c true on success, @c false on error (if we couldn't allocate
 * memory).
 */
bool string_builder_appendc(struct string_builder *sb, char c);

/**
 * Append a number of characters from a string to a @ref string_builder.
 *
 * @param[in] sb String builder.
 * @param[in] str String to append.
 * @param[in] len Number of characters from @c str to append.
 * @return @c true on success, @c false on error (if we couldn't allocate
 * memory).
 */
bool string_builder_appendn(struct string_builder *sb, const char *str,
			    size_t len);

/**
 * Append a null-terminated string to a @ref string_builder.
 *
 * @param[in] sb String builder.
 * @param[in] str String to append.
 * @return @c true on success, @c false on error (if we couldn't allocate
 * memory).
 */
static inline bool string_builder_append(struct string_builder *sb,
					 const char *str)
{
	return string_builder_appendn(sb, str, strlen(str));
}

/**
 * Append a string to a @ref string_builder from a printf-style format.
 *
 * @param[in] sb String builder.
 * @param[in] format printf-style format string.
 * @param[in] ... Arguments for the format string.
 * @return @c true on success, @c false on error (if we couldn't allocate
 * memory).
 */
bool string_builder_appendf(struct string_builder *sb, const char *format, ...)
	__attribute__((__format__(__printf__, 2, 3)));

/**
 * Append a string to a @ref string_builder from vprintf-style arguments.
 *
 * @sa string_builder_appendf()
 *
 * @param[in] sb String builder.
 * @param[in] format printf-style format string.
 * @param[in] ap Arguments for the format string.
 * @return @c true on success, @c false on error (if we couldn't allocate
 * memory).
 */
bool string_builder_vappendf(struct string_builder *sb, const char *format,
			     va_list ap);

/**
 * Append a newline character to a @ref string_builder if the string isn't empty
 * and doesn't already end in a newline.
 *
 * @param[in] sb String builder.
 * @return @c true on success, @c false on error (if we couldn't allocate
 * memory).
 */
bool string_builder_line_break(struct string_builder *sb);

/**
 * Callback to append to a string later.
 *
 * Instead of providing functionality to prepend to a @ref string_builder, we
 * achieve the same thing by passing around a callback until all prefixes have
 * been appended, then calling the callback to append the "infix". This avoids
 * the O(n) array shift required for prepend.
 */
struct string_callback {
	/** Callback function. */
	struct drgn_error *(*fn)(struct string_callback *str, void *arg,
				 struct string_builder *sb);
	/**
	 * Another string callback to be passed to the callback.
	 *
	 * This is useful for strings that need to be built recursively.
	 */
	struct string_callback *str;
	/** Callback argument. */
	void *arg;
};

/**
 * Call a string callback.
 *
 * The callback function will be passed @ref string_callback::str and @ref
 * string_callback::arg.
 *
 * @param[in] str String callback. If @c NULL, this is a no-op.
 * @param[in] sb String builder to append to.
 * @return @c true on success, @c false on error (if we couldn't allocate
 * memory).
 */
static inline struct drgn_error *string_callback_call(struct string_callback *str,
						      struct string_builder *sb)
{
	if (str)
		return str->fn(str->str, str->arg, sb);
	else
		return NULL;
}

/** @} */

#endif /* DRGN_STRING_BUILDER_H */
