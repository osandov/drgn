// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

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
	 * This may be reallocated when appending.
	 */
	char *str;
	/** Length of @c str. */
	size_t len;
	/** Allocated size of @c str. */
	size_t capacity;
};

/** String builder initializer. */
#define STRING_BUILDER_INIT { 0 }

/** Free memory allocated by a @ref string_builder. */
static inline void string_builder_deinit(struct string_builder *sb)
{
	free(sb->str);
}

/**
 * Define and initialize a @ref string_builder named @p sb that is automatically
 * deinitialized when it goes out of scope.
 */
#define STRING_BUILDER(sb)					\
	__attribute__((__cleanup__(string_builder_deinit)))	\
	struct string_builder sb = STRING_BUILDER_INIT

/**
 * Steal the string buffer from a @ref string_builder.
 *
 * The string builder can no longer be used except to be passed to @ref
 * string_builder_deinit(), which will do nothing.
 *
 * @return String buffer. This must be freed with @c free().
 */
static inline char *string_builder_steal(struct string_builder *sb)
{
	char *str = sb->str;
	sb->str = NULL;
	return str;
}

/**
 * Null-terminate a @ref string_builder.
 *
 * This appends a null character without incrementing @ref string_builder::len.
 *
 * @return @c true on success, @c false on error (if we couldn't allocate
 * memory).
 */
bool string_builder_null_terminate(struct string_builder *sb);

/**
 * Resize the buffer of a @ref string_builder to a given capacity.
 *
 * On success, the allocated size of the string buffer is at least @p capacity.
 *
 * @param[in] sb String builder.
 * @param[in] capacity New minimum allocated size of the string buffer.
 * @return @c true on success, @c false on error (if we couldn't allocate
 * memory).
 */
bool string_builder_reserve(struct string_builder *sb, size_t capacity);

/**
 * Resize the buffer of a @ref string_builder to accomodate appending
 * characters.
 *
 * On success, the allocated size of the string buffer is at least
 * `sb->len + n`. This will also allocate extra space so that appends have
 * amortized constant time complexity.
 *
 * @param[in] sb String builder.
 * @param[in] n Minimum number of additional characters to reserve.
 * @return @c true on success, @c false on error (if we couldn't allocate
 * memory).
 */
bool string_builder_reserve_for_append(struct string_builder *sb, size_t n);

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
