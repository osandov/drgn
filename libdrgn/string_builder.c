// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include "internal.h"
#include "string_builder.h"

struct drgn_error *string_builder_finalize(struct string_builder *sb,
					   char **ret)
{
	struct drgn_error *err;

	err = string_builder_reserve(sb, sb->len + 1);
	if (err)
		return err;
	sb->str[sb->len] = '\0';
	*ret = sb->str;
	return NULL;
}

struct drgn_error *string_builder_reserve(struct string_builder *sb,
					  size_t capacity)
{
	char *tmp;

	if (capacity <= sb->capacity)
		return NULL;

	capacity = next_power_of_two(capacity);
	tmp = realloc(sb->str, capacity);
	if (!tmp)
		return &drgn_enomem;
	sb->str = tmp;
	sb->capacity = capacity;
	return NULL;
}

struct drgn_error *string_builder_appendc(struct string_builder *sb, char c)
{
	struct drgn_error *err;

	err = string_builder_reserve(sb, sb->len + 1);
	if (err)
		return err;
	sb->str[sb->len++] = c;
	return NULL;
}

struct drgn_error *string_builder_appendn(struct string_builder *sb,
					  const char *str,
					  size_t len)
{
	struct drgn_error *err;

	err = string_builder_reserve(sb, sb->len + len);
	if (err)
		return err;
	memcpy(&sb->str[sb->len], str, len);
	sb->len += len;
	return NULL;
}

struct drgn_error *string_builder_vappendf(struct string_builder *sb,
					   const char *format,
					   va_list ap)
{
	struct drgn_error *err;
	va_list aq;
	int len;

again:
	va_copy(aq, ap);
	len = vsnprintf(&sb->str[sb->len], sb->capacity - sb->len, format, aq);
	va_end(aq);
	if (len < 0)
		return drgn_error_create_os(errno, NULL, "vsnprintf");
	if (sb->len + len < sb->capacity) {
		sb->len += len;
		return NULL;
	}

	/*
	 * vsnprintf() always null-terminates the string, so we have to allocate
	 * an extra character.
	 */
	err = string_builder_reserve(sb, sb->len + len + 1);
	if (err)
		return err;
	goto again;
}

struct drgn_error *string_builder_appendf(struct string_builder *sb,
					  const char *format, ...)
{
	struct drgn_error *err;
	va_list ap;

	va_start(ap, format);
	err = string_builder_vappendf(sb, format, ap);
	va_end(ap);
	return err;
}
