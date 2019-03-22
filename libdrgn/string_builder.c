// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include "internal.h"
#include "string_builder.h"

struct drgn_error *string_builder_init(struct string_builder *sb)
{
	sb->len = 0;
	sb->capacity = 16;
	sb->str = malloc(sb->capacity);
	if (!sb->str)
		return &drgn_enomem;
	sb->str[0] = '\0';
	return NULL;
}

struct drgn_error *string_builder_reserve(struct string_builder *sb,
					  size_t capacity)
{
	size_t new_capacity = sb->capacity;
	char *tmp;

	if (capacity < new_capacity)
		return NULL;

	while (capacity >= new_capacity)
		new_capacity *= 2;
	tmp = realloc(sb->str, new_capacity);
	if (!tmp)
		return &drgn_enomem;
	sb->str = tmp;
	sb->capacity = new_capacity;
	return NULL;
}

struct drgn_error *string_builder_appendc(struct string_builder *sb, char c)
{
	struct drgn_error *err;

	err = string_builder_reserve(sb, sb->len + 1);
	if (err)
		return err;
	sb->str[sb->len++] = c;
	sb->str[sb->len] = '\0';
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
	sb->str[sb->len] = '\0';
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
		sb->str[sb->len] = '\0';
		return NULL;
	}

	err = string_builder_reserve(sb, sb->len + len);
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
