// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "bitops.h"
#include "string_builder.h"
#include "util.h"

bool string_builder_null_terminate(struct string_builder *sb)
{
	if (!string_builder_reserve_for_append(sb, 1))
		return false;
	sb->str[sb->len] = '\0';
	return true;
}

bool string_builder_reserve(struct string_builder *sb, size_t capacity)
{
	if (capacity <= sb->capacity)
		return true;
	char *tmp = realloc(sb->str, capacity);
	if (!tmp)
		return false;
	sb->str = tmp;
	sb->capacity = capacity;
	return true;
}

bool string_builder_reserve_for_append(struct string_builder *sb, size_t n)
{
	if (n == 0)
		return true;
	size_t capacity;
	if (__builtin_add_overflow(sb->len, n, &capacity))
		return false;
	if (capacity < (SIZE_MAX / 2) + 1)
		capacity = next_power_of_two(capacity);
	return string_builder_reserve(sb, capacity);
}

bool string_builder_appendc(struct string_builder *sb, char c)
{
	if (!string_builder_reserve_for_append(sb, 1))
		return false;
	sb->str[sb->len++] = c;
	return true;
}

bool string_builder_appendn(struct string_builder *sb, const char *str,
			    size_t len)
{
	if (!string_builder_reserve_for_append(sb, len))
		return false;
	memcpy(&sb->str[sb->len], str, len);
	sb->len += len;
	return true;
}

bool string_builder_vappendf(struct string_builder *sb, const char *format,
			     va_list ap)
{
	va_list aq;
	int len;

again:
	va_copy(aq, ap);
	len = vsnprintf(add_to_possibly_null_pointer(sb->str, sb->len),
			sb->capacity - sb->len, format, aq);
	va_end(aq);
	if (len < 0)
		return false;
	if (sb->len + len < sb->capacity) {
		sb->len += len;
		return true;
	}

	/*
	 * vsnprintf() always null-terminates the string, so we have to allocate
	 * an extra character.
	 */
	if (!string_builder_reserve_for_append(sb, len + 1))
		return false;
	goto again;
}

bool string_builder_appendf(struct string_builder *sb, const char *format, ...)
{
	va_list ap;
	bool ret;

	va_start(ap, format);
	ret = string_builder_vappendf(sb, format, ap);
	va_end(ap);
	return ret;
}

bool string_builder_line_break(struct string_builder *sb)
{
	if (!sb->len || sb->str[sb->len - 1] == '\n')
		return true;
	return string_builder_appendc(sb, '\n');
}
