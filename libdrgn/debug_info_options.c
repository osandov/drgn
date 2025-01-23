// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <stdlib.h>

#include "cleanup.h"
#include "debug_info_options.h"
#include "string_builder.h"
#include "util.h"

static const char * const drgn_debug_info_options_default_directories[] = {
	"", ".debug", "/usr/lib/debug", NULL
};

void drgn_debug_info_options_init(struct drgn_debug_info_options *options)
{
#define LIST_OPTION(name)	\
	options->name = drgn_debug_info_options_default_##name;
#define BOOL_OPTION(name, default_value) options->name = default_value;
#define ENUM_OPTION(name, type, default_value) options->name = default_value;
	DRGN_DEBUG_INFO_OPTIONS
#undef ENUM_OPTION
#undef BOOL_OPTION
#undef LIST_OPTION
}

static void drgn_debug_info_options_list_destroy(const char * const *list,
						 const char * const *default_list)
{
	if (list && list != default_list) {
		for (size_t i = 0; list[i]; i++)
			free((void *)list[i]);
		free((void *)list);
	}
}

static void drgn_debug_info_options_listp_destroy(const char * const **listp)
{
	drgn_debug_info_options_list_destroy((const char * const *)*listp,
					     NULL);
}

void drgn_debug_info_options_deinit(struct drgn_debug_info_options *options)
{
#define LIST_OPTION(name)					\
	drgn_debug_info_options_list_destroy(options->name,	\
					     drgn_debug_info_options_default_##name);
#define BOOL_OPTION(name, default_value)
#define ENUM_OPTION(name, type, default_value)
	DRGN_DEBUG_INFO_OPTIONS
#undef ENUM_OPTION
#undef BOOL_OPTION
#undef LIST_OPTION
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_debug_info_options_create(struct drgn_debug_info_options **ret)
{
	struct drgn_debug_info_options *options = malloc(sizeof(*options));
	if (!options)
		return &drgn_enomem;
	drgn_debug_info_options_init(options);
	*ret = options;
	return NULL;
}

LIBDRGN_PUBLIC void
drgn_debug_info_options_destroy(struct drgn_debug_info_options *options)
{
	if (options) {
		drgn_debug_info_options_deinit(options);
		free(options);
	}
}

static const char * const *
drgn_debug_info_options_list_dup(const char * const *list)
{
	size_t n = 0;
	while (list[n])
		n++;
	char **copy = malloc_array(n + 1, sizeof(copy[0]));
	if (!copy)
		return NULL;
	for (size_t i = 0; i < n; i++) {
		copy[i] = strdup(list[i]);
		if (!copy[i]) {
			for (size_t j = 0; j < i; j++)
				free(copy[j]);
			free(copy);
			return NULL;
		}
	}
	copy[n] = NULL;
	return (const char * const *)copy;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_debug_info_options_copy(struct drgn_debug_info_options *dst,
			     const struct drgn_debug_info_options *src)
{
	if (dst == src)
		return NULL;

	// Since copying any list could fail, make all of the copies first.
	// Replace the default lists with NULL for now to avoid unnecessary
	// copies and simplify cleanup.
#define LIST_OPTION(name)							\
	_cleanup_(drgn_debug_info_options_listp_destroy)			\
	const char * const *name##_copy = NULL;					\
	if (src->name != drgn_debug_info_options_default_##name) {		\
		name##_copy = drgn_debug_info_options_list_dup(src->name);	\
		if (!name##_copy)						\
			return &drgn_enomem;					\
	}
#define BOOL_OPTION(name, default_value)
#define ENUM_OPTION(name, type, default_value)
	DRGN_DEBUG_INFO_OPTIONS
#undef ENUM_OPTION
#undef BOOL_OPTION
#undef LIST_OPTION

	// Now we can set everything.
#define LIST_OPTION(name)							\
	drgn_debug_info_options_list_destroy(dst->name,				\
					     drgn_debug_info_options_default_##name);\
	if (name##_copy)							\
		dst->name = no_cleanup_ptr(name##_copy);			\
	else									\
		dst->name = drgn_debug_info_options_default_##name;
#define BOOL_OPTION(name, default_value) dst->name = src->name;
#define ENUM_OPTION(name, type, default_value) dst->name = src->name;
	DRGN_DEBUG_INFO_OPTIONS
#undef ENUM_OPTION
#undef BOOL_OPTION
#undef LIST_OPTION
	return NULL;
}

#define DRGN_DEBUG_INFO_OPTIONS_GET(type, name)					\
LIBDRGN_PUBLIC type								\
drgn_debug_info_options_get_##name(const struct drgn_debug_info_options *options)\
{										\
	return options->name;							\
}

#define DRGN_DEBUG_INFO_OPTIONS_GETSET(type, name)				\
DRGN_DEBUG_INFO_OPTIONS_GET(type, name)						\
										\
LIBDRGN_PUBLIC void								\
drgn_debug_info_options_set_##name(struct drgn_debug_info_options *options,	\
				   type value)					\
{										\
	options->name = value;							\
}

#define LIST_OPTION(name)							\
DRGN_DEBUG_INFO_OPTIONS_GET(const char * const *, name)				\
										\
LIBDRGN_PUBLIC struct drgn_error *						\
drgn_debug_info_options_set_##name(struct drgn_debug_info_options *options,	\
				   const char * const *value)			\
{										\
	const char * const *copy;						\
	if (value == drgn_debug_info_options_default_##name) {			\
		copy = value;							\
	} else {								\
		copy = drgn_debug_info_options_list_dup(value);			\
		if (!copy)							\
			return &drgn_enomem;					\
	}									\
	drgn_debug_info_options_list_destroy(options->name,			\
					     drgn_debug_info_options_default_##name);\
	options->name = copy;							\
	return NULL;								\
}

#define BOOL_OPTION(name, default_value)	\
	DRGN_DEBUG_INFO_OPTIONS_GETSET(bool, name)
#define ENUM_OPTION(name, type, default_value)	\
	DRGN_DEBUG_INFO_OPTIONS_GETSET(enum type, name)

DRGN_DEBUG_INFO_OPTIONS

#undef ENUM_OPTION
#undef BOOL_OPTION
#undef LIST_OPTION

static bool drgn_format_debug_info_options_common(struct string_builder *sb,
						  const char *name,
						  bool *first)
{
	if (*first)
		*first = false;
	else if (!string_builder_append(sb, ", "))
		return false;
	return string_builder_append(sb, name) && string_builder_appendc(sb, '=');
}

static bool drgn_debug_info_options_lists_equal(const char * const *a,
						const char * const *b)
{
	if (a == b)
		return true;
	size_t i;
	for (i = 0; a[i]; i++) {
		if (!b[i] || strcmp(a[i], b[i]) != 0)
			return false;
	}
	return !b[i];
}

static bool drgn_format_debug_info_options_list(struct string_builder *sb,
						const char *name, bool *first,
						const char * const *list,
						const char * const *default_list)
{
	// Always include directories, skip other options set to the default.
	if (default_list != drgn_debug_info_options_default_directories
	    && drgn_debug_info_options_lists_equal(list, default_list))
		return true;

	if (!drgn_format_debug_info_options_common(sb, name, first)
	    || !string_builder_appendc(sb, '('))
		return false;
	size_t i;
	for (i = 0; list[i]; i++) {
		if (!string_builder_append(sb, i == 0 ? "'" : ", '")
		    || !string_builder_append(sb, list[i])
		    || !string_builder_appendc(sb, '\''))
			return false;
	}
	return string_builder_append(sb, i == 1 ? ",)" : ")");
}

__attribute__((__unused__))
static bool drgn_format_debug_info_options_bool(struct string_builder *sb,
						const char *name, bool *first,
						bool value, bool default_value)
{
	// Skip options set to the default.
	if (value == default_value)
		return true;
	return drgn_format_debug_info_options_common(sb, name, first)
	       && string_builder_append(sb, value ? "True" : "False");
}

char *drgn_format_debug_info_options(struct drgn_debug_info_options *options)
{
	STRING_BUILDER(sb);

	bool first = true;
#define LIST_OPTION(name)						\
	if (!drgn_format_debug_info_options_list(&sb, #name, &first,	\
						 options->name,		\
						 drgn_debug_info_options_default_##name))\
		return NULL;
#define BOOL_OPTION(name, default_value)					\
	if (!drgn_format_debug_info_options_bool(&sb, #name, &first,		\
						 options->name, default_value))	\
		return NULL;
#define ENUM_OPTION(name, type, default_value)					\
	if (!type##_format(&sb, #name, &first, options->name, default_value))	\
		return NULL;
	DRGN_DEBUG_INFO_OPTIONS
#undef ENUM_OPTION
#undef BOOL_OPTION
#undef LIST_OPTION
	if (!string_builder_null_terminate(&sb))
		return NULL;
	return string_builder_steal(&sb);
}
