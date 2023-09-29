// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <stdlib.h>
#include <string.h>

#include "object_index.h"

void drgn_object_index_init(struct drgn_object_index *oindex)
{
	oindex->finders = NULL;
}

void drgn_object_index_deinit(struct drgn_object_index *oindex)
{
	struct drgn_object_finder *finder = oindex->finders;
	while (finder) {
		struct drgn_object_finder *next = finder->next;
		if (finder->free)
			free(finder);
		finder = next;
	}
}

struct drgn_error *
drgn_object_index_add_finder(struct drgn_object_index *oindex,
			     struct drgn_object_finder *finder,
			     drgn_object_find_fn fn, void *arg)
{
	if (finder) {
		finder->free = false;
	} else {
		finder = malloc(sizeof(*finder));
		if (!finder)
			return &drgn_enomem;
		finder->free = true;
	}
	finder->fn = fn;
	finder->arg = arg;
	finder->next = oindex->finders;
	oindex->finders = finder;
	return NULL;
}

struct drgn_error *drgn_object_index_find(struct drgn_object_index *oindex,
					  const char *name,
					  const char *filename,
					  enum drgn_find_object_flags flags,
					  struct drgn_object *ret)
{
	struct drgn_error *err;
	size_t name_len;
	struct drgn_object_finder *finder;
	const char *kind_str;

	if ((flags & ~DRGN_FIND_OBJECT_ANY) || !flags) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "invalid find object flags");
	}

	name_len = strlen(name);
	finder = oindex->finders;
	while (finder) {
		err = finder->fn(name, name_len, filename, flags, finder->arg,
				 ret);
		if (err != &drgn_not_found)
			return err;
		finder = finder->next;
	}

	switch (flags) {
	case DRGN_FIND_OBJECT_CONSTANT:
		kind_str = "constant ";
		break;
	case DRGN_FIND_OBJECT_FUNCTION:
		kind_str = "function ";
		break;
	case DRGN_FIND_OBJECT_VARIABLE:
		kind_str = "variable ";
		break;
	default:
		kind_str = "";
		break;
	}
	if (filename) {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find %s'%s' in '%s'",
					 kind_str, name, filename);
	} else {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find %s'%s'", kind_str,
					 name);
	}
}
