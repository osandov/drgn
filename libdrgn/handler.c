// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <stdlib.h>
#include <string.h>

#include "cleanup.h"
#include "drgn.h"
#include "handler.h"
#include "hash_table.h"
#include "util.h"

struct drgn_error *drgn_handler_list_register(struct drgn_handler_list *list,
					      struct drgn_handler *new_handler,
					      size_t enable_idx,
					      const char *what)
{
	struct drgn_handler **insert_pos = &list->head;
	size_t num_enabled = 0;
	for (struct drgn_handler *handler = list->head; handler;
	     handler = handler->next) {
		if (strcmp(new_handler->name, handler->name) == 0) {
			return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
						 "duplicate %s name '%s'",
						 what, handler->name);
		}
		if (handler->enabled && num_enabled < enable_idx) {
			insert_pos = &handler->next;
			num_enabled++;
		}
	}
	new_handler->enabled = enable_idx != DRGN_HANDLER_REGISTER_DONT_ENABLE;
	new_handler->next = *insert_pos;
	*insert_pos = new_handler;
	return NULL;
}

#define drgn_handler_list_for_each_registered(handler, list)		\
	for (struct drgn_handler *handler = (list)->head; handler;	\
	     handler = handler->next)

struct drgn_error *drgn_handler_list_registered(struct drgn_handler_list *list,
						const char ***names_ret,
						size_t *count_ret)
{
	size_t n = 0;
	drgn_handler_list_for_each_registered(handler, list)
		n++;
	const char **names = malloc_array(n, sizeof(names[0]));
	if (!names)
		return &drgn_enomem;
	size_t i = 0;
	drgn_handler_list_for_each_registered(handler, list)
		names[i++] = handler->name;
	*names_ret = names;
	*count_ret = n;
	return NULL;
}

static inline const char *drgn_handler_entry_to_key(const uintptr_t *entry)
{
	return ((struct drgn_handler *)(*entry & ~1))->name;
}

DEFINE_HASH_TABLE(drgn_handler_table, uintptr_t, drgn_handler_entry_to_key,
		  c_string_key_hash_pair, c_string_key_eq);

struct drgn_error *drgn_handler_list_set_enabled(struct drgn_handler_list *list,
						 const char * const *names,
						 size_t count, const char *what)
{
	// Put all of the handlers in a hash table of tagged pointers.
	_cleanup_(drgn_handler_table_deinit)
		struct drgn_handler_table table = HASH_TABLE_INIT;
	drgn_handler_list_for_each_registered(handler, list) {
		uintptr_t entry = (uintptr_t)handler;
		if (drgn_handler_table_insert(&table, &entry, NULL) < 0)
			return &drgn_enomem;
	}

	// Check the list of names.
	for (size_t i = 0; i < count; i++) {
		auto it = drgn_handler_table_search(&table, &names[i]);
		if (!it.entry) {
			return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
						 "%s '%s' not found", what,
						 names[i]);
		}
		if (*it.entry & 1) {
			return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
						 "%s '%s' enabled multiple times",
						 what, names[i]);
		}
		*it.entry |= 1;
	}

	// Insert the enabled handlers and delete them from the hash table.
	struct drgn_handler **handlerp = &list->head;
	for (size_t i = 0; i < count; i++) {
		auto it = drgn_handler_table_search(&table, &names[i]);
		struct drgn_handler *handler =
			(struct drgn_handler *)(*it.entry & ~1);
		handler->enabled = true;
		*handlerp = handler;
		handlerp = &handler->next;
		drgn_handler_table_delete_iterator(&table, it);
	}

	// The remaining handlers in the hash table are disabled. Insert them.
	for (auto it = drgn_handler_table_first(&table); it.entry;
	     it = drgn_handler_table_next(it)) {
		struct drgn_handler *handler = (struct drgn_handler *)*it.entry;
		handler->enabled = false;
		*handlerp = handler;
		handlerp = &handler->next;
	}
	*handlerp = NULL;

	return NULL;
}

struct drgn_error *drgn_handler_list_enabled(struct drgn_handler_list *list,
					     const char ***names_ret,
					     size_t *count_ret)
{
	size_t n = 0;
	drgn_handler_list_for_each_enabled(struct drgn_handler, handler, list)
		n++;
	const char **names = malloc_array(n, sizeof(names[0]));
	if (!names)
		return &drgn_enomem;
	size_t i = 0;
	drgn_handler_list_for_each_enabled(struct drgn_handler, handler, list)
		names[i++] = handler->name;
	*names_ret = names;
	*count_ret = n;
	return NULL;
}
