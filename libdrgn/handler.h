// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * Chains of named handlers.
 */

#ifndef DRGN_HANDLER_H
#define DRGN_HANDLER_H

#include <stdint.h>

// This should be embedded as the first member in a structure containing the
// handler implementation.
struct drgn_handler {
	const char *name;
	struct drgn_handler *next;
	bool enabled;
	// Whether this structure and name need to be freed.
	bool free;
};

// This is optimized for frequent drgn_handler_list_for_each_enabled()
// operations; everything else is expected to be rare, so we keep this as small
// as possible.
struct drgn_handler_list {
	// All enabled handlers are first, in order, followed by disabled
	// handlers in no particular order.
	struct drgn_handler *head;
};

// handler->name and handler->free must be initialized.
struct drgn_error *drgn_handler_list_register(struct drgn_handler_list *list,
					      struct drgn_handler *handler,
					      size_t enable_index,
					      const char *what);

struct drgn_error *drgn_handler_list_registered(struct drgn_handler_list *list,
						const char ***names_ret,
						size_t *count_ret);

struct drgn_error *drgn_handler_list_set_enabled(struct drgn_handler_list *list,
						 const char * const *names,
						 size_t count,
						 const char *what);

struct drgn_error *drgn_handler_list_enabled(struct drgn_handler_list *list,
					     const char ***names_ret,
					     size_t *count_ret);

// Helper to simplify the casting and naming in drgn_handler_list_deinit().
static inline struct drgn_handler *
drgn_handler_free_and_next(struct drgn_handler *handler)
{
	struct drgn_handler *next = handler->next;
	if (handler->free) {
		free((char *)handler->name);
		free(handler);
	}
	return next;
}

// Free all registered handlers, optionally executing a statement for each one.
#define drgn_handler_list_deinit(type, handler, list, ...) do {	\
	type *handler = (type *)(list)->head;			\
	while (handler) {					\
		__VA_ARGS__					\
		handler = (type *)drgn_handler_free_and_next((struct drgn_handler *)handler);\
	}							\
} while (0)

#define drgn_handler_list_for_each_enabled(type, handler, list)		\
	for (type *handler = (type *)(list)->head;			\
	     handler && ((struct drgn_handler *)handler)->enabled;	\
	     handler = (type *)((struct drgn_handler *)handler)->next)

#endif /* DRGN_HANDLER_H */
