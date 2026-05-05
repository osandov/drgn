// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * Chains of named handlers.
 */

#ifndef DRGN_HANDLER_H
#define DRGN_HANDLER_H

#include <stdbool.h>
#include <stdlib.h>

// This should be embedded as the first member in a structure containing the
// handler implementation.
struct drgn_handler {
	const char *name;
	struct drgn_handler *next;
	bool enabled;
	// Whether this structure and name need to be freed.
	bool free;
};

static inline void drgn_handler_destroy(struct drgn_handler *handler)
{
	if (handler->free) {
		free((char *)handler->name);
		free(handler);
	}
}

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

bool drgn_handler_list_disable(struct drgn_handler_list *list,
			       const char *name);

struct drgn_handler *
drgn_handler_list_unregister(struct drgn_handler_list *list, const char *name);

static inline bool
drgn_handler_list_has_registered(struct drgn_handler_list *list)
{
	return list->head;
}

static inline bool drgn_handler_list_has_enabled(struct drgn_handler_list *list)
{
	return list->head && list->head->enabled;
}

static inline bool drgn_handler_is_last_enabled(struct drgn_handler *handler)
{
	return handler->enabled && (!handler->next || !handler->next->enabled);
}

#define drgn_handler_list_for_each_safe(type, handler, next, list)		\
	for (type *handler = (type *)(list)->head,				\
	     *next = handler							\
		     ? (type *)((struct drgn_handler *)handler)->next : NULL;	\
	     handler;								\
	     handler = next,							\
	     next = handler							\
		     ? (type *)((struct drgn_handler *)handler)->next : NULL)

#define drgn_handler_list_for_each_enabled(type, handler, list)		\
	for (type *handler = (type *)(list)->head;			\
	     handler && ((struct drgn_handler *)handler)->enabled;	\
	     handler = (type *)((struct drgn_handler *)handler)->next)

static inline void *
drgn_handler_list_first_enabled(struct drgn_handler_list *list)
{
	if (!drgn_handler_list_has_enabled(list))
		return NULL;
	return list->head;
}

#endif /* DRGN_HANDLER_H */
