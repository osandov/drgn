// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * Intrusive linked list adapted from the Linux kernel.
 */

#ifndef DRGN_LIST_H
#define DRGN_LIST_H

#include <stdbool.h>

#include "util.h"

struct list_head {
	struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define LIST_HEAD(name) struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
	struct list_head *next = head->next;
	next->prev = new;
	new->next = next;
	new->prev = head;
	head->next = new;
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	struct list_head *prev = head->prev;
	head->prev = new;
	new->next = head;
	new->prev = prev;
	prev->next = new;
}

static inline void list_del(struct list_head *entry)
{
	struct list_head *next = entry->next, *prev = entry->prev;
	next->prev = prev;
	prev->next = next;
}

static inline void list_del_init(struct list_head *entry)
{
	list_del(entry);
	INIT_LIST_HEAD(entry);
}

static inline void list_move(struct list_head *list, struct list_head *head)
{
	list_del(list);
	list_add(list, head);
}

static inline void list_move_tail(struct list_head *list, struct list_head *head)
{
	list_del(list);
	list_add_tail(list, head);
}

static inline bool list_empty(const struct list_head *head)
{
	return head->next == head;
}

static inline int list_is_singular(const struct list_head *head)
{
	return !list_empty(head) && (head->next == head->prev);
}

static inline void list_splice_impl(const struct list_head *list,
				    struct list_head *prev,
				    struct list_head *next)
{
	struct list_head *first = list->next;
	struct list_head *last = list->prev;

	first->prev = prev;
	prev->next = first;

	last->next = next;
	next->prev = last;
}

static inline void list_splice(const struct list_head *list,
			       struct list_head *head)
{
	if (!list_empty(list))
		list_splice_impl(list, head, head->next);
}

static inline void list_splice_tail(const struct list_head *list,
				    struct list_head *head)
{
	if (!list_empty(list))
		list_splice_impl(list, head->prev, head);
}

static inline void list_splice_init(struct list_head *list,
				    struct list_head *head)
{
	if (!list_empty(list)) {
		list_splice_impl(list, head, head->next);
		INIT_LIST_HEAD(list);
	}
}

static inline void list_splice_tail_init(struct list_head *list,
					 struct list_head *head)
{
	if (!list_empty(list)) {
		list_splice_impl(list, head->prev, head);
		INIT_LIST_HEAD(list);
	}
}

#define list_entry(ptr, type, member) container_of(ptr, type, member)

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define list_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)

#define list_first_entry_or_null(ptr, type, member) ({			\
	struct list_head *head__ = (ptr);				\
	struct list_head *pos__ = head__->next;				\
	pos__ != head__ ? list_entry(pos__, type, member) : NULL;	\
})

#define list_last_entry_or_null(ptr, type, member) ({			\
	struct list_head *head__ = (ptr);				\
	struct list_head *pos__ = head__->prev;				\
	pos__ != head__ ? list_entry(pos__, type, member) : NULL;	\
})

#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_for_each(pos, head)	\
	for (pos = (head)->next; pos != (head); pos = pos->next)

#define list_for_each_safe(pos, n, head)			\
	for (pos = (head)->next, n = pos->next; pos != (head);	\
	     pos = n, n = pos->next)

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_next_entry(pos, member))

#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_first_entry(head, typeof(*pos), member),	\
	     n = list_next_entry(pos, member);				\
	     &pos->member != (head);					\
	     pos = n, n = list_next_entry(n, member))

static inline size_t list_count_nodes(struct list_head *head)
{
	struct list_head *pos;
	size_t count = 0;

	list_for_each(pos, head)
		count++;

	return count;
}

#endif /* DRGN_LIST_H */
