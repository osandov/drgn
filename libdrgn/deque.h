// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * Double-ended queues.
 *
 * See @ref Deques.
 */

#ifndef DRGN_DEQUE_H
#define DRGN_DEQUE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h> // IWYU pragma: keep
#include <string.h> // IWYU pragma: keep

#include "minmax.h"
#include "util.h"

/**
 * @ingroup Internals
 *
 * @defgroup Deques Deques
 *
 * Double-ended queues.
 *
 * This is an implementation of generic, strongly-typed double-ended queues.
 *
 * A deque is defined with @ref DEFINE_DEQUE(). Each generated deque interface
 * is prefixed with a given name; the interface documented here uses the example
 * name @c deque.
 *
 * @{
 */

#ifdef DOXYGEN
/**
 * @struct deque
 *
 * Double-ended queue instance.
 *
 * There are no requirements on how this is allocated; it may be global, on the
 * stack, allocated by @c malloc(), embedded in another structure, etc.
 */
struct deque;

/**
 * Initialize a @ref deque.
 *
 * The new deque is empty.
 *
 * @sa DEQUE_INIT
 */
void deque_init(struct deque *deque);

/** Free memory allocated by a @ref deque. */
void deque_deinit(struct deque *deque);

/** Return the number of entries in a @ref deque. */
size_t deque_size(const struct deque *deque);

/** Return whether a @ref deque is empty. */
bool deque_empty(const struct deque *deque);

/**
 * Maximum possible number of entries in a @ref deque.
 *
 * Attempts to increase the size or capacity beyond this will fail.
 */
const size_t deque_max_size;

/**
 * Set the size of a @ref deque to zero.
 *
 * This does not change the capacity or free the entries.
 */
void deque_clear(struct deque *deque);

/** Return the number of allocated entries in a @ref deque. */
size_t deque_capacity(const struct deque *deque);

/**
 * Increase the capacity of a @ref deque.
 *
 * If @p capacity is greater than the current capacity, this increases the
 * capacity to at least @p capacity and reallocates the entries. Otherwise, it
 * does nothing.
 *
 * @return @c true on success, @c false on failure.
 */
bool deque_reserve(struct deque *deque, size_t capacity);

/**
 * Increase the capacity of a @ref deque to accomodate at least one append (or
 * prepend).
 *
 * If the current capacity is equal to the current size, this increases the
 * capacity by at least one and reallocates the entries. Otherwise, it does
 * nothing.
 *
 * @return @c true on success, @c false on failure.
 */
bool deque_reserve_for_append(struct deque *deque);

/**
 * Return the first entry in a @ref deque.
 *
 * This is equivalent to `deque_at(deque, 0)`. The deque must not be empty.
 */
entry_type *deque_first(struct deque *deque);

/**
 * Return the last entry in a @ref deque.
 *
 * This is equivalent to `deque_at(deque, deque_size(deque) - 1)`. The deque
 * must not be empty.
 */
entry_type *deque_last(struct deque *deque);

/**
 * Return the entry at the given index in a @ref deque.
 *
 * @param[in] i Entry index. Must be less than the size of the deque.
 */
entry_type *deque_at(struct deque *deque, size_t i);

/**
 * Append to a @ref deque.
 *
 * This increases the deque's size by one. If the current capacity is equal to
 * the current size, this increases the capacity by at least one and reallocates
 * the entries.
 *
 * @return @c true on success, @c false on failure.
 */
bool deque_append(struct deque *deque, const entry_type *entry);

/**
 * Prepend to a @ref deque.
 *
 * This increases the deque's size by one. If the current capacity is equal to
 * the current size, this increases the capacity by at least one and reallocates
 * the entries.
 *
 * @return @c true on success, @c false on failure.
 */
bool deque_prepend(struct deque *deque, const entry_type *entry);

/**
 * Append an uninitialized entry to a @ref deque.
 *
 * Like @ref deque_append(), but return a pointer to the new (uninitialized)
 * entry.
 *
 * @return The new entry on success, @c NULL on failure.
 */
entry_type *deque_append_entry(struct deque *deque);

/**
 * Prepend an uninitialized entry to a @ref deque.
 *
 * Like @ref deque_prepend(), but return a pointer to the new (uninitialized)
 * entry.
 *
 * @return The new entry on success, @c NULL on failure.
 */
entry_type *deque_prepend_entry(struct deque *deque);

/**
 * Remove and return the first entry in a @ref deque.
 *
 * The deque must not be empty. This decreases the size by one. It does not
 * change the capacity or reallocate the entries.
 *
 * @return A pointer to the removed entry, which remains valid until another
 * entry is inserted in its place or the entries are reallocated.
 */
entry_type *deque_pop_first(struct deque *deque);

/**
 * Remove and return the last entry in a @ref deque.
 *
 * The deque must not be empty. This decreases the size by one. It does not
 * change the capacity or reallocate the entries.
 *
 * @return A pointer to the removed entry, which remains valid until another
 * entry is inserted in its place or the entries are reallocated.
 */
entry_type *deque_pop_last(struct deque *deque);
#endif

/**
 * Define a deque type without defining its functions.
 *
 * This is useful when the deque type must be defined in one place (e.g., a
 * header) but the interface is defined elsewhere (e.g., a source file) with
 * @ref DEFINE_DEQUE_FUNCTIONS(). Otherwise, just use @ref DEFINE_DEQUE().
 *
 * This takes the same arguments as @ref DEFINE_DEQUE().
 */
#define DEFINE_DEQUE_TYPE(deque, entry_type)			\
typedef typeof(entry_type) deque##_entry_type;			\
								\
struct deque {							\
	deque##_entry_type *_data;				\
	/*							\
	 * Invariants:						\
	 * _size <= _capacity					\
	 * _capacity == 0 ? _head == 0 : _head < _capacity	\
	 */							\
	size_t _head;						\
	size_t _size;						\
	size_t _capacity;					\
};								\
struct DEFINE_DEQUE_needs_semicolon

/**
 * Define the functions for a deque.
 *
 * The deque type must have already been defined with @ref DEFINE_DEQUE_TYPE().
 *
 * Unless the type and function definitions must be in separate places, use @ref
 * DEFINE_DEQUE() instead.
 *
 * @sa DEFINE_DEQUE()
 */
#define DEFINE_DEQUE_FUNCTIONS(deque)						\
__attribute__((__unused__))							\
static void deque##_init(struct deque *deque)					\
{										\
	deque->_data = NULL;							\
	deque->_head = deque->_size = deque->_capacity = 0;			\
}										\
										\
__attribute__((__unused__))							\
static void deque##_deinit(struct deque *deque)					\
{										\
	free(deque->_data);							\
}										\
										\
__attribute__((__unused__))							\
static size_t deque##_size(const struct deque *deque)				\
{										\
	return deque->_size;							\
}										\
										\
__attribute__((__unused__))							\
static bool deque##_empty(const struct deque *deque)				\
{										\
	return deque->_size == 0;						\
}										\
										\
static const size_t deque##_max_size = PTRDIFF_MAX / sizeof(deque##_entry_type);\
										\
__attribute__((__unused__))							\
static void deque##_clear(struct deque *deque)					\
{										\
	deque->_size = 0;							\
}										\
										\
static size_t deque##_capacity(const struct deque *deque)			\
{										\
	return deque->_capacity;						\
}										\
										\
static bool deque##_reallocate(struct deque *deque, size_t capacity)		\
{										\
	deque##_entry_type *new_data =						\
		realloc(deque->_data, capacity * sizeof(deque##_entry_type));	\
	if (!new_data)								\
		return false;							\
										\
	if (deque->_size > deque->_capacity - deque->_head) {			\
		size_t old_wraparound =						\
			deque->_size - (deque->_capacity - deque->_head);	\
		size_t new_wraparound =						\
			deque->_size > capacity - deque->_head			\
			? deque->_size - (capacity - deque->_head) : 0;		\
		memcpy(&new_data[deque->_capacity], new_data,			\
		       (old_wraparound - new_wraparound) * sizeof(*new_data));	\
		if (new_wraparound > 0) {					\
			memmove(new_data,					\
				&new_data[old_wraparound - new_wraparound],	\
				new_wraparound * sizeof(*new_data));		\
		}								\
	}									\
										\
	deque->_data = new_data;						\
	deque->_capacity = capacity;						\
	return true;								\
}										\
										\
__attribute__((__unused__))							\
static bool deque##_reserve(struct deque *deque, size_t capacity)		\
{										\
	if (capacity <= deque##_capacity(deque))				\
		return true;							\
	if (capacity > deque##_max_size)					\
		return false;							\
	return deque##_reallocate(deque, capacity);				\
}										\
										\
static bool deque##_reserve_for_append(struct deque *deque)			\
{										\
	size_t size = deque##_size(deque);					\
	if (size < deque##_capacity(deque))					\
		return true;							\
	if (size == deque##_max_size)						\
		return false;							\
	size_t new_capacity = size + (size > 0 ? size : 1);			\
	if (new_capacity < size || new_capacity > deque##_max_size)		\
		new_capacity = deque##_max_size;				\
	return deque##_reallocate(deque, new_capacity);				\
}										\
										\
__attribute__((__unused__))							\
static deque##_entry_type *deque##_first(struct deque *deque)			\
{										\
	return &deque->_data[deque->_head];					\
}										\
										\
__attribute__((__unused__))							\
static deque##_entry_type *deque##_at(struct deque *deque, size_t i)		\
{										\
	i += deque->_head;							\
	if (i >= deque->_capacity)						\
		i -= deque->_capacity;						\
	return &deque->_data[i];						\
}										\
										\
__attribute__((__unused__))							\
static deque##_entry_type *deque##_last(struct deque *deque)			\
{										\
	return deque##_at(deque, deque->_size - 1);				\
}										\
										\
static deque##_entry_type *deque##_append_entry(struct deque *deque)		\
{										\
	if (!deque##_reserve_for_append(deque))					\
		return NULL;							\
	deque->_size++;								\
	return deque##_last(deque);						\
}										\
										\
static deque##_entry_type *deque##_prepend_entry(struct deque *deque)		\
{										\
	if (!deque##_reserve_for_append(deque))					\
		return NULL;							\
	if (deque->_head > 0)							\
		deque->_head--;							\
	else									\
		deque->_head = deque->_capacity - 1;				\
	deque->_size++;								\
	return &deque->_data[deque->_head];					\
}										\
										\
__attribute__((__unused__))							\
static bool deque##_append(struct deque *deque,					\
			   const deque##_entry_type *entry)			\
{										\
	deque##_entry_type *new_entry = deque##_append_entry(deque);		\
	if (!new_entry)								\
		return false;							\
	memcpy(new_entry, entry, sizeof(*entry));				\
	return true;								\
}										\
										\
__attribute__((__unused__))							\
static bool deque##_prepend(struct deque *deque,				\
			    const deque##_entry_type *entry)			\
{										\
	deque##_entry_type *new_entry = deque##_prepend_entry(deque);		\
	if (!new_entry)								\
		return false;							\
	memcpy(new_entry, entry, sizeof(*entry));				\
	return true;								\
}										\
										\
__attribute__((__unused__))							\
static deque##_entry_type *deque##_pop_first(struct deque *deque)		\
{										\
	deque##_entry_type *entry = &deque->_data[deque->_head];		\
	if (deque->_head + 1 < deque->_capacity)				\
		deque->_head++;							\
	else									\
		deque->_head = 0;						\
	deque->_size--;								\
	return entry;								\
}										\
										\
__attribute__((__unused__))							\
static deque##_entry_type *deque##_pop_last(struct deque *deque)		\
{										\
	deque##_entry_type *entry = deque##_last(deque);			\
	deque->_size--;								\
	return entry;								\
}										\
struct DEFINE_DEQUE_needs_semicolon

/**
 * Define a double-ended queue interface.
 *
 * This macro defines a deque type along with its functions.
 *
 * @param[in] deque Name of the type to define. This is prefixed to all of the
 * types and functions defined for that type.
 * @param[in] entry_type Type of entries in the deque.
 */
#define DEFINE_DEQUE(deque, entry_type)	\
DEFINE_DEQUE_TYPE(deque, entry_type);	\
DEFINE_DEQUE_FUNCTIONS(deque)

/**
 * Empty deque initializer.
 *
 * This can be used to initialize a deque when declaring it.
 *
 * @sa deque_init()
 */
#define DEQUE_INIT { 0 }

/**
 * Define and initialize an empty @ref deque of type @p deque_type named @p
 * deque that is automatically deinitialized when it goes out of scope.
 */
#define DEQUE(deque_type, deque)				\
	__attribute__((__cleanup__(deque_type##_deinit)))	\
	struct deque_type deque = DEQUE_INIT

/** @} */

#endif /* DRGN_DEQUE_H */
