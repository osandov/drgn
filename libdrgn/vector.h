// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file
 *
 * Dynamic arrays.
 *
 * See @ref Vectors.
 */

#ifndef DRGN_VECTOR_H
#define DRGN_VECTOR_H

#include <stdbool.h>
#include <stdlib.h> // IWYU pragma: keep
#include <string.h> // IWYU pragma: keep

/**
 * @ingroup Internals
 *
 * @defgroup Vectors Vectors
 *
 * Dynamic arrays (a.k.a.\ vectors).
 *
 * This is a basic implementation of generic, strongly-typed vectors.
 *
 * A vector is defined with @ref DEFINE_VECTOR(). Each generated vector
 * interface is prefixed with a given name; the interface documented here uses
 * the example name @c vector.
 *
 * @{
 */

#ifdef DOXYGEN
/**
 * Vector instance.
 *
 * There are no requirements on how this is allocated; it may be global, on the
 * stack, allocated by @c malloc(), embedded in another structure, etc.
 */
struct vector {
	/**
	 * The underlying array of entries.
	 *
	 * This may be accessed directly. It may be reallocated as noted.
	 *
	 * A common pattern is using a @c vector to build an array and then
	 * returning the raw array. To do so, don't call @ref vector_deinit(),
	 * then return @c data and free it with `free()`.
	 */
	entry_type *data;
	/** The number of entries in a @ref vector. */
	size_t size;
	/**
	 * The number of allocated elements in @ref vector::data.
	 *
	 * This should not be modified.
	 */
	size_t capacity;
};

/**
 * Initialize a @ref vector.
 *
 * The new vector is empty.
 *
 * @sa VECTOR_INIT
 */
void vector_init(struct vector *vector);

/**
 * Free memory allocated by a @ref vector.
 *
 * This frees @ref vector::data.
 */
void vector_deinit(struct vector *vector);

/**
 * Increase the capacity of a @ref vector.
 *
 * If @p capacity is greater than the current capacity of the @ref vector, this
 * reallocates @ref vector::data and increases @ref vector::capacity to at least
 * @p capacity. Otherwise, it does nothing.
 *
 * @return @c true on success, @c false on failure.
 */
bool vector_reserve(struct vector *vector, size_t capacity);

/**
 * Free unused memory in a @ref vector.
 *
 * This may reallocate @ref vector::data and set @ref vector::capacity to @ref
 * vector::size. It may also do nothing.
 */
void vector_shrink_to_fit(struct vector *vector);

/**
 * Append to a @ref vector.
 *
 * This increases @ref vector::size by one. It may reallocate @ref vector::data
 * and change @ref vector::capacity.
 *
 * @return @c true on success, @c false on failure to allocate memory.
 */
bool vector_append(struct vector *vector, const entry_type *entry);

/**
 * Append an uninitialized entry to a @ref vector.
 *
 * Like @ref vector_append(), but return a pointer to the new (uninitialized)
 * entry.
 *
 * @return The new entry on success, @c NULL on failure to allocate memory.
 */
entry_type *vector_append_entry(struct vector *vector);

/**
 * Remove and return the last entry in a @ref vector.
 *
 * The vector is assumed to be non-empty. This descreases @ref vector::size by
 * one. It does not reallocate @ref vector::data.
 *
 * @return A pointer to the removed entry, which remains valid until another
 * entry is inserted in its place or @ref vector::data is reallocated.
 */
entry_type *vector_pop(struct vector *vector);
#endif

bool vector_do_reserve(size_t new_capacity, size_t entry_size, void **data,
		       size_t *capacity);
void vector_do_shrink_to_fit(size_t size, size_t entry_size, void **data,
			     size_t *capacity);
bool vector_reserve_for_append(size_t size, size_t entry_size, void **data,
			       size_t *capacity);

/**
 * Define a vector type without defining its functions.
 *
 * This is useful when the vector type must be defined in one place (e.g., a
 * header) but the interface is defined elsewhere (e.g., a source file) with
 * @ref DEFINE_VECTOR_FUNCTIONS(). Otherwise, just use @ref DEFINE_VECTOR().
 *
 * @sa DEFINE_VECTOR()
 */
#define DEFINE_VECTOR_TYPE(vector, entry_type)	\
typedef typeof(entry_type) vector##_entry_type;	\
						\
struct vector {					\
	vector##_entry_type *data;		\
	size_t size;				\
	size_t capacity;			\
};

/**
 * Define the functions for a vector.
 *
 * The vector type must have already been defined with @ref
 * DEFINE_VECTOR_TYPE().
 *
 * Unless the type and function definitions must be in separate places, use @ref
 * DEFINE_VECTOR() instead.
 *
 * @sa DEFINE_VECTOR()
 */
#define DEFINE_VECTOR_FUNCTIONS(vector)						\
__attribute__((__unused__))							\
static void vector##_init(struct vector *vector)				\
{										\
	vector->data = NULL;							\
	vector->size = vector->capacity = 0;					\
}										\
										\
__attribute__((__unused__))							\
static void vector##_deinit(struct vector *vector)				\
{										\
	free(vector->data);							\
}										\
										\
__attribute__((__unused__))							\
static bool vector##_reserve(struct vector *vector, size_t capacity)		\
{										\
	return vector_do_reserve(capacity, sizeof(*vector->data),		\
				 (void **)&vector->data, &vector->capacity);	\
}										\
										\
__attribute__((__unused__))							\
static void vector##_shrink_to_fit(struct vector *vector)			\
{										\
	vector_do_shrink_to_fit(vector->size, sizeof(*vector->data),		\
				(void **)&vector->data, &vector->capacity);	\
}										\
										\
static vector##_entry_type *vector##_append_entry(struct vector *vector)	\
{										\
	if (!vector_reserve_for_append(vector->size, sizeof(*vector->data),	\
				       (void **)&vector->data,			\
				       &vector->capacity))			\
		return NULL;							\
	return &vector->data[vector->size++];					\
}										\
										\
__attribute__((__unused__))							\
static bool vector##_append(struct vector *vector,				\
			    const vector##_entry_type *entry)			\
{										\
	vector##_entry_type *new_entry;						\
										\
	new_entry = vector##_append_entry(vector);				\
	if (!new_entry)								\
		return false;							\
	memcpy(new_entry, entry, sizeof(*entry));				\
	return true;								\
}										\
										\
__attribute__((__unused__))							\
static vector##_entry_type *vector##_pop(struct vector *vector)			\
{										\
	return &vector->data[--vector->size];					\
}

/**
 * Define a vector interface.
 *
 * This macro defines a vector type along with its functions.
 *
 * @param[in] vector Name of the type to define. This is prefixed to all of the
 * types and functions defined for that type.
 * @param[in] entry_type Type of entries in the vector.
 */
#define DEFINE_VECTOR(vector, entry_type)	\
DEFINE_VECTOR_TYPE(vector, entry_type)		\
DEFINE_VECTOR_FUNCTIONS(vector)

/**
 * Empty vector initializer.
 *
 * This can be used to initialize a vector when declaring it.
 *
 * @sa vector_init()
 */
#define VECTOR_INIT { NULL }

/** @} */

#endif /* DRGN_VECTOR_H */
