// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

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

#include "generics.h"
#include "minmax.h"
#include "util.h"
#include "pp.h"

/**
 * @ingroup Internals
 *
 * @defgroup Vectors Vectors
 *
 * Dynamic arrays (a.k.a.\ vectors).
 *
 * This is an implementation of generic, strongly-typed vectors.
 *
 * A vector is defined with @ref DEFINE_VECTOR(). Each generated vector
 * interface is prefixed with a given name; the interface documented here uses
 * the example name @c vector.
 *
 * @{
 */

#ifdef DOXYGEN
/**
 * @struct vector
 *
 * Vector instance.
 *
 * There are no requirements on how this is allocated; it may be global, on the
 * stack, allocated by @c malloc(), embedded in another structure, etc.
 */
struct vector;

/**
 * Initialize a @ref vector.
 *
 * The new vector is empty.
 *
 * @sa VECTOR_INIT
 */
void vector_init(struct vector *vector);

/** Free memory allocated by a @ref vector. */
void vector_deinit(struct vector *vector);

/** Return the number of entries in a @ref vector. */
size_type vector_size(const struct vector *vector);

/** Return whether a @ref vector is empty. */
bool vector_empty(const struct vector *vector);

/**
 * Maximum possible number of entries in a @ref vector.
 *
 * Attempts to increase the size or capacity beyond this will fail.
 */
const size_type vector_max_size;

/**
 * Update the number of entries in a @ref vector.
 *
 * If @p size is greater than the current capacity, this increases the capacity
 * to at least @p size and reallocates the entries.
 *
 * If @p size is greater than the current size, the entries between the old size
 * and the new size are uninitialized.
 *
 * @return @c true on success, @c false on failure.
 */
bool vector_resize(struct vector *vector, size_t size);

/**
 * Set the size of a @ref vector to zero.
 *
 * This does not change the capacity or free the entries.
 */
void vector_clear(struct vector *vector);

/** Return the number of allocated entries in a @ref vector. */
size_type vector_capacity(const struct vector *vector);

/**
 * Increase the capacity of a @ref vector.
 *
 * If @p capacity is greater than the current capacity, this increases the
 * capacity to at least @p capacity and reallocates the entries. Otherwise, it
 * does nothing.
 *
 * @return @c true on success, @c false on failure.
 */
bool vector_reserve(struct vector *vector, size_t capacity);

/**
 * Increase the capacity of a @ref vector to accomodate at least one append.
 *
 * If the current capacity is equal to the current size, this increases the
 * capacity by at least one and reallocates the entries. Otherwise, it does
 * nothing.
 *
 * @return @c true on success, @c false on failure.
 */
bool vector_reserve_for_append(struct vector *vector);

/**
 * Increase the capacity of a @ref vector to accomodate at least @p n appends.
 *
 * If the current capacity minus the current size is not at least @p n, this
 * increases the capacity by at least @p n and reallocates the entries.
 * Otherwise, it does nothing.
 *
 * @return @c true on success, @c false on failure.
 */
bool vector_reserve_for_extend(struct vector *vector, size_t n);

/**
 * Free unused memory in a @ref vector.
 *
 * This may reduce the capacity and reallocate the entries. It may also do
 * nothing.
 */
void vector_shrink_to_fit(struct vector *vector);

/**
 * Steal the array of entries from a @ref vector.
 *
 * This returns the internal array of entries. The vector can no longer be used
 * except to be passed to @ref vector_deinit(), which will do nothing.
 *
 * This is undefined if the vector type was defined with a non-zero @c
 * inline_size.
 *
 * This can be used to build an array when the size isn't known ahead of time
 * but won't change after the array is built. For example:
 *
 * ```
 * DEFINE_VECTOR(int_vector, int);
 *
 * bool primes_less_than(int n, int **array_ret, size_t *size_ret)
 * {
 *
 *         _cleanup_(int_vector_deinit) struct int_vector vector = VECTOR_INIT;
 *         for (int i = 2; i < n; i++) {
 *                 if (is_prime(i) && !int_vector_push(&vector, &i))
 *                         return false;
 *         }
 *         int_vector_shrink_to_fit(&vector);
 *         int_vector_steal(&vector, array_ret, size_ret);
 *         return true;
 * }
 * ```
 *
 * As demonstrated here, it may be desirable to call @ref vector_shrink_to_fit()
 * first.
 *
 * @param[out] entries_ret Returned array. This must be freed with @c free().
 * @param[out] size_ret Returned number of entries in array. May be @c NULL.
 */
void vector_steal(struct vector *vector, entry_type **entries_ret,
		  size_type *size_ret);

/**
 * Return the array of entries in a @ref vector.
 *
 * The vector may be empty, in which case this is equal to `vector_end(vector)`.
 */
entry_type *vector_begin(struct vector *vector);

/**
 * Return one past the last entry in a @ref vector.
 *
 * The vector may be empty, in which case this is equal to
 * `vector_begin(vector)`.
 */
entry_type *vector_end(struct vector *vector);

/**
 * Return the first entry in a @ref vector.
 *
 * This is equivalent to `vector_at(vector, 0)`. The vector must not be empty
 * (in contrast to @ref vector_begin()).
 */
entry_type *vector_first(struct vector *vector);

/**
 * Return the last entry in a @ref vector.
 *
 * This is equivalent to `vector_at(vector, vector_size(vector) - 1)`. The
 * vector must not be empty.
 */
entry_type *vector_last(struct vector *vector);

/**
 * Return the entry at the given index in a @ref vector.
 *
 * @param[in] i Entry index. Must be less than the size of the vector.
 */
entry_type *vector_at(struct vector *vector, size_t i);

/**
 * Append to a @ref vector.
 *
 * This increases vector's size by one. If the current capacity is equal to the
 * current size, this increases the capacity by at least one and reallocates the
 * entries.
 *
 * @return @c true on success, @c false on failure.
 */
bool vector_append(struct vector *vector, const entry_type *entry);

/**
 * Append an uninitialized entry to a @ref vector.
 *
 * Like @ref vector_append(), but return a pointer to the new (uninitialized)
 * entry.
 *
 * @return The new entry on success, @c NULL on failure.
 */
entry_type *vector_append_entry(struct vector *vector);

/**
 * Append all of the entries from one vector to another.
 *
 * @param[in] dst Vector to append to.
 * @param[in] src Source vector. This is not modified.
 * @return @c true on success, @c false on failure.
 */
bool vector_extend(struct vector *dst, const struct vector *src);

/**
 * Remove and return the last entry in a @ref vector.
 *
 * The vector must not be empty. This decreases the size by one. It does not
 * change the capacity or reallocate the entries.
 *
 * @return A pointer to the removed entry, which remains valid until another
 * entry is inserted in its place or the entries are reallocated.
 */
entry_type *vector_pop(struct vector *vector);
#endif

/**
 * Inline as many entries as possible without making the vector type larger than
 * if @c inline_size was 0.
 *
 * This can be passed as the @c inline_size argument to @ref DEFINE_VECTOR().
 */
#define vector_inline_minimal -1

/**
 * Define a vector type without defining its functions.
 *
 * This is useful when the vector type must be defined in one place (e.g., a
 * header) but the interface is defined elsewhere (e.g., a source file) with
 * @ref DEFINE_VECTOR_FUNCTIONS(). Otherwise, just use @ref DEFINE_VECTOR().
 *
 * This takes the same arguments as @ref DEFINE_VECTOR().
 */
#define DEFINE_VECTOR_TYPE(...)	\
	PP_OVERLOAD(DEFINE_VECTOR_TYPE_I, __VA_ARGS__)(__VA_ARGS__)
#define DEFINE_VECTOR_TYPE_I2(vector, entry_type)	\
	DEFINE_VECTOR_TYPE_I3(vector, entry_type, 0)
#define DEFINE_VECTOR_TYPE_I3(vector, entry_type, inline_size)	\
	DEFINE_VECTOR_TYPE_I4(vector, entry_type, inline_size, size_t)
#define DEFINE_VECTOR_TYPE_I4(vector, entry_type, inline_size, size_type)	\
typedef typeof(entry_type) vector##_entry_type;					\
										\
typedef typeof(size_type) vector##_size_type;					\
_Static_assert((vector##_size_type)-1 > 0, "size_type must be unsigned");	\
_Static_assert((vector##_size_type)-1 <= SIZE_MAX,				\
	       "size_type must not be larger than size_t");			\
										\
enum { vector##_inline_size_arg = (inline_size) };				\
/*										\
 * If the vector was defined with a zero inline size, then we don't want to	\
 * require the complete definition of the entry type, so we do this to stub it	\
 * out.										\
 */										\
typedef_if(vector##_inline_entry_type, vector##_inline_size_arg == 0, void *,	\
	   vector##_entry_type);						\
enum {										\
	vector##_inline_size =							\
		vector##_inline_size_arg == vector_inline_minimal		\
		? sizeof(void *) / sizeof(vector##_inline_entry_type)		\
		: vector##_inline_size_arg,					\
	/* Used to avoid a zero-length array. */				\
	vector##_inline_size_non_zero =						\
		vector##_inline_size == 0 ? 1 : vector##_inline_size,		\
};										\
										\
struct vector {									\
	union {									\
		vector##_entry_type *_data;					\
		/*								\
		 * If the vector has no inline entries, then we want this to	\
		 * degrade to (entry_type *) instead of (entry_type [0]) so that\
		 * the vector is not over-aligned to alignof(entry_type) and to	\
		 * avoid zero-length arrays.					\
		 */								\
		type_if(vector##_inline_size == 0, vector##_entry_type *,	\
			vector##_inline_entry_type [vector##_inline_size_non_zero])\
		_idata;								\
	};									\
	vector##_size_type _size;						\
	vector##_size_type _capacity;						\
};										\
struct DEFINE_VECTOR_needs_semicolon

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
	if (vector##_inline_size == 0)						\
		vector->_data = NULL;						\
	vector->_size = vector->_capacity = 0;					\
}										\
										\
static bool vector##_is_inline(const struct vector *vector)			\
{										\
	return vector##_inline_size > 0	&& vector->_capacity == 0;		\
}										\
										\
__attribute__((__unused__))							\
static void vector##_deinit(struct vector *vector)				\
{										\
	if (!vector##_is_inline(vector))					\
		free(vector->_data);						\
}										\
										\
__attribute__((__unused__))							\
static vector##_size_type vector##_size(const struct vector *vector)		\
{										\
	return vector->_size;							\
}										\
										\
__attribute__((__unused__))							\
static bool vector##_empty(const struct vector *vector)				\
{										\
	return vector->_size == 0;						\
}										\
										\
static const vector##_size_type vector##_max_size =				\
	/* The redundant cast works around llvm/llvm-project#38137. */		\
	(vector##_size_type)min_iconst(PTRDIFF_MAX / sizeof(vector##_entry_type),\
				       (vector##_size_type)-1);			\
										\
static vector##_size_type vector##_capacity(const struct vector *vector)	\
{										\
	if (vector##_is_inline(vector))						\
		return vector##_inline_size;					\
	return vector->_capacity;						\
}										\
										\
static bool vector##_reallocate(struct vector *vector, size_t capacity)		\
{										\
	void *new_data;								\
	if (vector##_is_inline(vector)) {					\
		new_data = malloc(capacity * sizeof(vector##_entry_type));	\
		if (!new_data)							\
			return false;						\
		memcpy(new_data, vector->_idata,				\
		       vector##_size(vector) * sizeof(vector##_entry_type));	\
	} else {								\
		new_data = realloc(vector->_data,				\
				   capacity * sizeof(vector##_entry_type));	\
		if (!new_data)							\
			return false;						\
	}									\
	vector->_data = new_data;						\
	vector->_capacity = capacity;						\
	return true;								\
}										\
										\
static bool vector##_reserve_for_extend(struct vector *vector, size_t n)	\
{										\
	vector##_size_type size = vector##_size(vector);			\
	/*									\
	 * Cast to size_t to avoid -Wsign-error if size_type is promoted to int.\
	 */									\
	if (n <= (size_t)(vector##_capacity(vector) - size))			\
		return true;							\
	if (n > (size_t)(vector##_max_size - size))				\
		return false;							\
	vector##_size_type new_capacity = size + (n > size ? n : size);		\
	if (new_capacity < size || new_capacity > vector##_max_size)		\
		new_capacity = vector##_max_size;				\
	return vector##_reallocate(vector, new_capacity);			\
}										\
										\
__attribute__((__unused__))							\
static bool vector##_resize(struct vector *vector, size_t size)			\
{										\
	if (vector->_size < size						\
	    && !vector##_reserve_for_extend(vector, size - vector->_size))	\
		return false;							\
	vector->_size = size;							\
	return true;								\
}										\
										\
__attribute__((__unused__))							\
static void vector##_clear(struct vector *vector)				\
{										\
	vector->_size = 0;							\
}										\
										\
__attribute__((__unused__))							\
static bool vector##_reserve(struct vector *vector, size_t capacity)		\
{										\
	if (capacity <= vector##_capacity(vector))				\
		return true;							\
	if (capacity > vector##_max_size)					\
		return false;							\
	return vector##_reallocate(vector, capacity);				\
}										\
										\
static bool vector##_reserve_for_append(struct vector *vector)			\
{										\
	return vector##_reserve_for_extend(vector, 1);				\
}										\
										\
__attribute__((__unused__))							\
static void vector##_shrink_to_fit(struct vector *vector)			\
{										\
	vector##_size_type size = vector##_size(vector);			\
	if (vector->_capacity <= size)						\
		return;								\
	if (size > vector##_inline_size) {					\
		vector##_reallocate(vector, size);				\
	} else if (vector##_inline_size > 0) {					\
		void *old_data = vector->_data;					\
		memcpy(vector->_idata, old_data,				\
		       size * sizeof(vector##_entry_type));			\
		free(old_data);							\
		vector->_capacity = 0;						\
	} else {								\
		free(vector->_data);						\
		vector->_data = NULL;						\
		vector->_capacity = 0;						\
	}									\
}										\
										\
/*										\
 * If the vector was defined with a non-zero inline size, make vector_steal()	\
 * fail at compile time by having it take a dummy type incompatible with struct	\
 * vector (but close enough to the real thing so the function body compiles).	\
 */										\
struct vector##_steal_is_undefined_for_non_zero_inline_size {			\
	void *_data;								\
	vector##_size_type _size;						\
};										\
__attribute__((__unused__))							\
static void vector##_steal(type_if(vector##_inline_size_arg == 0,		\
				   struct vector,				\
				   struct vector##_steal_is_undefined_for_non_zero_inline_size)\
			   *vector,						\
			   vector##_entry_type **entries_ret,			\
			   vector##_size_type *size_ret)			\
{										\
	*entries_ret = vector->_data;						\
	if (size_ret)								\
		*size_ret = vector->_size;					\
	vector->_data = NULL;							\
}										\
										\
static vector##_entry_type *vector##_begin(struct vector *vector)		\
{										\
	if (vector##_is_inline(vector))						\
		return vector->_idata;						\
	return vector->_data;							\
}										\
										\
__attribute__((__unused__))							\
static vector##_entry_type *vector##_end(struct vector *vector)			\
{										\
	return add_to_possibly_null_pointer(vector##_begin(vector),		\
					    vector##_size(vector));		\
}										\
										\
__attribute__((__unused__))							\
static vector##_entry_type *vector##_first(struct vector *vector)		\
{										\
	return vector##_begin(vector);						\
}										\
										\
__attribute__((__unused__))							\
static vector##_entry_type *vector##_last(struct vector *vector)		\
{										\
	return vector##_begin(vector) + vector##_size(vector) - 1;		\
}										\
										\
__attribute__((__unused__))							\
static vector##_entry_type *vector##_at(struct vector *vector, size_t i)	\
{										\
	return vector##_begin(vector) + i;					\
}										\
										\
static vector##_entry_type *vector##_append_entry(struct vector *vector)	\
{										\
	if (!vector##_reserve_for_append(vector))				\
		return NULL;							\
	return vector##_begin(vector) + vector->_size++;			\
}										\
										\
__attribute__((__unused__))							\
static bool vector##_append(struct vector *vector,				\
			    const vector##_entry_type *entry)			\
{										\
	vector##_entry_type *new_entry = vector##_append_entry(vector);		\
	if (!new_entry)								\
		return false;							\
	memcpy(new_entry, entry, sizeof(*entry));				\
	return true;								\
}										\
										\
__attribute__((__unused__))							\
static bool vector##_extend(struct vector *dst, const struct vector *src)	\
{										\
	if (src->_size == 0)							\
		return true;							\
	if (!vector##_reserve_for_extend(dst, src->_size))			\
		return false;							\
	memcpy(vector##_end(dst), vector##_begin((struct vector *)src),		\
	       src->_size * sizeof(vector##_entry_type));			\
	dst->_size += src->_size;						\
	return true;								\
}										\
										\
__attribute__((__unused__))							\
static vector##_entry_type *vector##_pop(struct vector *vector)			\
{										\
	return vector##_begin(vector) + --vector->_size;			\
}										\
struct DEFINE_VECTOR_needs_semicolon

/**
 * Define a vector interface.
 *
 * This macro defines a vector type along with its functions. It accepts a
 * variable number of arguments:
 *
 * ```
 * DEFINE_VECTOR(vector, entry_type);
 * DEFINE_VECTOR(vector, entry_type, inline_size);
 * DEFINE_VECTOR(vector, entry_type, inline_size, size_type);
 * ```
 *
 * @param[in] vector Name of the type to define. This is prefixed to all of the
 * types and functions defined for that type.
 * @param[in] entry_type Type of entries in the vector.
 * @param[in] inline_size Number of entries to store directly in the vector type
 * instead of as a separate allocation, or @ref vector_inline_minimal. The
 * default is 0. If this is not 0, then the complete definition of @p entry_type
 * must be available.
 * @param[in] size_type Unsigned integer type to use to store size and capacity.
 * The default is `size_t`.
 */
#define DEFINE_VECTOR(vector, ...)		\
DEFINE_VECTOR_TYPE(vector, __VA_ARGS__);	\
DEFINE_VECTOR_FUNCTIONS(vector)

/**
 * Empty vector initializer.
 *
 * This can be used to initialize a vector when declaring it.
 *
 * @sa vector_init()
 */
#define VECTOR_INIT { { 0 } }

/**
 * Iterate over every entry in a @ref vector.
 *
 * This is roughly equivalent to
 *
 * ```
 *  for (entry_type *it = vector_begin(vector), *end = vector_end(vector);
 *       it != end; it++)
 * ```
 *
 * Except that @p vector is only evaluated once.
 *
 * @param[in] vector_type Name of vector type.
 * @param[out] it Name of iteration variable.
 * @param[in] vector Vector to iterate over.
 */
#define vector_for_each(vector_type, it, vector)			\
	for (vector_type##_entry_type *it,				\
	     *it##__end = ({						\
			struct vector_type *it##__vector = (vector);	\
			it = vector_type##_begin(it##__vector);		\
			vector_type##_end(it##__vector);		\
	     });							\
	     it != it##__end; it++)

/** @} */

#endif /* DRGN_VECTOR_H */
