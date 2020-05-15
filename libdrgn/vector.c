// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

#include "vector.h"

bool vector_do_reserve(size_t new_capacity, size_t entry_size, void **data,
		       size_t *capacity)
{
	size_t bytes;
	void *new_data;

	if (new_capacity <= *capacity || new_capacity == 0)
		return true;
	if (__builtin_mul_overflow(new_capacity, entry_size, &bytes))
		return false;
	new_data = realloc(*data, bytes);
	if (!new_data)
		return false;
	*data = new_data;
	*capacity = new_capacity;
	return true;
}

void vector_do_shrink_to_fit(size_t size, size_t entry_size, void **data,
			     size_t *capacity)
{
	void *new_data;

	if (*capacity > size) {
		/*
		 * We already have at least size * entry_size bytes allocated,
		 * so we don't need to worry about overflow.
		 */
		new_data = realloc(*data, size * entry_size);
		if (new_data) {
			*data = new_data;
			*capacity = size;
		}
	}
}

bool vector_reserve_for_append(size_t size, size_t entry_size, void **data,
			       size_t *capacity)
{
	size_t new_capacity, bytes;
	void *new_data;

	if (size < *capacity)
		return true;
	if (*capacity == 0)
		new_capacity = 1;
	else if (__builtin_mul_overflow(2U, *capacity, &new_capacity))
		return false;
	if (__builtin_mul_overflow(new_capacity, entry_size, &bytes))
		return false;
	new_data = realloc(*data, bytes);
	if (!new_data)
		return false;
	*data = new_data;
	*capacity = new_capacity;
	return true;
}
