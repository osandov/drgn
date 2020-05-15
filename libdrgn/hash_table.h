// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * High performance generic hash tables.
 *
 * See @ref HashTables.
 */

#ifndef DRGN_HASH_TABLE_H
#define DRGN_HASH_TABLE_H

#ifdef __SSE2__
#include <emmintrin.h>
#endif
#ifdef __SSE4_2__
#include <nmmintrin.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "cityhash.h"
#include "util.h"

/**
 * @ingroup Internals
 *
 * @defgroup HashTables Hash tables
 *
 * High performance generic hash tables.
 *
 * This is an implementation of Facebook's <a
 * href="https://github.com/facebook/folly/blob/master/folly/container/F14.md">
 * F14</a>, which provides both high performance and good memory efficiency by
 * using SIMD instructions to allow for a high load factor.
 *
 * These hash tables are generic, strongly typed (i.e., keys and values have
 * static types rather than <tt>void *</tt>), and don't have any function pointer
 * overhead. See @ref HashMaps and @ref HashSets.
 *
 * On non-x86 platforms, this falls back to a slower implementation that doesn't
 * use SIMD.
 *
 * Abstractly, a hash table stores @em entries which can be looked up by @em
 * key. A hash table is defined with @ref DEFINE_HASH_TABLE() (or the
 * higher-level wrappers, @ref DEFINE_HASH_MAP() and @ref DEFINE_HASH_SET()).
 * Each generated hash table interface is prefixed with a given name; the
 * interface documented here uses the example name @c hash_table, which could be
 * generated with this example code:
 *
 * @code{.c}
 * key_type entry_to_key(const entry_type *entry);
 * struct hash_pair hash_func(const key_type *key);
 * bool eq_func(const key_type *a, const key_type *b);
 * DEFINE_HASH_TABLE(hash_table, entry_type, entry_to_key, hash_func, eq_func)
 * @endcode
 *
 * @sa BinarySearchTrees
 *
 * @{
 */

/**
 * Hash function output.
 *
 * F14 resolves collisions by double hashing. This type comprises the two
 * hashes.
 *
 * @sa HashTableHelpers
 */
struct hash_pair {
	/**
	 * First hash.
	 *
	 * This is used for selecting the chunk.
	 */
	size_t first;
	/**
	 * Second hash.
	 *
	 * Only the 8 least-significant bits of this are used; the rest are zero
	 * (the folly implementation insists that storing this as @c size_t
	 * generates better code). The 8th bit is always set. This is derived
	 * from @ref hash_pair::first; see @ref
	 * hash_pair_from_avalanching_hash() and @ref
	 * hash_pair_from_non_avalanching_hash().
	 *
	 * This is used as a tag within the chunk, and for the probe stride when
	 * a chunk overflows.
	 */
	size_t second;
};

#ifdef DOXYGEN
/**
 * @struct hash_table
 *
 * Hash table instance.
 *
 * There are no requirements on how this is allocated; it may be global, on the
 * stack, allocated by @c malloc(), embedded in another structure, etc.
 */
struct hash_table;

/**
 * Hash table iterator.
 *
 * Several functions return an iterator or take one as an argument. This
 * iterator has a reference to an entry, which can be @c NULL to indicate that
 * there is no such entry. It may also contain private bookkeeping which should
 * not be used.
 *
 * An iterator remains valid as long as the entry is not deleted and the table
 * is not rehashed.
 */
struct hash_table_iterator {
	/** Pointer to the entry in the hash table. */
	entry_type *entry;
};

/**
 * Compute the hash for a given key.
 *
 * Note that this function is simply a wrapper around the hash function that was
 * passed when defining the hash table. It is provided for convenience.
 */
struct hash_pair hash_table_hash(const key_type *key);

/**
 * Initialize a @ref hash_table.
 *
 * The new hash table is empty. It must be deinitialized with @ref
 * hash_table_deinit().
 */
void hash_table_init(struct hash_table *table);

/**
 * Free memory allocated by a @ref hash_table.
 *
 * After this is called, the hash table must not be used unless it is
 * reinitialized with @ref hash_table_init(). Note that this only frees memory
 * allocated by the hash table implementation; if the keys, values, or the hash
 * table structure itself are dynamically allocated, those must be freed
 * separately.
 */
void hash_table_deinit(struct hash_table *table);

/**
 * Return whether a @ref hash_table has no entries.
 *
 * This is O(1).
 */
bool hash_table_empty(struct hash_table *table);

/**
 * Return the number of entries in a @ref hash_table.
 *
 * This is O(1).
 */
size_t hash_table_size(struct hash_table *table);

/**
 * Delete all entries in a @ref hash_table.
 *
 * This does not necessarily free memory used by the hash table.
 */
void hash_table_clear(struct hash_table *table);

/**
 * Reserve entries in a @ref hash_table.
 *
 * This allocates space up front to ensure that the table will not be rehashed
 * until the table contains the given number of entries.
 *
 * @return @c true on success, @c false on failure.
 */
bool hash_table_reserve(struct hash_table *table, size_t capacity);

/**
 * Insert an entry in a @ref hash_table.
 *
 * If an entry with the same key is already in the hash table, the entry is @em
 * not inserted.
 *
 * @param[out] it_ret If not @c NULL, a returned iterator pointing to the newly
 * inserted entry or the existing entry with the same key.
 * @return 1 if the entry was inserted, 0 if the key already existed, -1 if
 * allocating memory for a rehash failed.
 */
int hash_table_insert(struct hash_table *table, const entry_type *entry,
		      struct hash_table_iterator *it_ret);

/**
 * Insert an entry in a @ref hash_table with a precomputed hash.
 *
 * Like @ref hash_table_insert(), but the hash was already computed. This saves
 * recomputing the hash when doing multiple operations with the same key.
 */
int hash_table_insert_hashed(struct hash_table *table, const entry_type *entry,
			     struct hash_pair hp,
			     struct hash_table_iterator *it_ret);

/**
 * Insert an entry in a @ref hash_table which is not in the table.
 *
 * Like @ref hash_table_insert_hashed(), but a search was previously done and
 * the key is not already in the table. This saves doing a redundant search in
 * that case but is unsafe otherwise.
 */
int hash_table_insert_searched(struct hash_table *table,
			       const entry_type *entry, struct hash_pair hp,
			       struct hash_table_iterator *it_ret);

/**
 * Search for an entry in a @ref hash_table.
 *
 * @return An iterator pointing to the entry with the given key, or an iterator
 * with <tt>entry == NULL</tt> if the key was not found.
 */
struct hash_table_iterator hash_table_search(struct hash_table *table,
					     const key_type *key);

/**
 * Search for an entry in a @ref hash_table with a precomputed hash.
 *
 * Like @ref hash_table_search(), but the hash was already computed. This saves
 * recomputing the hash when doing multiple operations with the same key.
 */
struct hash_table_iterator hash_table_search_hashed(struct hash_table *table,
						    const key_type *key,
						    struct hash_pair hp);

/**
 * Delete an entry in a @ref hash_table.
 *
 * This deletes the entry with the given key. It will never rehash the table.
 *
 * @return @c true if the entry was found and deleted, @c false if not.
 */
bool hash_table_delete(struct hash_table *table, const key_type *key);

/**
 * Delete an entry in a @ref hash_table with a precomputed hash.
 *
 * Like @ref hash_table_delete(), but the hash was already computed. This saves
 * recomputing the hash when doing multiple operations with the same key.
 */
bool hash_table_delete_hashed(struct hash_table *table, struct hash_pair hp);

/**
 * Delete an entry given by an iterator in a @ref hash_table.
 *
 * This deletes the entry pointed to by the iterator. It will never rehash the
 * table.
 *
 * @return An iterator pointing to the next entry in the table. See @ref
 * hash_table_next().
 */
struct hash_table_iterator
hash_table_delete_iterator(struct hash_table *table,
			   struct hash_table_iterator it);

/**
 * Delete an entry given by an iterator in a @ref hash_table with a precomputed
 * hash.
 *
 * Like @ref hash_table_delete_iterator(), but the hash was already computed.
 * This saves recomputing the hash when doing multiple operations with the same
 * key.
 */
struct hash_table_iterator
hash_table_delete_iterator_hashed(struct hash_table *table,
				  struct hash_table_iterator it,
				  struct hash_pair hp);

/**
 * Get an iterator pointing to the first entry in a @ref hash_table.
 *
 * The first entry is arbitrary.
 *
 * @return An iterator pointing to the first entry, or an iterator with
 * <tt>entry == NULL</tt> if the table is empty.
 */
struct hash_table_iterator hash_table_first(struct hash_table *table);

/**
 * Get an iterator pointing to the next entry in a @ref hash_table.
 *
 * The order of entries is arbitrary.
 *
 * @return An iterator pointing to the next entry, or an iterator with <tt>entry
 * == NULL</tt> if there are no more entries.
 */
struct hash_table_iterator hash_table_next(struct hash_table_iterator it);
#endif

static inline size_t hash_table_probe_delta(struct hash_pair hp)
{
	return 2 * hp.second + 1;
}

/*
 * We could represent an empty hash table with chunks set to NULL. However, then
 * we would need a branch to check for this in insert, search, and delete. We
 * could avoid this by allocating an empty chunk, but that is wasteful since it
 * will never actually be used. Instead, we have a special empty chunk which is
 * used by all tables.
 */
extern const uint8_t hash_table_empty_chunk_header[];
#define hash_table_empty_chunk (void *)hash_table_empty_chunk_header

#ifdef __SSE2__
#define HASH_TABLE_CHUNK_MATCH(table)						\
static inline unsigned int table##_chunk_match(struct table##_chunk *chunk,	\
					       size_t needle)			\
{										\
	__m128i tag_vec = _mm_load_si128((__m128i *)chunk);			\
	__m128i needle_vec = _mm_set1_epi8((uint8_t)needle);			\
	__m128i eq_vec = _mm_cmpeq_epi8(tag_vec, needle_vec);			\
	return _mm_movemask_epi8(eq_vec) & table##_chunk_full_mask;		\
}

#define HASH_TABLE_CHUNK_OCCUPIED(table)					\
static inline unsigned int table##_chunk_occupied(struct table##_chunk *chunk)	\
{										\
	__m128i tag_vec = _mm_load_si128((__m128i *)chunk);			\
	return _mm_movemask_epi8(tag_vec) & table##_chunk_full_mask;		\
}
#else
#define HASH_TABLE_CHUNK_MATCH(table)						\
static inline unsigned int table##_chunk_match(struct table##_chunk *chunk,	\
					       size_t needle)			\
{										\
	unsigned int mask, i;							\
										\
	for (mask = 0, i = 0; i < table##_chunk_capacity; i++) {		\
		if (chunk->tags[i] == needle)					\
			mask |= 1U << i;					\
	}									\
	return mask;								\
}

#define HASH_TABLE_CHUNK_OCCUPIED(table)					\
static inline unsigned int table##_chunk_occupied(struct table##_chunk *chunk)	\
{										\
	unsigned int mask, i;							\
										\
	for (mask = 0, i = 0; i < table##_chunk_capacity; i++) {		\
		if (chunk->tags[i])						\
			mask |= 1U << i;					\
	}									\
	return mask;								\
}
#endif

/**
 * Define a hash table type without defining its functions.
 *
 * This is useful when the hash table type must be defined in one place (e.g., a
 * header) but the interface is defined elsewhere (e.g., a source file) with
 * @ref DEFINE_HASH_TABLE_FUNCTIONS(). Otherwise, just use @ref
 * DEFINE_HASH_TABLE().
 *
 * @sa DEFINE_HASH_TABLE()
 */
#define DEFINE_HASH_TABLE_TYPE(table, entry_type, entry_to_key)			\
typedef typeof(entry_type) table##_entry_type;					\
typedef typeof(entry_to_key((table##_entry_type *)0)) table##_key_type;		\
										\
static inline table##_key_type							\
table##_entry_to_key(const table##_entry_type *entry)				\
{										\
	return entry_to_key(entry);						\
}										\
										\
enum {										\
	/*									\
	 * The number of entries per chunk. 14 is the most space efficient, but	\
	 * if an entry is 4 bytes, 12 entries makes a chunk exactly one cache	\
	 * line.								\
	 */									\
	table##_chunk_capacity = sizeof(table##_entry_type) == 4 ? 12 : 14,	\
	/* The maximum load factor in terms of entries per chunk. */		\
	table##_chunk_desired_capacity = table##_chunk_capacity - 2,		\
	/*									\
	 * If an entry is 16 bytes, add an extra 16 bytes of padding to make a	\
	 * chunk exactly four cache lines.					\
	 */									\
	table##_chunk_allocated_capacity =					\
		(table##_chunk_capacity +					\
		 (sizeof(table##_entry_type) == 16 ? 1 : 0)),			\
	table##_chunk_full_mask = (1 << table##_chunk_capacity) - 1,		\
};										\
										\
struct table##_chunk {								\
	uint8_t tags[14];							\
	/*									\
	 * If this is the first chunk, the capacity of the table if it is also	\
	 * the only chunk, and one otherwise. Zero if this is not the first	\
	 * chunk.								\
	 */									\
	uint8_t chunk0_capacity : 4;						\
	/*									\
	 * The number of entries in this chunk that overflowed their desired	\
	 * chunk.								\
	 *									\
	 * Note that this bit field and chunk0_capacity are combined into a	\
	 * single uint8_t member named "control" in the folly implementation.	\
	 */									\
	uint8_t hosted_overflow_count : 4;					\
	/*									\
	 * The number of entries that would have been in this chunk if it were	\
	 * not full. This value saturates if it hits 255, after which it will	\
	 * not be updated.							\
	 */									\
	uint8_t outbound_overflow_count;					\
	table##_entry_type entries[table##_chunk_allocated_capacity];		\
} __attribute__((aligned(16)));							\
										\
struct table##_iterator {							\
	table##_entry_type *entry;						\
	size_t index;								\
};										\
										\
struct table {									\
	struct table##_chunk *chunks;						\
	/* Number of chunks minus one. */					\
	size_t chunk_mask;							\
	/* Number of used values. */						\
	size_t size;								\
	/* Cached first iterator. */						\
	uintptr_t first_packed;							\
};										\

/**
 * Define the functions for a hash table.
 *
 * The hash table type must have already been defined with @ref
 * DEFINE_HASH_TABLE_TYPE().
 *
 * Unless the type and function definitions must be in separate places, use @ref
 * DEFINE_HASH_TABLE() instead.
 *
 * @sa DEFINE_HASH_TABLE()
 */
#define DEFINE_HASH_TABLE_FUNCTIONS(table, hash_func, eq_func)			\
static inline struct hash_pair table##_hash(const table##_key_type *key)	\
{										\
	return hash_func(key);							\
}										\
										\
/*										\
 * We cache the first position in the table as a tagged pointer: we steal the	\
 * bottom bits of the chunk pointer for the entry index. We can do this because	\
 * chunks are aligned to 16 bytes and the index is always less than 16.		\
 *										\
 * The folly implementation mentions this strategy but uses a more complicated	\
 * scheme in order to avoid computing the chunk pointer from an entry pointer.	\
 * We always have the chunk pointer readily available when we want to pack an	\
 * entry, so we can use this much simpler scheme.				\
 */										\
static inline uintptr_t table##_pack_iterator(struct table##_chunk *chunk,	\
					      size_t index)			\
{										\
	return (uintptr_t)chunk | (uintptr_t)index;				\
}										\
										\
static inline struct table##_chunk *table##_unpack_chunk(uintptr_t packed)	\
{										\
	return (struct table##_chunk *)(packed & ~(uintptr_t)0xf);		\
}										\
										\
static inline size_t table##_unpack_index(uintptr_t packed)			\
{										\
	return packed & 0xf;							\
}										\
										\
static inline struct table##_iterator table##_unpack_iterator(uintptr_t packed)	\
{										\
	struct table##_chunk *chunk;						\
	size_t index;								\
										\
	chunk = table##_unpack_chunk(packed);					\
	index = table##_unpack_index(packed);					\
	return (struct table##_iterator){					\
		.entry = chunk ? &chunk->entries[index] : NULL,			\
		.index = index,							\
	};									\
}										\
										\
static inline struct table##_chunk *						\
table##_iterator_chunk(struct table##_iterator it)				\
{										\
	return container_of(it.entry - it.index, struct table##_chunk,		\
			    entries[0]);					\
}										\
										\
HASH_TABLE_CHUNK_MATCH(table)							\
HASH_TABLE_CHUNK_OCCUPIED(table)						\
										\
static inline unsigned int							\
table##_chunk_first_empty(struct table##_chunk *chunk)				\
{										\
	unsigned int mask;							\
										\
	mask = table##_chunk_occupied(chunk) ^ table##_chunk_full_mask;		\
	return mask ? ctz(mask) : (unsigned int)-1;				\
}										\
										\
static inline unsigned int							\
table##_chunk_last_occupied(struct table##_chunk *chunk)			\
{										\
	unsigned int mask;							\
										\
	mask = table##_chunk_occupied(chunk);					\
	return mask ? fls(mask) - 1 : (unsigned int)-1;				\
}										\
										\
static inline void								\
table##_chunk_inc_outbound_overflow_count(struct table##_chunk *chunk)		\
{										\
	if (chunk->outbound_overflow_count != UINT8_MAX)			\
		chunk->outbound_overflow_count++;				\
}										\
										\
static inline void								\
table##_chunk_dec_outbound_overflow_count(struct table##_chunk *chunk)		\
{										\
	if (chunk->outbound_overflow_count != UINT8_MAX)			\
		chunk->outbound_overflow_count--;				\
}										\
										\
__attribute__((unused))								\
static void table##_init(struct table *table)					\
{										\
	table->chunks = hash_table_empty_chunk;					\
	table->chunk_mask = 0;							\
	table->size = 0;							\
	table->first_packed = 0;						\
}										\
										\
__attribute__((unused))								\
static void table##_deinit(struct table *table)					\
{										\
	if (table->chunks != hash_table_empty_chunk)				\
		free(table->chunks);						\
}										\
										\
__attribute__((unused))								\
static inline bool table##_empty(struct table *table)				\
{										\
	return table->size == 0;						\
}										\
										\
__attribute__((unused))								\
static inline size_t table##_size(struct table *table)				\
{										\
	return table->size;							\
}										\
										\
static table##_entry_type *table##_allocate_tag(struct table *table,		\
						uint8_t *fullness,		\
						struct hash_pair hp)		\
{										\
    struct table##_chunk *chunk;						\
    size_t index = hp.first;							\
    size_t delta = hash_table_probe_delta(hp);					\
    uint8_t hosted_inc = 0;							\
    size_t entry_index;								\
										\
    for (;;) {									\
	    index &= table->chunk_mask;						\
	    chunk = &table->chunks[index];					\
	    if (likely(fullness[index] < table##_chunk_capacity))		\
		    break;							\
	    table##_chunk_inc_outbound_overflow_count(chunk);			\
	    hosted_inc = 1;							\
	    index += delta;							\
    }										\
    entry_index = fullness[index]++;						\
    chunk->tags[entry_index] = hp.second;					\
    chunk->hosted_overflow_count += hosted_inc;					\
    return &chunk->entries[entry_index];					\
}										\
										\
static void table##_set_first_packed_after_rehash(struct table *table,		\
						  uint8_t *fullness)		\
{										\
	size_t i;								\
										\
	i = table->chunk_mask;							\
	while (fullness[i] == 0)						\
		i--;								\
	table->first_packed = table##_pack_iterator(&table->chunks[i],		\
						    fullness[i] - 1);		\
}										\
										\
static inline size_t table##_alloc_size(size_t chunk_count, size_t max_size)	\
{										\
	/*									\
	 * Small hash tables are common, so for capacities of less than a full	\
	 * chunk we only allocate the required entries.				\
	 */									\
	if (chunk_count == 1) {							\
		return (offsetof(struct table##_chunk, entries) +		\
			max_size * sizeof(table##_entry_type));			\
	} else {								\
		return chunk_count * sizeof(struct table##_chunk);		\
	}									\
}										\
										\
static bool table##_rehash(struct table *table, size_t new_chunk_count,		\
			   size_t new_max_size)					\
{										\
	struct table##_chunk *orig_chunks = table->chunks;			\
	size_t orig_chunk_mask = table->chunk_mask;				\
	size_t orig_chunk_count = orig_chunk_mask + 1;				\
	size_t alloc_size = table##_alloc_size(new_chunk_count, new_max_size);	\
										\
	/*									\
	 * aligned_alloc() requires that the allocation size is aligned to the	\
	 * allocation alignment.						\
	 */									\
	table->chunks = aligned_alloc(16, (alloc_size + 0xf) & ~(size_t)0xf);	\
	if (!table->chunks)							\
		goto err;							\
	memset(table->chunks, 0, alloc_size);					\
	table->chunks[0].chunk0_capacity =					\
		new_chunk_count == 1 ? new_max_size : 1;			\
	table->chunk_mask = new_chunk_count - 1;				\
										\
	if (table->size == 0) {							\
		/* Nothing to do. */						\
	} else if (orig_chunk_count == 1 && new_chunk_count == 1) {		\
		struct table##_chunk *src, *dst;				\
		size_t src_i = 0, dst_i = 0;					\
										\
		src = &orig_chunks[0];						\
		dst = &table->chunks[0];					\
		while (dst_i < table->size) {					\
			if (likely(src->tags[src_i])) {				\
				dst->tags[dst_i] = src->tags[src_i];		\
				memcpy(&dst->entries[dst_i],			\
				       &src->entries[src_i],			\
				       sizeof(dst->entries[dst_i]));		\
				dst_i++;					\
			}							\
			src_i++;						\
		}								\
		table->first_packed = table##_pack_iterator(dst, dst_i - 1);	\
	} else {								\
		struct table##_chunk *src;					\
		uint8_t stack_fullness[256];					\
		uint8_t *fullness;						\
		size_t remaining;						\
										\
		if (new_chunk_count <= sizeof(stack_fullness)) {		\
			memset(stack_fullness, 0, sizeof(stack_fullness));	\
			fullness = stack_fullness;				\
		} else {							\
			fullness = calloc(new_chunk_count, 1);			\
			if (!fullness)						\
				goto err;					\
		}								\
										\
		src = &orig_chunks[orig_chunk_count - 1];			\
		remaining = table->size;					\
		while (remaining) {						\
			unsigned int mask, i;					\
										\
			mask = table##_chunk_occupied(src);			\
			for_each_bit(i, mask) {					\
				table##_entry_type *src_entry;			\
				table##_entry_type *dst_entry;			\
				table##_key_type key;				\
				struct hash_pair hp;				\
										\
				remaining--;					\
				src_entry = &src->entries[i];			\
				key = table##_entry_to_key(src_entry);		\
				hp = table##_hash(&key);			\
				dst_entry = table##_allocate_tag(table,		\
								 fullness,	\
								 hp);		\
				memcpy(dst_entry, src_entry,			\
				       sizeof(*dst_entry));			\
			}							\
			src--;							\
		}								\
										\
		table##_set_first_packed_after_rehash(table, fullness);		\
										\
		if (fullness != stack_fullness)					\
			free(fullness);						\
	}									\
										\
	if (orig_chunks != hash_table_empty_chunk)				\
		free(orig_chunks);						\
	return true;								\
										\
err:										\
	free(table->chunks);							\
	table->chunks = orig_chunks;						\
	table->chunk_mask = orig_chunk_mask;					\
	return false;								\
}										\
										\
static bool table##_do_reserve(struct table *table, size_t capacity,		\
			       size_t orig_max_size)				\
{										\
	static const size_t initial_capacity = 2;				\
	static const size_t half_chunk_capacity =				\
		(table##_chunk_desired_capacity / 2) & ~(size_t)1;		\
	size_t new_chunk_count, new_max_size;					\
										\
	if (capacity <= half_chunk_capacity) {					\
		new_chunk_count = 1;						\
		new_max_size = (capacity < initial_capacity ?			\
				initial_capacity : half_chunk_capacity);	\
	} else {								\
		new_chunk_count = ((capacity - 1) /				\
				   table##_chunk_desired_capacity + 1);		\
		new_chunk_count = next_power_of_two(new_chunk_count);		\
		new_max_size = (new_chunk_count *				\
				table##_chunk_desired_capacity);		\
										\
		if (new_chunk_count >						\
		    SIZE_MAX / table##_chunk_desired_capacity)			\
			return false;						\
	}									\
										\
	if (new_max_size != orig_max_size)					\
		return table##_rehash(table, new_chunk_count, new_max_size);	\
	else									\
		return true;							\
}										\
										\
static size_t table##_max_size(struct table *table)				\
{										\
	if (table->chunk_mask == 0) {						\
		return table->chunks[0].chunk0_capacity;			\
	} else {								\
		return ((table->chunk_mask + 1) *				\
			table##_chunk_desired_capacity);			\
	}									\
}										\
										\
__attribute__((unused))								\
static bool table##_reserve(struct table *table, size_t capacity)		\
{										\
	if (table->size > capacity)						\
		capacity = table->size;						\
	return table##_do_reserve(table, capacity, table##_max_size(table));	\
}										\
										\
__attribute__((unused))								\
static void table##_clear(struct table *table)					\
{										\
	size_t chunk_count;							\
										\
	if (table->chunks == hash_table_empty_chunk)				\
		return;								\
										\
	/* For large tables, free the chunks. For small tables, zero them. */	\
	chunk_count = table->chunk_mask + 1;					\
	if (chunk_count >= 16) {						\
		free(table->chunks);						\
		table->chunks = hash_table_empty_chunk;				\
		table->chunk_mask = 0;						\
	} else if (table->size) {						\
		uint8_t chunk0_capacity;					\
		size_t alloc_size;						\
										\
		chunk0_capacity = table->chunks[0].chunk0_capacity;		\
		alloc_size = table##_alloc_size(chunk_count,			\
						table##_max_size(table));	\
		memset(table->chunks, 0, alloc_size);				\
		table->chunks[0].chunk0_capacity = chunk0_capacity;		\
	}									\
	table->size = 0;							\
	table->first_packed = 0;						\
}										\
										\
static struct table##_iterator							\
table##_search_hashed(struct table *table, const table##_key_type *key,		\
		      struct hash_pair hp)					\
{										\
	size_t index = hp.first;						\
	size_t delta = hash_table_probe_delta(hp);				\
	size_t tries;								\
										\
	for (tries = 0; tries <= table->chunk_mask; tries++) {			\
		struct table##_chunk *chunk;					\
		unsigned int mask, i;						\
										\
		chunk = &table->chunks[index & table->chunk_mask];		\
		if (sizeof(*chunk) > 64)					\
			__builtin_prefetch(&chunk->entries[8]);			\
		mask = table##_chunk_match(chunk, hp.second);			\
		for_each_bit(i, mask) {						\
			table##_entry_type *entry;				\
			table##_key_type entry_key;				\
										\
			entry = &chunk->entries[i];				\
			entry_key = table##_entry_to_key(entry);		\
			if (likely(eq_func(key, &entry_key))) {			\
				return (struct table##_iterator){		\
					.entry = entry,				\
					.index = i,				\
				};						\
			}							\
		}								\
		if (likely(chunk->outbound_overflow_count == 0))		\
			break;							\
		index += delta;							\
	}									\
	return (struct table##_iterator){};					\
}										\
										\
__attribute__((unused))								\
static struct table##_iterator							\
table##_search(struct table *table, const table##_key_type *key)		\
{										\
	return table##_search_hashed(table, key, table##_hash(key));		\
}										\
										\
static bool table##_reserve_for_insert(struct table *table)			\
{										\
	size_t capacity, max_size;						\
										\
	capacity = table->size + 1;						\
	max_size = table##_max_size(table);					\
	if (capacity - 1 >= max_size)						\
		return table##_do_reserve(table, capacity, max_size);		\
	else									\
		return true;							\
}										\
										\
static void									\
table##_adjust_size_and_first_after_insert(struct table *table,			\
					   struct table##_chunk *chunk,		\
					   size_t index)			\
{										\
	uintptr_t first_packed;							\
										\
	first_packed = table##_pack_iterator(chunk, index);			\
	if (first_packed > table->first_packed)					\
		table->first_packed = first_packed;				\
	table->size++;								\
}										\
										\
static int table##_insert_searched(struct table *table,				\
				   const table##_entry_type *entry,		\
				   struct hash_pair hp,				\
				   struct table##_iterator *it_ret)		\
{										\
	size_t index = hp.first;						\
	struct table##_chunk *chunk;						\
	unsigned int first_empty;						\
										\
	if (!table##_reserve_for_insert(table))					\
		return -1;							\
										\
	chunk = &table->chunks[index & table->chunk_mask];			\
	first_empty = table##_chunk_first_empty(chunk);				\
	if (first_empty == (unsigned int)-1) {					\
		size_t delta = hash_table_probe_delta(hp);			\
										\
		do {								\
			table##_chunk_inc_outbound_overflow_count(chunk);	\
			index += delta;						\
			chunk = &table->chunks[index & table->chunk_mask];	\
			first_empty = table##_chunk_first_empty(chunk);		\
		} while (first_empty == (unsigned int)-1);			\
		chunk->hosted_overflow_count++;					\
	}									\
	chunk->tags[first_empty] = hp.second;					\
	memcpy(&chunk->entries[first_empty], entry, sizeof(*entry));		\
	table##_adjust_size_and_first_after_insert(table, chunk, first_empty);	\
	if (it_ret) {								\
		it_ret->entry = &chunk->entries[first_empty];			\
		it_ret->index = first_empty;					\
	}									\
	return 1;								\
}										\
										\
static int table##_insert_hashed(struct table *table,				\
				 const table##_entry_type *entry,		\
				 struct hash_pair hp,				\
				 struct table##_iterator *it_ret)		\
{										\
	table##_key_type key = table##_entry_to_key(entry);			\
	struct table##_iterator it = table##_search_hashed(table, &key, hp);	\
										\
	if (it.entry) {								\
		if (it_ret)							\
			*it_ret = it;						\
		return 0;							\
	} else {								\
		return table##_insert_searched(table, entry, hp, it_ret);	\
	}									\
}										\
										\
__attribute__((unused))								\
static int table##_insert(struct table *table,					\
			  const table##_entry_type *entry,			\
			  struct table##_iterator *it_ret)			\
{										\
	table##_key_type key = table##_entry_to_key(entry);			\
										\
	return table##_insert_hashed(table, entry, table##_hash(&key), it_ret);	\
}										\
										\
/* Similar to table##_next_impl() but for the cached first position. */		\
static void table##_advance_first_packed(struct table *table)			\
{										\
	uintptr_t packed = table->first_packed;					\
	struct table##_chunk *chunk;						\
	size_t index;								\
										\
	chunk = table##_unpack_chunk(packed);					\
	index = table##_unpack_index(packed);					\
	while (index > 0) {							\
		index--;							\
		if (chunk->tags[index]) {					\
			table->first_packed = table##_pack_iterator(chunk, index);\
			return;							\
		}								\
	}									\
										\
	/*									\
	 * This is only called when there is another entry in the table, so we	\
	 * don't need to check if we hit the end.				\
	 */									\
	for (;;) {								\
		unsigned int last;						\
										\
		chunk--;							\
		last = table##_chunk_last_occupied(chunk);			\
		if (last != (unsigned int)-1) {					\
			table->first_packed = table##_pack_iterator(chunk, last);\
			return;							\
		}								\
	}									\
}										\
										\
static void									\
table##_adjust_size_and_first_before_delete(struct table *table,		\
					    struct table##_chunk *chunk,	\
					    size_t index)			\
{										\
	uintptr_t packed;							\
										\
	table->size--;								\
	packed = table##_pack_iterator(chunk, index);				\
	if (packed == table->first_packed) {					\
		if (table->size == 0)						\
			table->first_packed = 0;				\
		else								\
			table##_advance_first_packed(table);			\
	}									\
}										\
										\
/*										\
 * We want this inlined so that the whole function call can be optimized away	\
 * in the likely_dead case, and so that the counter can be optimized away in	\
 * the not likely_dead case.							\
 */										\
__attribute__((always_inline))							\
static inline struct table##_iterator						\
table##_next_impl(struct table##_iterator it, bool likely_dead)			\
{										\
	struct table##_chunk *chunk;						\
	size_t i;								\
										\
	chunk = table##_iterator_chunk(it);					\
	while (it.index > 0) {							\
		it.index--;							\
		it.entry--;							\
		if (likely(chunk->tags[it.index]))				\
			return it;						\
	}									\
										\
	/*									\
	 * This hack is copied from the folly implementation: this is dead code	\
	 * if the return value is not used (e.g., the return value of		\
	 * table##_delete_iterator() is often ignored), but the compiler needs	\
	 * some help proving that the following loop terminates.		\
	 */									\
	for (i = 1; !likely_dead || i != 0; i++) {				\
		unsigned int last;						\
										\
		if (unlikely(chunk->chunk0_capacity != 0))			\
			break;							\
										\
		chunk--;							\
		last = table##_chunk_last_occupied(chunk);			\
		if (!likely_dead)						\
			__builtin_prefetch(chunk - 1);				\
		if (likely(last != (unsigned int)-1)) {				\
			it.index = last;					\
			it.entry = &chunk->entries[last];			\
			return it;						\
		}								\
	}									\
	return (struct table##_iterator){};					\
}										\
										\
static void table##_do_delete(struct table *table, struct table##_iterator it,	\
			      struct hash_pair hp)				\
{										\
	struct table##_chunk *it_chunk, *chunk;					\
										\
	it_chunk = table##_iterator_chunk(it);					\
	it_chunk->tags[it.index] = 0;						\
										\
	table##_adjust_size_and_first_before_delete(table, it_chunk, it.index);	\
										\
	if (it_chunk->hosted_overflow_count) {					\
		size_t index = hp.first;					\
		size_t delta = hash_table_probe_delta(hp);			\
		uint8_t hosted_dec = 0;						\
										\
		for (;;) {							\
			chunk = &table->chunks[index & table->chunk_mask];	\
			if (chunk == it_chunk) {				\
				chunk->hosted_overflow_count -= hosted_dec;	\
				break;						\
			}							\
			table##_chunk_dec_outbound_overflow_count(chunk);	\
			hosted_dec = -1;					\
			index += delta;						\
		}								\
	}									\
}										\
										\
/*										\
 * We want this inlined so that the call to table##_next_impl() can be		\
 * optimized away.								\
 */										\
__attribute__((always_inline))							\
static inline struct table##_iterator						\
table##_delete_iterator_hashed(struct table *table, struct table##_iterator it,	\
			       struct hash_pair hp)				\
{										\
	table##_do_delete(table, it, hp);					\
	return table##_next_impl(it, true);					\
}										\
										\
__attribute__((always_inline))							\
static inline struct table##_iterator						\
table##_delete_iterator(struct table *table, struct table##_iterator it)	\
{										\
	struct hash_pair hp = {};						\
										\
	/* We only need the hash if the chunk hosts an overflowed entry. */	\
	if (table##_iterator_chunk(it)->hosted_overflow_count) {		\
		table##_key_type key = table##_entry_to_key(it.entry);		\
										\
		hp = table##_hash(&key);					\
	}									\
	table##_do_delete(table, it, hp);					\
	return table##_next_impl(it, true);					\
}										\
										\
static bool table##_delete_hashed(struct table *table,				\
				  const table##_key_type *key,			\
				  struct hash_pair hp)				\
{										\
	struct table##_iterator it;						\
										\
	it = table##_search_hashed(table, key, hp);				\
	if (it.entry) {								\
		table##_do_delete(table, it, hp);				\
		return true;							\
	} else {								\
		return false;							\
	}									\
}										\
										\
__attribute__((unused))								\
static bool table##_delete(struct table *table, const table##_key_type *key)	\
{										\
	return table##_delete_hashed(table, key, table##_hash(key));		\
}										\
										\
__attribute__((unused))								\
static struct table##_iterator table##_first(struct table *table)		\
{										\
	return table##_unpack_iterator(table->first_packed);			\
}										\
										\
__attribute__((unused))								\
static struct table##_iterator table##_next(struct table##_iterator it)		\
{										\
	return table##_next_impl(it, false);					\
}

/**
 * Define a hash table interface.
 *
 * This macro defines a hash table type along with its functions.
 *
 * @param[in] table Name of the type to define. This is prefixed to all of the
 * types and functions defined for that type.
 * @param[in] entry_type Type of entries in the table.
 * @param[in] entry_to_key Name of function or macro which is passed a <tt>const
 * entry_type *</tt> and returns the key for that entry. The return type is the
 * @c key_type of the hash table. The passed entry is never @c NULL.
 * @param[in] hash_func Hash function which takes a <tt>const key_type *</tt>
 * and returns a @ref hash_pair.
 * @param[in] eq_func Comparison function which takes two <tt>const key_type
 * *</tt> and returns a @c bool.
 */
#define DEFINE_HASH_TABLE(table, entry_type, entry_to_key, hash_func, eq_func)	\
DEFINE_HASH_TABLE_TYPE(table, entry_type, entry_to_key)				\
DEFINE_HASH_TABLE_FUNCTIONS(table, hash_func, eq_func)

#define HASH_MAP_ENTRY_TO_KEY(entry) ((entry)->key)

/**
 * Define a hash map type without defining its functions.
 *
 * The functions are defined with @ref DEFINE_HASH_TABLE_FUNCTIONS().
 *
 * @sa DEFINE_HASH_MAP(), DEFINE_HASH_TABLE_TYPE()
 */
#define DEFINE_HASH_MAP_TYPE(table, key_type, value_type)			\
struct table##_entry {								\
	typeof(key_type) key;							\
	typeof(value_type) value;						\
};										\
DEFINE_HASH_TABLE_TYPE(table, struct table##_entry, HASH_MAP_ENTRY_TO_KEY)

/**
 * Define a hash map interface.
 *
 * This is a higher-level wrapper for @ref DEFINE_HASH_TABLE() with entries of
 * the following type (with the example name @c hash_map):
 *
 * @code{.c}
 * struct hash_map_entry {
 *     key_type key;
 *     value_type value;
 * };
 * @endcode
 *
 * @param[in] table Name of the map type to define. This is prefixed to all of
 * the types and functions defined for that type.
 * @param[in] key_type Type of keys in the map.
 * @param[in] value_type Type of values in the map.
 * @param[in] hash_func See @ref DEFINE_HASH_TABLE().
 * @param[in] eq_func See @ref DEFINE_HASH_TABLE().
 */
#define DEFINE_HASH_MAP(table, key_type, value_type, hash_func, eq_func)	\
DEFINE_HASH_MAP_TYPE(table, key_type, value_type)				\
DEFINE_HASH_TABLE_FUNCTIONS(table, hash_func, eq_func)

#define HASH_SET_ENTRY_TO_KEY(entry) (*(entry))

/**
 * Define a hash set type without defining its functions.
 *
 * The functions are defined with @ref DEFINE_HASH_TABLE_FUNCTIONS().
 *
 * @sa DEFINE_HASH_SET(), DEFINE_HASH_TABLE_TYPE()
 */
#define DEFINE_HASH_SET_TYPE(table, key_type)	\
	DEFINE_HASH_TABLE_TYPE(table, key_type, HASH_SET_ENTRY_TO_KEY)

/**
 * Define a hash set interface.
 *
 * This is a higher-level wrapper for @ref DEFINE_HASH_TABLE() where @p
 * entry_type is the same as @p key_type.
 *
 * @param[in] table Name of the set type to define. This is prefixed to all of
 * the types and functions defined for that type.
 * @param[in] key_type Type of keys in the set.
 * @param[in] hash_func See @ref DEFINE_HASH_TABLE().
 * @param[in] eq_func See @ref DEFINE_HASH_TABLE().
 */
#define DEFINE_HASH_SET(table, key_type, hash_func, eq_func)	\
DEFINE_HASH_SET_TYPE(table, key_type)				\
DEFINE_HASH_TABLE_FUNCTIONS(table, hash_func, eq_func)

/**
 * @defgroup HashTableHelpers Hash table helpers
 *
 * Hash functions and comparators for common key types.
 *
 * F14 requires that hash functions are avalanching, which means that each bit
 * of the hash value has a 50% chance of being the same for different inputs.
 * This is the case for cryptographic hash functions as well as certain
 * non-cryptographic hash functions like CityHash, MurmurHash, SipHash, xxHash,
 * etc.
 *
 * Simple hashes like DJBX33A, ad-hoc combinations like <tt>53 * x + y</tt>, and
 * the identity function are not avalanching.
 *
 * These hash functions are all avalanching.
 *
 * @{
 */

/**
 * Split an avalanching hash into a @ref hash_pair.
 *
 * We construct the second hash from the upper bits of the first hash, which we
 * would otherwise discard when masking to select the chunk.
 */
static inline struct hash_pair hash_pair_from_avalanching_hash(size_t hash)
{
	return (struct hash_pair){
		.first = hash,
		.second = (hash >> (8 * sizeof(hash) - 8)) | 0x80,
	};
}

/** Mix a non-avalanching hash and split it into a @ref hash_pair. */
static inline struct hash_pair hash_pair_from_non_avalanching_hash(size_t hash)
{
#if SIZE_MAX == 0xffffffffffffffff
#ifdef __SSE4_2__
/* 64-bit with SSE4.2 uses CRC32 */
	size_t c = _mm_crc32_u64(0, hash);

	return (struct hash_pair){
		.first = hash + c,
		.second = (c >> 24) | 0x80,
	};
#else
/* 64-bit without SSE4.2 uses a 128-bit multiplication-based mixer */
	static const uint64_t multiplier = UINT64_C(0xc4ceb9fe1a85ec53);
	uint64_t hi, lo;

	hi = ((unsigned __int128)hash * multiplier) >> 64;
	lo = hash * multiplier;
	hash = hi ^ lo;
	hash *= multiplier;
	return (struct hash_pair){
		.first = hash >> 22,
		.second = (hash >> 15) | 0x80,
	};
#endif
#elif SIZE_MAX == 0xffffffff
/* 32-bit with SSE4.2 uses CRC32 */
#ifdef __SSE4_2__
	size_t c = _mm_crc32_u32(0, hash);

	return (struct hash_pair){
		.first = hash + c,
		.second = (uint8_t)(~(c >> 25)),
	};
#else
/* 32-bit without SSE4.2 uses the 32-bit Murmur2 finalizer */
	hash ^= hash >> 13;
	hash *= 0x5bd1e995;
	hash ^= hash >> 15;
	return (struct hash_pair){
		.first = hash,
		.second = (uint8_t)(~(hash >> 25)),
	};
#endif
#else
#error "unknown SIZE_MAX"
#endif
}

#ifdef DOXYGEN
/**
 * Hash an integral key.
 *
 * A common hash function for integers is the identity function, which clearly
 * does not avalanche at all. This avalanching hash function can be used for any
 * integer key type.
 */
struct hash_pair hash_pair_int_type(const T *key);
#else
#if SIZE_MAX == 0xffffffffffffffff
static inline uint64_t hash_128_to_64(unsigned __int128 hash)
{
	return cityhash_128_to_64(hash, hash >> 64);
}

#define hash_pair_int_type(key) ({				\
	__auto_type _key = *(key);				\
								\
	sizeof(_key) > sizeof(size_t) ?				\
	hash_pair_from_avalanching_hash(hash_128_to_64(_key)) :	\
	hash_pair_from_non_avalanching_hash(_key);		\
})
#else
/* Thomas Wang downscaling hash function. */
static inline uint32_t hash_64_to_32(uint64_t hash)
{
	hash = (~hash) + (hash << 18);
	hash = hash ^ (hash >> 31);
	hash = hash * 21;
	hash = hash ^ (hash >> 11);
	hash = hash + (hash << 6);
	hash = hash ^ (hash >> 22);
	return hash;
}

#define hash_pair_int_type(key) ({				\
	__auto_type _key = *(key);				\
								\
	sizeof(_key) > sizeof(size_t) ?				\
	hash_pair_from_avalanching_hash(hash_64_to_32(_key)) :	\
	hash_pair_from_non_avalanching_hash(_key);		\
})
#endif
#endif

#ifdef DOXYGEN
/**
 * Hash a pointer type.
 *
 * This avalanching hash function can be used when the key is a pointer value
 * (rather than the dereferenced value).
 */
struct hash_pair hash_pair_ptr_type(T * const *key);
#else
#define hash_pair_ptr_type(key) ({		\
	uintptr_t _ptr = (uintptr_t)*key;	\
						\
	hash_pair_int_type(&_ptr);		\
})
#endif

#ifdef DOXYGEN
/**
 * Return whether two scalar keys are equal.
 *
 * This can be used as the key comparison function for any scalar key type
 * (e.g., integers, floating-point numbers, pointers).
 */
bool hash_table_scalar_eq(const T *a, const T *b);
#else
#define hash_table_scalar_eq(a, b) ((bool)(*(a) == *(b)))
#endif

/**
 * Combine two hash values into one.
 *
 * This is useful for compound types (e.g., a 3D point type or an array). The
 * input hash functions need not be avalanching; the output will be avalanching
 * regardless, so the following would be valid:
 *
 * <tt>hash_pair_from_avalanching_hash(hash_combine(hash_combine(p->x, p->y), p->z))</tt>
 */
static inline size_t hash_combine(size_t a, size_t b)
{
#if SIZE_MAX == 0xffffffffffffffff
	return cityhash_128_to_64(b, a);
#else
	return hash_64_to_32(((uint64_t)a << 32) | b);
#endif
}

#ifdef DOXYGEN
/** Hash a null-terminated string. */
struct hash_pair c_string_hash(const char * const *key);
#else
#define c_string_hash(key) ({					\
	const char *_key = *(key);				\
	size_t _hash = cityhash_size_t(_key, strlen(_key));	\
								\
	hash_pair_from_avalanching_hash(_hash);			\
})
#endif

#ifdef DOXYGEN
/** Compare two null-terminated string keys for equality. */
bool c_string_eq(const char * const *a, const char * const *b);
#else
#define c_string_eq(a, b) ({			\
	const char *_a = *(a), *_b = *(b);	\
						\
	(bool)(strcmp(_a, _b) == 0);		\
})
#endif

/** A string with a given length. */
struct string {
	/**
	 * The string, which is not necessarily null-terminated and may have
	 * embedded null bytes.
	 */
	const char *str;
	/** The length in bytes of the string. */
	size_t len;
};

/** Hash a @ref string. */
static inline struct hash_pair string_hash(const struct string *key)
{
	size_t hash = cityhash_size_t(key->str, key->len);

	return hash_pair_from_avalanching_hash(hash);
}

/** Compare two @ref string keys for equality. */
static inline bool string_eq(const struct string *a, const struct string *b)
{
	/*
	 * len == 0 is a special case because memcmp(NULL, NULL, 0) is
	 * technically undefined.
	 */
	return (a->len == b->len &&
		(a->len == 0 || memcmp(a->str, b->str, a->len) == 0));
}

/** @} */

/** @} */

#endif /* DRGN_HASH_TABLE_H */
