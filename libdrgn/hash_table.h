// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

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
#include <emmintrin.h> // IWYU pragma: keep
#endif
#ifdef __SSE4_2__
#include <nmmintrin.h>
#endif
#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "bitops.h"
#include "cityhash.h"
#include "minmax.h"
#include "nstring.h" // IWYU pragma: export
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
 * static types rather than <tt>void *</tt>), and don't have any function
 * pointer overhead.
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
 * Double hash.
 *
 * @sa HashTableHelpers
 */
struct hash_pair {
	/**
	 * First hash.
	 *
	 * F14 uses this to select the chunk.
	 */
	size_t first;
	/**
	 * Second hash.
	 *
	 * F14 uses this as the tag within the chunk and as the probe stride
	 * when a chunk overflows.
	 *
	 * Only the 8 least-significant bits of this are used; the rest are zero
	 * (the folly implementation insists that storing this as @c size_t
	 * generates better code). The 8th bit is always set. This is derived
	 * from @ref hash_pair::first; see @ref
	 * hash_pair_from_avalanching_hash() and @ref
	 * hash_pair_from_non_avalanching_hash().
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
 * there is no such entry. It also contains private bookkeeping which should not
 * be used.
 *
 * An iterator remains valid until the table is rehashed or the entry or one
 * before it is deleted.
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
 *
 * @sa HASH_TABLE_INIT
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
 * This allocates space up front and rehashes the table to ensure that it will
 * not be rehashed until it contains the given number of entries.
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

enum {
	hash_table_chunk_alignment = max_iconst(alignof(max_align_t),
						(size_t)16),
};

static inline size_t hash_table_probe_delta(struct hash_pair hp)
{
	return 2 * hp.second + 1;
}

static const uint8_t hosted_overflow_count_inc = 0x10;
static const uint8_t hosted_overflow_count_dec = -0x10;

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
#define DEFINE_HASH_TABLE_TYPE(table, entry_type)				\
typedef typeof(entry_type) table##_entry_type;					\
										\
enum {										\
	/*									\
	 * Whether this table uses the vector storage policy.			\
	 *									\
	 * The vector policy provides the best performance and memory		\
	 * efficiency for medium and large entries.				\
	 */									\
	table##_vector_policy = sizeof(table##_entry_type) >= 24,		\
};										\
										\
struct table {									\
	struct table##_chunk *chunks;						\
	struct {								\
		/*								\
		 * The vector storage policy stores 32-bit indices, so we only	\
		 * need 32-bit sizes.						\
		 */								\
		uint32_t chunk_mask;						\
		uint32_t size;							\
		/* Allocated together with chunks. */				\
		table##_entry_type *entries;					\
	} vector[table##_vector_policy];					\
	struct {								\
		size_t chunk_mask;						\
		size_t size;							\
		uintptr_t first_packed;						\
	} basic[!table##_vector_policy];					\
};

/*
 * Common search function implementation returning an item iterator. This is
 * shared by key lookups and index lookups.
 */
#define HASH_TABLE_SEARCH_IMPL(table, func, key_type, item_to_key, eq_func)	\
static struct table##_iterator table##_##func(struct table *table,		\
					      const key_type *key,		\
					      struct hash_pair hp)		\
{										\
	const size_t delta = hash_table_probe_delta(hp);			\
	size_t index = hp.first;						\
	for (size_t tries = 0; tries <= table##_chunk_mask(table); tries++) {	\
		struct table##_chunk *chunk =					\
			&table->chunks[index & table##_chunk_mask(table)];	\
		if (sizeof(*chunk) > 64)					\
			__builtin_prefetch(&chunk->items[8]);			\
		unsigned int mask = table##_chunk_match(chunk, hp.second), i;	\
		for_each_bit(i, mask) {						\
			table##_item_type *item = &chunk->items[i];		\
			key_type item_key = item_to_key(table, item);		\
			if (likely(eq_func(key, &item_key))) {			\
				return (struct table##_iterator){		\
					.item = item,				\
					.index = i,				\
				};						\
			}							\
		}								\
		if (likely(chunk->outbound_overflow_count == 0))		\
			break;							\
		index += delta;							\
	}									\
	return (struct table##_iterator){};					\
}

#define HASH_TABLE_SEARCH_BY_INDEX_ITEM_TO_KEY(table, item) (*(item)->index)

/**
 * Define the functions for a hash table.
 *
 * The hash table type must have already been defined with @ref
 * DEFINE_HASH_TABLE_TYPE().
 *
 * Unless the type and function definitions must be in separate places, use @ref
 * DEFINE_HASH_TABLE() instead.
 */
#define DEFINE_HASH_TABLE_FUNCTIONS(table, entry_to_key, hash_func, eq_func)	\
typedef typeof(entry_to_key((table##_entry_type *)0)) table##_key_type;		\
										\
static inline table##_key_type							\
table##_entry_to_key(const table##_entry_type *entry)				\
{										\
	return entry_to_key(entry);						\
}										\
										\
/*										\
 * Item stored in a chunk.							\
 *										\
 * When using the basic policy, the entry is stored directly in the item. When	\
 * using the vector policy, the item is an index to an out-of-band vector of	\
 * entries.									\
 *										\
 * C doesn't make it easy to define a type conditionally, so we use a nasty	\
 * hack: the member for the used policy is an array of length 1, and the unused	\
 * member is an array of length 0. We also have to force the struct to be	\
 * aligned only for the used member.						\
 */										\
typedef struct {								\
	uint32_t index[table##_vector_policy];					\
	table##_entry_type entry[!table##_vector_policy];			\
} __attribute__((__packed__,							\
		 __aligned__(table##_vector_policy ?				\
			     alignof(uint32_t) : alignof(table##_entry_type))))	\
table##_item_type;								\
										\
enum {										\
	/*									\
	 * The number of items per chunk. 14 is the most space efficient, but	\
	 * if an item is 4 bytes, 12 items makes a chunk exactly one cache	\
	 * line.								\
	 */									\
	table##_chunk_capacity = sizeof(table##_item_type) == 4 ? 12 : 14,	\
	/* The maximum load factor in terms of items per chunk. */		\
	table##_chunk_desired_capacity = table##_chunk_capacity - 2,		\
	/*									\
	 * If an item is 16 bytes, add an extra 16 bytes of padding to make a	\
	 * chunk exactly four cache lines.					\
	 */									\
	table##_chunk_allocated_capacity =					\
		(table##_chunk_capacity +					\
		 (sizeof(table##_item_type) == 16 ? 1 : 0)),			\
	/*									\
	 * If the chunk capacity is 12, we can use tags 12 and 13 for 16 bits.	\
	 * Otherwise, we only get 4 from control.				\
	 */									\
	table##_capacity_scale_bits = table##_chunk_capacity == 12 ? 16 : 4,	\
	table##_capacity_scale_shift = table##_capacity_scale_bits - 4,		\
	table##_chunk_full_mask = (1 << table##_chunk_capacity) - 1,		\
};										\
										\
struct table##_chunk {								\
	uint8_t tags[14];							\
	/*									\
	 * The lower 4 bits are capacity_scale: for the first chunk, this is	\
	 * the scaling factor between the chunk count and the capacity; for	\
	 * other chunks, this is zero.						\
	 *									\
	 * The upper 4 bits are hosted_overflow_count: the number of entries in	\
	 * this chunk that overflowed their desired chunk.			\
	 */									\
	uint8_t control;							\
	/*									\
	 * The number of entries that would have been in this chunk if it were	\
	 * not full. This value saturates if it hits 255, after which it will	\
	 * not be updated.							\
	 */									\
	uint8_t outbound_overflow_count;					\
	table##_item_type items[table##_chunk_allocated_capacity];		\
} __attribute__((__aligned__(hash_table_chunk_alignment)));			\
										\
/*										\
 * This may be a "public iterator" (used by the public interface to refer to an	\
 * entry) or an "item iterator" (used by certain internal functions to refer to	\
 * an item regardless of the storage policy).					\
 */										\
struct table##_iterator {							\
	union {									\
		/* Entry if public iterator. */					\
		table##_entry_type *entry;					\
		/*								\
		 * Item if item iterator. Interchangable with entry when using	\
		 * the basic storage policy.					\
		 */								\
		table##_item_type *item;					\
	};									\
	union {									\
		/*								\
		 * Lowest entry if public iterator and using the vector storage	\
		 * policy (i.e., table->vector->entries).			\
		 */								\
		table##_entry_type *lowest;					\
		/*								\
		 * Index of item in its containing chunk if item iterator or	\
		 * using the basic storage policy.				\
		 */								\
		size_t index;							\
	};									\
};										\
										\
static inline struct hash_pair table##_hash(const table##_key_type *key)	\
{										\
	return hash_func(key);							\
}										\
										\
static inline table##_entry_type *						\
table##_item_to_entry(struct table *table, table##_item_type *item)		\
{										\
	if (table##_vector_policy) {						\
		return &table->vector->entries[*item->index];			\
	} else {								\
		/*								\
		 * Returning item->entry directly results in a false positive	\
		 * -Waddress-of-packed-member warning.				\
		 */								\
		void *entry = item->entry;					\
		return entry;							\
	}									\
}										\
										\
static inline table##_key_type							\
table##_item_to_key(struct table *table, table##_item_type *item)		\
{										\
	return table##_entry_to_key(table##_item_to_entry(table, item));	\
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
	struct table##_chunk *chunk = table##_unpack_chunk(packed);		\
	size_t index = table##_unpack_index(packed);				\
	return (struct table##_iterator) {					\
		.item = chunk ? &chunk->items[index] : NULL,			\
		.index = index,							\
	};									\
}										\
										\
static inline struct table##_chunk *						\
table##_iterator_chunk(struct table##_iterator it)				\
{										\
	return container_of(it.item - it.index, struct table##_chunk, items[0]);\
}										\
										\
HASH_TABLE_CHUNK_MATCH(table)							\
HASH_TABLE_CHUNK_OCCUPIED(table)						\
										\
static inline unsigned int							\
table##_chunk_first_empty(struct table##_chunk *chunk)				\
{										\
	unsigned int mask =							\
		table##_chunk_occupied(chunk) ^ table##_chunk_full_mask;	\
	return mask ? ctz(mask) : (unsigned int)-1;				\
}										\
										\
static inline unsigned int							\
table##_chunk_last_occupied(struct table##_chunk *chunk)			\
{										\
	unsigned int mask = table##_chunk_occupied(chunk);			\
	return mask ? fls(mask) - 1 : (unsigned int)-1;				\
}										\
										\
static inline size_t								\
table##_chunk_hosted_overflow_count(struct table##_chunk *chunk)		\
{										\
	return chunk->control >> 4;						\
}										\
										\
static inline void								\
table##_chunk_adjust_hosted_overflow_count(struct table##_chunk *chunk,		\
					   size_t op)				\
{										\
	chunk->control += op;							\
}										\
										\
static inline size_t table##_chunk_capacity_scale(struct table##_chunk *chunk)	\
{										\
	if (table##_capacity_scale_bits == 4) {					\
		return chunk->control & 0xf;					\
	} else {								\
		uint16_t val;							\
		memcpy(&val, &chunk->tags[12], 2);				\
		return val;							\
	}									\
}										\
										\
static inline bool table##_chunk_eof(struct table##_chunk *chunk)		\
{										\
	return table##_chunk_capacity_scale(chunk) != 0;			\
}										\
										\
static inline void table##_chunk_mark_eof(struct table##_chunk *chunk,		\
					  size_t capacity_scale)		\
{										\
	if (table##_capacity_scale_bits == 4) {					\
		chunk->control = capacity_scale;				\
	} else {								\
		uint16_t val = capacity_scale;					\
		memcpy(&chunk->tags[12], &val, 2);				\
	}									\
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
__attribute__((__unused__))							\
static void table##_init(struct table *table)					\
{										\
	table->chunks = hash_table_empty_chunk;					\
	if (table##_vector_policy) {						\
		table->vector->chunk_mask = 0;					\
		table->vector->size = 0;					\
		table->vector->entries = NULL;					\
	} else {								\
		table->basic->chunk_mask = 0;					\
		table->basic->size = 0;						\
		table->basic->first_packed = 0;					\
	}									\
}										\
										\
__attribute__((__unused__))							\
static void table##_deinit(struct table *table)					\
{										\
	if (table->chunks != hash_table_empty_chunk)				\
		free(table->chunks);						\
}										\
										\
static inline size_t table##_size(struct table *table)				\
{										\
	if (table##_vector_policy)						\
		return table->vector->size;					\
	else									\
		return table->basic->size;					\
}										\
										\
static inline void table##_set_size(struct table *table, size_t size)		\
{										\
	if (table##_vector_policy)						\
		table->vector->size = size;					\
	else									\
		table->basic->size = size;					\
}										\
										\
static inline size_t table##_chunk_mask(struct table *table)			\
{										\
	if (table##_vector_policy)						\
		return table->vector->chunk_mask;				\
	else									\
		return table->basic->chunk_mask;				\
}										\
										\
static inline void table##_set_chunk_mask(struct table *table,			\
					  size_t chunk_mask)			\
{										\
	if (table##_vector_policy)						\
		table->vector->chunk_mask = chunk_mask;				\
	else									\
		table->basic->chunk_mask = chunk_mask;				\
}										\
										\
__attribute__((__unused__))							\
static inline bool table##_empty(struct table *table)				\
{										\
	return table##_size(table) == 0;					\
}										\
										\
static table##_item_type *table##_allocate_tag(struct table *table,		\
					       uint8_t *fullness,		\
					       struct hash_pair hp)		\
{										\
    const size_t delta = hash_table_probe_delta(hp);				\
    size_t index = hp.first;							\
    struct table##_chunk *chunk;						\
    uint8_t hosted_op = 0;							\
    for (;;) {									\
	    index &= table##_chunk_mask(table);					\
	    chunk = &table->chunks[index];					\
	    if (likely(fullness[index] < table##_chunk_capacity))		\
		    break;							\
	    table##_chunk_inc_outbound_overflow_count(chunk);			\
	    hosted_op = hosted_overflow_count_inc;				\
	    index += delta;							\
    }										\
    size_t item_index = fullness[index]++;					\
    chunk->tags[item_index] = hp.second;					\
    table##_chunk_adjust_hosted_overflow_count(chunk, hosted_op);		\
    return &chunk->items[item_index];						\
}										\
										\
static size_t table##_compute_capacity(size_t chunk_count, size_t scale)	\
{										\
	return (((chunk_count - 1) >> table##_capacity_scale_shift) + 1) * scale;\
}										\
										\
static bool									\
table##_compute_chunk_count_and_scale(size_t capacity,				\
				      bool continuous_single_chunk_capacity,	\
				      bool continuous_multi_chunk_capacity,	\
				      size_t *chunk_count_ret,			\
				      size_t *scale_ret)			\
{										\
	if (capacity <= table##_chunk_capacity) {				\
		if (!continuous_single_chunk_capacity) {			\
			if (capacity <= 2)					\
				capacity = 2;					\
			else if (capacity <= 6)					\
				capacity = 6;					\
			else							\
				capacity = table##_chunk_capacity;		\
		}								\
		*chunk_count_ret = 1;						\
		*scale_ret = capacity;						\
	} else {								\
		size_t min_chunks =						\
			(capacity - 1) / table##_chunk_desired_capacity + 1;	\
		size_t chunk_pow = fls(min_chunks - 1);				\
		if (chunk_pow == 8 * sizeof(size_t))				\
			return false;						\
		size_t chunk_count = (size_t)1 << chunk_pow;			\
		size_t ss = (chunk_pow >= table##_capacity_scale_shift ?	\
			     chunk_pow - table##_capacity_scale_shift : 0);	\
		size_t scale =							\
			continuous_multi_chunk_capacity ?			\
			((capacity - 1) >> ss) + 1 :				\
			table##_chunk_desired_capacity << (chunk_pow - ss);	\
		if (table##_vector_policy &&					\
		    table##_compute_capacity(chunk_count, scale) > UINT32_MAX)	\
			return false;						\
		*chunk_count_ret = chunk_count;					\
		*scale_ret = scale;						\
	}									\
	return true;								\
}										\
										\
static inline size_t table##_chunk_alloc_size(size_t chunk_count,		\
					      size_t capacity_scale)		\
{										\
	/*									\
	 * Small hash tables are common, so for capacities of less than a full	\
	 * chunk, we only allocate the required items.				\
	 */									\
	if (chunk_count == 1) {							\
		return (offsetof(struct table##_chunk, items) +			\
			table##_compute_capacity(1, capacity_scale) *		\
			sizeof(table##_item_type));				\
	} else {								\
		return chunk_count * sizeof(struct table##_chunk);		\
	}									\
}										\
										\
static bool table##_rehash(struct table *table, size_t orig_chunk_count,	\
			   size_t orig_capacity_scale, size_t new_chunk_count,	\
			   size_t new_capacity_scale)				\
{										\
	size_t chunk_alloc_size = table##_chunk_alloc_size(new_chunk_count,	\
							   new_capacity_scale);	\
	size_t alloc_size, entries_offset;					\
	if (table##_vector_policy) {						\
		entries_offset = chunk_alloc_size;				\
		if (alignof(table##_entry_type) > alignof(table##_item_type)) {	\
			entries_offset = -(-entries_offset &			\
					   ~(alignof(table##_entry_type) - 1));	\
		}								\
		size_t new_capacity =						\
			table##_compute_capacity(new_chunk_count,		\
						 new_capacity_scale);		\
		alloc_size = (entries_offset +					\
			      new_capacity * sizeof(table##_entry_type));	\
	} else {								\
		alloc_size = chunk_alloc_size;					\
	}									\
										\
	void *new_chunks;							\
	if (posix_memalign(&new_chunks, hash_table_chunk_alignment, alloc_size))\
		return false;							\
										\
	struct table##_chunk *orig_chunks = table->chunks;			\
	table->chunks = new_chunks;						\
	table##_entry_type *orig_entries;					\
	if (table##_vector_policy) {						\
		orig_entries = table->vector->entries;				\
		table->vector->entries = new_chunks + entries_offset;		\
		if (table##_size(table) > 0) {					\
			memcpy(table->vector->entries, orig_entries,		\
			       table##_size(table) *				\
			       sizeof(table##_entry_type));			\
		}								\
	}									\
										\
	memset(table->chunks, 0, chunk_alloc_size);				\
	table##_chunk_mark_eof(table->chunks, new_capacity_scale);		\
	table##_set_chunk_mask(table, new_chunk_count - 1);			\
										\
	if (table##_size(table) == 0) {						\
		/* Nothing to do. */						\
	} else if (orig_chunk_count == 1 && new_chunk_count == 1) {		\
		struct table##_chunk *src = orig_chunks;			\
		struct table##_chunk *dst = table->chunks;			\
		size_t src_i = 0, dst_i = 0;					\
		while (dst_i < table##_size(table)) {				\
			if (likely(src->tags[src_i])) {				\
				dst->tags[dst_i] = src->tags[src_i];		\
				memcpy(&dst->items[dst_i], &src->items[src_i],	\
				       sizeof(dst->items[dst_i]));		\
				dst_i++;					\
			}							\
			src_i++;						\
		}								\
		if (!table##_vector_policy) {					\
			table->basic->first_packed =				\
				table##_pack_iterator(dst, dst_i - 1);		\
		}								\
	} else {								\
		uint8_t stack_fullness[256];					\
		uint8_t *fullness;						\
		if (new_chunk_count <= sizeof(stack_fullness)) {		\
			memset(stack_fullness, 0, sizeof(stack_fullness));	\
			fullness = stack_fullness;				\
		} else {							\
			fullness = calloc(new_chunk_count, 1);			\
			if (!fullness)						\
				goto err;					\
		}								\
										\
		struct table##_chunk *src = &orig_chunks[orig_chunk_count - 1];	\
		size_t remaining = table##_size(table);				\
		while (remaining) {						\
			unsigned int mask = table##_chunk_occupied(src), i;	\
			if (table##_vector_policy) {				\
				unsigned int pmask = mask;			\
				for_each_bit(i, pmask)				\
					__builtin_prefetch(&src->items[i]);	\
			}							\
			for_each_bit(i, mask) {					\
				remaining--;					\
										\
				table##_item_type *src_item = &src->items[i];	\
				table##_key_type key =				\
					table##_item_to_key(table, src_item);	\
				struct hash_pair hp = table##_hash(&key);	\
				table##_item_type *dst_item =			\
					table##_allocate_tag(table, fullness,	\
							     hp);		\
				memcpy(dst_item, src_item, sizeof(*dst_item));	\
			}							\
			src--;							\
		}								\
										\
		if (!table##_vector_policy) {					\
			size_t i = table##_chunk_mask(table);			\
			while (fullness[i] == 0)				\
				i--;						\
			table->basic->first_packed =				\
				table##_pack_iterator(&table->chunks[i],	\
						      fullness[i] - 1);		\
		}								\
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
	table##_set_chunk_mask(table, orig_chunk_count - 1);			\
	if (table##_vector_policy)						\
		table->vector->entries = orig_entries;				\
	return false;								\
}										\
										\
static void table##_do_clear(struct table *table, bool reset)			\
{										\
	if (table->chunks == hash_table_empty_chunk)				\
		return;								\
										\
	size_t chunk_count = table##_chunk_mask(table) + 1;			\
	/* Always reset large tables. */					\
	if (chunk_count >= 16)							\
		reset = true;							\
	if (!table##_empty(table)) {						\
		if (!reset) {							\
			size_t capacity_scale =					\
				table##_chunk_capacity_scale(table->chunks);	\
			memset(table->chunks, 0,				\
			       table##_chunk_alloc_size(chunk_count,		\
							capacity_scale));	\
			table##_chunk_mark_eof(table->chunks, capacity_scale);	\
		}								\
		if (!table##_vector_policy)					\
			table->basic->first_packed = 0;				\
		table##_set_size(table, 0);					\
	}									\
	if (reset) {								\
		free(table->chunks);						\
		table->chunks = hash_table_empty_chunk;				\
		table##_set_chunk_mask(table, 0);				\
		if (table##_vector_policy)					\
			table->vector->entries = NULL;				\
	}									\
}										\
										\
__attribute__((__unused__))							\
static bool table##_reserve(struct table *table, size_t capacity)		\
{										\
	capacity = max(capacity, table##_size(table));				\
	if (!capacity) {							\
		table##_do_clear(table, true);					\
		return true;							\
	}									\
										\
	size_t orig_chunk_count = table##_chunk_mask(table) + 1;		\
	size_t orig_capacity_scale = table##_chunk_capacity_scale(table->chunks);\
	size_t orig_capacity = table##_compute_capacity(orig_chunk_count,	\
							orig_capacity_scale);	\
										\
	/*									\
	 * To avoid pathological behavior, ignore decreases that aren't at	\
	 * least a 1/8 decrease, and double for increases that aren't at least	\
	 * a 1/8 increase.							\
	 */									\
	if (capacity <= orig_capacity &&					\
	    capacity >= orig_capacity - orig_capacity / 8)			\
		return true;							\
	bool attempt_exact = !(capacity > orig_capacity &&			\
			       capacity < orig_capacity + orig_capacity / 8);	\
										\
	size_t new_chunk_count;							\
	size_t new_capacity_scale;						\
	if (!table##_compute_chunk_count_and_scale(capacity, attempt_exact,	\
						   table##_vector_policy &&	\
						   attempt_exact,		\
						   &new_chunk_count,		\
						   &new_capacity_scale))	\
		return false;							\
	size_t new_capacity = table##_compute_capacity(new_chunk_count,		\
						       new_capacity_scale);	\
	if (new_capacity == orig_capacity)					\
		return true;							\
	return table##_rehash(table, orig_chunk_count, orig_capacity_scale,	\
			      new_chunk_count, new_capacity_scale);		\
}										\
										\
__attribute__((__unused__))							\
static void table##_clear(struct table *table)					\
{										\
	table##_do_clear(table, false);						\
}										\
										\
										\
HASH_TABLE_SEARCH_IMPL(table, search_by_key, table##_key_type,			\
		       table##_item_to_key, eq_func)				\
HASH_TABLE_SEARCH_IMPL(table, search_by_index, uint32_t,			\
		       HASH_TABLE_SEARCH_BY_INDEX_ITEM_TO_KEY, scalar_key_eq)	\
										\
										\
static struct table##_iterator							\
table##_search_hashed(struct table *table, const table##_key_type *key,		\
		      struct hash_pair hp)					\
{										\
	struct table##_iterator it = table##_search_by_key(table, key, hp);	\
	/* Convert the item iterator to a public iterator. */			\
	if (table##_vector_policy && it.item) {					\
		it.entry = table##_item_to_entry(table, it.item);		\
		it.lowest = table->vector->entries;				\
	}									\
	return it;								\
}										\
										\
__attribute__((__unused__))							\
static struct table##_iterator							\
table##_search(struct table *table, const table##_key_type *key)		\
{										\
	return table##_search_hashed(table, key, table##_hash(key));		\
}										\
										\
static bool table##_reserve_for_insert(struct table *table)			\
{										\
	size_t orig_chunk_count = table##_chunk_mask(table) + 1;		\
	size_t orig_capacity_scale = table##_chunk_capacity_scale(table->chunks);\
	size_t orig_capacity = table##_compute_capacity(orig_chunk_count,	\
							orig_capacity_scale);	\
	size_t capacity = table##_size(table) + 1;				\
	if (capacity <= orig_capacity)						\
		return true;							\
	/* Grow by at least orig_capacity * 2^0.5. */				\
	size_t min_growth = (orig_capacity +					\
			     (orig_capacity >> 2) +				\
			     (orig_capacity >> 3) +				\
			     (orig_capacity >> 5));				\
	capacity = max(capacity, min_growth);					\
	size_t new_chunk_count, new_capacity_scale;				\
	if (!table##_compute_chunk_count_and_scale(capacity, false, false,	\
						   &new_chunk_count,		\
						   &new_capacity_scale))	\
		return false;							\
	return table##_rehash(table, orig_chunk_count, orig_capacity_scale,	\
			      new_chunk_count, new_capacity_scale);		\
}										\
										\
static void									\
table##_adjust_size_and_first_after_insert(struct table *table,			\
					   struct table##_chunk *chunk,		\
					   size_t index)			\
{										\
	if (!table##_vector_policy) {						\
		uintptr_t first_packed = table##_pack_iterator(chunk, index);	\
		if (first_packed > table->basic->first_packed)			\
			table->basic->first_packed = first_packed;		\
	}									\
	table##_set_size(table, table##_size(table) + 1);			\
}										\
										\
static int table##_insert_searched(struct table *table,				\
				   const table##_entry_type *entry,		\
				   struct hash_pair hp,				\
				   struct table##_iterator *it_ret)		\
{										\
	if (!table##_reserve_for_insert(table))					\
		return -1;							\
										\
	size_t index = hp.first;						\
	struct table##_chunk *chunk =						\
		&table->chunks[index & table##_chunk_mask(table)];		\
	unsigned int first_empty = table##_chunk_first_empty(chunk);		\
	if (first_empty == (unsigned int)-1) {					\
		size_t delta = hash_table_probe_delta(hp);			\
		do {								\
			table##_chunk_inc_outbound_overflow_count(chunk);	\
			index += delta;						\
			chunk = &table->chunks[index & table##_chunk_mask(table)];\
			first_empty = table##_chunk_first_empty(chunk);		\
		} while (first_empty == (unsigned int)-1);			\
		table##_chunk_adjust_hosted_overflow_count(chunk,		\
							   hosted_overflow_count_inc);\
	}									\
	chunk->tags[first_empty] = hp.second;					\
	if (table##_vector_policy) {						\
		*chunk->items[first_empty].index = table##_size(table);		\
		memcpy(&table->vector->entries[table##_size(table)], entry,	\
		       sizeof(*entry));						\
	} else {								\
		memcpy(&chunk->items[first_empty], entry, sizeof(*entry));	\
	}									\
	table##_adjust_size_and_first_after_insert(table, chunk, first_empty);	\
	if (it_ret) {								\
		if (table##_vector_policy) {					\
			it_ret->entry =						\
				&table->vector->entries[table##_size(table) - 1];\
			it_ret->lowest = table->vector->entries;		\
		} else {							\
			it_ret->item = &chunk->items[first_empty];		\
			it_ret->index = first_empty;				\
		}								\
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
	if (it.entry) {								\
		if (it_ret)							\
			*it_ret = it;						\
		return 0;							\
	} else {								\
		return table##_insert_searched(table, entry, hp, it_ret);	\
	}									\
}										\
										\
__attribute__((__unused__))							\
static int table##_insert(struct table *table,					\
			  const table##_entry_type *entry,			\
			  struct table##_iterator *it_ret)			\
{										\
	table##_key_type key = table##_entry_to_key(entry);			\
	return table##_insert_hashed(table, entry, table##_hash(&key), it_ret);	\
}										\
										\
/* Similar to table##_next_impl() but for the cached first position. */		\
static void table##_advance_first_packed(struct table *table)			\
{										\
	uintptr_t packed = table->basic->first_packed;				\
	struct table##_chunk *chunk = table##_unpack_chunk(packed);		\
	size_t index = table##_unpack_index(packed);				\
	while (index > 0) {							\
		index--;							\
		if (chunk->tags[index]) {					\
			table->basic->first_packed =				\
				table##_pack_iterator(chunk, index);		\
			return;							\
		}								\
	}									\
										\
	/*									\
	 * This is only called when there is another entry in the table, so we	\
	 * don't need to check if we hit the end.				\
	 */									\
	for (;;) {								\
		chunk--;							\
		unsigned int last = table##_chunk_last_occupied(chunk);		\
		if (last != (unsigned int)-1) {					\
			table->basic->first_packed =				\
				table##_pack_iterator(chunk, last);		\
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
	table##_set_size(table, table##_size(table) - 1);			\
	if (!table##_vector_policy &&						\
	    table##_pack_iterator(chunk, index) == table->basic->first_packed) {\
		if (table##_empty(table))					\
			table->basic->first_packed = 0;				\
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
__attribute__((__always_inline__))						\
static inline struct table##_iterator						\
table##_next_impl(struct table##_iterator it, bool likely_dead)			\
{										\
	struct table##_chunk *chunk = table##_iterator_chunk(it);		\
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
	for (size_t i = 1; !likely_dead || i != 0; i++) {			\
		if (unlikely(table##_chunk_eof(chunk)))				\
			break;							\
										\
		chunk--;							\
		unsigned int last = table##_chunk_last_occupied(chunk);		\
		if (!likely_dead)						\
			__builtin_prefetch(chunk - 1);				\
		if (likely(last != (unsigned int)-1)) {				\
			it.index = last;					\
			it.item = &chunk->items[last];				\
			return it;						\
		}								\
	}									\
	return (struct table##_iterator){};					\
}										\
										\
static void table##_delete_impl(struct table *table,				\
				struct table##_iterator item_it,		\
				struct hash_pair hp)				\
{										\
	struct table##_chunk *it_chunk = table##_iterator_chunk(item_it);	\
	it_chunk->tags[item_it.index] = 0;					\
										\
	table##_adjust_size_and_first_before_delete(table, it_chunk,		\
						    item_it.index);		\
										\
	if (table##_chunk_hosted_overflow_count(it_chunk)) {			\
		const size_t delta = hash_table_probe_delta(hp);		\
		size_t index = hp.first;					\
		uint8_t hosted_op = 0;						\
		for (;;) {							\
			struct table##_chunk *chunk =				\
				&table->chunks[index & table##_chunk_mask(table)];\
			if (chunk == it_chunk) {				\
				table##_chunk_adjust_hosted_overflow_count(chunk,\
									   hosted_op);\
				break;						\
			}							\
			table##_chunk_dec_outbound_overflow_count(chunk);	\
			hosted_op = hosted_overflow_count_dec;			\
			index += delta;						\
		}								\
	}									\
}										\
										\
static void table##_vector_delete_impl(struct table *table,			\
				       struct table##_iterator item_it,		\
				       struct hash_pair hp)			\
{										\
	/* Delete the index from the table. */					\
	uint32_t index = *item_it.item->index;					\
	table##_delete_impl(table, item_it, hp);				\
										\
	/* Replace it with the last entry and update its index in the table. */	\
	uint32_t tail_index = table##_size(table);				\
	if (tail_index != index) {						\
		table##_entry_type *tail =					\
			&table->vector->entries[tail_index];			\
		table##_key_type tail_key = table##_entry_to_key(tail);		\
		item_it = table##_search_by_index(table, &tail_index,		\
						  table##_hash(&tail_key));	\
		*item_it.item->index = index;					\
		memcpy(&table->vector->entries[index], tail, sizeof(*tail));	\
	}									\
}										\
										\
/*										\
 * We want this inlined so that the call to table##_next_impl() can be		\
 * optimized away.								\
 */										\
__attribute__((__always_inline__))						\
static inline struct table##_iterator						\
table##_delete_iterator_hashed(struct table *table, struct table##_iterator it,	\
			       struct hash_pair hp)				\
{										\
	if (table##_vector_policy) {						\
		uint32_t index = it.entry - it.lowest;				\
		struct table##_iterator item_it =				\
			table##_search_by_index(table, &index, hp);		\
		table##_vector_delete_impl(table, item_it, hp);			\
		if (index == 0) {						\
			return (struct table##_iterator){};			\
		} else {							\
			it.entry--;						\
			return it;						\
		}								\
	} else {								\
		table##_delete_impl(table, it, hp);				\
		return table##_next_impl(it, true);				\
	}									\
}										\
										\
__attribute__((__always_inline__, __unused__))					\
static inline struct table##_iterator						\
table##_delete_iterator(struct table *table, struct table##_iterator it)	\
{										\
	struct hash_pair hp = {};						\
	/*									\
	 * The basic policy only needs the hash if the chunk hosts an		\
	 * overflowed entry.							\
	 */									\
	if (table##_vector_policy ||						\
	    table##_chunk_hosted_overflow_count(table##_iterator_chunk(it))) {	\
		table##_key_type key = table##_entry_to_key(it.entry);		\
		hp = table##_hash(&key);					\
	}									\
	return table##_delete_iterator_hashed(table, it, hp);			\
}										\
										\
static bool table##_delete_hashed(struct table *table,				\
				  const table##_key_type *key,			\
				  struct hash_pair hp)				\
{										\
	struct table##_iterator item_it = table##_search_by_key(table, key, hp);\
	if (!item_it.item)							\
		return false;							\
	if (table##_vector_policy)						\
		table##_vector_delete_impl(table, item_it, hp);			\
	else									\
		table##_delete_impl(table, item_it, hp);			\
	return true;								\
}										\
										\
__attribute__((__unused__))							\
static bool table##_delete(struct table *table, const table##_key_type *key)	\
{										\
	return table##_delete_hashed(table, key, table##_hash(key));		\
}										\
										\
__attribute__((__unused__))							\
static struct table##_iterator table##_first(struct table *table)		\
{										\
	if (table##_vector_policy) {						\
		table##_entry_type *entry;					\
		if (table##_empty(table))					\
			entry = NULL;						\
		else								\
			entry = &table->vector->entries[table##_size(table) - 1];\
		return (struct table##_iterator){				\
			.entry = entry,						\
			.lowest = table->vector->entries,			\
		};								\
	} else {								\
		return table##_unpack_iterator(table->basic->first_packed);	\
	}									\
}										\
										\
__attribute__((__unused__))							\
static struct table##_iterator table##_next(struct table##_iterator it)		\
{										\
	if (table##_vector_policy) {						\
		if (it.entry == it.lowest) {					\
			return (struct table##_iterator){};			\
		} else {							\
			it.entry--;						\
			return it;						\
		}								\
	} else {								\
		return table##_next_impl(it, false);				\
	}									\
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
DEFINE_HASH_TABLE_TYPE(table, entry_type)					\
DEFINE_HASH_TABLE_FUNCTIONS(table, entry_to_key, hash_func, eq_func)

/**
 * Define a hash map type without defining its functions.
 *
 * The functions are defined with @ref DEFINE_HASH_MAP_FUNCTIONS().
 *
 * @sa DEFINE_HASH_MAP(), DEFINE_HASH_TABLE_TYPE()
 */
#define DEFINE_HASH_MAP_TYPE(table, key_type, value_type)	\
struct table##_entry {						\
	typeof(key_type) key;					\
	typeof(value_type) value;				\
};								\
DEFINE_HASH_TABLE_TYPE(table, struct table##_entry)

#define HASH_MAP_ENTRY_TO_KEY(entry) ((entry)->key)

/**
 * Define the functions for a hash map.
 *
 * The hash map type must have already been defined with @ref
 * DEFINE_HASH_MAP_TYPE().
 *
 * Unless the type and function definitions must be in separate places, use @ref
 * DEFINE_HASH_MAP() instead.
 *
 * @sa DEFINE_HASH_TABLE_FUNCTIONS
 */
#define DEFINE_HASH_MAP_FUNCTIONS(table, hash_func, eq_func)			\
DEFINE_HASH_TABLE_FUNCTIONS(table, HASH_MAP_ENTRY_TO_KEY, hash_func, eq_func)

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
DEFINE_HASH_MAP_FUNCTIONS(table, hash_func, eq_func)

/**
 * Define a hash set type without defining its functions.
 *
 * The functions are defined with @ref DEFINE_HASH_SET_FUNCTIONS().
 *
 * @sa DEFINE_HASH_SET(), DEFINE_HASH_TABLE_TYPE()
 */
#define DEFINE_HASH_SET_TYPE DEFINE_HASH_TABLE_TYPE

#define HASH_SET_ENTRY_TO_KEY(entry) (*(entry))

/**
 * Define the functions for a hash set.
 *
 * The hash set type must have already been defined with @ref
 * DEFINE_HASH_SET_TYPE().
 *
 * Unless the type and function definitions must be in separate places, use @ref
 * DEFINE_HASH_SET() instead.
 *
 * @sa DEFINE_HASH_TABLE_FUNCTIONS
 */
#define DEFINE_HASH_SET_FUNCTIONS(table, hash_func, eq_func)			\
DEFINE_HASH_TABLE_FUNCTIONS(table, HASH_SET_ENTRY_TO_KEY, hash_func, eq_func)

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
DEFINE_HASH_SET_FUNCTIONS(table, hash_func, eq_func)

/**
 * Empty hash table initializer.
 *
 * This can be used to initialize a hash table when declaring it.
 *
 * @sa hash_table_init()
 */
#define HASH_TABLE_INIT { hash_table_empty_chunk }

/**
 * @defgroup HashTableHelpers Hash table helpers
 *
 * Hash functions and comparators for use with @ref HashTables.
 *
 * F14 resolves collisions by double hashing. Rather than using two independent
 * hash functions, this provides two options for efficiently deriving a pair of
 * hashes from a single input hash function depending on whether the hash
 * function is _avalanching_. See @ref hash_pair_from_avalanching_hash() and
 * @ref hash_pair_from_non_avalanching_hash().
 *
 * This provides:
 * * Functions for double hashing common key types: `*_hash_pair()`.
 * * Primitives for double hashing more complicated key types.
 * * Equality functions for common key types: `*_eq()`.
 *
 * @{
 */

/**
 * Split an avalanching hash into a @ref hash_pair.
 *
 * A hash function is avalanching if each bit of the hash value has a 50% chance
 * of being the same for different inputs. This is true for cryptographic hash
 * functions as well as certain non-cryptographic hash functions including
 * CityHash, MurmurHash, SipHash, and xxHash. Simple hashes like DJBX33A, ad-hoc
 * combinations like `53 * x + y`, and the identity function are not
 * avalanching.
 *
 * We use the input hash value as the first hash and the upper bits of the input
 * hash value as the second hash (which would otherwise be discarded when
 * masking to select the bucket).
 */
static inline struct hash_pair hash_pair_from_avalanching_hash(size_t hash)
{
	return (struct hash_pair){
		.first = hash,
		.second = (hash >> (8 * sizeof(hash) - 8)) | 0x80,
	};
}

/**
 * Mix a non-avalanching hash and split it into a @ref hash_pair.
 *
 * This is architecture-dependent.
 */
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
	uint64_t hi = ((unsigned __int128)hash * multiplier) >> 64;
	uint64_t lo = hash * multiplier;
	hash = hi ^ lo;
	hash *= multiplier;
	return (struct hash_pair){
		.first = hash >> 22,
		.second = ((hash >> 15) & 0x7f) | 0x80,
	};
#endif
#elif SIZE_MAX == 0xffffffff
#ifdef __SSE4_2__
	/* 32-bit with SSE4.2 uses CRC32 */
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
 * Double hash an integral key.
 *
 * This can be used for any integer key type.
 */
struct hash_pair int_key_hash_pair(const T *key);
#else
#if SIZE_MAX == 0xffffffffffffffff
static inline uint64_t hash_128_to_64(unsigned __int128 hash)
{
	return cityhash_128_to_64(hash, hash >> 64);
}

#define int_key_hash_pair(key) ({				\
	__auto_type _key = *(key);				\
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

#define int_key_hash_pair(key) ({				\
	__auto_type _key = *(key);				\
	sizeof(_key) > sizeof(size_t) ?				\
	hash_pair_from_avalanching_hash(hash_64_to_32(_key)) :	\
	hash_pair_from_non_avalanching_hash(_key);		\
})
#endif
#endif

#ifdef DOXYGEN
/**
 * Double hash a pointer key.
 *
 * This can be used when the key is a pointer value (rather than the
 * dereferenced value).
 */
struct hash_pair ptr_key_hash_pair(T * const *key);
#else
#define ptr_key_hash_pair(key) ({		\
	uintptr_t _ptr = (uintptr_t)*(key);	\
	int_key_hash_pair(&_ptr);		\
})
#endif

#ifdef DOXYGEN
/**
 * Return whether two scalar keys are equal.
 *
 * This can be used as the key comparison function for any scalar key type
 * (e.g., integers, floating-point numbers, pointers).
 */
bool scalar_key_eq(const T *a, const T *b);
#else
#define scalar_key_eq(a, b) ((bool)(*(a) == *(b)))
#endif

/**
 * Combine two hash values into one.
 *
 * This is useful for hashing records with multiple fields (e.g., a structure or
 * an array). The input hash functions need not be avalanching; the output will
 * be avalanching regardless, so the following would be valid:
 *
 * ```
 * static struct hash_pair point3d_key_hash(const struct point3d *key)
 * {
 *         return hash_pair_from_avalanching_hash(hash_combine(hash_combine(p->x, p->y), p->z));
 * }
 * ```
 */
static inline size_t hash_combine(size_t a, size_t b)
{
#if SIZE_MAX == 0xffffffffffffffff
	return cityhash_128_to_64(b, a);
#else
	return hash_64_to_32(((uint64_t)a << 32) | b);
#endif
}

/**
 * Hash a byte buffer.
 *
 * This is an avalanching hash function.
 */
static inline size_t hash_bytes(const void *data, size_t len)
{
	return cityhash_size_t(data, len);
}

/**
 * Hash a null-terminated string.
 *
 * This is an avalanching hash function.
 */
static inline size_t hash_c_string(const char *s)
{
	return hash_bytes(s, strlen(s));
}

#ifdef DOXYGEN
/** Double hash a null-terminated string key. */
struct hash_pair c_string_key_hash_pair(const char * const *key);
#else
/* This is a macro so that it works with char * and const char * keys. */
#define c_string_key_hash_pair(key)	\
	hash_pair_from_avalanching_hash(hash_c_string(*(key)))
#endif

#ifdef DOXYGEN
/** Compare two null-terminated string keys for equality. */
bool c_string_key_eq(const char * const *a, const char * const *b);
#else
#define c_string_key_eq(a, b) ((bool)(strcmp(*(a), *(b)) == 0))
#endif

/** Double hash a @ref nstring. */
static inline struct hash_pair nstring_hash_pair(const struct nstring *key)
{
	return hash_pair_from_avalanching_hash(hash_bytes(key->str, key->len));
}

/** @} */

/** @} */

#endif /* DRGN_HASH_TABLE_H */
