// Copyright 2018-2019 - Omar Sandoval
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
#include "internal.h"

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
 * @{
 */

/**
 * Pair of hash values.
 *
 * F14 resolves collisions by double hashing. This type comprises the two
 * hashes.
 *
 * This first hash is a @c size_t used for selecting the chunk, and the second
 * is a @c uint8_t used as a tag within the chunk. We can construct the latter
 * from the upper bits of the former (which we would otherwise discard when
 * masking to select the chunk), assuming that the hash function properly
 * avalanches all bits.
 *
 * @sa HashTableHelpers
 */
struct hash_pair {
	size_t first;
	size_t second;
};

#ifdef DOXYGEN
/**
 * @defgroup HashMaps Hash maps
 *
 * Hash maps (a.k.a., dictionaries or associative arrays).
 *
 * A hash map type is defined with @ref DEFINE_HASH_MAP(). The defined types and
 * functions will have the given name; the interface documented here uses an
 * example name of @c hash_map.
 *
 * @{
 */

/**
 * @struct hash_map
 *
 * Hash map instance.
 *
 * There are no requirements on how this is allocated; it may be global, on the
 * stack, allocated by @c malloc(), embedded in another structure, etc.
 */
struct hash_map;

/**
 * Hash map entry (i.e., key-value pair).
 *
 * Keys and values are copied into the hash table by value (i.e., with the
 * equivalent of <tt>memcpy(&item->key, &key, sizeof(key)))</tt>.
 */
struct hash_map_item {
	key_type key;
	value_type value;
};

/**
 * Hash map iterator.
 *
 * Several functions return an iterator or take one as an argument. This
 * iterator has a reference to an item, which can be @c NULL to indicate a not
 * found or error case. It also contains private bookkeeping which should not be
 * used.
 *
 * A position remains valid as long as the item is not deleted and the table is
 * not rehashed.
 */
struct hash_map_pos {
	/* Pointer to the item in the hash table. */
	struct hash_map_item *item;
};

/**
 * Compute the hash for a given key.
 *
 * Note that this function is simply a wrapper around the hash function that was
 * passed when defining the hash map. It is provided for convenience.
 */
struct hash_pair hash_map_hash(const key_type *key);

/**
 * Initialize a @ref hash_map.
 *
 * The new hash map is empty. It must be deinitialized with @ref
 * hash_map_deinit().
 */
void hash_map_init(struct hash_map *map);

/**
 * Free memory allocated by a @ref hash_map.
 *
 * After this is called, the hash map must not be used unless it is
 * reinitialized with @ref hash_map_init(). Note that this only frees memory
 * allocated by the hash table itself; if keys, values, or the hash table
 * structure itself are dynamically allocated, those must be freed separately.
 */
void hash_map_deinit(struct hash_map *map);

/** Return the number of items in a @ref hash_map. */
size_t hash_map_size(struct hash_map *map);

/**
 * Delete all items in a @ref hash_map.
 *
 * This does not necessarily free memory used by the hash table.
 */
void hash_map_clear(struct hash_map *map);

/**
 * Reserve items in a @ref hash_map.
 *
 * This allocates space up front to ensure that the table will not be rehashed
 * until the map contains the given number of items.
 *
 * @return @c true on success, @c false on failure.
 */
bool hash_map_reserve(struct hash_map *map, size_t capacity);

/**
 * Insert an item in a @ref hash_map.
 *
 * This inserts or overwrites the item at the given key with the given value.
 *
 * @return @c true on success, @c false on failure (which can only happen if
 * allocating for a rehash fails).
 */
bool hash_map_insert(struct hash_map *map, const key_type *key,
		     const value_type *value);

/**
 * Insert an item in a @ref hash_map with a precomputed hash.
 *
 * Like @ref hash_map_insert(), but the hash was already computed. This saves
 * recomputing the hash when doing multiple operations with the same key.
 */
bool hash_map_insert_hashed(struct hash_map *map, const key_type *key,
			    const value_type *value, struct hash_pair hp);

/**
 * Insert an item in a @ref hash_map which is not in the map.
 *
 * Like @ref hash_map_insert_hashed(), but a search was previously done and the
 * key is not already in the map. This saves doing a redundant search in that
 * case but is unsafe otherwise.
 */
bool hash_map_insert_searched(struct hash_map *map, const key_type *key,
			      const value_type *value, struct hash_pair hp);

/**
 * Insert an item in a @ref hash_map and get the iterator.
 *
 * Like @ref hash_map_insert_hashed(), but returns an iterator.
 *
 * @return The position at which the item was inserted, or a position with
 * <tt>item == NULL</tt> if the insertion failed.
 */
struct hash_map_pos hash_map_insert_pos(struct hash_map *map,
					const key_type *key,
					const value_type *value,
					struct hash_pair hp);

/**
 * Insert an item in a @ref hash_map which is not in the map and get the
 * iterator.
 *
 * Like @ref hash_map_insert_searched(), but returns an iterator.
 *
 * @return The position at which the item was inserted, or a position with
 * <tt>item == NULL</tt> if the insertion failed.
 */
struct hash_map_pos hash_map_insert_searched_pos(struct hash_map *map,
						 const key_type *key,
						 const value_type *value,
						 struct hash_pair hp);

/**
 * Search for an item in a @ref hash_map.
 *
 * This searches for the value with the given key.
 *
 * @return A pointer to the value if it was found, @c NULL if it was not.
 */
value_type *hash_map_search(struct hash_map *map, const key_type *key);

/**
 * Search for an item in a @ref hash_map with a precomputed hash.
 *
 * Like @ref hash_map_search(), but the hash was already computed. This saves
 * recomputing the hash when doing multiple operations with the same key.
 */
value_type *hash_map_search_hashed(struct hash_map *map, const key_type *key,
				   struct hash_pair hp);

/**
 * Search for an item in a @ref hash_map and get the position.
 *
 * Like @ref hash_map_search_hashed(), but returns an iterator.
 *
 * @return The position of the item with the given key, or a position with
 * <tt>item == NULL</tt> if the key was not found.
 */
struct hash_map_pos hash_map_search_pos(struct hash_map *map,
					const key_type *key,
					struct hash_pair hp);

/**
 * Delete an item in a @ref hash_map.
 *
 * This deletes the item with the given key. It will never rehash the table.
 *
 * @return @c true if the item was found, @c false if not.
 */
bool hash_map_delete(struct hash_map *map, const key_type *key);

/**
 * Delete an item in a @ref hash_map with a precomputed hash.
 *
 * Like @ref hash_map_delete(), but the hash was already computed. This saves
 * recomputing the hash when doing multiple operations with the same key.
 */
bool hash_map_delete_hashed(struct hash_map *map, struct hash_pair hp);

/**
 * Delete an item given by an iterator in a @ref hash_map.
 *
 * This deletes the item (with the given hash) at the given position.
 */
void hash_map_delete_pos(struct hash_map *map, struct hash_map_pos pos,
			 struct hash_pair hp);

/**
 * Get an iterator over a @ref hash_map.
 *
 * @return The position of the first item in the map, or a position with
 * <tt>item == NULL</tt> if the map is empty.
 */
struct hash_map_pos hash_map_first_pos(struct hash_map *map);

/**
 * Advance a @ref hash_map iterator.
 *
 * The position will have <tt>item == NULL</tt> when there are no more items in
 * the map.
 */
void hash_map_next_pos(struct hash_map_pos *pos);

/** @} */

/**
 * @defgroup HashSets Hash sets
 *
 * Hash sets.
 *
 * A hash set type is defined with @ref DEFINE_HASH_SET(). The defined types and
 * functions will have the given name; the interface documented here uses an
 * example name of @c hash_set.
 *
 * @{
 */

/**
 * @struct hash_set
 *
 * Hash set instance.
 *
 * There are no requirements on how this is allocated; it may be global, on the
 * stack, allocated by @c malloc(), embedded in another structure, etc.
 */
struct hash_set;

/**
 * Hash set iterator.
 *
 * Several functions return an iterator or take one as an argument. This
 * iterator has a reference to an item (i.e., key), which can be @c NULL to
 * indicate a not found or error case. It also contains private bookkeeping
 * which should not be used.
 *
 * A position remains valid as long as the key is not deleted and the table is
 * not rehashed.
 */
struct hash_set_pos {
	key_type *item;
};

/**
 * Compute the hash for a given key.
 *
 * Note that this function is simply a wrapper around the hash function that was
 * passed when defining the hash set. It is provided for convenience.
 */
struct hash_pair hash_set_hash(const key_type *key);

/**
 * Initialize a @ref hash_set.
 *
 * The new hash set is empty. It must be deinitialized with @ref
 * hash_set_deinit().
 */
void hash_set_init(struct hash_set *set);

/**
 * Free memory allocated by a @ref hash_set.
 *
 * After this is called, the hash set must not be used unless it is
 * reinitialized with @ref hash_set_init(). Note that this only frees memory
 * allocated by the hash table itself; if keys or the hash table structure
 * itself are dynamically allocated, those must be freed separately.
 */
void hash_set_deinit(struct hash_set *set);

/** Return the number of keys in a @ref hash_set. */
size_t hash_set_size(struct hash_set *set);

/**
 * Delete all keys in a @ref hash_set.
 *
 * This does not necessarily free memory used by the hash table.
 */
void hash_set_clear(struct hash_set *set);

/**
 * Reserve keys in a @ref hash_set.
 *
 * This allocates space up front to ensure that the table will not be rehashed
 * until the set contains the given number of keys.
 *
 * @return @c true on success, @c false on failure.
 */
bool hash_set_reserve(struct hash_set *set, size_t capacity);

/**
 * Insert a key in a @ref hash_set.
 *
 * This is a no-op if the key was already in the set.
 *
 * @return @c true on success, @c false on failure (which can only happen if
 * allocating for a rehash fails).
 */
bool hash_set_insert(struct hash_set *set, const key_type *key);

/**
 * Insert a key in a @ref hash_set with a precomputed hash.
 *
 * Like @ref hash_set_insert(), but the hash was already computed. This saves
 * recomputing the hash when doing multiple operations with the same key.
 */
bool hash_set_insert_hashed(struct hash_set *set, const key_type *key,
			    struct hash_pair hp);

/**
 * Insert a key in a @ref hash_set which is not in the set.
 *
 * Like @ref hash_set_insert_hashed(), but a search was previously done and the
 * key is not already in the set. This saves doing a redundant search in that
 * case but is unsafe otherwise.
 */
bool hash_set_insert_searched(struct hash_set *set, const key_type *key,
			      struct hash_pair hp);

/**
 * Insert a key in a @ref hash_set and get the iterator.
 *
 * Like @ref hash_set_insert_hashed(), but returns an iterator.
 *
 * @return The position at which the key was inserted, or a position with
 * <tt>item == NULL</tt> if the insertion failed.
 */
struct hash_set_pos hash_set_insert_pos(struct hash_set *set,
					const key_type *key,
					struct hash_pair hp);

/**
 * Insert a key in a @ref hash_set which is not in the set and get the iterator.
 *
 * Like @ref hash_set_insert_searched(), but returns an iterator.
 *
 * @return The position at which the key was inserted, or a position with
 * <tt>item == NULL</tt> if the insertion failed.
 */
struct hash_set_pos hash_set_insert_searched(struct hash_set *set,
					     const key_type *key,
					     struct hash_pair hp);

/**
 * Search for a key in a @ref hash_set.
 *
 * @return @c true if the key was found, @c false if not.
 */
bool hash_set_search(struct hash_set *set, const key_type *key);

/**
 * Search for a key in a @ref hash_set with a precomputed hash.
 *
 * Like @ref hash_set_search(), but the hash was already computed. This saves
 * recomputing the hash when doing multiple operations with the same key.
 */
bool hash_set_search_hashed(struct hash_set *set, const key_type *key,
			    struct hash_pair hp);

/**
 * Search for a key in a @ref hash_set and get the position.
 *
 * Like @ref hash_set_search_hashed(), but returns an iterator.
 *
 * @return The position of the given key, or a position with <tt>item ==
 * NULL</tt> if the key was not found.
 */
struct hash_set_pos hash_set_search_pos(struct hash_set *set,
					const key_type *key,
					struct hash_pair hp);

/**
 * Delete a key in a @ref hash_set.
 *
 * This will never rehash the table.
 *
 * @return @c true if the key was found, @c false if not.
 */
bool hash_set_delete(struct hash_set *set, const key_type *key);

/**
 * Delete a key in a @ref hash_set with a precomputed hash.
 *
 * Like @ref hash_set_delete(), but the hash was already computed. This saves
 * recomputing the hash when doing multiple operations with the same key.
 */
bool hash_set_delete_hashed(struct hash_set *set, struct hash_pair hp);

/**
 * Delete a key given by an iterator in a @ref hash_set.
 *
 * This deletes the key (with the given hash) at the given position.
 */
void hash_set_delete_pos(struct hash_set *set, struct hash_set_pos pos,
			 struct hash_pair hp);

/**
 * Get an iterator over a @ref hash_set.
 *
 * @return The position of the first key in the set, or a position with
 * <tt>item == NULL</tt> if the set is empty.
 */
struct hash_set_pos hash_set_first_pos(struct hash_set *set);

/**
 * Advance a @ref hash_set iterator.
 *
 * The position will have <tt>item == NULL</tt> when there are no more keys in
 * the set.
 */
void hash_set_next_pos(struct hash_set_pos *pos);

/** @} */
#endif

static inline size_t hash_table_probe_delta(struct hash_pair hp)
{
	return 2 * hp.second + 1;
}

#define HASH_TABLE_TYPE(name) struct name
#define HASH_TABLE_CHUNK(name) struct name##_chunk
#define HASH_TABLE_POS(name) struct name##_pos
#define HASH_MAP_ITEM_KEY(item) &(item)->key
#define HASH_SET_ITEM_KEY(item) item

/*
 * We could represent an empty hash table with chunks set to NULL. However, then
 * we would need a branch to check for this in insert, search, and delete. We
 * could avoid this by allocating an empty chunk, but that is wasteful since it
 * will never actually be used. Instead, we have a special empty chunk which is
 * used by all tables.
 */
extern const uint8_t hash_table_empty_chunk_header[];
#define hash_table_empty_chunk (void *)hash_table_empty_chunk_header

/*
 * F14 hash table implementation as monstrous macros. See DEFINE_HASH_MAP() and
 * DEFINE_HASH_SET() for the public interface.
 */

#ifdef __SSE2__
#define HASH_TABLE_CHUNK_MATCH(table)						\
static inline unsigned int							\
table##_chunk_match(HASH_TABLE_CHUNK(table) *chunk, size_t needle)		\
{										\
	__m128i tag_vec = _mm_load_si128((__m128i *)chunk);			\
	/*									\
	 * Note that we could pass needle as a uint8_t (and make		\
	 * hash_pair.second a uint8_t as well), but the folly implementation	\
	 * insists that using size_t generates better code.			\
	 */									\
	__m128i needle_vec = _mm_set1_epi8((uint8_t)needle);			\
	__m128i eq_vec = _mm_cmpeq_epi8(tag_vec, needle_vec);			\
	return _mm_movemask_epi8(eq_vec) & table##_chunk_full_mask;		\
}

#define HASH_TABLE_CHUNK_OCCUPIED(table)				\
static inline unsigned int						\
table##_chunk_occupied(HASH_TABLE_CHUNK(table) *chunk)			\
{									\
	__m128i tag_vec = _mm_load_si128((__m128i *)chunk);		\
	return _mm_movemask_epi8(tag_vec) & table##_chunk_full_mask;	\
}
#else
#define HASH_TABLE_CHUNK_MATCH(table)					\
static inline unsigned int						\
table##_chunk_match(HASH_TABLE_CHUNK(table) *chunk, size_t needle)	\
{									\
	unsigned int mask, i;						\
									\
	for (mask = 0, i = 0; i < table##_chunk_capacity; i++) {	\
		if (chunk->tags[i] == needle)				\
			mask |= 1U << i;				\
	}								\
	return mask;							\
}

#define HASH_TABLE_CHUNK_OCCUPIED(table)				\
static inline unsigned int						\
table##_chunk_occupied(HASH_TABLE_CHUNK(table) *chunk)			\
{									\
	unsigned int mask, i;						\
									\
	for (mask = 0, i = 0; i < table##_chunk_capacity; i++) {	\
		if (chunk->tags[i])					\
			mask |= 1U << i;				\
	}								\
	return mask;							\
}
#endif

#define DEFINE_HASH_TABLE_TYPES(table, key_type, item_type)			\
enum {										\
	/*									\
	 * The number of items per chunk. 14 is the most space efficient, but	\
	 * if an item is 4 bytes, 12 items makes a chunk exactly one cache	\
	 * line.								\
	 */									\
	table##_chunk_capacity = sizeof(item_type) == 4 ? 12 : 14,		\
	/* The maximum load factor in terms of items per chunk. */		\
	table##_chunk_desired_capacity = table##_chunk_capacity - 2,		\
	/*									\
	 * If an item is 16 bytes, add an extra 16 bytes of padding to make a	\
	 * chunk exactly four cache lines.					\
	 */									\
	table##_chunk_allocated_capacity =					\
		(table##_chunk_capacity + (sizeof(item_type) == 16 ? 1 : 0)),	\
	table##_chunk_full_mask = (1 << table##_chunk_capacity) - 1,		\
};										\
										\
HASH_TABLE_CHUNK(table) {							\
	uint8_t tags[14];							\
	/*									\
	 * If this is the first chunk, the capacity of the table if it is also	\
	 * the only chunk, and one otherwise. Zero if this is not the first	\
	 * chunk.								\
	 */									\
	uint8_t chunk0_capacity : 4;						\
	/*									\
	 * The number of values in this chunk that overflowed their desired	\
	 * chunk.								\
	 *									\
	 * Note that this bit field and chunk0_capacity are combined into a	\
	 * single uint8_t member, control, in the folly implementation.		\
	 */									\
	uint8_t hosted_overflow_count : 4;					\
	/*									\
	 * The number of values that would have been in this chunk if it were	\
	 * not full. This value saturates if it hits 255, after which it will	\
	 * not be updated.							\
	 */									\
	uint8_t outbound_overflow_count;					\
	item_type items[table##_chunk_allocated_capacity];			\
} __attribute__((aligned(16)));							\
										\
HASH_TABLE_POS(table) {								\
	item_type *item;							\
	size_t index;								\
};										\
										\
HASH_TABLE_TYPE(table) {							\
	HASH_TABLE_CHUNK(table) *chunks;					\
	/* Number of chunks minus one. */					\
	size_t chunk_mask;							\
	/* Number of used values. */						\
	size_t size;								\
	/* Cached position of first item. */					\
	uintptr_t first_packed;							\
};										\

#define DEFINE_HASH_TABLE_FUNCTIONS(table, key_type, item_type, item_key,	\
				    hash_func, eq_func)				\
/*										\
 * We use typeof() here and elsewhere because key_type * is not always the	\
 * syntax for a pointer to key_type (e.g., if key_type is int [2], int [2] *key	\
 * is invalid sytax).								\
 */										\
static inline struct hash_pair table##_hash(const typeof(key_type) *key)	\
{										\
	return hash_func(key);							\
}										\
										\
/*										\
 * We cache the first position in the table as a tagged pointer: we steal the	\
 * bottom bits of the chunk pointer for the item index. We can do this because	\
 * chunks are aligned to 16 bytes and the index is always less than 16.		\
 *										\
 * The folly implementation mentions this strategy but uses a more complicated	\
 * scheme in order to avoid computing the chunk pointer from an item pointer.	\
 * We always have the chunk pointer readily available when we want to pack an	\
 * item, so we can use this much simpler scheme.				\
 */										\
static inline uintptr_t table##_pack_pos(HASH_TABLE_CHUNK(table) *chunk,	\
					 size_t index)				\
{										\
	return (uintptr_t)chunk | (uintptr_t)index;				\
}										\
										\
static inline HASH_TABLE_CHUNK(table) *table##_unpack_chunk(uintptr_t packed)	\
{										\
	return (HASH_TABLE_CHUNK(table) *)(packed & ~0xf);			\
}										\
										\
static inline size_t table##_unpack_index(uintptr_t packed)			\
{										\
	return packed & 0xf;							\
}										\
										\
static inline HASH_TABLE_POS(table) table##_unpack_pos(uintptr_t packed)	\
{										\
	HASH_TABLE_CHUNK(table) *chunk;						\
	size_t index;								\
										\
	chunk = table##_unpack_chunk(packed);					\
	index = table##_unpack_index(packed);					\
	return (HASH_TABLE_POS(table)){						\
		.item = chunk ? &chunk->items[index] : NULL,			\
		.index = index,							\
	};									\
}										\
										\
static inline HASH_TABLE_CHUNK(table) *						\
table##_pos_chunk(HASH_TABLE_POS(table) pos)					\
{										\
	return container_of(pos.item - pos.index, HASH_TABLE_CHUNK(table),	\
			    items[0]);						\
}										\
										\
HASH_TABLE_CHUNK_MATCH(table)							\
HASH_TABLE_CHUNK_OCCUPIED(table)						\
										\
static inline unsigned int							\
table##_chunk_first_empty(HASH_TABLE_CHUNK(table) *chunk)			\
{										\
	unsigned int mask;							\
										\
	mask = table##_chunk_occupied(chunk) ^ table##_chunk_full_mask;		\
	return mask ? ctz(mask) : (unsigned int)-1;				\
}										\
										\
static inline unsigned int							\
table##_chunk_last_occupied(HASH_TABLE_CHUNK(table) *chunk)			\
{										\
	unsigned int mask;							\
										\
	mask = table##_chunk_occupied(chunk);					\
	return mask ? fls(mask) - 1 : (unsigned int)-1;				\
}										\
										\
static inline void								\
table##_chunk_inc_outbound_overflow_count(HASH_TABLE_CHUNK(table) *chunk)	\
{										\
	if (chunk->outbound_overflow_count != UINT8_MAX)			\
		chunk->outbound_overflow_count++;				\
}										\
										\
static inline void								\
table##_chunk_dec_outbound_overflow_count(HASH_TABLE_CHUNK(table) *chunk)	\
{										\
	if (chunk->outbound_overflow_count != UINT8_MAX)			\
		chunk->outbound_overflow_count--;				\
}										\
										\
__attribute__((unused))								\
static void table##_init(HASH_TABLE_TYPE(table) *table)				\
{										\
	table->chunks = hash_table_empty_chunk;					\
	table->chunk_mask = 0;							\
	table->size = 0;							\
	table->first_packed = 0;						\
}										\
										\
__attribute__((unused))								\
static void table##_deinit(HASH_TABLE_TYPE(table) *table)			\
{										\
	if (table->chunks != hash_table_empty_chunk)				\
		free(table->chunks);						\
}										\
										\
__attribute__((unused))								\
static inline size_t table##_size(HASH_TABLE_TYPE(table) *table)		\
{										\
	return table->size;							\
}										\
										\
static item_type *table##_allocate_tag(HASH_TABLE_TYPE(table) *table,		\
				       uint8_t *fullness,			\
				       struct hash_pair hp)			\
{										\
    HASH_TABLE_CHUNK(table) *chunk;						\
    size_t index = hp.first;							\
    size_t delta = hash_table_probe_delta(hp);					\
    uint8_t hosted_inc = 0;							\
    size_t item_index;								\
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
    item_index = fullness[index]++;						\
    chunk->tags[item_index] = hp.second;					\
    chunk->hosted_overflow_count += hosted_inc;					\
    return &chunk->items[item_index];						\
}										\
										\
static void									\
table##_set_first_packed_after_rehash(HASH_TABLE_TYPE(table) *table,		\
				      uint8_t *fullness)			\
{										\
	size_t i;								\
										\
	i = table->chunk_mask;							\
	while (fullness[i] == 0)						\
		i--;								\
	table->first_packed = table##_pack_pos(&table->chunks[i],		\
					       fullness[i] - 1);		\
}										\
										\
static inline size_t table##_alloc_size(size_t chunk_count, size_t max_size)	\
{										\
	/*									\
	 * Small hash tables are common, so for capacities of less than a full	\
	 * chunk we only allocate the required items.				\
	 */									\
	if (chunk_count == 1) {							\
		return (offsetof(HASH_TABLE_CHUNK(table), items) +		\
			max_size * sizeof(item_type));				\
	} else {								\
		return chunk_count * sizeof(HASH_TABLE_CHUNK(table));		\
	}									\
}										\
										\
static bool table##_rehash(HASH_TABLE_TYPE(table) *table,			\
			   size_t new_chunk_count, size_t new_max_size)		\
{										\
	HASH_TABLE_CHUNK(table) *orig_chunks = table->chunks;			\
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
		HASH_TABLE_CHUNK(table) *src, *dst;				\
		size_t src_i = 0, dst_i = 0;					\
										\
		src = &orig_chunks[0];						\
		dst = &table->chunks[0];					\
		while (dst_i < table->size) {					\
			if (likely(src->tags[src_i])) {				\
				dst->tags[dst_i] = src->tags[src_i];		\
				memcpy(&dst->items[dst_i], &src->items[src_i],	\
				       sizeof(dst->items[dst_i]));		\
				dst_i++;					\
			}							\
			src_i++;						\
		}								\
		table->first_packed = table##_pack_pos(dst, dst_i - 1);		\
	} else {								\
		HASH_TABLE_CHUNK(table) *src;					\
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
				item_type *src_item;				\
				item_type *dst_item;				\
				struct hash_pair hp;				\
										\
				remaining--;					\
				src_item = &src->items[i];			\
				hp = table##_hash(item_key(src_item));		\
				dst_item = table##_allocate_tag(table,		\
								fullness,	\
								hp);		\
				memcpy(dst_item, src_item, sizeof(*dst_item));	\
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
static bool table##_do_reserve(HASH_TABLE_TYPE(table) *table, size_t capacity,	\
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
static size_t table##_max_size(HASH_TABLE_TYPE(table) *table)			\
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
static bool table##_reserve(HASH_TABLE_TYPE(table) *table, size_t capacity)	\
{										\
	if (table->size > capacity)						\
		capacity = table->size;						\
	return table##_do_reserve(table, capacity, table##_max_size(table));	\
}										\
										\
__attribute__((unused))								\
static void table##_clear(HASH_TABLE_TYPE(table) *table)			\
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
static HASH_TABLE_POS(table) table##_search_pos(HASH_TABLE_TYPE(table) *table,	\
						const typeof(key_type) *key,	\
						struct hash_pair hp)		\
{										\
	size_t index = hp.first;						\
	size_t delta = hash_table_probe_delta(hp);				\
	size_t tries;								\
										\
	for (tries = 0; tries <= table->chunk_mask; tries++) {			\
		HASH_TABLE_CHUNK(table) *chunk;					\
		unsigned int mask, i;						\
										\
		chunk = &table->chunks[index & table->chunk_mask];		\
		if (sizeof(*chunk) > 64)					\
			__builtin_prefetch(&chunk->items[8]);			\
		mask = table##_chunk_match(chunk, hp.second);			\
		for_each_bit(i, mask) {						\
			item_type *item;					\
										\
			item = &chunk->items[i];				\
			if (likely(eq_func(key, item_key(item)))) {		\
				return (HASH_TABLE_POS(table)){			\
					.item = item,				\
					.index = i,				\
				};						\
			}							\
		}								\
		if (likely(chunk->outbound_overflow_count == 0))		\
			break;							\
		index += delta;							\
	}									\
	return (HASH_TABLE_POS(table)){};					\
}										\
										\
static bool table##_reserve_for_insert(HASH_TABLE_TYPE(table) *table)		\
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
table##_adjust_size_and_first_after_insert(HASH_TABLE_TYPE(table) *table,	\
					   HASH_TABLE_CHUNK(table) *chunk,	\
					   size_t index)			\
{										\
	uintptr_t first_packed;							\
										\
	first_packed = table##_pack_pos(chunk, index);				\
	if (first_packed > table->first_packed)					\
		table->first_packed = first_packed;				\
	table->size++;								\
}										\
										\
static HASH_TABLE_POS(table) table##_do_insert(HASH_TABLE_TYPE(table) *table,	\
					       const typeof(key_type) *key,	\
					       struct hash_pair hp)		\
{										\
	size_t index = hp.first;						\
	HASH_TABLE_CHUNK(table) *chunk;						\
	unsigned int first_empty;						\
										\
	if (!table##_reserve_for_insert(table))					\
		return (HASH_TABLE_POS(table)){};				\
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
	table##_adjust_size_and_first_after_insert(table, chunk, first_empty);	\
	return (HASH_TABLE_POS(table)){						\
		.item = &chunk->items[first_empty],				\
		.index = first_empty,						\
	};									\
}										\
										\
/* Similar to advance_pos() but for the cached first position. */		\
static void table##_advance_first_packed(HASH_TABLE_TYPE(table) *table)		\
{										\
	uintptr_t packed = table->first_packed;					\
	HASH_TABLE_CHUNK(table) *chunk;						\
	size_t index;								\
										\
	chunk = table##_unpack_chunk(packed);					\
	index = table##_unpack_index(packed);					\
	while (index > 0) {							\
		index--;							\
		if (chunk->tags[index]) {					\
			table->first_packed = table##_pack_pos(chunk, index);	\
			return;							\
		}								\
	}									\
										\
	/*									\
	 * This is only called when there is another item in the table, so we	\
	 * don't need to check if we hit the end.				\
	 */									\
	for (;;) {								\
		unsigned int last;						\
										\
		chunk--;							\
		last = table##_chunk_last_occupied(chunk);			\
		if (last != (unsigned int)-1) {					\
			table->first_packed = table##_pack_pos(chunk, last);	\
			return;							\
		}								\
	}									\
}										\
										\
static void									\
table##_adjust_size_and_first_before_delete(HASH_TABLE_TYPE(table) *table,	\
					    HASH_TABLE_CHUNK(table) *chunk,	\
					    size_t index)			\
{										\
	uintptr_t packed;							\
										\
	table->size--;								\
	packed = table##_pack_pos(chunk, index);				\
	if (packed == table->first_packed) {					\
		if (table->size == 0)						\
			table->first_packed = 0;				\
		else								\
			table##_advance_first_packed(table);			\
	}									\
}										\
										\
static void table##_delete_pos(HASH_TABLE_TYPE(table) *table,			\
			       HASH_TABLE_POS(table) pos,			\
			       struct hash_pair hp)				\
{										\
	HASH_TABLE_CHUNK(table) *pos_chunk, *chunk;				\
										\
	pos_chunk = table##_pos_chunk(pos);					\
	pos_chunk->tags[pos.index] = 0;						\
										\
	table##_adjust_size_and_first_before_delete(table, pos_chunk,		\
						    pos.index);			\
										\
	/*									\
	 * Note: we only need the hash pair if the chunk hosts an overflowed	\
	 * item.								\
	 */									\
	if (pos_chunk->hosted_overflow_count) {					\
		size_t index = hp.first;					\
		size_t delta = hash_table_probe_delta(hp);			\
		uint8_t hosted_dec = 0;						\
										\
		for (;;) {							\
			chunk = &table->chunks[index & table->chunk_mask];	\
			if (chunk == pos_chunk) {				\
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
static bool table##_delete_hashed(HASH_TABLE_TYPE(table) *table,		\
				  const typeof(key_type) *key,			\
				  struct hash_pair hp)				\
{										\
	HASH_TABLE_POS(table) pos;						\
										\
	pos = table##_search_pos(table, key, hp);				\
	if (pos.item) {								\
		table##_delete_pos(table, pos, hp);				\
		return true;							\
	} else {								\
		return false;							\
	}									\
}										\
										\
__attribute__((unused))								\
static bool table##_delete(HASH_TABLE_TYPE(table) *table,			\
			   const typeof(key_type) *key)				\
{										\
	return table##_delete_hashed(table, key, table##_hash(key));		\
}										\
										\
__attribute__((unused))								\
static HASH_TABLE_POS(table) table##_first_pos(HASH_TABLE_TYPE(table) *table)	\
{										\
	return table##_unpack_pos(table->first_packed);				\
}										\
										\
__attribute__((unused))								\
static void table##_next_pos(HASH_TABLE_POS(table) *pos)			\
{										\
	HASH_TABLE_CHUNK(table) *chunk;						\
										\
	chunk = table##_pos_chunk(*pos);					\
	while (pos->index > 0) {						\
		pos->index--;							\
		pos->item--;							\
		if (chunk->tags[pos->index])					\
			return;							\
	}									\
										\
	while (chunk->chunk0_capacity == 0) {					\
		unsigned int last;						\
										\
		chunk--;							\
		last = table##_chunk_last_occupied(chunk);			\
		__builtin_prefetch(chunk - 1);					\
		if (last != (unsigned int)-1) {					\
			pos->index = last;					\
			pos->item = &chunk->items[last];			\
			return;							\
		}								\
	}									\
	pos->item = NULL;							\
}

/**
 * @ingroup HashMaps
 *
 * Define a hash map type without defining its functions.
 *
 * This is useful when the map type must be defined in one place (e.g., a
 * header) but the interface is defined elsewhere (e.g., a source file) with
 * @ref DEFINE_HASH_MAP_FUNCTIONS(). Otherwise, just use @ref DEFINE_HASH_MAP().
 *
 * @sa DEFINE_HASH_MAP()
 */
#define DEFINE_HASH_MAP_TYPES(table, key_type, value_type)	\
struct table##_item {						\
	typeof(key_type) key;					\
	typeof(value_type) value;				\
};								\
DEFINE_HASH_TABLE_TYPES(table, key_type, struct table##_item)

/**
 * @ingroup HashMaps
 *
 * Define the functions for a hash map.
 *
 * The map type must have already been defined with @ref
 * DEFINE_HASH_MAP_TYPES().
 *
 * Unless the type and function definitions must be in separate places, use @ref
 * DEFINE_HASH_MAP() instead.
 *
 * @sa DEFINE_HASH_MAP()
 */
#define DEFINE_HASH_MAP_FUNCTIONS(table, key_type, value_type, hash_func,	\
				  eq_func)					\
DEFINE_HASH_TABLE_FUNCTIONS(table, key_type, struct table##_item,		\
			    HASH_MAP_ITEM_KEY, hash_func, eq_func)		\
										\
static inline typeof(value_type) *						\
table##_search_hashed(HASH_TABLE_TYPE(table) *table,				\
		      const typeof(key_type) *key,				\
		      struct hash_pair hp)					\
{										\
	HASH_TABLE_POS(table) pos = table##_search_pos(table, key, hp);		\
										\
	return pos.item ? &pos.item->value : NULL;				\
}										\
										\
__attribute__((unused))								\
static inline typeof(value_type) *table##_search(HASH_TABLE_TYPE(table) *table,	\
						 const typeof(key_type) *key)	\
{										\
	return table##_search_hashed(table, key, table##_hash(key));		\
}										\
										\
static HASH_TABLE_POS(table)							\
table##_insert_searched_pos(HASH_TABLE_TYPE(table) *table,			\
			    const typeof(key_type) *key,			\
			    const typeof(value_type) *value,			\
			    struct hash_pair hp)				\
{										\
	HASH_TABLE_POS(table) pos = table##_do_insert(table, key, hp);		\
										\
	if (pos.item) {								\
		memcpy(&pos.item->key, key, sizeof(*key));			\
		memcpy(&pos.item->value, value, sizeof(*value));		\
	}									\
	return pos;								\
}										\
										\
static HASH_TABLE_POS(table)							\
table##_insert_pos(HASH_TABLE_TYPE(table) *table, const typeof(key_type) *key,	\
		   const typeof(value_type) *value, struct hash_pair hp)	\
{										\
	HASH_TABLE_POS(table) pos = table##_search_pos(table, key, hp);		\
										\
	if (pos.item) {								\
		memcpy(&pos.item->value, value, sizeof(*value));		\
		return pos;							\
	} else {								\
		return table##_insert_searched_pos(table, key, value, hp);	\
	}									\
}										\
										\
__attribute__((unused))								\
static bool table##_insert_searched(HASH_TABLE_TYPE(table) *table,		\
				    const typeof(key_type) *key,		\
				    const typeof(value_type) *value,		\
				    struct hash_pair hp)			\
{										\
	return table##_insert_searched_pos(table, key, value, hp).item != NULL;	\
}										\
										\
static bool table##_insert_hashed(HASH_TABLE_TYPE(table) *table,		\
				  const typeof(key_type) *key,			\
				  const typeof(value_type) *value,		\
				  struct hash_pair hp)				\
{										\
	return table##_insert_pos(table, key, value, hp).item != NULL;		\
}										\
										\
__attribute__((unused))								\
static bool table##_insert(HASH_TABLE_TYPE(table) *table,			\
			   const typeof(key_type) *key,				\
			   const typeof(value_type) *value)			\
{										\
	return table##_insert_hashed(table, key, value, table##_hash(key));	\
}

/**
 * @ingroup HashMaps
 *
 * Define a hash map interface.
 *
 * This macro defines a hash map type along with its functions.
 *
 * @param[in] table Name of the map type to define. This is prefixed to all of
 * the types and functions defined for that type.
 * @param[in] key_type Type of keys in the map.
 * @param[in] value_type Type of values in the map.
 * @param[in] hash_func Hash function which takes a <tt>const key_type *</tt>
 * and returns a @ref hash_pair.
 * @param[in] eq_func Comparison function which takes two <tt>const key_type
 * *</tt> and returns a @c bool.
 */
#define DEFINE_HASH_MAP(table, key_type, value_type, hash_func, eq_func)	\
DEFINE_HASH_MAP_TYPES(table, key_type, value_type)				\
DEFINE_HASH_MAP_FUNCTIONS(table, key_type, value_type, hash_func, eq_func)

/**
 * @ingroup HashSets
 *
 * Define a hash set type without defining its functions.
 *
 * This is useful when the set type must be defined in one place (e.g., a
 * header) but the interface is defined elsewhere (e.g., a source file) with
 * @ref DEFINE_HASH_SET_FUNCTIONS(). Otherwise, just use @ref DEFINE_HASH_SET().
 *
 * @sa DEFINE_HASH_SET()
 */
#define DEFINE_HASH_SET_TYPES(table, key_type)	\
	DEFINE_HASH_TABLE_TYPES(table, key_type, typeof(key_type))

/**
 * @ingroup HashSets
 *
 * Define the functions for a hash set.
 *
 * The set type must have already been defined with @ref
 * DEFINE_HASH_SET_TYPES().
 *
 * Unless the type and function definitions must be in separate places, use @ref
 * DEFINE_HASH_SET() instead.
 *
 * @sa DEFINE_HASH_SET()
 */
#define DEFINE_HASH_SET_FUNCTIONS(table, key_type, hash_func, eq_func)		\
DEFINE_HASH_TABLE_FUNCTIONS(table, key_type, typeof(key_type),			\
			    HASH_SET_ITEM_KEY, hash_func, eq_func)		\
										\
static inline bool table##_search_hashed(HASH_TABLE_TYPE(table) *table,		\
					 const typeof(key_type) *key,		\
					 struct hash_pair hp)			\
{										\
	return table##_search_pos(table, key, hp).item != NULL;			\
}										\
										\
__attribute__((unused))								\
static inline bool table##_search(HASH_TABLE_TYPE(table) *table,		\
				  const typeof(key_type) *key)			\
{										\
	return table##_search_hashed(table, key, table##_hash(key));		\
}										\
										\
static HASH_TABLE_POS(table)							\
table##_insert_searched_pos(HASH_TABLE_TYPE(table) *table,			\
			    const typeof(key_type) *key,			\
			    struct hash_pair hp)				\
{										\
	HASH_TABLE_POS(table) pos = table##_do_insert(table, key, hp);		\
										\
	if (pos.item)								\
		memcpy(pos.item, key, sizeof(*key));				\
	return pos;								\
}										\
										\
static HASH_TABLE_POS(table) table##_insert_pos(HASH_TABLE_TYPE(table) *table,	\
						const typeof(key_type) *key,	\
						struct hash_pair hp)		\
{										\
	HASH_TABLE_POS(table) pos = table##_search_pos(table, key, hp);		\
										\
	if (pos.item)								\
		return pos;							\
	else									\
		return table##_insert_searched_pos(table, key, hp);		\
}										\
										\
__attribute__((unused))								\
static bool table##_insert_searched(HASH_TABLE_TYPE(table) *table,		\
				    const typeof(key_type) *key,		\
				    struct hash_pair hp)			\
{										\
	return table##_insert_searched_pos(table, key, hp).item != NULL;	\
}										\
										\
static bool table##_insert_hashed(HASH_TABLE_TYPE(table) *table,		\
				  const typeof(key_type) *key,			\
				  struct hash_pair hp)				\
{										\
	return table##_insert_pos(table, key, hp).item != NULL;			\
}										\
										\
__attribute__((unused))								\
static bool table##_insert(HASH_TABLE_TYPE(table) *table,			\
			   const typeof(key_type) *key)				\
{										\
	return table##_insert_hashed(table, key, table##_hash(key));		\
}

/**
 * @ingroup HashSets
 *
 * Define a hash set interface.
 *
 * This macro defines a hash set type along with its functions.
 *
 * @param[in] table Name of the set type to define. This is prefixed to all of
 * the types and functions defined for that type.
 * @param[in] key_type Type of keys in the set.
 * @param[in] hash_func Hash function which takes a <tt>const key_type *</tt>
 * and returns a @ref hash_pair.
 * @param[in] eq_func Comparison function which takes two <tt>const key_type
 * *</tt> and returns a @c bool.
 */
#define DEFINE_HASH_SET(table, key_type, hash_func, eq_func)	\
DEFINE_HASH_SET_TYPES(table, key_type)				\
DEFINE_HASH_SET_FUNCTIONS(table, key_type, hash_func, eq_func)

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

/** Split an avalanching hash into a @ref hash_pair. */
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
		.second = ((hash >> 15) & 0x7f) | 0x80,
	};
#endif
#elif SIZE_MAX == 0xffffffff
/* 32-bit with SSE4.2 uses CRC32 */
#ifdef __SSE4_2__
	size_t c = _mm_crc32_u32(0, hash);

	return (struct hash_pair){
		.first = hash + c,
		.second = (c >> 24) | 0x80,
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
 * (e.g., integers, float-point numbers, pointers).
 */
bool hash_table_scalar_eq(const T *a, const T *b);
#else
#define hash_table_scalar_eq(a, b) (*(a) == *(b))
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

/** Hash a null-terminated string. */
static inline struct hash_pair c_string_hash(const char * const *key)
{
	size_t hash = cityhash_size_t(*key, strlen(*key));

	return hash_pair_from_avalanching_hash(hash);
}

/** Compare two null-terminated string keys for equality. */
static inline bool c_string_eq(const char * const *a, const char * const *b)
{
	return strcmp(*a, *b) == 0;
}

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
	return a->len == b->len && memcmp(a->str, b->str, a->len) == 0;
}

/** @} */

/** @} */

#endif /* DRGN_HASH_TABLE_H */
