// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file
 *
 * Memory reading interface.
 *
 * See @ref MemoryReader.
 */

#ifndef DRGN_MEMORY_READER_H
#define DRGN_MEMORY_READER_H

#include "binary_search_tree.h"
#include "drgn.h"

/**
 * @ingroup Internals
 *
 * @defgroup MemoryReader Memory reader
 *
 * Memory reading interface.
 *
 * @ref drgn_memory_reader provides a common interface for registering regions
 * of memory in a program and reading from memory.
 *
 * @{
 */

/** Memory segment in a @ref drgn_memory_reader. */
struct drgn_memory_segment {
	struct binary_tree_node node;
	/** Address of the segment in memory. */
	uint64_t address;
	/** Size of the segment in bytes; */
	uint64_t size;
	/**
	 * The address of the segment when it was added, before any truncations.
	 *
	 * This is always greater than or equal to @ref
	 * drgn_memory_segment::address.
	 */
	uint64_t orig_address;
	/** Read callback. */
	drgn_memory_read_fn read_fn;
	/** Argument to pass to @ref drgn_memory_segment::read_fn. */
	void *arg;
};

static inline uint64_t
drgn_memory_segment_to_key(const struct drgn_memory_segment *entry)
{
	return entry->address;
}

DEFINE_BINARY_SEARCH_TREE_TYPE(drgn_memory_segment_tree,
			       struct drgn_memory_segment,
			       node, drgn_memory_segment_to_key)

/**
 * Memory reader.
 *
 * A memory reader maps the segments of memory in an address space to callbacks
 * which can be used to read memory from those segments.
 */
struct drgn_memory_reader {
	/** Virtual memory segments. */
	struct drgn_memory_segment_tree virtual_segments;
	/** Physical memory segments. */
	struct drgn_memory_segment_tree physical_segments;
};

/**
 * Initialize a @ref drgn_memory_reader.
 *
 * The reader is initialized with no segments.
 */
void drgn_memory_reader_init(struct drgn_memory_reader *reader);

/** Deinitialize a @ref drgn_memory_reader. */
void drgn_memory_reader_deinit(struct drgn_memory_reader *reader);

/** Return whether a @ref drgn_memory_reader has no segments. */
bool drgn_memory_reader_empty(struct drgn_memory_reader *reader);

/** @sa drgn_program_add_memory_segment() */
struct drgn_error *
drgn_memory_reader_add_segment(struct drgn_memory_reader *reader,
			       uint64_t address, uint64_t size,
			       drgn_memory_read_fn read_fn, void *arg,
			       bool physical);

/**
 * Read from a @ref drgn_memory_reader.
 *
 * @param[in] reader Memory reader.
 * @param[out] buf Buffer to read into.
 * @param[in] address Starting address in memory to read.
 * @param[in] count Number of bytes to read.
 * @param[in] physical Whether @c address is physical.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_memory_reader_read(struct drgn_memory_reader *reader,
					   void *buf, uint64_t address,
					   size_t count, bool physical);

/** Argument for @ref drgn_read_memory_file(). */
struct drgn_memory_file_segment {
	/** Offset in the file where the segment starts. */
	uint64_t file_offset;
	/**
	 * Size of the segment in the file. This may be less than the size of
	 * the segment in memory, in which case the remaining bytes are treated
	 * as if they contained zeroes.
	 */
	uint64_t file_size;
	/** File descriptor. */
	int fd;
	/**
	 * If @c true, EIO is treated as a fault. Otherwise, it is treated as an
	 * OS error.
	 */
	bool eio_is_fault;
};

/** @ref drgn_memory_read_fn which reads from a file. */
struct drgn_error *drgn_read_memory_file(void *buf, uint64_t address,
					 size_t count, uint64_t offset,
					 void *arg, bool physical);

/** @} */

#endif /* DRGN_MEMORY_READER_H */
