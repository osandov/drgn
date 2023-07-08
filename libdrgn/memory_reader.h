// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

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
 * @ref drgn_memory_reader does not have a notion of the maximum address or
 * address overflow/wrap-around. Those must be handled at a higher layer.
 *
 * @{
 */

DEFINE_BINARY_SEARCH_TREE_TYPE(drgn_memory_segment_tree,
			       struct drgn_memory_segment)

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

/**
 * Add a segment to a @ref drgn_memory_reader.
 *
 * @param[in] reader Memory reader.
 * @param[in] min_address Start address (inclusive).
 * @param[in] max_address End address (inclusive). Must be `>= min_address`.
 * @param[in] read_fn Callback to read from segment.
 * @param[in] arg Argument to pass to @p read_fn.
 * @param[in] physical Whether to add a physical memory segment.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_memory_reader_add_segment(struct drgn_memory_reader *reader,
			       uint64_t min_address, uint64_t max_address,
			       const struct drgn_memory_ops *ops, void *arg,
			       bool physical);

/**
 * Read from a @ref drgn_memory_reader.
 *
 * @param[in] reader Memory reader.
 * @param[out] buf Buffer to read into.
 * @param[in] address Starting address in memory to read.
 * @param[in] count Number of bytes to read. `address + count - 1` must be
 * `<= UINT64_MAX`
 * @param[in] physical Whether @c address is physical.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_memory_reader_read(struct drgn_memory_reader *reader,
					   void *buf, uint64_t address,
					   size_t count, bool physical);

struct drgn_error *
drgn_memory_reader_read_cstr(struct drgn_memory_reader *reader,
			     struct string_builder *buf, bool *done,
			     uint64_t address, size_t count, bool physical);

/** Argument for @ref drgn_read_memory_file(). */
struct drgn_memory_file_segment {
	/** Offset in the file where the segment starts. */
	uint64_t file_offset;
	/**
	 * Size of the segment in the file. This may be less than the size of
	 * the segment in memory.
	 */
	uint64_t file_size;
	/** File descriptor. */
	int fd;
	/**
	 * If @c true, EIO is treated as a fault. Otherwise, it is treated as an
	 * OS error.
	 */
	bool eio_is_fault;
	/**
	 * If @c true, reads between @ref file_size and the size of the segment
	 * in memory will be returned as zeroes. Otherwise, such reads will
	 * result in a fault.
	 */
	bool zerofill;
};

extern const struct drgn_memory_ops segment_file_ops;

/** @} */

#endif /* DRGN_MEMORY_READER_H */
