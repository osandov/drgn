// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * Memory reading interface.
 *
 * See @ref MemoryReader.
 */

#ifndef DRGN_MEMORY_INTERFACE_H
#define DRGN_MEMORY_INTERFACE_H

#include "binary_search_tree.h"
#include "drgn.h"

/**
 * @ingroup Internals
 *
 * @defgroup MemoryReader Memory interface
 *
 * Memory reading and writing interface.
 *
 * @ref drgn_memory_interface provides a common interface for registering regions
 * of memory in a program, reading from and writing to memory.
 *
 * @ref drgn_memory_interface does not have a notion of the maximum address or
 * address overflow/wrap-around. Those must be handled at a higher layer.
 *
 * @{
 */

DEFINE_BINARY_SEARCH_TREE_TYPE(drgn_memory_segment_tree,
			       struct drgn_memory_segment);

/**
 * Memory interface.
 *
 * A memory interface maps the segments of memory in an address space to callbacks
 * which can be used to read and write memory from those segments.
 */
struct drgn_memory_interface {
	/** Virtual memory segments. */
	struct drgn_memory_segment_tree virtual_segments;
	/** Physical memory segments. */
	struct drgn_memory_segment_tree physical_segments;
};

/**
 * Initialize a @ref drgn_memory_interface.
 *
 * The memory interface is initialized with no segments.
 */
void drgn_memory_interface_init(struct drgn_memory_interface *memory);

/** Deinitialize a @ref drgn_memory_interface. */
void drgn_memory_interface_deinit(struct drgn_memory_interface *memory);

/** Return whether a @ref drgn_memory_interface has no segments. */
bool drgn_memory_interface_empty(struct drgn_memory_interface *memory);

/**
 * Add a segment to a @ref drgn_memory_interface.
 *
 * @param[in] memory Memory interface.
 * @param[in] min_address Start address (inclusive).
 * @param[in] max_address End address (inclusive). Must be `>= min_address`.
 * @param[in] read_fn Callback to read from segment.
 * @param[in] arg Argument to pass to @p read_fn.
 * @param[in] physical Whether to add a physical memory segment.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_memory_interface_add_segment(struct drgn_memory_interface *memory,
				  uint64_t min_address, uint64_t max_address,
				  drgn_memory_read_fn read_fn, void *arg,
				  bool physical);

/**
 * Read from a @ref drgn_memory_interface.
 *
 * @param[in] memory Memory interface.
 * @param[out] buf Buffer to read into.
 * @param[in] address Starting address in memory to read.
 * @param[in] count Number of bytes to read. `address + count - 1` must be
 * `<= UINT64_MAX`
 * @param[in] physical Whether @c address is physical.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_memory_interface_read(struct drgn_memory_interface *memory,
					      void *buf, uint64_t address,
					      size_t count, bool physical);

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

/** @ref drgn_memory_read_fn which reads from a file. */
struct drgn_error *drgn_read_memory_file(void *buf, uint64_t address,
					 size_t count, uint64_t offset,
					 void *arg, bool physical);

/** @} */

#endif /* DRGN_MEMORY_READER_H */
