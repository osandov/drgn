// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * Memory reading interface.
 *
 * See @ref MemoryReader.
 */

#ifndef DRGN_MEMORY_READER_H
#define DRGN_MEMORY_READER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

struct drgn_memory_segment;

/**
 * Callback implementing a memory read.
 *
 * @param[out] buf Buffer to read into.
 * @param[in] address Address which we are reading from.
 * @param[in] count Number of bytes to read.
 * @param[in] physical Whether @c address is physical.
 * @param[in] offset Offset in bytes of @p address from the beginning of the
 * segment.
 * @param[in] arg Argument passed to @ref drgn_memory_reader_add_segment().
 * @return @c NULL on success, non-@c NULL on error.
 */
typedef struct drgn_error *(*drgn_memory_read_fn)(void *buf, uint64_t address,
						  size_t count, bool physical,
						  uint64_t offset, void *arg);

/** Memory segment in a @ref drgn_memory_reader. */
struct drgn_memory_segment {
	/**
	 * Virtual address of the segment in memory. If @c UINT64_MAX, the
	 * segment does not have a known virtual address.
	 */
	uint64_t virt_addr;
	/**
	 * Physical address of the segment in memory. If @c UINT64_MAX, the
	 * segment does not have a known physical address.
	 */
	uint64_t phys_addr;
	/** Size of the segment in bytes. */
	uint64_t size;
	/** Read callback. */
	drgn_memory_read_fn read_fn;
	/** Argument to pass to @ref drgn_memory_segment::read_fn. */
	void *arg;
};

/**
 * Memory reader.
 *
 * A memory reader maps the segments of memory in an address space to callbacks
 * which can be used to read memory from those segments.
 */
struct drgn_memory_reader {
	/** Memory segments. */
	struct drgn_memory_segment *segments;
	/** Number of segments. */
	size_t num_segments;
	/** Allocated number of segments. */
	size_t capacity;
};

/**
 * Initialize a @ref drgn_memory_reader.
 *
 * The reader is initialized with no segments.
 */
void drgn_memory_reader_init(struct drgn_memory_reader *reader);

/** Deinitialize a @ref drgn_memory_reader. */
void drgn_memory_reader_deinit(struct drgn_memory_reader *reader);

struct drgn_error *drgn_memory_reader_create(struct drgn_memory_reader **ret);

void drgn_memory_reader_destroy(struct drgn_memory_reader *reader);

/**
 * Register a segment of memory in a @ref drgn_memory_reader.
 *
 * If the segment overlaps a previously registered segment, the new segment
 * takes precedence.
 *
 * @param[in] reader Reader to add segment to.
 * @param[in] virt_addr Virtual address of segment, or @c UINT64_MAX if the
 * segment does not have a virtual address.
 * @param[in] phys_addr Physical address of segment, or @c UINT64_MAX if the
 * segment does not have a physical address.
 * @param[in] size Size of the segment in bytes.
 * @param[in] read_fn Callback to read from segment.
 * @param[in] arg Argument to pass to @p read_fn.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_memory_reader_add_segment(struct drgn_memory_reader *reader,
			       uint64_t virt_addr, uint64_t phys_addr,
			       uint64_t size, drgn_memory_read_fn read_fn,
			       void *arg);

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
};

/** @ref drgn_memory_read_fn which reads from a file. */
struct drgn_error *drgn_read_memory_file(void *buf, uint64_t address,
					 size_t count, bool physical,
					 uint64_t offset, void *arg);

/** Memory segment for testing. */
struct drgn_mock_memory_segment {
	/**
	 * Virtual address of the segment in memory. If @c UINT64_MAX, the
	 * segment does not have a known virtual address.
	 */
	uint64_t virt_addr;
	/**
	 * Physical address of the segment in memory. If @c UINT64_MAX, the
	 * segment does not have a known physical address.
	 */
	uint64_t phys_addr;
	/** Size of the segment in bytes. */
	uint64_t size;
	/** Segment memory. */
	const void *buf;
};

/** @} */

#endif /* DRGN_MEMORY_READER_H */
