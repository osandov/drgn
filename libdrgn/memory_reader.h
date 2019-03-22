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
 * @ref drgn_memory_reader provides a common interface for reading from the
 * memory of a program.
 *
 * @{
 */

struct drgn_memory_reader;

/** Memory reader operations. */
struct drgn_memory_reader_ops {
	/** Implements @ref drgn_memory_reader_destroy(). */
	void (*destroy)(struct drgn_memory_reader *reader);
	/** Implements @ref drgn_memory_reader_read(). */
	struct drgn_error *(*read)(struct drgn_memory_reader *reader, void *buf,
				   uint64_t address, size_t count,
				   bool physical);
};

/**
 * Abstract memory reader.
 *
 * A memory reader can be backed by a few things:
 *   - A file (@ref drgn_memory_file_reader).
 *   - Arbitrary memory (@ref drgn_mock_memory_reader).
 *
 * It is read from with @ref drgn_memory_reader_read() and freed with @ref
 * drgn_memory_reader_destroy().
 */
struct drgn_memory_reader {
	/** Operation dispatch table. */
	const struct drgn_memory_reader_ops *ops;
};

/**
 * Free a @ref drgn_memory_reader.
 *
 * @param[in] reader Memory reader to destroy.
 */
static inline void drgn_memory_reader_destroy(struct drgn_memory_reader *reader)
{
	if (reader)
		reader->ops->destroy(reader);
}

/**
 * Read from a @ref drgn_memory_reader.
 *
 * @param[in] reader Memory reader.
 * @param[out] buf Buffer to read into.
 * @param[in] address Starting address in memory to read.
 * @param[in] count Number of bytes to read.
 * @param[in] physical Whether @c address is physical. A reader may support only
 * virtual or physical addresses or both.
 * @return @c NULL on success, non-@c NULL on error.
 */
static inline struct drgn_error *
drgn_memory_reader_read(struct drgn_memory_reader *reader, void *buf,
			uint64_t address, size_t count, bool physical)
{
	return reader->ops->read(reader, buf, address, count, physical);
}

/** Memory segment in a @ref drgn_mock_memory_reader. */
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

/**
 * Memory reader backed by arbitrary memory.
 *
 * This is mostly useful for testing. It is created with @ref
 * drgn_mock_memory_reader_create().
 */
struct drgn_mock_memory_reader {
	/** Abstract memory reader. */
	struct drgn_memory_reader reader;
	/** Memory segments. */
	struct drgn_mock_memory_segment *segments;
	/** Number of segments. */
	size_t num_segments;
};

/**
 * Create a @ref drgn_mock_memory_reader.
 *
 * @param[in] segments Memory segments. This will not be freed when the reader
 * is destroyed.
 * @param[in] num_segments Number of segments.
 * @param[out] ret Returned memory reader.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_mock_memory_reader_create(struct drgn_mock_memory_segment *segments,
			       size_t num_segments,
			       struct drgn_mock_memory_reader **ret);

/** Memory segment in a @ref drgn_memory_file_reader. */
struct drgn_memory_file_segment {
	/** Offset in the file where the segment starts. */
	uint64_t file_offset;
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
	/** Size of the segment in the file. */
	uint64_t file_size;
	/**
	 * Size of the segment in memory. If greater than @ref
	 * drgn_memory_file_segment::file_size, the remainder of the segment is
	 * treated as if it contained zeroes.
	 */
	uint64_t mem_size;
};

/**
 * Memory file reader.
 *
 * This is a concrete @ref drgn_memory_reader which is backed by a file. This
 * may be, for example, an ELF core dump file, or a flat file like
 * <tt>/proc/$pid/mem</tt>. It is created with @ref
 * drgn_memory_file_reader_create(). Segments are added with @ref
 * drgn_memory_file_reader_add_segment().
 */
struct drgn_memory_file_reader {
	/** Abstract memory reader. */
	struct drgn_memory_reader reader;
	/** Memory segments. */
	struct drgn_memory_file_segment *segments;
	/** Number of segments. */
	size_t num_segments;
	/** Capacity of @c segments. */
	size_t capacity;
	/** File descriptor. */
	int fd;
};

/**
 * Create a @ref drgn_memory_file_reader.
 *
 * This creates a memory file reader with no segments.
 *
 * @param[in] fd File descriptor referring to the file. It will not be closed
 * when the reader is destroyed.
 * @param[out] ret Returned memory reader.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_memory_file_reader_create(int fd, struct drgn_memory_file_reader **ret);

/**
 * Add a memory segment to a @ref drgn_memory_file_reader.
 *
 * If there are overlapping segments, then the most recently added segment is
 * used.
 *
 * @param[in] freader Memory file reader.
 * @param[in] segment Memory segment to add.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_memory_file_reader_add_segment(struct drgn_memory_file_reader *freader,
				    const struct drgn_memory_file_segment *segment);

/** @} */

#endif /* DRGN_MEMORY_READER_H */
