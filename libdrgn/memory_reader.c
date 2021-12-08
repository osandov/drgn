// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "memory_reader.h"
#include "minmax.h"

DEFINE_BINARY_SEARCH_TREE_FUNCTIONS(drgn_memory_segment_tree,
				    binary_search_tree_scalar_cmp, splay)

void drgn_memory_reader_init(struct drgn_memory_reader *reader)
{
	drgn_memory_segment_tree_init(&reader->virtual_segments);
	drgn_memory_segment_tree_init(&reader->physical_segments);
}

static void free_memory_segment_tree(struct drgn_memory_segment_tree *tree)
{
	struct drgn_memory_segment_tree_iterator it;

	it = drgn_memory_segment_tree_first_post_order(tree);
	while (it.entry) {
		struct drgn_memory_segment *entry = it.entry;

		it = drgn_memory_segment_tree_next_post_order(it);
		free(entry);
	}
}

void drgn_memory_reader_deinit(struct drgn_memory_reader *reader)
{
	free_memory_segment_tree(&reader->physical_segments);
	free_memory_segment_tree(&reader->virtual_segments);
}

bool drgn_memory_reader_empty(struct drgn_memory_reader *reader)
{
	return (drgn_memory_segment_tree_empty(&reader->virtual_segments) &&
		drgn_memory_segment_tree_empty(&reader->physical_segments));
}

struct drgn_error *
drgn_memory_reader_add_segment(struct drgn_memory_reader *reader,
			       uint64_t min_address, uint64_t max_address,
			       drgn_memory_read_fn read_fn, void *arg,
			       bool physical)
{
	assert(min_address <= max_address);

	struct drgn_memory_segment_tree *tree = (physical ?
						 &reader->physical_segments :
						 &reader->virtual_segments);

	/*
	 * This is split into two steps: the first step handles an overlapping
	 * segment with address <= new address, and the second step handles
	 * overlapping segments with address > new address. In some cases, we
	 * can steal an existing segment instead of allocating a new one.
	 */

	struct drgn_memory_segment *stolen = NULL, *segment;
	struct drgn_memory_segment *truncate_head = NULL, *truncate_tail = NULL;
	struct drgn_memory_segment_tree_iterator it =
		drgn_memory_segment_tree_search_le(tree, &min_address);
	if (it.entry) {
		if (max_address < it.entry->max_address) {
			/*
			 * The new segment lies entirely within an existing
			 * segment, and part of the existing segment extends
			 * after the new segment (a "tail").
			 */
			struct drgn_memory_segment *tail =
				malloc(sizeof(*tail));
			if (!tail)
				return &drgn_enomem;

			if (it.entry->min_address == min_address) {
				/*
				 * The new segment starts at the same address as
				 * the existing segment, so we can steal the
				 * existing segment and just add the tail.
				 */
				stolen = segment = it.entry;
			} else {
				/*
				 * Part of the existing segment extends before
				 * the new segment. We have to create the new
				 * segment and truncate the existing segment.
				 */
				segment = malloc(sizeof(*segment));
				if (!segment) {
					free(tail);
					return &drgn_enomem;
				}
				truncate_tail = it.entry;
			}

			tail->min_address = max_address + 1;
			tail->max_address = it.entry->max_address;
			tail->orig_min_address = it.entry->orig_min_address;
			tail->read_fn = it.entry->read_fn;
			tail->arg = it.entry->arg;

			drgn_memory_segment_tree_insert(tree, tail, NULL);
			goto insert;
		}
		if (it.entry->min_address == min_address) {
			/*
			 * The new segment subsumes an existing segment at the
			 * same address. We can steal the existing segment.
			 */
			stolen = it.entry;
		} else if (min_address <= it.entry->max_address) {
			/*
			 * The new segment overlaps an existing segment before
			 * it, and part of the existing segment extends before
			 * the new segment. We need to truncate the existing
			 * segment.
			 */
			truncate_tail = it.entry;
		} else {
			/*
			 * The new segment does not overlap any existing
			 * segments before it.
			 */
		}
		it = drgn_memory_segment_tree_next(it);
	} else {
		/* The new segment will be the new first segment. */
		it = drgn_memory_segment_tree_first(tree);
	}

	while (it.entry) {
		if (max_address >= it.entry->max_address) {
			/*
			 * The new segment subsumes an existing segment after
			 * it.
			 */
			if (stolen) {
				/*
				 * We already stole a segment. We can delete the
				 * existing segment. Since we won't try to
				 * allocate a new segment later, it's safe to
				 * modify the tree now.
				 */
				struct drgn_memory_segment *existing_segment = it.entry;
				it = drgn_memory_segment_tree_delete_iterator(tree, it);
				free(existing_segment);
			} else {
				/*
				 * We haven't stolen a segment yet, so steal
				 * this one.
				 *
				 * This segment is the first existing segment
				 * that starts after the new segment, and the
				 * previous existing segment must start before
				 * the new segment (otherwise we would've stolen
				 * it). Therefore, this won't disturb the tree
				 * order.
				 */
				stolen = it.entry;
				it = drgn_memory_segment_tree_next(it);
			}
			continue;
		}
		if (max_address >= it.entry->min_address) {
			/*
			 * The new segment overlaps an existing segment after
			 * it, and part of the existing segment extends after
			 * the new segment. We need to truncate the beginning of
			 * the existing segment.
			 */
			truncate_head = it.entry;
		}
		/*
		 * The existing segment ends after the new segment ends. We're
		 * done.
		 */
		break;
	}

	if (stolen) {
		segment = stolen;
	} else {
		segment = malloc(sizeof(*segment));
		if (!segment)
			return &drgn_enomem;
	}
insert:
	/*
	 * Now that we've allocated the new segment if necessary, we can safely
	 * modify the tree.
	 */
	if (truncate_head)
		truncate_head->min_address = max_address + 1;
	if (truncate_tail)
		truncate_tail->max_address = min_address - 1;
	segment->min_address = segment->orig_min_address = min_address;
	segment->max_address = max_address;
	segment->read_fn = read_fn;
	segment->arg = arg;
	/* If the segment is stolen, then it's already in the tree. */
	if (!stolen)
		drgn_memory_segment_tree_insert(tree, segment, NULL);
	return NULL;
}

struct drgn_error *drgn_memory_reader_read(struct drgn_memory_reader *reader,
					   void *buf, uint64_t address,
					   size_t count, bool physical)
{
	assert(count == 0 || count - 1 <= UINT64_MAX - address);

	struct drgn_error *err;
	struct drgn_memory_segment_tree *tree = (physical ?
						 &reader->physical_segments :
						 &reader->virtual_segments);
	char *p = buf;
	while (count > 0) {
		struct drgn_memory_segment *segment =
			drgn_memory_segment_tree_search_le(tree,
							   &address).entry;
		if (!segment || segment->max_address < address) {
			return drgn_error_create_fault("could not find memory segment",
						       address);
		}

		size_t n = min((uint64_t)(count - 1),
			       segment->max_address - address) + 1;
		err = segment->read_fn(p, address, n,
				       address - segment->orig_min_address,
				       segment->arg, physical);
		if (err)
			return err;
		p += n;
		address += n;
		count -= n;
	}
	return NULL;
}

struct drgn_error *drgn_read_memory_file(void *buf, uint64_t address,
					 size_t count, uint64_t offset,
					 void *arg, bool physical)
{
	struct drgn_memory_file_segment *file_segment = arg;

	if (offset > file_segment->file_size ||
	    count > file_segment->file_size - offset) {
		if (offset <= file_segment->file_size)
			address += file_segment->file_size - offset;
		return drgn_error_create_fault("memory not saved in core dump",
					       address);
	}

	uint64_t file_offset = file_segment->file_offset + offset;
	char *p = buf;
	while (count) {
		ssize_t ret = pread(file_segment->fd, p, count, file_offset);
		if (ret == -1) {
			if (errno == EINTR) {
				continue;
			} else if (errno == EIO && file_segment->eio_is_fault) {
				return drgn_error_create_fault("could not read memory",
							       address);
			} else {
				return drgn_error_create_os("pread", errno, NULL);
			}
		} else if (ret == 0) {
			return drgn_error_create_fault("short read from memory file",
						       address);
		}
		p += ret;
		address += ret;
		count -= ret;
		file_offset += ret;
	}
	return NULL;
}
