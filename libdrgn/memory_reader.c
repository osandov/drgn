// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <inttypes.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"
#include "memory_reader.h"

void drgn_memory_reader_init(struct drgn_memory_reader *reader)
{
	reader->segments = NULL;
	reader->num_segments = reader->capacity = 0;
}

void drgn_memory_reader_deinit(struct drgn_memory_reader *reader)
{
	free(reader->segments);
}

struct drgn_error *
drgn_memory_reader_add_segment(struct drgn_memory_reader *reader,
			       uint64_t virt_addr, uint64_t phys_addr,
			       uint64_t size, drgn_memory_read_fn read_fn,
			       void *arg)
{
	struct drgn_memory_segment *segment;

	if ((virt_addr == UINT64_MAX && phys_addr == UINT64_MAX) || size == 0)
		return NULL;

	if (reader->num_segments >= reader->capacity) {
		size_t new_capacity;

		new_capacity = reader->capacity ? 2 * reader->capacity : 1;
		if (!resize_array(&reader->segments, new_capacity))
			return &drgn_enomem;
		reader->capacity = new_capacity;
	}

	segment = &reader->segments[reader->num_segments++];
	segment->virt_addr = virt_addr;
	segment->phys_addr = phys_addr;
	segment->size = size;
	segment->read_fn = read_fn;
	segment->arg = arg;
	return NULL;
}

struct drgn_error *drgn_memory_reader_read(struct drgn_memory_reader *reader,
					   void *buf, uint64_t address,
					   size_t count, bool physical)
{
	struct drgn_error *err;
	size_t read = 0;

	while (read < count) {
		struct drgn_memory_segment *segment;
		uint64_t segment_address, segment_offset;
		size_t i, n;

		/*
		 * The most recently used segments are at the end of the list,
		 * so search backwards.
		 */
		i = reader->num_segments;
		for (;;) {
			if (i == 0) {
				return drgn_error_format(DRGN_ERROR_FAULT,
							 "could not find memory segment containing 0x%" PRIx64,
							 address);
			}
			segment = &reader->segments[--i];
			segment_address = (physical ? segment->phys_addr :
					   segment->virt_addr);
			if (segment_address != UINT64_MAX &&
			    segment_address <= address &&
			    address < segment_address + segment->size)
				break;
		}

		/* Move the used segment to the end of the list. */
		if (i != reader->num_segments - 1) {
			struct drgn_memory_segment tmp = *segment;

			memmove(&reader->segments[i], &reader->segments[i + 1],
				(reader->num_segments - i - 1) *
				sizeof(*reader->segments));
			segment = &reader->segments[reader->num_segments - 1];
			*segment = tmp;
		}

		segment_offset = address - segment_address;
		n = min(segment->size - segment_offset, (uint64_t)(count - read));
		err = segment->read_fn((char *)buf + read, address, n, physical,
				       segment_offset, segment->arg);
		if (err)
			return err;

		read += n;
		address += n;
	}
	return NULL;
}

struct drgn_error *drgn_read_memory_file(void *buf, uint64_t address,
					 size_t count, bool physical,
					 uint64_t offset, void *arg)
{
	struct drgn_memory_file_segment *file_segment = arg;
	char *p = buf;
	uint64_t file_offset = file_segment->file_offset + offset;

	while (count) {
		ssize_t ret;

		ret = pread(file_segment->fd, p, count, file_offset);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			return drgn_error_create_os(errno, NULL, "pread");
		} else if (ret == 0) {
			return drgn_error_format(DRGN_ERROR_FAULT,
						 "short read from memory file");
		}
		p += ret;
		count -= ret;
		file_offset += ret;
	}
	return NULL;
}
