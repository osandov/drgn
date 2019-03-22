// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"
#include "memory_reader.h"

static struct drgn_error *pread_all(int fd, void *buf, size_t count,
				    off_t offset)
{
	char *p = buf;

	while (count) {
		ssize_t ret;

		ret = pread(fd, p, count, offset);
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
		offset += ret;
	}
	return NULL;
}

static struct drgn_error *
drgn_memory_file_reader_read(struct drgn_memory_reader *reader, void *buf,
			     uint64_t address, size_t count, bool physical)
{
	struct drgn_error *err;
	struct drgn_memory_file_reader *freader;
	char *p = buf;

	freader = container_of(reader, struct drgn_memory_file_reader, reader);
	while (count) {
		struct drgn_memory_file_segment *segment;
		uint64_t segment_address;
		uint64_t segment_offset;
		off_t read_offset;
		size_t read_count, zero_count;
		int i;

		/*
		 * The most recently used segments are at the end of the list,
		 * so search backwards.
		 */
		for (i = freader->num_segments - 1; i >= 0; i--) {
			segment = &freader->segments[i];
			segment_address = (physical ? segment->phys_addr :
					   segment->virt_addr);
			if (segment_address == UINT64_MAX)
				continue;
			if (segment_address <= address &&
			    address < segment_address + segment->mem_size)
				break;
		}
		if (i < 0) {
			return drgn_error_format(DRGN_ERROR_FAULT,
						 "could not find memory segment containing 0x%" PRIx64,
						 address);
		}

		/* Move the used segment to the end of the list. */
		if ((size_t)i != freader->num_segments - 1) {
			struct drgn_memory_file_segment tmp = *segment;

			memmove(&freader->segments[i],
				&freader->segments[i + 1],
				(freader->num_segments - i - 1) *
				sizeof(*freader->segments));
			segment = &freader->segments[freader->num_segments - 1];
			*segment = tmp;
		}

		segment_offset = address - segment_address;
		if (segment_offset < segment->file_size)
			read_count = min(segment->file_size - segment_offset,
					 (uint64_t)count);
		else
			read_count = 0;
		if (segment_offset + read_count < segment->mem_size)
			zero_count = min(segment->mem_size - segment_offset - read_count,
					 (uint64_t)(count - read_count));
		else
			zero_count = 0;
		read_offset = segment->file_offset + segment_offset;
		err = pread_all(freader->fd, p, read_count, read_offset);
		if (err)
			return err;
		memset(p + read_count, 0, zero_count);

		p += read_count + zero_count;
		count -= read_count + zero_count;
		address += read_count + zero_count;
	}
	return NULL;
}

static void drgn_memory_file_reader_destroy(struct drgn_memory_reader *reader)
{
	struct drgn_memory_file_reader *freader;

	freader = container_of(reader, struct drgn_memory_file_reader, reader);
	free(freader->segments);
	free(freader);
}

static const struct drgn_memory_reader_ops drgn_memory_file_reader_ops = {
	.destroy = drgn_memory_file_reader_destroy,
	.read = drgn_memory_file_reader_read,
};

struct drgn_error *
drgn_memory_file_reader_create(int fd, struct drgn_memory_file_reader **ret)
{
	struct drgn_memory_file_reader *freader;

	freader = malloc(sizeof(*freader));
	if (!freader)
		return &drgn_enomem;
	freader->reader.ops = &drgn_memory_file_reader_ops;
	freader->segments = NULL;
	freader->num_segments = 0;
	freader->capacity = 0;
	freader->fd = fd;
	*ret = freader;
	return NULL;
}

struct drgn_error *
drgn_memory_file_reader_add_segment(struct drgn_memory_file_reader *freader,
				    const struct drgn_memory_file_segment *segment)
{
	if (segment->file_offset > OFF_MAX) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "segment offset does not fit in off_t");
	}
	if (segment->file_size > OFF_MAX - segment->file_offset) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "segment end does not fit in off_t");
	}

	if (freader->num_segments >= freader->capacity) {
		size_t new_capacity;

		if (freader->capacity)
			new_capacity = freader->capacity * 2;
		else
			new_capacity = 1;
		if (!resize_array(&freader->segments, new_capacity))
			return &drgn_enomem;
		freader->capacity = new_capacity;
	}

	freader->segments[freader->num_segments++] = *segment;
	return NULL;
}
