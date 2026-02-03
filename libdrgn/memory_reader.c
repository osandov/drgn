// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <assert.h>
#include <byteswap.h>
#include <endian.h>
#include <errno.h>
#ifdef WITH_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bitops.h"
#include "cleanup.h"
#include "error.h"
#include "helpers.h"
#include "memory_reader.h"
#include "minmax.h"
#include "program.h"
#include "string_builder.h"
#include "vector.h"

#ifdef WITH_PCRE2
#define _cleanup_pcre2_code_ _cleanup_(pcre2_code_freep)
static inline void pcre2_code_freep(pcre2_code **codep)
{
	pcre2_code_free(*codep);
}

#define _cleanup_pcre2_match_data_ _cleanup_(pcre2_match_data_freep)
static inline void pcre2_match_data_freep(pcre2_match_data **mdp)
{
	pcre2_match_data_free(*mdp);
}

__attribute__((__returns_nonnull__))
static struct drgn_error *drgn_error_pcre2(int errorcode, PCRE2_SIZE *offset)
{
	PCRE2_UCHAR buf[128];
	int len = pcre2_get_error_message(errorcode, buf, sizeof(buf));
	if (len == PCRE2_ERROR_BADDATA) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "unknown pcre2 error");
	}
	if (offset) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "pcre2 error at offset %zu: %s",
					 (size_t)*offset, (char *)buf);
	} else {
		return drgn_error_format(DRGN_ERROR_OTHER, "pcre2 error: %s",
					 (char *)buf);
	}
}

// pcre2_next_match() was added in PCRE2 10.47. For older versions, use our own
// copy based on PCRE2's. Doing it ourselves requires a bunch of extra arguments
// that are usually saved in the pcre2_match_data but we can't access.
#if PCRE2_MAJOR > 10 || (PCRE2_MAJOR == 10 && PCRE2_MINOR >= 47)
static int drgn_pcre2_next_match(pcre2_match_data *match_data, bool utf,
				 const unsigned char *subject,
				 PCRE2_SIZE subject_length,
				 PCRE2_SIZE start_offset, PCRE2_SIZE *ovector,
				 PCRE2_SIZE *pstart_offset, uint32_t *poptions)
{
	return pcre2_next_match(match_data, pstart_offset, poptions);
}
#else
static int drgn_pcre2_next_match(pcre2_match_data *match_data, bool utf,
				 const unsigned char *subject,
				 PCRE2_SIZE subject_length,
				 PCRE2_SIZE start_offset, PCRE2_SIZE *ovector,
				 PCRE2_SIZE *pstart_offset, uint32_t *poptions)
{
	if (ovector[0] != start_offset && ovector[1] == start_offset) {
		if (start_offset >= subject_length)
			return 0;

		PCRE2_SIZE offset = ovector[1] + 1;
		if (utf) {
			for (; offset < subject_length; offset++) {
				if ((subject[offset] & 0xc0) != 0x80)
					break;
			}
		}
		*pstart_offset = offset;
		*poptions = 0;
		return 1;
	}

	if (ovector[0] == ovector[1]) {
		if (ovector[0] >= subject_length)
			return 0;
		*pstart_offset = ovector[1];
		*poptions = PCRE2_NOTEMPTY_ATSTART;
		return 1;
	}

	*pstart_offset = ovector[1];
	*poptions = 0;
	return 1;
}
#endif
#endif

/** Memory segment in a @ref drgn_memory_reader. */
struct drgn_memory_segment {
	struct binary_tree_node node;
	/** Address range of the segment in memory (inclusive). */
	uint64_t min_address, max_address;
	/**
	 * The address of the segment when it was added, before any truncations.
	 *
	 * This is always less than or equal to @ref
	 * drgn_memory_segment::min_address.
	 */
	uint64_t orig_min_address;
	/** Read callback. */
	drgn_memory_read_fn read_fn;
	/** Argument to pass to @ref drgn_memory_segment::read_fn. */
	void *arg;
};

static inline uint64_t
drgn_memory_segment_to_key(const struct drgn_memory_segment *entry)
{
	return entry->min_address;
}

DEFINE_BINARY_SEARCH_TREE_FUNCTIONS(drgn_memory_segment_tree, node,
				    drgn_memory_segment_to_key,
				    binary_search_tree_scalar_cmp, splay);

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
			return drgn_error_format_fault(address,
						       "could not find %smemory segment",
						       physical ? "physical " : "");
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
	size_t file_count;
	if (offset < file_segment->file_size) {
		file_count = min((uint64_t)count,
				 file_segment->file_size - offset);
	} else {
		file_count = 0;
	}
	size_t zero_count = count - file_count;
	if (!file_segment->zerofill && zero_count > 0) {
		return drgn_error_create_fault("memory not saved in core dump",
					       address + file_count);
	}

	uint64_t file_offset = file_segment->file_offset + offset;
	char *p = buf;
	while (file_count) {
		ssize_t ret = pread(file_segment->fd, p, file_count, file_offset);
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
		file_count -= ret;
		file_offset += ret;
	}
	memset(p, '\0', zero_count);
	return NULL;
}

struct drgn_memory_search_iterator {
	struct drgn_program *prog;

	enum {
		DRGN_MEMORY_SEARCH_ITERATOR_MODE_MEMMEM,
#define X(bits)	DRGN_MEMORY_SEARCH_ITERATOR_MODE_U##bits,	\
		DRGN_MEMORY_SEARCH_ITERATOR_MODE_U##bits##_MULTI,
		SEARCH_MEMORY_UINT_SIZES
#undef X
#ifdef WITH_PCRE2
		DRGN_MEMORY_SEARCH_ITERATOR_MODE_REGEX,
#endif
	} mode;

	union {
		struct {
			void *needle;
			size_t size;
			uint64_t alignment_mask;
		} memmem;
#define X(bits)						\
		uint##bits##_t u##bits;			\
		struct {				\
			uint##bits##_t *values;		\
			size_t num_values;		\
			uint##bits##_t mask;		\
			uint##bits##_t (*ranges)[2];	\
			size_t num_ranges;		\
			bool bswap;			\
		} u##bits##_multi;
		SEARCH_MEMORY_UINT_SIZES
#undef X
#ifdef WITH_PCRE2
		struct {
			pcre2_code *code;
			pcre2_match_data *match_data;
			uint32_t min_length;
			uint32_t partial_option;
			uint32_t next_match_options;
			bool need_refill;
			bool utf8;
		} regex;
#endif
	};

	unsigned char *buf;
	size_t buf_available;
	size_t pos;
	uint64_t buf_address;

	size_t buf_capacity;
	// Round the end address of reads up to this alignment.
	size_t read_alignment_mask;

	uint64_t min_address;
	uint64_t max_address;
	uint64_t address_offset;
	// -1 if address range is not set yet.
	int physical;
};

static inline uint64_t align_down_mask(uint64_t value, uint64_t mask)
{
	return value & ~mask;
}

static inline uint64_t align_up_mask(uint64_t value, uint64_t mask)
{
	return (value + mask) & ~mask;
}

static struct drgn_memory_search_iterator *
drgn_memory_search_iterator_create_common(struct drgn_program *prog,
					  size_t refill_size,
					  uint64_t alignment_mask)
{
	// Reading memory tends to be slow, so whenever we read from memory, we
	// buffer some extra. Instead of reading ahead a fixed amount, we read
	// to the next boundary of some power of two.
	//
	// We start with a generous alignment that was found to give good
	// throughput in most scenarios. If we're searching for a large string,
	// then we want at least double its size so that we can check a couple
	// of candidates per read.
	static const size_t default_read_alignment = 64 * 1024;
	size_t read_alignment;
	if (refill_size <= default_read_alignment / 2)
		read_alignment = default_read_alignment;
	else if (refill_size <= SIZE_MAX / 4 + 1)
		read_alignment = next_power_of_two(refill_size) * 2;
	else // Would overflow.
		return NULL;

	struct drgn_memory_search_iterator *it = malloc(sizeof(*it));
	if (!it)
		return NULL;
	it->prog = prog;

	// The largest amount that we will buffer occurs when a read crosses a
	// read alignment boundary with as much as possible before the boundary.
	it->buf_capacity = align_down_mask(refill_size - 1, alignment_mask)
			   + read_alignment;
	it->buf = malloc(it->buf_capacity);
	if (!it->buf) {
		free(it);
		return NULL;
	}
	it->read_alignment_mask = read_alignment - 1;
	it->physical = -1;
	return it;
}

LIBDRGN_PUBLIC void
drgn_memory_search_iterator_destroy(struct drgn_memory_search_iterator *it)
{
	if (!it)
		return;
	SWITCH_ENUM(it->mode) {
	case DRGN_MEMORY_SEARCH_ITERATOR_MODE_MEMMEM:
		free(it->memmem.needle);
		break;
#define X(bits)							\
	case DRGN_MEMORY_SEARCH_ITERATOR_MODE_U##bits:		\
		break;						\
	case DRGN_MEMORY_SEARCH_ITERATOR_MODE_U##bits##_MULTI:	\
		free(it->u##bits##_multi.ranges);		\
		free(it->u##bits##_multi.values);		\
		break;
	SEARCH_MEMORY_UINT_SIZES
#undef X
#ifdef WITH_PCRE2
	case DRGN_MEMORY_SEARCH_ITERATOR_MODE_REGEX:
		pcre2_match_data_free(it->regex.match_data);
		pcre2_code_free(it->regex.code);
		break;
#endif
	default:
		UNREACHABLE();
	}
	free(it->buf);
	free(it);
}

LIBDRGN_PUBLIC struct drgn_program *
drgn_memory_search_iterator_program(const struct drgn_memory_search_iterator *it)
{
	return it->prog;
}

static inline size_t
drgn_memory_search_iterator_remaining_bytes(struct drgn_memory_search_iterator *it)
{
	return it->buf_available - it->pos;
}

static inline bool
drgn_memory_search_iterator_calc_buf_target(struct drgn_memory_search_iterator *it,
					    size_t needed, size_t *ret)
{
	if (needed - 1 > it->max_address - it->buf_address)
		return false;

	// This calculation still works if it->buf_address + needed wraps to 0.
	uint64_t max_address = align_up_mask(it->buf_address + needed,
					     it->read_alignment_mask) - 1;
	if (max_address > it->max_address)
		max_address = it->max_address;

	assert(max_address - it->buf_address < SIZE_MAX);
	*ret = max_address - it->buf_address + 1;
	return true;
}

static struct drgn_error *
drgn_memory_search_iterator_refill(struct drgn_memory_search_iterator *it,
				   drgn_blocking_state *blocking_state,
				   size_t needed, uint64_t alignment_mask,
				   bool *gap_ret)
{
	struct drgn_error *err;
	struct drgn_memory_segment_tree *tree =
		it->physical ? &it->prog->reader.physical_segments
			     : &it->prog->reader.virtual_segments;

	if (drgn_memory_search_iterator_remaining_bytes(it) >= needed)
		return NULL;

	err = drgn_blocking_check_signals(blocking_state);
	if (err)
		return err;

	// Stop if we've reached the maximum addresses, being very careful about
	// overflow: if max_address == UINT64_MAX, then buf_address + pos can
	// overflow. Additionally, if buf_address + pos is close to UINT64_MAX,
	// then aligning that up could overflow. Instead, note that anything
	// above max_address, aligned down, would get aligned up to beyond
	// max_address (or overflow).
	uint64_t new_buf_address;
	if (__builtin_add_overflow(it->buf_address, it->pos, &new_buf_address)
	    || new_buf_address > align_down_mask(it->max_address, alignment_mask))
		return &drgn_stop;
	new_buf_address = align_up_mask(new_buf_address, alignment_mask);

	// If there's anything left at the end of the buffer, move it to the
	// beginning.
	if (new_buf_address - it->buf_address < it->buf_available) {
		size_t remaining =
			it->buf_available - (new_buf_address - it->buf_address);
		memmove(it->buf, it->buf + (new_buf_address - it->buf_address),
			remaining);
		it->buf_available = remaining;
	} else {
		it->buf_available = 0;
	}
	it->buf_address = new_buf_address;
	it->pos = 0;

	for (;;) {
		size_t target;
		if (!drgn_memory_search_iterator_calc_buf_target(it, needed,
								 &target))
			return &drgn_stop;
		assert(target <= it->buf_capacity);

		for (;;) {
			uint64_t address = it->buf_address + it->buf_available;

			auto tree_it =
				drgn_memory_segment_tree_search_le(tree, &address);
			if (!tree_it.entry || tree_it.entry->max_address < address) {
				// We encountered a gap in the address space.
				if (it->buf_available >= needed) {
					// We read enough data before the gap.
					// Return it now.
					*gap_ret = true;
					return NULL;
				}

				// Skip to the next memory segment and start over.
				if (tree_it.entry)
					tree_it = drgn_memory_segment_tree_next(tree_it);
				else
					tree_it = drgn_memory_segment_tree_first(tree);
				// This mirrors the new_buf_address checks
				// above.
				if (!tree_it.entry
				    || tree_it.entry->min_address
				       > align_down_mask(it->max_address,
							 alignment_mask))
					return &drgn_stop;
				it->buf_address =
					align_up_mask(tree_it.entry->min_address,
						      alignment_mask);
				it->buf_available = 0;
				break;
			}

			struct drgn_memory_segment *segment = tree_it.entry;
			size_t n = target - it->buf_available;
			if (n - 1 > segment->max_address - address)
				n = segment->max_address - address + 1;
			err = segment->read_fn(it->buf + it->buf_available,
					       address, n,
					       address - segment->orig_min_address,
					       segment->arg, it->physical);
			if (err)
				return err;
			it->buf_available += n;
			if (it->buf_available == target) {
				*gap_ret = false;
				return NULL;
			}
		}
	}
}

#define X(bits)									\
static struct drgn_memory_search_iterator *					\
drgn_program_search_memory_u##bits##_no_bswap(struct drgn_program *prog,	\
					      uint##bits##_t value)		\
{										\
	struct drgn_memory_search_iterator *it =				\
		drgn_memory_search_iterator_create_common(prog, sizeof(value),	\
							  sizeof(value) - 1);	\
	if (!it)								\
		return NULL;							\
	it->mode = DRGN_MEMORY_SEARCH_ITERATOR_MODE_U##bits;			\
	it->u##bits = value;							\
	return it;								\
}										\
										\
LIBDRGN_PUBLIC struct drgn_error *						\
drgn_program_search_memory_u##bits(struct drgn_program *prog,			\
				   uint##bits##_t value,			\
				   struct drgn_memory_search_iterator **ret)	\
{										\
	struct drgn_error *err;							\
	bool bswap;								\
	err = drgn_program_bswap(prog, &bswap);					\
	if (err)								\
		return err;							\
	/*									\
	 * Save the value in host byte order so that we don't need to byte swap	\
	 * every read value.							\
	 */									\
	if (bswap)								\
		value = bswap_##bits(value);					\
	struct drgn_memory_search_iterator *it =				\
		drgn_program_search_memory_u##bits##_no_bswap(prog, value);	\
	if (!it)								\
		return &drgn_enomem;						\
	*ret = it;								\
	return NULL;								\
}										\
										\
static struct drgn_error *							\
drgn_memory_search_iterator_next_u##bits(struct drgn_memory_search_iterator *it,\
					 drgn_blocking_state *blocking_state,	\
					 uint64_t *addr_ret,			\
					 const void **match_ret,		\
					 size_t *match_len_ret)			\
{										\
	struct drgn_error *err;							\
	for (;;) {								\
		bool unused;							\
		err = drgn_memory_search_iterator_refill(it, blocking_state,	\
							 sizeof(uint##bits##_t),\
							 sizeof(uint##bits##_t) - 1,\
							 &unused);		\
		if (err)							\
			return err;						\
										\
		size_t n = it->buf_available / sizeof(uint##bits##_t);		\
		for (size_t i = it->pos / sizeof(uint##bits##_t); i < n; i++) {	\
			if (((uint##bits##_t *)it->buf)[i] == it->u##bits) {	\
				if (addr_ret) {					\
					*addr_ret = it->buf_address		\
						    + i * sizeof(uint##bits##_t)\
						    + it->address_offset;	\
				}						\
				if (match_ret)					\
					*match_ret = &((uint##bits##_t *)it->buf)[i];\
				if (match_len_ret)				\
					*match_len_ret = sizeof(uint##bits##_t);\
				it->pos = (i + 1) * sizeof(uint##bits##_t);	\
				return NULL;					\
			}							\
		}								\
		it->pos = it->buf_available;					\
	}									\
}										\
										\
LIBDRGN_PUBLIC struct drgn_error *						\
drgn_program_search_memory_u##bits##_multi(struct drgn_program *prog,		\
					   const uint##bits##_t *values,	\
					   size_t num_values,			\
					   uint##bits##_t ignore_mask,		\
					   const uint##bits##_t (*ranges)[2],	\
					   size_t num_ranges,			\
					   struct drgn_memory_search_iterator **ret)\
{										\
	struct drgn_error *err;							\
	/* Trivial cases that we can optimize as single-value searches. */	\
	if (num_values == 1 && num_ranges == 0 && ignore_mask == 0) {		\
		return drgn_program_search_memory_u##bits(prog, values[0], ret);\
	}									\
	if (num_values == 0 && num_ranges == 1					\
	    && ranges[0][0] == ranges[0][1]) {					\
		return drgn_program_search_memory_u##bits(prog, ranges[0][0],	\
							  ret);			\
	}									\
	if (num_values == 0 && num_ranges == 0) {				\
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,		\
					 "at least one value or range is required");\
	}									\
										\
	/*									\
	 * For values, we save everything in host byte order so that we don't	\
	 * need to byte swap read values. For ranges, we have to save the	\
	 * original range values and byte swap every read value.		\
	 */									\
	bool bswap;								\
	err = drgn_program_bswap(prog, &bswap);					\
	if (err)								\
		return err;							\
										\
	_cleanup_free_ uint##bits##_t *values_copy = NULL;			\
	if (num_values > 0) {							\
		values_copy = memdup(values, num_values * sizeof(values[0]));	\
		if (!values_copy)						\
			return &drgn_enomem;					\
										\
		if (ignore_mask) {						\
			for (size_t i = 0; i < num_values; i++)			\
				values_copy[i] &= ~ignore_mask;			\
		}								\
		if (bswap) {							\
			for (size_t i = 0; i < num_values; i++)			\
				values_copy[i] = bswap_##bits(values_copy[i]);	\
			ignore_mask = bswap_##bits(ignore_mask);		\
		}								\
	}									\
										\
	_cleanup_free_ uint##bits##_t (*ranges_copy)[2] = NULL;			\
	if (num_ranges > 0) {							\
		ranges_copy = memdup(ranges, num_ranges * sizeof(ranges[0]));	\
		if (!ranges_copy)						\
			return &drgn_enomem;					\
	}									\
										\
	struct drgn_memory_search_iterator *it =				\
		drgn_memory_search_iterator_create_common(			\
			prog, sizeof(uint##bits##_t), sizeof(uint##bits##_t) - 1);\
	if (!it)								\
		return &drgn_enomem;						\
										\
	it->mode = DRGN_MEMORY_SEARCH_ITERATOR_MODE_U##bits##_MULTI;		\
	it->u##bits##_multi.values = no_cleanup_ptr(values_copy);		\
	it->u##bits##_multi.num_values = num_values;				\
	it->u##bits##_multi.mask = ~ignore_mask;				\
	it->u##bits##_multi.ranges = no_cleanup_ptr(ranges_copy);		\
	it->u##bits##_multi.num_ranges = num_ranges;				\
	it->u##bits##_multi.bswap = bswap;					\
	*ret = it;								\
	return NULL;								\
}										\
										\
static inline bool								\
drgn_memory_search_iterator_u##bits##_multi_match(struct drgn_memory_search_iterator *it,\
						  uint##bits##_t raw_value)	\
{										\
	uint##bits##_t masked_value = raw_value & it->u##bits##_multi.mask;	\
	for (size_t i = 0; i < it->u##bits##_multi.num_values; i++) {		\
		if (masked_value == it->u##bits##_multi.values[i])		\
			return true;						\
	}									\
										\
	if (it->u##bits##_multi.num_ranges > 0) {				\
		uint##bits##_t value = raw_value;				\
		if (it->u##bits##_multi.bswap)					\
			value = bswap_##bits(value);				\
		for (size_t i = 0; i < it->u##bits##_multi.num_ranges; i++) {	\
			uint##bits##_t *range = it->u##bits##_multi.ranges[i];	\
			if (range[0] <= value && value <= range[1])		\
				return true;					\
		}								\
	}									\
	return false;								\
}										\
										\
static struct drgn_error *							\
drgn_memory_search_iterator_next_u##bits##_multi(struct drgn_memory_search_iterator *it,\
						 drgn_blocking_state *blocking_state,\
						 uint64_t *addr_ret,		\
						 const void **match_ret,	\
						 size_t *match_len_ret)		\
{										\
	struct drgn_error *err;							\
	for (;;) {								\
		bool gap;							\
		err = drgn_memory_search_iterator_refill(it,			\
							 blocking_state,	\
							 sizeof(uint##bits##_t),\
							 sizeof(uint##bits##_t) - 1,\
							 &gap);			\
		if (err)							\
			return err;						\
										\
		size_t n = it->buf_available / sizeof(uint##bits##_t);		\
		for (size_t i = it->pos / sizeof(uint##bits##_t); i < n; i++) {	\
			if (drgn_memory_search_iterator_u##bits##_multi_match(	\
					it, ((uint##bits##_t *)it->buf)[i])) {	\
				if (addr_ret) {					\
					*addr_ret = it->buf_address		\
						    + i * sizeof(uint##bits##_t)\
						    + it->address_offset;	\
				}						\
				if (match_ret)					\
					*match_ret = &((uint##bits##_t *)it->buf)[i];\
				if (match_len_ret)				\
					*match_len_ret = sizeof(uint##bits##_t);\
				it->pos = (i + 1) * sizeof(uint##bits##_t);	\
				return NULL;					\
			}							\
		}								\
		it->pos = it->buf_available;					\
	}									\
}
SEARCH_MEMORY_UINT_SIZES
#undef X

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_search_memory_word(struct drgn_program *prog, uint64_t value,
				struct drgn_memory_search_iterator **ret)
{
	struct drgn_error *err;
	bool is_64_bit;
	err = drgn_program_is_64_bit(prog, &is_64_bit);
	if (err)
		return err;
	if (is_64_bit) {
		return drgn_program_search_memory_u64(prog, value, ret);
	} else {
		if (value > UINT32_MAX) {
			return drgn_error_create(DRGN_ERROR_OVERFLOW,
						 "value is too large");
		}
		return drgn_program_search_memory_u32(prog, value, ret);
	}
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_search_memory_word_multi(struct drgn_program *prog,
				      const uint64_t *values, size_t num_values,
				      uint64_t ignore_mask,
				      const uint64_t (*ranges)[2],
				      size_t num_ranges,
				      struct drgn_memory_search_iterator **ret)
{
	struct drgn_error *err;
	bool is_64_bit;
	err = drgn_program_is_64_bit(prog, &is_64_bit);
	if (err)
		return err;
	if (is_64_bit) {
		return drgn_program_search_memory_u64_multi(prog, values,
							    num_values,
							    ignore_mask, ranges,
							    num_ranges, ret);
	}

	_cleanup_free_ uint32_t *values32 = NULL;
	if (num_values > 0) {
		values32 = malloc_array(num_values, sizeof(values32[0]));
		if (!values32)
			return &drgn_enomem;
		for (size_t i = 0; i < num_values; i++) {
			if (values[i] > UINT32_MAX) {
				return drgn_error_create(DRGN_ERROR_OVERFLOW,
							 "value is too large");
			}
			values32[i] = values[i];
		}
	}

	if (ignore_mask > UINT32_MAX) {
		return drgn_error_create(DRGN_ERROR_OVERFLOW,
					 "ignore_mask is too large");
	}

	_cleanup_free_ uint32_t (*ranges32)[2] = NULL;
	if (num_ranges > 0) {
		ranges32 = malloc_array(num_ranges, sizeof(ranges32[0]));
		if (!ranges32)
			return &drgn_enomem;
		for (size_t i = 0; i < num_ranges; i++) {
			if (ranges[i][0] > UINT32_MAX
			    || ranges[i][1] > UINT32_MAX) {
				return drgn_error_create(DRGN_ERROR_OVERFLOW,
							 "range values are too large");
			}
			ranges32[i][0] = ranges[i][0];
			ranges32[i][1] = ranges[i][1];
		}
	}

	return drgn_program_search_memory_u32_multi(prog, values32, num_values,
						    ignore_mask, ranges32,
						    num_ranges, ret);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_search_memory(struct drgn_program *prog, const void *needle,
			   size_t size, uint64_t alignment,
			   struct drgn_memory_search_iterator **ret)
{
	struct drgn_memory_search_iterator *it;

	// Cases that we can optimize as aligned integer searches.
	if (size == sizeof(uint32_t) && alignment == sizeof(uint32_t)) {
		uint32_t value;
		memcpy(&value, needle, sizeof(value));
		it = drgn_program_search_memory_u32_no_bswap(prog, value);
		if (!it)
			return &drgn_enomem;
		*ret = it;
		return NULL;
	}
	if (size == sizeof(uint64_t) && alignment == sizeof(uint64_t)) {
		uint64_t value;
		memcpy(&value, needle, sizeof(value));
		it = drgn_program_search_memory_u64_no_bswap(prog, value);
		if (!it)
			return &drgn_enomem;
		*ret = it;
		return NULL;
	}

	if (size == 0) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "needle cannot be empty");
	}
	if (!is_power_of_two(alignment)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "alignment must be power of 2");
	}

	_cleanup_free_ void *needle_copy = memdup(needle, size);
	if (!needle_copy)
		return &drgn_enomem;

	it = drgn_memory_search_iterator_create_common(prog, size,
						       alignment - 1);
	if (!it)
		return &drgn_enomem;

	it->mode = DRGN_MEMORY_SEARCH_ITERATOR_MODE_MEMMEM;
	it->memmem.needle = no_cleanup_ptr(needle_copy);
	it->memmem.size = size;
	it->memmem.alignment_mask = alignment - 1;
	*ret = it;
	return NULL;
}

static struct drgn_error *
drgn_memory_search_iterator_next_memmem(struct drgn_memory_search_iterator *it,
					drgn_blocking_state *blocking_state,
					uint64_t *addr_ret,
					const void **match_ret,
					size_t *match_len_ret)
{
	struct drgn_error *err;
	for (;;) {
		bool gap;
		err = drgn_memory_search_iterator_refill(it, blocking_state,
							 it->memmem.size,
							 it->memmem.alignment_mask,
							 &gap);
		if (err)
			return err;

		const unsigned char *match =
			memmem(it->buf + it->pos,
			       drgn_memory_search_iterator_remaining_bytes(it),
			       it->memmem.needle, it->memmem.size);
		if (match) {
			uint64_t address = it->buf_address + (match - it->buf)
					   + it->address_offset;
			if ((address & it->memmem.alignment_mask) == 0) {
				it->pos = match - it->buf + it->memmem.size;
				if (addr_ret)
					*addr_ret = address;
				if (match_ret)
					*match_ret = match;
				if (match_len_ret)
					*match_len_ret = it->memmem.size;
				return NULL;
			}
			// Match wasn't aligned. Keep looking.
			it->pos = (match - it->buf) + 1;
		} else {
			// No match found. We have to keep the last (size - 1)
			// bytes in case a match starts in those bytes.
			it->pos = it->buf_available - it->memmem.size + 1;
		}
	}
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_search_memory_for_object(const struct drgn_object *obj,
			      struct drgn_memory_search_iterator **ret)
{
	struct drgn_error *err;
	struct drgn_memory_search_iterator *it;

	uint64_t size = drgn_object_size(obj);
	uint64_t alignment;
	err = drgn_type_alignof(drgn_object_qualified_type(obj), &alignment);
	if (err)
		return err;

	// Cases that we can optimize as aligned integer searches.
	if (size == sizeof(uint32_t) && alignment == sizeof(uint32_t)) {
		uint32_t value;
		err = drgn_object_read_bytes(obj, &value);
		if (err)
			return err;
		it = drgn_program_search_memory_u32_no_bswap(drgn_object_program(obj),
							     value);
		if (!it)
			return &drgn_enomem;
		*ret = it;
		return NULL;
	}
	if (size == sizeof(uint64_t) && alignment == sizeof(uint64_t)) {
		uint64_t value;
		err = drgn_object_read_bytes(obj, &value);
		if (err)
			return err;
		it = drgn_program_search_memory_u64_no_bswap(drgn_object_program(obj),
							     value);
		if (!it)
			return &drgn_enomem;
		*ret = it;
		return NULL;
	}

	if (size == 0) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "can't search for object with size 0");
	}
	// Ignore the alignment if it's bogus.
	if (!is_power_of_two(alignment))
		alignment = 1;

	_cleanup_free_ void *needle = malloc64(size);
	if (!needle)
		return &drgn_enomem;
	err = drgn_object_read_bytes(obj, needle);
	if (err)
		return err;

	it = drgn_memory_search_iterator_create_common(drgn_object_program(obj),
						       size, alignment - 1);
	if (!it)
		return &drgn_enomem;

	it->mode = DRGN_MEMORY_SEARCH_ITERATOR_MODE_MEMMEM;
	it->memmem.needle = no_cleanup_ptr(needle);
	it->memmem.size = size;
	it->memmem.alignment_mask = alignment - 1;
	*ret = it;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_search_memory_regex(struct drgn_program *prog, const void *pattern,
				 size_t pattern_len, bool utf8,
				 struct drgn_memory_search_iterator **ret)
{
#ifdef WITH_PCRE2
	int errorcode;
	PCRE2_SIZE erroroffset;
	uint32_t options;

#if PCRE2_MAJOR > 10 || (PCRE2_MAJOR == 10 && PCRE2_MINOR >= 34)
	options = utf8 ? PCRE2_MATCH_INVALID_UTF : PCRE2_NEVER_UTF;
#else
	if (utf8)
		return drgn_error_format(
			DRGN_ERROR_NOT_IMPLEMENTED,
			"The PCRE2 version (%d.%d) is too old to support matching UTF-8 "
			"patterns within invalid UTF-8 data. Use a bytes pattern, or "
			"build against a newer PCRE2 version (10.34 or later).",
			PCRE2_MAJOR, PCRE2_MINOR
		);
	options = PCRE2_NEVER_UTF;
#endif
	_cleanup_pcre2_code_ pcre2_code *code =
		pcre2_compile(pattern, pattern_len, options,
			      &errorcode, &erroroffset, NULL);
	if (!code)
		return drgn_error_pcre2(errorcode, &erroroffset);
	errorcode = pcre2_jit_compile(code,
				      PCRE2_JIT_COMPLETE
				      | PCRE2_JIT_PARTIAL_HARD);
	// PCRE2_ERROR_JIT_BADOPTION is returned if JIT is not supported.
	if (errorcode && errorcode != PCRE2_ERROR_JIT_BADOPTION)
		return drgn_error_pcre2(errorcode, NULL);

	uint32_t max_lookbehind;
	errorcode = pcre2_pattern_info(code, PCRE2_INFO_MAXLOOKBEHIND,
				       &max_lookbehind);
	if (errorcode)
		return drgn_error_pcre2(errorcode, NULL);
	if (max_lookbehind != 0) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "lookbehind is not allowed");
	}

	uint32_t min_length;
	errorcode = pcre2_pattern_info(code, PCRE2_INFO_MINLENGTH, &min_length);
	if (errorcode)
		return drgn_error_pcre2(errorcode, NULL);
	if (min_length == 0)
		min_length = 1;

	_cleanup_pcre2_match_data_ pcre2_match_data *match_data =
		pcre2_match_data_create(1, NULL);
	if (!match_data)
		return &drgn_enomem;

	struct drgn_memory_search_iterator *it =
		drgn_memory_search_iterator_create_common(prog, min_length, 1);
	if (!it)
		return &drgn_enomem;

	it->mode = DRGN_MEMORY_SEARCH_ITERATOR_MODE_REGEX;
	it->regex.code = no_cleanup_ptr(code);
	it->regex.match_data = no_cleanup_ptr(match_data);
	it->regex.min_length = min_length;
	it->regex.utf8 = utf8;
	*ret = it;
	return NULL;
#else
	return drgn_error_create(DRGN_ERROR_NOT_IMPLEMENTED,
				 "drgn was built without regular expression support");
#endif
}

#ifdef WITH_PCRE2
static struct drgn_error *
drgn_memory_search_iterator_try_extend(struct drgn_memory_search_iterator *it,
				       bool *gap_ret)
{
	struct drgn_error *err;
	struct drgn_memory_segment_tree *tree =
		it->physical ? &it->prog->reader.physical_segments
			     : &it->prog->reader.virtual_segments;

	size_t target;
	if (!drgn_memory_search_iterator_calc_buf_target(it,
							 it->buf_available + 1,
							 &target)) {
		*gap_ret = true;
		return NULL;
	}
	if (target > it->buf_capacity) {
		size_t new_capacity = target;
		if (new_capacity <= SIZE_MAX / 2)
			new_capacity = next_power_of_two(new_capacity);
		unsigned char *new_buf = realloc(it->buf, new_capacity);
		if (!new_buf)
			return &drgn_enomem;
		it->buf = new_buf;
		it->buf_capacity = new_capacity;
	}

	while (it->buf_available < target) {
		uint64_t address = it->buf_address + it->buf_available;

		auto tree_it = drgn_memory_segment_tree_search_le(tree, &address);
		if (!tree_it.entry || tree_it.entry->max_address < address) {
			// We encountered a gap in the address space.
			*gap_ret = true;
			return NULL;
		}

		struct drgn_memory_segment *segment = tree_it.entry;
		size_t n = target - it->buf_available;
		if (n - 1 > segment->max_address - address)
			n = segment->max_address - address + 1;
		err = segment->read_fn(it->buf + it->buf_available, address, n,
				       address - segment->orig_min_address,
				       segment->arg, it->physical);
		if (err)
			return err;
		it->buf_available += n;
	}
	*gap_ret = false;
	return NULL;
}

static struct drgn_error *
drgn_memory_search_iterator_next_regex(struct drgn_memory_search_iterator *it,
				       drgn_blocking_state *blocking_state,
				       uint64_t *addr_ret,
				       const void **match_ret,
				       size_t *match_len_ret)
{
	struct drgn_error *err;

	if (it->regex.need_refill) {
		it->regex.next_match_options = 0;
		bool gap;
		err = drgn_memory_search_iterator_refill(it, blocking_state,
							 it->regex.min_length,
							 0, &gap);
		if (err)
			return err;
		it->regex.partial_option = gap ? 0 : PCRE2_PARTIAL_HARD;
		it->regex.need_refill = false;
	}

	for (;;) {
		uint32_t options = it->regex.partial_option
				   | it->regex.next_match_options;
		if (it->buf_address != it->min_address)
			options |= PCRE2_NOTBOL;
		if (it->buf_address + it->buf_available - 1 < it->max_address)
			options |= PCRE2_NOTEOL;
		int rc = pcre2_match(it->regex.code, (PCRE2_SPTR)it->buf,
				     it->buf_available, it->pos, options,
				     it->regex.match_data, NULL);
		if (rc == PCRE2_ERROR_NOMATCH) {
			it->pos = it->buf_available;
			it->regex.next_match_options = 0;
			bool gap;
			err = drgn_memory_search_iterator_refill(it,
								 blocking_state,
								 it->regex.min_length,
								 0, &gap);
			if (err)
				return err;
			it->regex.partial_option = gap ? 0 : PCRE2_PARTIAL_HARD;
		} else if (rc >= 0) {
			PCRE2_SIZE *ovector =
				pcre2_get_ovector_pointer(it->regex.match_data);
			PCRE2_SIZE match_start = ovector[0];
			PCRE2_SIZE match_end = ovector[1];

			if (addr_ret) {
				*addr_ret = it->buf_address + match_start
					    + it->address_offset;
			}
			if (match_ret)
				*match_ret = it->buf + match_start;
			if (match_len_ret)
				*match_len_ret = match_end - match_start;

			PCRE2_SIZE next_pos;
			if (drgn_pcre2_next_match(it->regex.match_data,
						  it->regex.utf8, it->buf,
						  it->buf_available, it->pos,
						  ovector, &next_pos,
						  &it->regex.next_match_options)) {
				it->pos = next_pos;
			} else {
				it->pos = it->buf_available;
				it->regex.need_refill = true;
			}
			return NULL;
		} else if (rc == PCRE2_ERROR_PARTIAL) {
			bool gap;
			err = drgn_memory_search_iterator_try_extend(it, &gap);
			if (err)
				return err;
			it->regex.partial_option = gap ? 0 : PCRE2_PARTIAL_HARD;
		} else {
			return drgn_error_pcre2(rc, NULL);
		}
	}
}
#endif

LIBDRGN_PUBLIC struct drgn_error *
drgn_memory_search_iterator_next(struct drgn_memory_search_iterator *it,
				 uint64_t *addr_ret, const void **match_ret,
				 size_t *match_len_ret)
{
	struct drgn_error *err;

	drgn_blocking_guard(blocking_state);

	if (it->physical < 0) {
		err = drgn_memory_search_iterator_set_address_range(it, 0,
								    UINT64_MAX,
								    false);
		if (err)
			return err;
	}

	SWITCH_ENUM(it->mode) {
	case DRGN_MEMORY_SEARCH_ITERATOR_MODE_MEMMEM:
		return drgn_memory_search_iterator_next_memmem(it,
							       &blocking_state,
							       addr_ret,
							       match_ret,
							       match_len_ret);
#define X(bits)									\
	case DRGN_MEMORY_SEARCH_ITERATOR_MODE_U##bits:				\
		return drgn_memory_search_iterator_next_u##bits(it,		\
								&blocking_state,\
								addr_ret,	\
								match_ret,	\
								match_len_ret);	\
	case DRGN_MEMORY_SEARCH_ITERATOR_MODE_U##bits##_MULTI:			\
		return drgn_memory_search_iterator_next_u##bits##_multi(it,	\
									&blocking_state,\
									addr_ret,\
									match_ret,\
									match_len_ret);
	SEARCH_MEMORY_UINT_SIZES
#undef X
#ifdef WITH_PCRE2
	case DRGN_MEMORY_SEARCH_ITERATOR_MODE_REGEX:
		return drgn_memory_search_iterator_next_regex(it,
							      &blocking_state,
							      addr_ret,
							      match_ret,
							      match_len_ret);
#endif
	default:
		UNREACHABLE();
	}
}

// This is a bit of a hack to work around Linux kernel address translation
// issues: if we're searching all memory or a specific range in the direct
// mapping, then do it as a physical memory search (but still return virtual
// addresses).
static struct drgn_error *
drgn_memory_search_iterator_replace_linux_kernel_address_range(struct drgn_memory_search_iterator *it)
{
	struct drgn_error *err;

	if (!(it->prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) || it->physical)
		return NULL;

	struct drgn_memory_segment_tree *tree =
		&it->prog->reader.physical_segments;
	if (drgn_memory_segment_tree_empty(tree))
		return NULL;

	uint64_t offset;
	err = linux_helper_direct_mapping_offset(it->prog, &offset);
	if (drgn_error_catch(&err, DRGN_ERROR_LOOKUP))
		return NULL;
	else if (err)
		return err;

	uint64_t address_mask = drgn_platform_address_mask(&it->prog->platform);
	if (it->min_address == 0 && it->max_address == address_mask) {
		it->address_offset = offset;
		it->physical = true;
		return NULL;
	}

	auto first_it = drgn_memory_segment_tree_first(tree);
	auto last_it = drgn_memory_segment_tree_last(tree);
	if (first_it.entry->min_address <= it->min_address - offset
	    && last_it.entry->max_address >= it->max_address - offset) {
		it->min_address -= offset;
		it->max_address -= offset;
		it->address_offset = offset;
		it->physical = true;
	}
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_memory_search_iterator_set_address_range(struct drgn_memory_search_iterator *it,
					      uint64_t min_address,
					      uint64_t max_address,
					      bool physical)
{
	struct drgn_error *err;

	if (min_address > max_address) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "invalid memory search address range");
	}

	uint64_t address_mask;
	err = drgn_program_address_mask(it->prog, &address_mask);
	if (err)
		return err;
	if (max_address > address_mask)
		max_address = address_mask;

	it->min_address = min_address;
	it->max_address = max_address;
	it->address_offset = 0;
	it->physical = physical;
	err = drgn_memory_search_iterator_replace_linux_kernel_address_range(it);
	if (err)
		return err;

	it->buf_available = 0;
	it->pos = 0;
	it->buf_address = it->min_address;

#ifdef WITH_PCRE2
	if (it->mode == DRGN_MEMORY_SEARCH_ITERATOR_MODE_REGEX)
		it->regex.need_refill = true;
#endif

	return NULL;
}
