// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * ELF files.
 *
 * See @ref ElfFile.
 */

#ifndef DRGN_ELF_FILE_H
#define DRGN_ELF_FILE_H

#include <elf.h>
#include <elfutils/libdw.h>
#include <libelf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "binary_buffer.h"
#include "elf_sections.h" // IWYU pragma: export
#include "platform.h"

struct drgn_module;

/**
 * @ingroup Internals
 *
 * @defgroup ElfFile ELF files
 *
 * ELF file handling.
 *
 * @{
 */

/**
 * Read the raw data from an ELF section, decompressing it first if it is
 * compressed.
 *
 * This returns an error if the section type is `SHT_NOBITS`.
 */
struct drgn_error *read_elf_section(Elf_Scn *scn, Elf_Data **ret);

/**
 * Truncate any bytes beyond the last null character in an ELF string table.
 *
 * This sets `data->d_size` so that any string table index less than
 * `data->d_size` is guaranteed to be valid.
 */
void truncate_elf_string_data(Elf_Data *data);

static inline bool elf_data_contains_ptr(Elf_Data *data, const void *ptr)
{
	uintptr_t bufi = (uintptr_t)data->d_buf;
	uintptr_t ptri = (uintptr_t)ptr;
	return ptri >= bufi && ptri - bufi < data->d_size;
}

/** An ELF file used by a @ref drgn_module. */
struct drgn_elf_file {
	/** Module using this file. */
	struct drgn_module *module;
	/** Filesystem path to this file. */
	char *path;
	/**
	 * Memory image backing @ref elf.
	 *
	 * @c NULL if not backed by a memory image.
	 */
	char *image;
	/**
	 * File descriptor backing @ref elf.
	 *
	 * -1 if not backed by a file.
	 */
	int fd;
	/** Whether the file is loadable. */
	bool is_loadable;
	/** Whether the file is relocatable. */
	bool is_relocatable;
	/** Whether the file still need to have relocations applied. */
	bool needs_relocation;
	/** Whether the file is a Linux kernel image (`vmlinux`). */
	bool is_vmlinux;
	/** libelf handle. */
	Elf *elf;
	/**
	 * libdw handle.
	 *
	 * @c NULL if not yet created.
	 *
	 * Don't access this directly. Get it with @ref
	 * drgn_elf_file_get_dwarf() instead.
	 */
	Dwarf *_dwarf;
	/**
	 * Platform of this file.
	 *
	 * This should take precedence over @ref drgn_program::platform when
	 * parsing this file. Note that there are some cases where it doesn't
	 * make sense for the program and file platforms to differ (e.g., stack
	 * unwinding), in which case the file should be ignored if its platform
	 * doesn't match the program's.
	 */
	struct drgn_platform platform;
	/** Important ELF sections. */
	Elf_Scn *scns[DRGN_SECTION_INDEX_NUM];
	/** Data cached for important ELF sections. */
	Elf_Data *scn_data[DRGN_SECTION_INDEX_NUM_DATA];
	/**
	 * If the file has a debugaltlink file, the debugaltlink file's
	 * `.debug_info` section data.
	 */
	Elf_Data *alt_debug_info_data;
	/**
	 * If the file has a debugaltlink file, the debugaltlink file's
	 * `.debug_str` section data.
	 */
	Elf_Data *alt_debug_str_data;
	/**
	 * For relocatable files, a bitmap of which sections have their address
	 * set.
	 */
	unsigned long *sections_with_address;
};

/**
 * Create a @ref drgn_elf_file.
 *
 * On success, this takes ownership of @p fd, @p image, and @p elf. @p path is
 * copied.
 */
struct drgn_error *drgn_elf_file_create(struct drgn_module *module,
					const char *path, int fd, char *image,
					Elf *elf, struct drgn_elf_file **ret);

void drgn_elf_file_destroy(struct drgn_elf_file *file);

/** Apply ELF relocations to the file if needed. */
struct drgn_error *
drgn_elf_file_apply_relocations(struct drgn_elf_file *file);

/**
 * Read an indexed ELF section.
 *
 * This applies ELF relocations to the file first if needed.
 */
struct drgn_error *drgn_elf_file_read_section(struct drgn_elf_file *file,
					      enum drgn_section_index scn,
					      Elf_Data **ret);

struct drgn_error *drgn_elf_file_get_dwarf(struct drgn_elf_file *file,
					   Dwarf **ret);

static inline bool
drgn_elf_file_is_little_endian(const struct drgn_elf_file *file)
{
	return drgn_platform_is_little_endian(&file->platform);
}

static inline bool drgn_elf_file_bswap(const struct drgn_elf_file *file)
{
	return drgn_platform_bswap(&file->platform);
}

static inline bool
drgn_elf_file_is_64_bit(const struct drgn_elf_file *file)
{
	return drgn_platform_is_64_bit(&file->platform);
}

static inline uint8_t
drgn_elf_file_address_size(const struct drgn_elf_file *file)
{
	return drgn_platform_address_size(&file->platform);
}

static inline uint64_t
drgn_elf_file_address_mask(const struct drgn_elf_file *file)
{
	return drgn_platform_address_mask(&file->platform);
}

static inline bool drgn_elf_file_has_dwarf(const struct drgn_elf_file *file)
{
	return (file->scns[DRGN_SCN_DEBUG_INFO]
		&& file->scns[DRGN_SCN_DEBUG_ABBREV]);
}

struct drgn_error *
drgn_elf_file_section_error(struct drgn_elf_file *file, Elf_Scn *scn,
			    Elf_Data *data, const char *ptr,
			    const char *message)
	__attribute__((__returns_nonnull__));

struct drgn_error *
drgn_elf_file_section_errorf(struct drgn_elf_file *file, Elf_Scn *scn,
			     Elf_Data *data, const char *ptr,
			     const char *format, ...)
	__attribute__((__returns_nonnull__, __format__(__printf__, 5, 6)));

struct drgn_elf_file_section_buffer {
	struct binary_buffer bb;
	struct drgn_elf_file *file;
	Elf_Scn *scn;
	Elf_Data *data;
};

struct drgn_error *drgn_elf_file_section_buffer_error(struct binary_buffer *bb,
						      const char *ptr,
						      const char *message);

static inline void
drgn_elf_file_section_buffer_init(struct drgn_elf_file_section_buffer *buffer,
				  struct drgn_elf_file *file, Elf_Scn *scn,
				  Elf_Data *data)
{
	binary_buffer_init(&buffer->bb, data->d_buf, data->d_size,
			   drgn_elf_file_is_little_endian(file),
			   drgn_elf_file_section_buffer_error);
	buffer->file = file;
	buffer->scn = scn;
	buffer->data = data;
}

/**
 * Initialize a @ref binary_buffer for an indexed ELF section that has already
 * been read.
 */
static inline void
drgn_elf_file_section_buffer_init_index(struct drgn_elf_file_section_buffer *buffer,
					struct drgn_elf_file *file,
					enum drgn_section_index scn)
{
	drgn_elf_file_section_buffer_init(buffer, file, file->scns[scn],
					  file->scn_data[scn]);
}

/**
 * Read an indexed ELF section (applying ELF relocations if needed) and
 * initialize a @ref binary_buffer for it.
 */
static inline struct drgn_error *
drgn_elf_file_section_buffer_read(struct drgn_elf_file_section_buffer *buffer,
				  struct drgn_elf_file *file,
				  enum drgn_section_index scn)
{
	Elf_Data *data;
	struct drgn_error *err = drgn_elf_file_read_section(file, scn, &data);
	if (err)
		return err;
	drgn_elf_file_section_buffer_init(buffer, file, file->scns[scn], data);
	return NULL;
}

/**
 * Return the virtual address range of an ELF file.
 *
 * @param[out] start_ret Minimum virtual address (inclusive).
 * @param[out] end_ret Maximum virtual address (exclusive).
 */
bool drgn_elf_file_address_range(struct drgn_elf_file *file,
				 uint64_t *start_ret, uint64_t *end_ret);

/**
 * Return whether an ELF file is a vmlinux file.
 *
 * @return > 0 if the file is vmlinux, 0 if it is not, < 0 on libelf error.
 */
int elf_is_vmlinux(Elf *elf);

/**
 * Get the Linux release from a vmlinux file.
 *
 * @param[out] ret Returned release.
 * @return Length of @p ret on success, 0 if not found, < 0 on libelf error.
 */
ssize_t elf_vmlinux_release(Elf *elf, const char **ret);

/** @} */

#endif /* DRGN_ELF_FILE_H */
