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

#include <elfutils/libdw.h>
#include <libelf.h>
#include <stdbool.h>
#include <stdint.h>

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
 * @warning If the section is `SHT_NOBITS`, this returns an `Elf_Data` with
 * `d_size >= 0 && d_buf == NULL`.
 */
struct drgn_error *read_elf_section(Elf_Scn *scn, Elf_Data **ret);

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
	const char *path;
	/** libelf handle. */
	Elf *elf;
	/** libdw handle if we're using DWARF information from this file. */
	Dwarf *dwarf;
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
};

struct drgn_error *drgn_elf_file_create(struct drgn_module *module,
					const char *path, Elf *elf,
					struct drgn_elf_file **ret);

void drgn_elf_file_destroy(struct drgn_elf_file *file);

struct drgn_error *drgn_elf_file_precache_sections(struct drgn_elf_file *file);

struct drgn_error *
drgn_elf_file_cache_section(struct drgn_elf_file *file, enum drgn_section_index scn);

static inline bool
drgn_elf_file_is_little_endian(const struct drgn_elf_file *file)
{
	return drgn_platform_is_little_endian(&file->platform);
}

static inline bool drgn_elf_file_bswap(const struct drgn_elf_file *file)
{
	return drgn_platform_bswap(&file->platform);
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

static inline void
drgn_elf_file_section_buffer_init_index(struct drgn_elf_file_section_buffer *buffer,
					struct drgn_elf_file *file,
					enum drgn_section_index scn)
{
	drgn_elf_file_section_buffer_init(buffer, file, file->scns[scn],
					  file->scn_data[scn]);
}

/**
 * Parse the next ELF note out of a buffer.
 *
 * @note
 * Alignment of ELF notes is a mess. The [System V
 * gABI](http://www.sco.com/developers/gabi/latest/ch5.pheader.html#note_section)
 * says that the note header and descriptor should be aligned to 4 bytes for
 * 32-bit files and 8 bytes for 64-bit files. However, on Linux, 4-byte
 * alignment is used for both 32-bit and 64-bit files.
 * @note
 * The only exception as of 2024 is `NT_GNU_PROPERTY_TYPE_0`, which is defined
 * to follow the gABI alignment. See
 * ["PT_NOTE alignment, NT_GNU_PROPERTY_TYPE_0, glibc and gold"](https://public-inbox.org/libc-alpha/13a92cb0-a993-f684-9a96-e02e4afb1bef@redhat.com/).
 * But, note that the 12-byte note header plus the 4-byte `"GNU\0"` name is a
 * multiple of 8 bytes, and the `NT_GNU_PROPERTY_TYPE_0` descriptor is defined
 * to be a multiple of 4 bytes for 32-bit files and 8 bytes for 64-bit files. As
 * a result, `NT_GNU_PROPERTY_TYPE_0` is never actually padded, and 4-byte vs.
 * 8-byte alignment are equivalent for parsing purposes.
 * @note
 * According to the [gABI Linux
 * Extensions](https://gitlab.com/x86-psABIs/Linux-ABI), consumers are now
 * supposed to use the `p_align` of the `PT_NOTE` segment instead of assuming an
 * alignment. However, the Linux kernel as of 6.0 generates core dumps with
 * `PT_NOTE` segments with a `p_align` of 0 or 1 which are actually aligned to 4
 * bytes. So, when parsing notes from an ELF file, you need to use 8-byte
 * alignment if `p_align` is 8 and 4-byte alignment otherwise. binutils and
 * elfutils appear to do the same.
 * @note
 * Before Linux kernel commit f7ba52f302fd ("vmlinux.lds.h: Discard
 * .note.gnu.property section") (in v6.4), the vmlinux linker script can create
 * a `PT_NOTE` segment with a `p_align` of 8 where the entries other than
 * `NT_GNU_PROPERTY_TYPE_0` are actually aligned to 4 bytes.
 * @note
 * Finally, there are cases where we don't know `p_align`. For example,
 * `/sys/kernel/notes` contains the contents of the vmlinux `.notes` section,
 * which (ignoring the aforementioned bug) we can assume has 4-byte alignment.
 * As another example, `/sys/module/$module/notes/` contains a file for each
 * note section. Since `NT_GNU_PROPERTY_TYPE_0` can be parsed assuming 4-byte
 * alignment, we can again assume 4-byte alignment. This will work as long as
 * any future note types requiring 8-byte alignment also happen to have an
 * 8-byte aligned header+name and descriptor (but hopefully no one ever adds an
 * 8-byte aligned note again).
 *
 * @param[in,out] p Current position. Initialize to the beginning of the buffer.
 * @param[in,out] size Remaining size. Initialize to the size of the buffer.
 * @param[in] align Note alignment. Usually `p_align == 8 ? 8 : 4` if the
 * program header is available, otherwise 4.
 * @param[in] bswap Whether the note header needs to be byte-swapped.
 * @param[out] name_ret Returned note name.
 * @param[out] desc_ret Returned note descriptor.
 * @return @c true if a note was parsed, @c false if there are no more notes.
 */
bool next_elf_note(const void **p, size_t *size, unsigned int align, bool bswap,
		   Elf32_Nhdr *nhdr_ret, const char **name_ret,
		   const void **desc_ret);

/** @} */

#endif /* DRGN_ELF_FILE_H */
