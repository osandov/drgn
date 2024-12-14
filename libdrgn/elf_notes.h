// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * ELF note parsing.
 */

#ifndef DRGN_ELF_NOTES_H
#define DRGN_ELF_NOTES_H

#include <elfutils/version.h>
#include <gelf.h>
#include <stdbool.h>

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
		   GElf_Nhdr *nhdr_ret, const char **name_ret,
		   const void **desc_ret);


/**
 * Parse a GNU build ID from a buffer containing note data.
 *
 * @param[in] buf Buffer containing note data.
 * @param[in] size Size of @p buf in bytes.
 * @param[in] align Note alignment. See @ref next_elf_note().
 * @param[in] bswap Whether the note header needs to be byte-swapped.
 * @param[out] ret Returned build ID, or @c NULL if not found.
 * @return Size of returned build ID in bytes, or @c NULL if not found.
 */
size_t parse_gnu_build_id_from_notes(const void *buf, size_t size,
				     unsigned int align, bool bswap,
				     const void **ret);

#if _ELFUTILS_PREREQ(0, 175)
/**
 * Find an ELF file's GNU build ID, working around `vmlinux` files with broken
 * note alignment when possible.
 *
 * @param[out] ret Returned build ID, or @c NULL if not found.
 * @return Size of returned build ID in bytes, or @c NULL if not found.
 */
ssize_t drgn_elf_gnu_build_id(Elf *elf, const void **ret);
#else
#include <elfutils/libdwelf.h>

static inline ssize_t drgn_elf_gnu_build_id(Elf *elf, const void **ret)
{
	return dwelf_elf_gnu_build_id(elf, ret);
}
#endif

static inline Elf_Type note_header_type(uint64_t p_align)
{
#if _ELFUTILS_PREREQ(0, 175)
	if (p_align == 8)
		return ELF_T_NHDR8;
#endif
	return ELF_T_NHDR;
}

#endif /* DRGN_ELF_NOTES_H */
