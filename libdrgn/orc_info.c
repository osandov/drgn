// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <byteswap.h>
#include <gelf.h>
#include <limits.h>
#include <stdalign.h>
#include <stdlib.h>
#include <string.h>

#include "debug_info.h" // IWYU pragma: associated
#include "elf_file.h"
#include "error.h"
#include "orc.h"
#include "platform.h"
#include "util.h"

void drgn_module_orc_info_deinit(struct drgn_module *module)
{
	free(module->orc.entries);
	free(module->orc.pc_offsets);
}

/*
 * Get the program counter of an ORC entry before pc_offsets is in the native
 * byte order.
 */
static inline uint64_t drgn_raw_orc_pc(struct drgn_module *module,
				       unsigned int i)
{
	int32_t offset = module->orc.pc_offsets[i];
	if (drgn_elf_file_bswap(module->debug_file))
		offset = bswap_32(offset);
	return module->orc.pc_base + UINT64_C(4) * i + offset;
}

static _Thread_local struct drgn_module *compare_orc_entries_module;
static int compare_orc_entries(const void *a, const void *b)
{
	struct drgn_module *module = compare_orc_entries_module;
	unsigned int index_a = *(unsigned int *)a;
	unsigned int index_b = *(unsigned int *)b;

	uint64_t pc_a = drgn_raw_orc_pc(module, index_a);
	uint64_t pc_b = drgn_raw_orc_pc(module, index_b);
	if (pc_a < pc_b)
		return -1;
	else if (pc_a > pc_b)
		return 1;

	/*
	 * If two entries have the same PC, then one is probably a "terminator"
	 * at the end of a compilation unit. Prefer the real entry.
	 */
	uint16_t flags_a = module->orc.entries[index_a].flags;
	uint16_t flags_b = module->orc.entries[index_b].flags;
	if (drgn_elf_file_bswap(module->debug_file)) {
		flags_a = bswap_16(flags_a);
		flags_b = bswap_16(flags_b);
	}
	return (drgn_orc_flags_is_terminator(flags_b)
		- drgn_orc_flags_is_terminator(flags_a));
}

static unsigned int keep_orc_entry(struct drgn_module *module,
				   unsigned int *indices,
				   unsigned int num_entries, unsigned int i)
{

	const struct drgn_orc_entry *entries = module->orc.entries;
	if (num_entries > 0 &&
	    memcmp(&entries[indices[num_entries - 1]], &entries[indices[i]],
		   sizeof(entries[0])) == 0) {
		/*
		 * The previous entry is identical to this one, so we can skip
		 * this entry (which effectively merges it into the previous
		 * one). This usually happens for "terminator" entries.
		 */
		return num_entries;
	}
	indices[num_entries] = indices[i];
	return num_entries + 1;
}

/*
 * The vast majority of ORC entries are redundant with DWARF CFI, and it's a
 * waste to store and binary search those entries. This removes ORC entries that
 * are entirely shadowed by DWARF FDEs.
 *
 * Note that we don't bother checking EH CFI because currently ORC is only used
 * for the Linux kernel on x86-64, which explicitly disables EH data.
 */
static unsigned int remove_fdes_from_orc(struct drgn_module *module,
					 unsigned int *indices,
					 unsigned int num_entries)
{
	if (module->dwarf.debug_frame.num_fdes == 0)
		return num_entries;

	struct drgn_dwarf_fde *fde = module->dwarf.debug_frame.fdes;
	struct drgn_dwarf_fde *last_fde =
		fde + module->dwarf.debug_frame.num_fdes - 1;

	unsigned int new_num_entries = 0;

	/* Keep any entries that start before the first DWARF FDE. */
	uint64_t start_pc;
	for (;;) {
		start_pc = drgn_raw_orc_pc(module, new_num_entries);
		if (fde->initial_location <= start_pc)
			break;
		new_num_entries++;
		if (new_num_entries == num_entries)
			return num_entries;
	}

	for (unsigned int i = new_num_entries; i < num_entries - 1; i++) {
		uint64_t end_pc = drgn_raw_orc_pc(module, i + 1);

		/*
		 * Find the last FDE that starts at or before the current ORC
		 * entry.
		 */
		while (fde != last_fde && fde[1].initial_location <= start_pc)
			fde++;

		/*
		 * Check whether the current ORC entry is completely covered by
		 * one or more FDEs.
		 */
		while (end_pc - fde->initial_location > fde->address_range) {
			/*
			 * The current FDE doesn't cover the current ORC entry.
			 */
			if (fde == last_fde) {
				/*
				 * There are no more FDEs. Keep the remaining
				 * ORC entries.
				 */
				if (i != new_num_entries) {
					memmove(&indices[new_num_entries],
						&indices[i],
						(num_entries - i) *
						sizeof(indices[0]));
				}
				return new_num_entries + (num_entries - i);
			}
			if (fde[1].initial_location - fde->initial_location
			    > fde->address_range) {
				/*
				 * There is a gap between the current FDE and
				 * the next FDE that exposes the current ORC
				 * entry. Keep it.
				 */
				new_num_entries = keep_orc_entry(module,
								 indices,
								 new_num_entries,
								 i);
				break;
			}
			fde++;
		}

		start_pc = end_pc;
	}
	/* We don't know where the last ORC entry ends, so always keep it. */
	return keep_orc_entry(module, indices, new_num_entries,
			      num_entries - 1);
}

static struct drgn_error *drgn_read_orc_sections(struct drgn_module *module)
{
	struct drgn_error *err;
	Elf *elf = module->debug_file->elf;

	size_t shstrndx;
	if (elf_getshdrstrndx(elf, &shstrndx))
		return drgn_error_libelf();

	Elf_Scn *orc_unwind_ip_scn = NULL;
	Elf_Scn *orc_unwind_scn = NULL;

	Elf_Scn *scn = NULL;
	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr shdr_mem, *shdr = gelf_getshdr(scn, &shdr_mem);
		if (!shdr)
			return drgn_error_libelf();

		if (shdr->sh_type != SHT_PROGBITS)
			continue;

		const char *scnname = elf_strptr(elf, shstrndx, shdr->sh_name);
		if (!scnname)
			return drgn_error_libelf();

		if (!orc_unwind_ip_scn
		    && strcmp(scnname, ".orc_unwind_ip") == 0) {
			orc_unwind_ip_scn = scn;
			module->orc.pc_base = shdr->sh_addr;
		} else if (!orc_unwind_scn
			   && strcmp(scnname, ".orc_unwind") == 0) {
			orc_unwind_scn = scn;
		}
	}

	if (!orc_unwind_ip_scn || !orc_unwind_scn) {
		module->orc.num_entries = 0;
		return NULL;
	}

	Elf_Data *orc_unwind_ip, *orc_unwind;
	err = read_elf_section(orc_unwind_ip_scn, &orc_unwind_ip);
	if (err)
		return err;
	err = read_elf_section(orc_unwind_scn, &orc_unwind);
	if (err)
		return err;

	size_t num_entries = orc_unwind_ip->d_size / sizeof(int32_t);
	if (num_entries > UINT_MAX) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 ".orc_unwind_ip is too large");
	}
	module->orc.num_entries = num_entries;

	if (orc_unwind_ip->d_size % sizeof(int32_t) != 0 ||
	    orc_unwind->d_size % sizeof(struct drgn_orc_entry) != 0 ||
	    orc_unwind->d_size / sizeof(struct drgn_orc_entry)
	    != module->orc.num_entries) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 ".orc_unwind_ip and/or .orc_unwind has invalid size");
	}
	if ((uintptr_t)orc_unwind_ip->d_buf % alignof(int32_t)) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 ".orc_unwind_ip is not sufficiently aligned");
	}
	if ((uintptr_t)orc_unwind->d_buf % alignof(struct drgn_orc_entry)) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 ".orc_unwind is not sufficiently aligned");
	}

	module->orc.pc_offsets = orc_unwind_ip->d_buf;
	module->orc.entries = orc_unwind->d_buf;

	return NULL;
}

static struct drgn_error *drgn_debug_info_parse_orc(struct drgn_module *module)
{
	struct drgn_error *err;

	if (!module->debug_file->platform.arch->orc_to_cfi)
		return NULL;

	err = drgn_read_orc_sections(module);
	if (err || !module->orc.num_entries)
		goto out_clear;

	unsigned int num_entries = module->orc.num_entries;
	unsigned int *indices = malloc_array(num_entries, sizeof(indices[0]));
	if (!indices) {
		err = &drgn_enomem;
		goto out_clear;
	}
	for (unsigned int i = 0; i < num_entries; i++)
		indices[i] = i;

	compare_orc_entries_module = module;
	/*
	 * Sort the ORC entries for binary search. Since Linux kernel commit
	 * f14bf6a350df ("x86/unwind/orc: Remove boot-time ORC unwind tables
	 * sorting") (in v5.6), this is already sorted for vmlinux, so only sort
	 * it if necessary.
	 */
	for (unsigned int i = 1; i < num_entries; i++) {
		if (compare_orc_entries(&indices[i - 1], &indices[i]) > 0) {
			qsort(indices, num_entries, sizeof(indices[0]),
			      compare_orc_entries);
			break;
		}
	}

	num_entries = remove_fdes_from_orc(module, indices, num_entries);

	int32_t *pc_offsets = malloc_array(num_entries, sizeof(pc_offsets[0]));
	if (!pc_offsets) {
		err = &drgn_enomem;
		goto out;
	}
	struct drgn_orc_entry *entries = malloc_array(num_entries,
						      sizeof(entries[0]));
	if (!entries) {
		free(pc_offsets);
		err = &drgn_enomem;
		goto out;
	}
	const int32_t *orig_offsets = module->orc.pc_offsets;
	const struct drgn_orc_entry *orig_entries = module->orc.entries;
	bool bswap = drgn_elf_file_bswap(module->debug_file);
	for (unsigned int i = 0; i < num_entries; i++) {
		unsigned int index = indices[i];
		int32_t offset = orig_offsets[index];
		struct drgn_orc_entry entry = orig_entries[index];
		if (bswap) {
			offset = bswap_32(offset);
			entry.sp_offset = bswap_16(entry.sp_offset);
			entry.bp_offset = bswap_16(entry.bp_offset);
			entry.flags = bswap_16(entry.flags);
		}
		pc_offsets[i] = UINT64_C(4) * index + offset - UINT64_C(4) * i;
		entries[i] = entry;
	}

	module->orc.pc_offsets = pc_offsets;
	module->orc.entries = entries;
	module->orc.num_entries = num_entries;

	err = NULL;
out:
	free(indices);
	if (err) {
out_clear:
		module->orc.pc_offsets = NULL;
		module->orc.entries = NULL;
	}
	return err;
}

static inline uint64_t drgn_orc_pc(struct drgn_module *module, unsigned int i)
{
	return module->orc.pc_base + UINT64_C(4) * i + module->orc.pc_offsets[i];
}

struct drgn_error *
drgn_module_find_orc_cfi(struct drgn_module *module, uint64_t pc,
			 struct drgn_cfi_row **row_ret, bool *interrupted_ret,
			 drgn_register_number *ret_addr_regno_ret)
{
	struct drgn_error *err;

	if (!module->parsed_orc) {
		err = drgn_debug_info_parse_orc(module);
		if (err)
			return err;
		module->parsed_orc = true;
	}

	uint64_t unbiased_pc = pc - module->debug_file_bias;
	/*
	 * We don't know the maximum program counter covered by the ORC data,
	 * but the last entry seems to always be a terminator, so it doesn't
	 * matter. All addresses beyond the max will fall into the last entry.
	 */
	if (!module->orc.num_entries || unbiased_pc < drgn_orc_pc(module, 0))
		return &drgn_not_found;
	unsigned int lo = 0, hi = module->orc.num_entries, found = 0;
	while (lo < hi) {
		unsigned int mid = lo + (hi - lo) / 2;
		if (drgn_orc_pc(module, mid) <= unbiased_pc) {
			found = mid;
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}
	return module->debug_file->platform.arch->orc_to_cfi(&module->orc.entries[found],
							     row_ret,
							     interrupted_ret,
							     ret_addr_regno_ret);
}
