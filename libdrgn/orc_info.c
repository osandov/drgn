// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <byteswap.h>
#include <gelf.h>
#include <stdlib.h>
#include <string.h>

#include "debug_info.h" // IWYU pragma: associated
#include "error.h"
#include "orc.h"
#include "util.h"

void drgn_orc_module_info_deinit(struct drgn_debug_info_module *module)
{
	free(module->orc.entries);
	free(module->orc.pc_offsets);
}

/*
 * Get the program counter of an ORC entry directly from the .orc_unwind_ip
 * section.
 */
static inline uint64_t drgn_raw_orc_pc(struct drgn_debug_info_module *module,
				       size_t i)
{
	int32_t offset;
	memcpy(&offset,
	       (int32_t *)module->scn_data[DRGN_SCN_ORC_UNWIND_IP]->d_buf + i,
	       sizeof(offset));
	if (drgn_platform_bswap(&module->platform))
		offset = bswap_32(offset);
	return module->orc.pc_base + UINT64_C(4) * i + offset;
}

static int compare_orc_entries(const void *a, const void *b, void *arg)
{
	struct drgn_debug_info_module *module = arg;
	size_t index_a = *(size_t *)a;
	size_t index_b = *(size_t *)b;

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
	const struct drgn_orc_entry *entries =
		module->scn_data[DRGN_SCN_ORC_UNWIND]->d_buf;
	uint16_t flags_a, flags_b;
	memcpy(&flags_a, &entries[index_a].flags, sizeof(flags_a));
	memcpy(&flags_b, &entries[index_b].flags, sizeof(flags_b));
	if (drgn_platform_bswap(&module->platform)) {
		flags_a = bswap_16(flags_a);
		flags_b = bswap_16(flags_b);
	}
	return (drgn_orc_flags_is_terminator(flags_b)
		- drgn_orc_flags_is_terminator(flags_a));
}

static size_t keep_orc_entry(struct drgn_debug_info_module *module,
			     size_t *indices, size_t num_entries, size_t i)
{

	const struct drgn_orc_entry *entries =
		module->scn_data[DRGN_SCN_ORC_UNWIND]->d_buf;
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
 */
static size_t remove_fdes_from_orc(struct drgn_debug_info_module *module,
				   size_t *indices, size_t num_entries)
{
	if (module->dwarf.num_fdes == 0)
		return num_entries;

	struct drgn_dwarf_fde *fde = module->dwarf.fdes;
	struct drgn_dwarf_fde *last_fde = fde + module->dwarf.num_fdes - 1;

	size_t new_num_entries = 0;

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

	for (size_t i = new_num_entries; i < num_entries - 1; i++) {
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

static struct drgn_error *
drgn_debug_info_parse_orc(struct drgn_debug_info_module *module)
{
	struct drgn_error *err;

	if (!module->platform.arch->orc_to_cfi ||
	    !module->scns[DRGN_SCN_ORC_UNWIND_IP] ||
	    !module->scns[DRGN_SCN_ORC_UNWIND])
		return NULL;

	GElf_Shdr shdr_mem, *shdr;
	shdr = gelf_getshdr(module->scns[DRGN_SCN_ORC_UNWIND_IP], &shdr_mem);
	if (!shdr)
		return drgn_error_libelf();
	module->orc.pc_base = shdr->sh_addr;

	err = drgn_debug_info_module_cache_section(module,
						   DRGN_SCN_ORC_UNWIND_IP);
	if (err)
		return err;
	err = drgn_debug_info_module_cache_section(module, DRGN_SCN_ORC_UNWIND);
	if (err)
		return err;
	Elf_Data *orc_unwind_ip = module->scn_data[DRGN_SCN_ORC_UNWIND_IP];
	Elf_Data *orc_unwind = module->scn_data[DRGN_SCN_ORC_UNWIND];

	size_t num_entries = orc_unwind_ip->d_size / sizeof(int32_t);
	if (orc_unwind_ip->d_size % sizeof(int32_t) != 0 ||
	    orc_unwind->d_size % sizeof(struct drgn_orc_entry) != 0 ||
	    orc_unwind->d_size / sizeof(struct drgn_orc_entry) != num_entries) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 ".orc_unwind_ip and/or .orc_unwind has invalid size");
	}
	if (!num_entries)
		return NULL;

	size_t *indices = malloc_array(num_entries, sizeof(indices[0]));
	if (!indices)
		return &drgn_enomem;
	for (size_t i = 0; i < num_entries; i++)
		indices[i] = i;

	/*
	 * Sort the ORC entries for binary search. Since Linux kernel commit
	 * f14bf6a350df ("x86/unwind/orc: Remove boot-time ORC unwind tables
	 * sorting") (in v5.6), this is already sorted for vmlinux, so only sort
	 * it if necessary.
	 */
	for (size_t i = 1; i < num_entries; i++) {
		if (compare_orc_entries(&indices[i - 1], &indices[i],
					module) > 0) {
			qsort_r(indices, num_entries, sizeof(indices[0]),
				compare_orc_entries, module);
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
	const int32_t *orig_offsets = orc_unwind_ip->d_buf;
	const struct drgn_orc_entry *orig_entries = orc_unwind->d_buf;
	bool bswap = drgn_platform_bswap(&module->platform);
	for (size_t i = 0; i < num_entries; i++) {
		size_t index = indices[i];
		int32_t offset;
		memcpy(&offset, &orig_offsets[index], sizeof(offset));
		struct drgn_orc_entry entry;
		memcpy(&entry, &orig_entries[index], sizeof(entry));
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
	return err;
}

static inline uint64_t drgn_orc_pc(struct drgn_debug_info_module *module,
				   size_t i)
{
	return module->orc.pc_base + UINT64_C(4) * i + module->orc.pc_offsets[i];
}

struct drgn_error *
drgn_debug_info_find_orc_cfi(struct drgn_debug_info_module *module,
			     uint64_t unbiased_pc,
			     struct drgn_cfi_row **row_ret,
			     bool *interrupted_ret,
			     drgn_register_number *ret_addr_regno_ret)
{
	struct drgn_error *err;

	if (!module->parsed_orc) {
		err = drgn_debug_info_parse_orc(module);
		if (err)
			return err;
		module->parsed_orc = true;
	}

	/*
	 * We don't know the maximum program counter covered by the ORC data,
	 * but the last entry seems to always be a terminator, so it doesn't
	 * matter. All addresses beyond the max will fall into the last entry.
	 */
	if (!module->orc.num_entries || unbiased_pc < drgn_orc_pc(module, 0))
		return &drgn_not_found;
	size_t lo = 0, hi = module->orc.num_entries, found = 0;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		if (drgn_orc_pc(module, mid) <= unbiased_pc) {
			found = mid;
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}
	return module->platform.arch->orc_to_cfi(&module->orc.entries[found],
						 row_ret, interrupted_ret,
						 ret_addr_regno_ret);
}
