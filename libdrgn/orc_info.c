// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <byteswap.h>
#include <elf.h>
#include <gelf.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "binary_search.h"
#include "cleanup.h"
#include "debug_info.h" // IWYU pragma: associated
#include "elf_file.h"
#include "error.h"
#include "log.h"
#include "orc.h"
#include "platform.h"
#include "program.h"
#include "util.h"

DEFINE_VECTOR(uint64_range_vector, struct uint64_range);

#define ORC_HEADER_SIZE 20

void drgn_module_orc_info_deinit(struct drgn_module *module)
{
	free(module->orc.entries);
	free(module->orc.pc_offsets);
	free(module->orc.preferred);
}

// Getters for "raw" ORC information, i.e., before it is aligned, byte swapped,
// and normalized to the latest version.
static inline uint64_t drgn_raw_orc_pc(struct drgn_module *module,
				       unsigned int i)
{
	int32_t offset;
	memcpy(&offset, &module->orc.pc_offsets[i], sizeof(offset));
	if (module->orc.bswap)
		offset = bswap_32(offset);
	return module->orc.pc_base + UINT64_C(4) * i + offset;
}

static bool
drgn_raw_orc_entry_is_terminator(struct drgn_module *module, unsigned int i)
{
	uint16_t flags;
	memcpy(&flags, &module->orc.entries[i].flags, sizeof(flags));
	if (module->orc.bswap)
		flags = bswap_16(flags);
	if (module->orc.version >= 3) {
		// orc->type == ORC_TYPE_UNDEFINED
		return (flags & 0x700) == 0;
	} else if (module->orc.version == 2) {
		// orc->sp_reg == ORC_REG_UNDEFINED && !orc->end
		return (flags & 0x80f) == 0;
	} else {
		// orc->sp_reg == ORC_REG_UNDEFINED && !orc->end
		return (flags & 0x40f) == 0;
	}
}

static bool
drgn_raw_orc_entry_is_preferred(struct drgn_module *module, unsigned int i)
{
	uint16_t flags;
	memcpy(&flags, &module->orc.entries[i].flags, sizeof(flags));
	if (module->orc.bswap)
		flags = bswap_16(flags);
	// ORC_REG_SP_INDIRECT is used for the stack switching pattern used in
	// the Linux kernel's call_on_stack()/call_on_irqstack() macros. See
	// Linux kernel commits 87ccc826bf1c ("x86/unwind/orc: Change
	// REG_SP_INDIRECT"), aafeb14e9da2 ("objtool: Support stack-swizzle"),
	// and a0cfc74d0b00 ("x86/irq: Provide macro for inlining irq stack
	// switching") (in v5.12). These macros switch the stack pointer in
	// inline assembly, resulting in inaccurate DWARF CFI. So, we should use
	// ORC to unwind these instead.
	return (flags & 0xf) == DRGN_ORC_REG_SP_INDIRECT;
}

static int compare_orc_entries(const void *a, const void *b, void *arg)
{
	struct drgn_module *module = arg;
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
	return (drgn_raw_orc_entry_is_terminator(module, index_b)
		- drgn_raw_orc_entry_is_terminator(module, index_a));
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
static struct drgn_error *
remove_fdes_from_orc(struct drgn_module *module, unsigned int *indices,
		     struct uint64_range_vector *preferred,
		     unsigned int *num_entriesp)
{
	char *env = getenv("DRGN_PREFER_ORC_UNWINDER");
	if (env && atoi(env)) {
		struct uint64_range *range =
			uint64_range_vector_append_entry(preferred);
		if (!range)
			return &drgn_enomem;
		range->start = 0;
		range->end = UINT64_MAX;
		return NULL;
	}

	if (module->dwarf.debug_frame.num_fdes == 0)
		return NULL;

	struct drgn_dwarf_fde *fde = module->dwarf.debug_frame.fdes;
	struct drgn_dwarf_fde *last_fde =
		fde + module->dwarf.debug_frame.num_fdes - 1;

	unsigned int num_entries = *num_entriesp;
	unsigned int new_num_entries = 0;

	// ORC can be built-in or from the debug file. Because of that, we
	// always store the biased/actual address at orc.pc_base. Since we are
	// comparing to the unbiased addresses in the debug_frame FDEs, we need
	// to subtract the bias from the ORC PC.
	uint64_t start_pc = drgn_raw_orc_pc(module, 0) - module->debug_file_bias;
	uint64_t end_pc;
	for (unsigned int i = 0; i < num_entries; i++, start_pc = end_pc) {
		if (i < num_entries - 1)
			end_pc = drgn_raw_orc_pc(module, i + 1) - module->debug_file_bias;
		else
			end_pc = UINT64_MAX;

		if (drgn_raw_orc_entry_is_preferred(module, i)) {
			struct uint64_range *range =
				uint64_range_vector_append_entry(preferred);
			if (!range)
				return &drgn_enomem;
			range->start = start_pc;
			range->end = end_pc;
			new_num_entries = keep_orc_entry(module, indices,
							 new_num_entries, i);
			continue;
		}

		if (start_pc < fde->initial_location) {
			// The current ORC entry starts before the current FDE
			// (which can only happen if it is the first FDE). Keep
			// it.
			new_num_entries = keep_orc_entry(module, indices,
							 new_num_entries, i);
			continue;
		}

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
			if (fde == last_fde
			    || fde[1].initial_location - fde->initial_location
			       > fde->address_range) {
				// Either there are no more FDEs or there is a
				// gap between the current FDE and the next FDE
				// that exposes the current ORC entry. Keep it.
				new_num_entries = keep_orc_entry(module,
								 indices,
								 new_num_entries,
								 i);
				break;
			}
			fde++;
		}
	}
	*num_entriesp = new_num_entries;
	return NULL;
}

static int orc_version_from_header(const void *buffer)
{
	// Known version identifiers in .orc_header. These can be generated in
	// the kernel source tree with:
	// sh ./scripts/orc_hash.sh < arch/x86/include/asm/orc_types.h | sed -e 's/^#define ORC_HASH //' -e 's/,/, /g'

	// Linux kernel commit fb799447ae29 ("x86,objtool: Split
	// UNWIND_HINT_EMPTY in two") (in v6.4)
	static const uint8_t orc_hash_6_4[ORC_HEADER_SIZE] = {
		0xfe, 0x5d, 0x32, 0xbf, 0x58, 0x1b, 0xd6, 0x3b, 0x2c, 0xa9,
		0xa5, 0xc6, 0x5b, 0xa5, 0xa6, 0x25, 0xea, 0xb3, 0xfe, 0x24,
	};
	// Linux kernel commit ffb1b4a41016 ("x86/unwind/orc: Add 'signal' field
	// to ORC metadata") (in v6.3)
	static const uint8_t orc_hash_6_3[ORC_HEADER_SIZE] = {
		0xdb, 0x84, 0xae, 0xd4, 0x10, 0x3b, 0x31, 0xdd, 0x51, 0xe0,
		0x17, 0xf8, 0xf7, 0x97, 0x83, 0xca, 0x98, 0x5c, 0x2c, 0x51,
	};

	if (memcmp(buffer, orc_hash_6_4, ORC_HEADER_SIZE) == 0)
		return 3;
	else if (memcmp(buffer, orc_hash_6_3, ORC_HEADER_SIZE) == 0)
		return 2;
	return -1;
}

static int orc_version_from_osrelease(struct drgn_program *prog)
{
	char *p = (char *)prog->vmcoreinfo.osrelease;
	long major = strtol(p, &p, 10);
	long minor = 0;
	if (*p == '.')
		minor = strtol(p + 1, NULL, 10);

	// RHEL & derivatives started shipping backported ORC patches without
	// the ".orc_header" section in 9.6. According to git history this was
	// introduced in kernel version 5.14.0-517.el9. With those changes, the
	// kernel's ORC "format" is indeed v3, but we cannot detect that without
	// the ORC header hash. Add special-case detection for this situation.
	// If it is fixed by including the ".orc_header" section, this fix will
	// not be active, but will still be necessary for the already released
	// kernels.
	char *rhrelease = NULL;
	if (major == 5 && minor == 14 && strstr(p, ".el9")
	    && (rhrelease = strchr(p, '-'))
	    && strtol(rhrelease + 1, NULL, 10) >= 517)
		return 3;

	if (major > 6 || (major == 6 && minor >= 4))
		return 3;
	else if (major == 6 && minor == 3)
		return 2;
	else
		return 1;
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
	Elf_Scn *orc_header_scn = NULL;

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
		} else if (!orc_header_scn
			   && strcmp(scnname, ".orc_header") == 0) {
			orc_header_scn = scn;
		}
	}

	if (!orc_unwind_ip_scn || !orc_unwind_scn) {
		module->orc.num_entries = 0;
		return NULL;
	}

	err = drgn_elf_file_apply_relocations(module->debug_file);
	if (err)
		return err;

	// Since Linux kernel b9f174c811e3 ("x86/unwind/orc: Add ELF section
	// with ORC version identifier") (in v6.4), which was also backported to
	// Linux 6.3.10, vmlinux and kernel modules have a .orc_header ELF
	// section containing a 20-byte hash identifying the ORC version.
	//
	// Because there are 6.3 and 6.4 kernels without .orc_header, we have to
	// fall back to checking the kernel version.
	if (orc_header_scn) {
		Elf_Data *orc_header;
		err = read_elf_section(orc_header_scn, &orc_header);
		if (err)
			return err;
		module->orc.version = -1;
		if (orc_header->d_size == ORC_HEADER_SIZE)
			module->orc.version = orc_version_from_header(orc_header->d_buf);
		if (module->orc.version < 0) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "unrecognized .orc_header");
		}
	} else {
		module->orc.version = orc_version_from_osrelease(module->prog);
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

	module->orc.pc_offsets = orc_unwind_ip->d_buf;
	module->orc.entries = orc_unwind->d_buf;

	return NULL;
}

static struct drgn_error *
copy_builtin_orc_buffers(struct drgn_module *module, uint64_t num_entries,
			 uint64_t unwind, uint64_t unwind_ip, uint64_t header)
{
	uint8_t header_data[ORC_HEADER_SIZE];

	struct drgn_error *err;

	if (header) {
		err = drgn_program_read_memory(module->prog, header_data,
					       header, sizeof(header_data),
					       false);

		if (err)
			return err;

		module->orc.version = orc_version_from_header(header_data);
		if (module->orc.version < 0)
			return drgn_error_create(DRGN_ERROR_OTHER,
							"unrecognized .orc_header");
	} else {
		module->orc.version = orc_version_from_osrelease(module->prog);
	}

	_cleanup_free_ int32_t *pc_offsets = malloc_array(num_entries,
							  sizeof(pc_offsets[0]));
	if (!pc_offsets)
		return &drgn_enomem;
	err = drgn_program_read_memory(module->prog, pc_offsets, unwind_ip,
				       num_entries * sizeof(pc_offsets[0]), false);
	if (err)
		return err;

	_cleanup_free_ struct drgn_orc_entry *entries =
		malloc_array(num_entries, sizeof(entries[0]));
	if (!entries)
		return &drgn_enomem;
	err = drgn_program_read_memory(module->prog, entries, unwind,
				       num_entries * sizeof(entries[0]), false);
	if (err)
		return err;

	module->orc.entries = no_cleanup_ptr(entries);
	module->orc.pc_offsets = no_cleanup_ptr(pc_offsets);
	module->orc.num_entries = num_entries;
	module->orc.pc_base = unwind_ip;
	drgn_log_debug(module->prog, "Loaded built-in ORC (v%d) for module %s",
		       module->orc.version, module->name);
	return NULL;
}

static struct drgn_error *drgn_read_vmlinux_orc(struct drgn_module *module)
{
	struct drgn_error *err;
	struct drgn_symbol *sym;

	uint64_t unwind_ip_start, unwind_ip_end;
	uint64_t unwind_start, unwind_end;
	uint64_t header_start = 0, header_end = 0;

#define get_symbol(name, var, optional) \
	err = drgn_program_find_symbol_by_name(module->prog, name, &sym); \
	if (!err) { \
		var = sym->address; \
		drgn_symbol_destroy(sym); \
		sym = NULL; \
	} else if (optional && drgn_error_catch(&err, DRGN_ERROR_LOOKUP)) { \
		sym = NULL; \
	} else { \
		drgn_error_catch(&err, DRGN_ERROR_LOOKUP); \
		return err; \
	}

	get_symbol("__start_orc_unwind_ip", unwind_ip_start, false);
	get_symbol("__stop_orc_unwind_ip", unwind_ip_end, false);
	get_symbol("__start_orc_unwind", unwind_start, false);
	get_symbol("__stop_orc_unwind", unwind_end, false);
	get_symbol("__start_orc_header", header_start, true);
	get_symbol("__stop_orc_header", header_end, true);
#undef get_symbol

	if ((unwind_ip_end - unwind_ip_start) % sizeof(int32_t))
		return drgn_error_create(DRGN_ERROR_OTHER, "invalid built-in orc_unwind_ip range");
	uint64_t num_entries = (unwind_ip_end - unwind_ip_start) / sizeof(int32_t);
	if (num_entries > UINT_MAX)
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "built-in orc_unwind_ip range is too large");

	if ((unwind_end - unwind_start) % sizeof(struct drgn_orc_entry)
	    || (unwind_end - unwind_start) / sizeof(struct drgn_orc_entry) != num_entries)
		return drgn_error_create(DRGN_ERROR_OTHER, "invalid built-in orc_unwind range");

	if (header_start && header_end && header_end - header_start != ORC_HEADER_SIZE)
		return drgn_error_create(DRGN_ERROR_OTHER, "invalid built-in orc_header size");

	return copy_builtin_orc_buffers(module, num_entries, unwind_start,
					unwind_ip_start, header_start);
}

static struct drgn_error *drgn_read_builtin_orc(struct drgn_module *module)
{
	if (!(module->prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL))
		return NULL;
	if (module->kind == DRGN_MODULE_MAIN)
		return drgn_read_vmlinux_orc(module);
	else if (module->kind != DRGN_MODULE_RELOCATABLE)
		return NULL;
	else if (module->object.kind == DRGN_OBJECT_ABSENT)
		return NULL;

	// num_entries is implied by the size of the arrays. We can get the
	// array addresses from the section address info, but not their size. So
	// we need to find num_orcs by reading it out of the arch-specific
	// module info.
	DRGN_OBJECT(tmp, module->prog);
	struct drgn_error *err;

	err = drgn_object_dereference(&tmp, &module->object);
	if (err)
		return err;

	err = drgn_object_member(&tmp, &tmp, "arch");
	if (err)
		return err;

	err = drgn_object_member(&tmp, &tmp, "num_orcs");
	// If the kernel does not support ORC (e.g. it is too old), this will be
	// the first lookup error we encounter. Catch it and don't return any
	// error.
	if (drgn_error_catch(&err, DRGN_ERROR_LOOKUP) || err)
		return err;

	uint64_t num_entries;
	err = drgn_object_read_unsigned(&tmp, &num_entries);
	if (err)
		return err;

	// We'll still use the section addresses for everything else, because
	// the orc_header is only present there, and it should be a bit faster
	// to read data which we already parsed, rather than going back to read
	// it from program memory.
	uint64_t orc_unwind;
	uint64_t orc_unwind_ip;
	uint64_t orc_header = 0;
	err = drgn_module_get_section_address(module, ".orc_unwind", &orc_unwind);
	if (err)
		return err;
	err = drgn_module_get_section_address(module, ".orc_unwind_ip", &orc_unwind_ip);
	if (err)
		return err;
	err = drgn_module_get_section_address(module, ".orc_header", &orc_header);
	drgn_error_catch(&err, DRGN_ERROR_LOOKUP);
	if (err)
		return err;

	return copy_builtin_orc_buffers(module, num_entries, orc_unwind,
					orc_unwind_ip, orc_header);
}

static inline void drgn_module_clear_orc(struct drgn_module **modulep)
{
	if (*modulep) {
		(*modulep)->orc.pc_offsets = NULL;
		(*modulep)->orc.entries = NULL;
	}
}

struct drgn_error *drgn_module_parse_orc(struct drgn_module *module,
					 bool use_builtin)
{
	struct drgn_error *err;

	if (module->prog->platform.arch->arch != DRGN_ARCH_X86_64)
		return NULL;

	// When loading from the debug_file, pc_offsets and entries point to the
	// Elf_Data buffers until the end of this function, when copies are made.
	// When loading built-in ORC, we own both buffers. In either case, we
	// don't want these pointers freed by drgn_module_orc_info_deinit() if
	// we fail early. So we use this to reset the pointers to NULL on
	// failure.
	_cleanup_(drgn_module_clear_orc) struct drgn_module *clear = module;

	// For the built-in ORC, we use these to clean up the memory allocated
	// in drgn_read_builtin_orc(). This happens even on success, because the
	// buffers are copied at the end of this function.
	_cleanup_free_ void *cleanup_pc_offsets = NULL;
	_cleanup_free_ void *cleanup_entries = NULL;

	if (use_builtin) {
		err = drgn_read_builtin_orc(module);
		cleanup_pc_offsets = module->orc.pc_offsets;
		cleanup_entries = module->orc.entries;
	} else {
		err = drgn_read_orc_sections(module);
		module->orc.pc_base += module->debug_file_bias;
	}
	if (err || !module->orc.num_entries)
		return err;

	// We may need to byte swap ORC entries. Rather than checking the
	// debug_file's platform, use the program's platform (since they are the
	// same) because it's possible there is no debug_file (e.g. for builtin
	// ORC).
	bool bswap;
	err = drgn_program_bswap(module->prog, &bswap);
	if (err)
		return err;

	unsigned int num_entries = module->orc.num_entries;
	_cleanup_free_ unsigned int *indices =
		malloc_array(num_entries, sizeof(indices[0]));
	if (!indices)
		return &drgn_enomem;
	for (unsigned int i = 0; i < num_entries; i++)
		indices[i] = i;

	/*
	 * Sort the ORC entries for binary search. Since Linux kernel commit
	 * f14bf6a350df ("x86/unwind/orc: Remove boot-time ORC unwind tables
	 * sorting") (in v5.6), this is already sorted for vmlinux, so only sort
	 * it if necessary.
	 */
	for (unsigned int i = 1; i < num_entries; i++) {
		if (compare_orc_entries(&indices[i - 1], &indices[i], module) > 0) {
			qsort_arg(indices, num_entries, sizeof(indices[0]),
				  compare_orc_entries, module);
			break;
		}
	}

	VECTOR(uint64_range_vector, preferred);

	err = remove_fdes_from_orc(module, indices, &preferred, &num_entries);
	if (err)
		return err;

	_cleanup_free_ int32_t *pc_offsets =
		malloc_array(num_entries, sizeof(pc_offsets[0]));
	if (!pc_offsets)
		return &drgn_enomem;
	_cleanup_free_ struct drgn_orc_entry *entries =
		malloc_array(num_entries, sizeof(entries[0]));
	if (!entries)
		return &drgn_enomem;
	const int32_t *orig_offsets = module->orc.pc_offsets;
	const struct drgn_orc_entry *orig_entries = module->orc.entries;
	const int version = module->orc.version;
	for (unsigned int i = 0; i < num_entries; i++) {
		unsigned int index = indices[i];
		int32_t offset;
		memcpy(&offset, &orig_offsets[index], sizeof(offset));
		memcpy(&entries[i], &orig_entries[index], sizeof(entries[i]));
		if (bswap) {
			offset = bswap_32(offset);
			entries[i].sp_offset = bswap_16(entries[i].sp_offset);
			entries[i].bp_offset = bswap_16(entries[i].bp_offset);
			entries[i].flags = bswap_16(entries[i].flags);
		}
		// "Upgrade" the format to version 3. See struct
		// drgn_orc_type::flags.
		if (version == 2) {
			// There are no UNDEFINED or END_OF_STACK types in
			// versions 1 and 2. Instead, sp_reg ==
			// ORC_REG_UNDEFINED && !end is equivalent to UNDEFINED,
			// and sp_reg == ORC_REG_UNDEFINED && end is equivalent
			// to END_OF_STACK.
			int type;
			if ((entries[i].flags & 0x80f) == 0)
				type = DRGN_ORC_TYPE_UNDEFINED << 8;
			else if ((entries[i].flags & 0x80f) == 0x800)
				type = DRGN_ORC_TYPE_END_OF_STACK << 8;
			else
				type = (entries[i].flags & 0x300) + 0x200;
			int signal = (entries[i].flags & 0x400) << 1;
			entries[i].flags = ((entries[i].flags & 0xff)
					    | type
					    | signal);
		} else if (version == 1) {
			int type;
			if ((entries[i].flags & 0x40f) == 0)
				type = DRGN_ORC_TYPE_UNDEFINED << 8;
			else if ((entries[i].flags & 0x40f) == 0x400)
				type = DRGN_ORC_TYPE_END_OF_STACK << 8;
			else
				type = (entries[i].flags & 0x300) + 0x200;
			// There is no signal flag in version 1. Instead,
			// ORC_TYPE_REGS and ORC_TYPE_REGS_PARTIAL imply the
			// signal flag, and ORC_TYPE_CALL does not.
			int signal = (entries[i].flags & 0x300) > 0 ? 0x800 : 0;
			entries[i].flags = ((entries[i].flags & 0xff)
					    | type
					    | signal);
		}
		pc_offsets[i] = UINT64_C(4) * index + offset - UINT64_C(4) * i;
	}

	uint64_range_vector_shrink_to_fit(&preferred);
	uint64_range_vector_steal(&preferred, &module->orc.preferred,
				  &module->orc.num_preferred);
	module->orc.pc_offsets = no_cleanup_ptr(pc_offsets);
	module->orc.entries = no_cleanup_ptr(entries);
	module->orc.num_entries = num_entries;
	module->orc.bswap = bswap;
	clear = NULL;
	return NULL;
}

bool drgn_module_should_prefer_orc_cfi(struct drgn_module *module, uint64_t pc)
{
	uint64_t unbiased_pc = pc - module->debug_file_bias;
	#define less_than_uint64_range_start(a, b) (*(a) < (b)->start)
	size_t i = binary_search_gt(module->orc.preferred,
				    module->orc.num_preferred, &unbiased_pc,
				    less_than_uint64_range_start);
	#undef less_than_uint64_range_start
	return i > 0 && module->orc.preferred[i - 1].end > unbiased_pc;
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
	#define less_than_orc_pc(a, b)	\
		(*(a) < drgn_orc_pc(module, (b) - module->orc.pc_offsets))
	size_t i = binary_search_gt(module->orc.pc_offsets,
				    module->orc.num_entries, &pc,
				    less_than_orc_pc);
	#undef less_than_orc_pc
	// We can tell when the program counter is below the minimum program
	// counter included in the ORC data, but we don't know the maximum. The
	// last entry seems to always be a terminator, so it doesn't matter. All
	// addresses beyond the max will fall into the last entry.
	if (i == 0)
		return &drgn_not_found;
	return drgn_orc_to_cfi_x86_64(&module->orc.entries[i - 1], row_ret,
				      interrupted_ret, ret_addr_regno_ret);
}
