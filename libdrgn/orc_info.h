// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file
 *
 * ORC unwinder support.
 *
 * See @ref DebugInfo.
 */

#ifndef DRGN_ORC_INFO_H
#define DRGN_ORC_INFO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cfi.h"

struct drgn_debug_info_module;

/**
 * @ingroup DebugInfo
 *
 * @{
 */

/** ORC unwinder data for a @ref drgn_debug_info_module. */
struct drgn_orc_module_info {
	/**
	 * Base for calculating program counter corresponding to an ORC unwinder
	 * entry.
	 *
	 * This is the address of the `.orc_unwind_ip` ELF section.
	 *
	 * @sa drgn_orc_module_info::entries
	 */
	uint64_t pc_base;
	/**
	 * Offsets for calculating program counter corresponding to an ORC
	 * unwinder entry.
	 *
	 * This is the contents of the `.orc_unwind_ip` ELF section, byte
	 * swapped to the host's byte order if necessary.
	 *
	 * @sa drgn_orc_module_info::entries
	 */
	int32_t *pc_offsets;
	/**
	 * ORC unwinder entries.
	 *
	 * This is the contents of the `.orc_unwind` ELF section, byte swapped
	 * to the host's byte order if necessary.
	 *
	 * Entry `i` specifies how to unwind the stack if
	 * `orc_pc(i) <= PC < orc_pc(i + 1)`, where
	 * `orc_pc(i) = pc_base + 4 * i + pc_offsets[i]`.
	 */
	struct drgn_orc_entry *entries;
	/** Number of ORC unwinder entries. */
	size_t num_entries;
};

void drgn_orc_module_info_deinit(struct drgn_debug_info_module *module);

struct drgn_error *
drgn_debug_info_find_orc_cfi(struct drgn_debug_info_module *module,
			     uint64_t unbiased_pc,
			     struct drgn_cfi_row **row_ret,
			     bool *interrupted_ret,
			     drgn_register_number *ret_addr_regno_ret);

/** @} */

#endif /* DRGN_ORC_INFO_H */
