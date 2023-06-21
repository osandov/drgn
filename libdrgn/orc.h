// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * ORC unwinder definitions.
 *
 * As of Linux v6.4, ORC is only defined for x86-64. This file assumes that the
 * overall format would be the same for other architectures other than
 * architecture-specific register numbers, but this may require reorganization
 * if that isn't the case.
 *
 * There are multiple versions of the ORC format:
 *
 * - Version 3 since since Linux kernel commit fb799447ae29 ("x86,objtool: Split
 *   UNWIND_HINT_EMPTY in two") (in v6.4).
 * - Version 2 between that and Linux kernel commit ffb1b4a41016
 *   ("x86/unwind/orc: Add 'signal' field to ORC metadata") (in v6.3).
 * - Version 1 before that, introduced in Linux kernel commit ee9f8fce9964
 *   ("x86/unwind: Add the ORC unwinder") (in v4.14).
 *
 * (The version numbers are our own invention and aren't used upstream.)
 *
 * So far, the format changes only affect the interpretation of @ref
 * drgn_orc_entry::flags. The getters assume the latest version.
 */

#ifndef DRGN_ORC_H
#define DRGN_ORC_H

#include <stdbool.h>
#include <stdint.h>

struct drgn_orc_entry {
	int16_t sp_offset;
	int16_t bp_offset;
	/**
	 * Bit layout by version:
	 *
	 * |Version| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10| 11|
	 * |-------|---|---|---|---|---|---|---|---|---|---|---|---|
	 * |      3| sp_reg     |||| bp_reg     |||| type    ||| S |
	 * |      2| sp_reg     |||| bp_reg     |||| type || S | E |
	 * |      1| sp_reg     |||| bp_reg     |||| type || E |   |
	 *
	 * S = signal
	 * E = end
	 */
	uint16_t flags;
};

enum {
	// In versions 1 and 2, UNDEFINED and END_OF_STACK didn't exist, and
	// CALL = 0, REGS = 1, and REGS_PARTIAL = 2.
	DRGN_ORC_TYPE_UNDEFINED = 0,
	DRGN_ORC_TYPE_END_OF_STACK = 1,
	DRGN_ORC_TYPE_CALL = 2,
	DRGN_ORC_TYPE_REGS = 3,
	DRGN_ORC_TYPE_REGS_PARTIAL = 4,
};

static inline int drgn_orc_sp_reg(const struct drgn_orc_entry *orc)
{
	return orc->flags & 0xf;
}

static inline int drgn_orc_bp_reg(const struct drgn_orc_entry *orc)
{
	return (orc->flags >> 4) & 0xf;
}

static inline int drgn_orc_type(const struct drgn_orc_entry *orc)
{
	return (orc->flags >> 8) & 0x7;
}

static inline bool drgn_orc_signal(const struct drgn_orc_entry *orc)
{
	return orc->flags & 0x800;
}

#endif /* DRGN_ORC_H */
