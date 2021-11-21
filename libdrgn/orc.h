// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file
 *
 * ORC unwinder definitions.
 *
 * As of Linux v5.12, ORC is only defined for x86-64. This file assumes that the
 * overall format would be the same for other architectures other than
 * architecture-specific register numbers, but this may require reorganization
 * if that isn't the case.
 */

#ifndef DRGN_ORC_H
#define DRGN_ORC_H

#include <stdbool.h>
#include <stdint.h>

struct drgn_orc_entry {
	int16_t sp_offset;
	int16_t bp_offset;
	/*
	 * This is represented by 4 bit fields in the Linux kernel, but this is
	 * easier to deal with.
	 */
	uint16_t flags;
};

/* These correspond to UNWIND_HINT_* in the Linux kernel. */
enum {
	DRGN_ORC_TYPE_CALL = 0,
	DRGN_ORC_TYPE_REGS = 1,
	DRGN_ORC_TYPE_REGS_PARTIAL = 2,
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
	return (orc->flags >> 8) & 0x3;
}

static inline bool drgn_orc_is_end(const struct drgn_orc_entry *orc)
{
	return orc->flags & 0x400;
}

static inline bool drgn_orc_flags_is_terminator(uint16_t flags)
{
	return (flags & 0x40f) == 0;
}

#endif /* DRGN_ORC_H */
