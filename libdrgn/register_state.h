// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file
 *
 * Register state.
 *
 * See @ref RegisterState.
 */

#ifndef DRGN_REGISTER_STATE_H
#define DRGN_REGISTER_STATE_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cfi.h"
#include "platform.h"
#include "program.h"
#include "serialize.h"
#include "util.h"

/**
 * @ingroup Internals
 *
 * @defgroup RegisterState Register state
 *
 * Buffer of processor register values.
 *
 * This defines @ref drgn_register_state for storing the values of processor
 * registers.
 *
 * Several macros defined here take a register identifier as defined by @ref
 * DRGN_REGISTER_LAYOUT(). These are intended for use in architecture definition
 * files. These macros also have function equivalents (with names ending in
 * `_impl`) that take the register number, offset, and size instead.
 *
 * @{
 */

/**
 * State of processor registers (e.g., in a stack frame), including the program
 * counter and Canonical Frame Address (some of which may not be known).
 */
struct drgn_register_state {
	/**
	 * Cached @ref drgn_debug_info_module that contains the program counter.
	 *
	 * This is `NULL` if the program counter is not known, if the containing
	 * module could not be found, or if the containing module's platform
	 * does not match the program's platform (in which case we can't use it
	 * anyways).
	 */
	struct drgn_debug_info_module *module;
	/** Total size of registers allocated in @ref drgn_register_state::buf. */
	uint32_t regs_size;
	/** Number of registers allocated in @ref drgn_register_state::buf. */
	uint16_t num_regs;
	/** Whether this frame was interrupted (e.g., by a signal). */
	bool interrupted;
	/** Program counter. Access with @ref drgn_register_state_get_pc(). */
	uint64_t _pc;
	/**
	 * Canonical Frame Address. Access with @ref
	 * drgn_register_state_get_cfa().
	 */
	uint64_t _cfa;
	/**
	 * Buffer of register values followed by bitset indicating which
	 * register values are known.
	 *
	 * The layout of the register values is architecture-specific and
	 * defined by @ref DRGN_ARCH_REGISTER_LAYOUT.
	 *
	 * Bit 0 of the bitset is whether the PC is known, bit 1 is whether the
	 * CFA is known, and the remaining @ref drgn_register_state::num_regs
	 * bits are whether each register is known.
	 *
	 * Registers beyond @ref drgn_register_state::regs_size ""/@ref
	 * drgn_register_state::num_regs are not allocated here and are assumed
	 * to be unknown.
	 */
	unsigned char buf[];
};

struct drgn_register_state *drgn_register_state_create_impl(uint32_t regs_size,
							    uint16_t num_regs,
							    bool interrupted);

/**
 * Create a @ref drgn_register_state large enough to store up to and including a
 * given register.
 *
 * @param[in] last_reg Identifier of last register to allocate.
 * @param[in] interrupted @ref drgn_register_state::interrupted
 * @return New register state on success, @c NULL on failure to allocate memory.
 */
#define drgn_register_state_create(last_reg, interrupted)			\
	drgn_register_state_create_impl(DRGN_REGISTER_END(last_reg),		\
					DRGN_REGISTER_NUMBER(last_reg) + 1,	\
					interrupted)

/** Free a @ref drgn_register_state. */
static inline void
drgn_register_state_destroy(struct drgn_register_state *regs)
{
	free(regs);
}

/**
 * Get whether the value of a register is known in a @ref drgn_register_state.
 *
 * @param[in] regno Register number to check. May be @c
 * DRGN_REGISTER_NUMBER_UNKNOWN, in which case this always returns @c false.
 */
bool drgn_register_state_has_register(const struct drgn_register_state *regs,
				      drgn_register_number regno)
	__attribute__((__pure__));

/**
 * Mark a register as known in a @ref drgn_register_state.
 *
 * @param[in] regno Register number to mark as known. Must be less than @ref
 * drgn_register_state::num_regs.
 */
void drgn_register_state_set_has_register(struct drgn_register_state *regs,
					  drgn_register_number regno);

/**
 * Mark a range of adjacent registers as known in a @ref drgn_register_state.
 *
 * @param[in] first_regno First register number to mark as known (inclusive).
 * Must be less than or equal to @p last_regno.
 * @param[in] last_regno Last register number to mark as known (inclusive). Must
 * be less than @ref drgn_register_state::num_regs.
 */
void
drgn_register_state_set_has_register_range(struct drgn_register_state *regs,
					   drgn_register_number first_regno,
					   drgn_register_number last_regno);

/** A `uint64_t` which may or may not be present. */
struct optional_uint64 {
	uint64_t value;
	bool has_value;
};

/** Get the value of the program counter in a @ref drgn_register_state. */
struct optional_uint64
drgn_register_state_get_pc(const struct drgn_register_state *regs)
	__attribute__((__pure__));

/**
 * Set the value of the program counter in a @ref drgn_register_state and mark
 * it as known.
 */
void drgn_register_state_set_pc(struct drgn_program *prog,
				struct drgn_register_state *regs, uint64_t pc);

static inline void
drgn_register_state_set_pc_from_register_impl(struct drgn_program *prog,
					      struct drgn_register_state *regs,
					      drgn_register_number regno,
					      size_t reg_offset,
					      size_t reg_size)
{
	assert(drgn_register_state_has_register(regs, regno));
	uint64_t pc;
	copy_lsbytes(&pc, sizeof(pc), HOST_LITTLE_ENDIAN,
		     &regs->buf[reg_offset], reg_size,
		     drgn_platform_is_little_endian(&prog->platform));
	drgn_register_state_set_pc(prog, regs, pc);
}

/**
 * Set the value of the program counter in a @ref drgn_register_state from the
 * value of a register and mark it as known.
 *
 * @param[in] reg Identifier of register to set from. Value must be known.
 */
#define drgn_register_state_set_pc_from_register(prog, regs, reg)		\
	drgn_register_state_set_pc_from_register_impl(prog, regs,		\
						      DRGN_REGISTER_NUMBER(reg),\
						      DRGN_REGISTER_OFFSET(reg),\
						      DRGN_REGISTER_SIZE(reg))

/**
 * Get the value of the Canonical Frame Address in a @ref drgn_register_state.
 */
struct optional_uint64
drgn_register_state_get_cfa(const struct drgn_register_state *regs)
	__attribute__((__pure__));

/**
 * Set the value of the Canonical Frame Address in a @ref drgn_register_state
 * and mark it as known.
 */
void drgn_register_state_set_cfa(struct drgn_program *prog,
				 struct drgn_register_state *regs,
				 uint64_t cfa);

static inline void
drgn_register_state_set_from_buffer_impl(struct drgn_register_state *regs,
					 drgn_register_number regno,
					 size_t reg_offset, size_t reg_size,
					 const void *buf)
{
	memcpy(&regs->buf[reg_offset], buf, reg_size);
	drgn_register_state_set_has_register(regs, regno);
}

/**
 * Set the value of a register in a @ref drgn_register_state from a buffer and
 * mark it as known.
 *
 * The buffer must be at least as large as the register.
 *
 * @param[in] reg Identifier of register to set. Number must be less than @ref
 * drgn_register_state::num_regs.
 */
#define drgn_register_state_set_from_buffer(regs, reg, buf)			\
	drgn_register_state_set_from_buffer_impl(regs,				\
						 DRGN_REGISTER_NUMBER(reg),	\
						 DRGN_REGISTER_OFFSET(reg),	\
						 DRGN_REGISTER_SIZE(reg),	\
						 buf)

static inline void
drgn_register_state_set_range_from_buffer_impl(struct drgn_register_state *regs,
					       drgn_register_number first_regno,
					       drgn_register_number last_regno,
					       size_t first_reg_offset,
					       size_t last_reg_end,
					       const void *buf)
{
	memcpy(&regs->buf[first_reg_offset], buf,
	       last_reg_end - first_reg_offset);
	drgn_register_state_set_has_register_range(regs, first_regno, last_regno);
}

/**
 * Set the values of a range of adjacent registers in a @ref drgn_register_state
 * from a buffer and mark them as known.
 *
 * @param[in] first_reg Identifier of first register to set (inclusive). Number
 * must be less than or equal to number of @p last_reg.
 * @param[in] last_reg Identifier of last register to set (inclusive). Number
 * must be less than @ref drgn_register_state::num_regs.
 */
#define drgn_register_state_set_range_from_buffer(regs, first_reg, last_reg, buf)	\
	drgn_register_state_set_range_from_buffer_impl(regs,				\
						       DRGN_REGISTER_NUMBER(first_reg),	\
						       DRGN_REGISTER_NUMBER(last_reg),	\
						       DRGN_REGISTER_OFFSET(first_reg),	\
						       DRGN_REGISTER_END(last_reg),	\
						       buf)

static inline void
drgn_register_state_set_from_integer_impl(struct drgn_program *prog,
					  struct drgn_register_state *regs,
					  drgn_register_number regno,
					  size_t reg_offset, size_t reg_size,
					  uint64_t value)
{
	copy_lsbytes(&regs->buf[reg_offset], reg_size,
		     drgn_platform_is_little_endian(&prog->platform), &value,
		     sizeof(value), HOST_LITTLE_ENDIAN);
	drgn_register_state_set_has_register(regs, regno);
}

/**
 * Set the value of a register in a @ref drgn_register_state from a `uint64_t`
 * and mark it as known.
 *
 * If the register is smaller than 8 bytes, then the value is truncated to the
 * least significant bytes. If it is larger, then the value is zero-extended.
 *
 * @param[in] reg Identifier of register to set. Number must be less than @ref
 * drgn_register_state::num_regs.
 */
#define drgn_register_state_set_from_integer(prog, regs, reg, value)		\
	drgn_register_state_set_from_integer_impl(prog, regs,			\
						  DRGN_REGISTER_NUMBER(reg),	\
						  DRGN_REGISTER_OFFSET(reg),	\
						  DRGN_REGISTER_SIZE(reg),	\
						  value)

/** @} */

#endif /* DRGN_REGISTER_STATE_H */
