// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * Register state internals.
 *
 * See @ref RegisterStateInternals.
 */

#ifndef DRGN_REGISTER_STATE_H
#define DRGN_REGISTER_STATE_H

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "cfi.h"
#include "drgn_internal.h"
#include "platform.h"
#include "program.h"
#include "serialize.h"
#include "util.h"

/**
 * @ingroup Internals
 *
 * @defgroup RegisterStateInternals Register states
 *
 * The external register state APIs take @ref drgn_register arguments.
 *
 * There are also internal APIs with names ending in `_id` taking register
 * identifiers as defined in an architecture definition file for use in the
 * corresponding architecture support file, as well as generic internal APIs
 * with names ending in `_internal` that take register numbers and layout
 * information.
 *
 * The external APIs automatically reallocate the register buffer as needed and
 * have additional safety checks (for a valid platform and that the register
 * state is not frozen). The internal APIs require that the register buffer is
 * pre-reserved and do not have safety checks.
 *
 * @{
 */

static inline void drgn_register_state_init(struct drgn_register_state *regs,
					    struct drgn_program *prog)
{
	regs->prog = prog;
}

static inline void drgn_register_state_deinit(struct drgn_register_state *regs)
{
	free(regs->buf);
}

/**
 * Return the internal register number of a register.
 *
 * @param[in] id Register identifier.
 */
#define DRGN_REGISTER_NUMBER(id) DRGN_REGISTER_NUMBER__##id

/**
 * Return the offset of a register in the register buffer.
 *
 * @param[in] id Register identifier.
 */
#define DRGN_REGISTER_OFFSET(id) offsetof(struct drgn_arch_register_layout, id)

/**
 * Return the size of a register in bytes.
 *
 * @param[in] id Register identifier.
 */
#define DRGN_REGISTER_SIZE(id) sizeof(((struct drgn_arch_register_layout *)0)->id)

/**
 * Return one past the last byte of a register in the register buffer.
 *
 * @param[in] id Register identifier.
 */
#define DRGN_REGISTER_END(id) (DRGN_REGISTER_OFFSET(id) + DRGN_REGISTER_SIZE(id))

#define _cleanup_register_state_	\
	__attribute__((__cleanup__(drgn_register_state_decrefp)))

static inline void drgn_register_state_decrefp(struct drgn_register_state **regsp)
{
	drgn_register_state_decref(*regsp);
}

bool drgn_register_state_is_known(const struct drgn_register_state *regs,
				  size_t i);

void drgn_register_state_set_known(struct drgn_register_state *regs, size_t i);

void drgn_register_state_unset_known(struct drgn_register_state *regs,
				     size_t i);

struct drgn_register_state *
drgn_register_state_alloc(struct drgn_program *prog);

/**
 * Like @ref drgn_register_state_create(), but can preallocate @ref
 * drgn_register_state::buf and the program must already have been checked to
 * have a platform.
 */
struct drgn_register_state *
drgn_register_state_create_internal(struct drgn_program *prog, bool interrupted,
				    size_t buf_capacity);

/**
 * Create a @ref drgn_register_state large enough to store up to and including a
 * given register.
 *
 * @param[in] last_reg Identifier of last register to reserve.
 * @return New register state on success, @c NULL on failure to allocate memory.
 */
#define drgn_register_state_create_id(prog, interrupted, last_reg)	\
	drgn_register_state_create_internal(prog, interrupted,		\
					    DRGN_REGISTER_END(last_reg))

/**
 * Like @ref drgn_register_state_get_u64() but takes the register number and
 * layout.
 */
struct drgn_optional_u64
drgn_register_state_get_u64_internal(struct drgn_register_state *regs,
				     drgn_register_number regno,
				     size_t reg_offset, size_t reg_size)
	__attribute__((__pure__));

/**
 * Like @ref drgn_register_state_set_pc() but doesn't check whether the state is
 * frozen.
 */
void drgn_register_state_set_pc_internal(struct drgn_register_state *regs,
					 uint64_t pc);

static inline void
drgn_register_state_set_pc_from_register_impl(struct drgn_register_state *regs,
					      drgn_register_number regno,
					      size_t reg_offset,
					      size_t reg_size)
{
	struct drgn_optional_u64 reg =
		drgn_register_state_get_u64_internal(regs, regno, reg_offset,
						     reg_size);
	assert(reg.has_value);
	drgn_register_state_set_pc_internal(regs, reg.value);
}

/**
 * Set the value of the program counter in a @ref drgn_register_state from the
 * value of a register.
 *
 * Doesn't check whether the state is frozen and requires that the register is
 * set.
 *
 * @param[in] reg Identifier of register to set from. Register must be set.
 */
#define drgn_register_state_set_pc_from_register_id(regs, reg)			\
	drgn_register_state_set_pc_from_register_impl(regs,			\
						      DRGN_REGISTER_NUMBER(reg),\
						      DRGN_REGISTER_OFFSET(reg),\
						      DRGN_REGISTER_SIZE(reg))

/** Like @ref drgn_register_state_is_set() but takes the register number. */
static inline bool
drgn_register_state_is_set_internal(const struct drgn_register_state *regs,
				    drgn_register_number regno)
{
	return drgn_register_state_is_known(regs, regno + 2);
}

/**
 * Like @ref drgn_register_state_get_u64() but takes the register identifier.
 *
 * @param[in] reg Identifier of register to get.
 */
#define drgn_register_state_get_u64_id(regs, reg)				\
	drgn_register_state_get_u64_internal(regs, DRGN_REGISTER_NUMBER(reg),	\
					     DRGN_REGISTER_OFFSET(reg),		\
					     DRGN_REGISTER_SIZE(reg))

/**
 * Mark a register as known in a @ref drgn_register_state.
 *
 * @param[in] regno Register number to mark as known.
 */
static inline void
drgn_register_state_set_register_known(struct drgn_register_state *regs,
				       drgn_register_number regno)
{
	drgn_register_state_set_known(regs, regno + 2);
}

/**
 * Mark a range of adjacent registers as known in a @ref drgn_register_state.
 *
 * @param[in] first_regno First register number to mark as known (inclusive).
 * Must be less than or equal to @p last_regno.
 * @param[in] last_regno Last register number to mark as known (inclusive).
 */
void
drgn_register_state_set_register_range_known(struct drgn_register_state *regs,
					     drgn_register_number first_regno,
					     drgn_register_number last_regno);

/**
 * Like @ref drgn_register_state_set_u64() but takes the register number and
 * layout, doesn't check whether the state is frozen, and requires that the
 * register was already reserved.
 */
static inline void
drgn_register_state_set_u64_internal(struct drgn_register_state *regs,
				     drgn_register_number regno,
				     size_t reg_offset, size_t reg_size,
				     uint64_t value)
{
	assert(reg_offset + reg_size <= regs->buf_capacity);
	copy_lsbytes(&regs->buf[reg_offset], reg_size,
		     drgn_platform_is_little_endian(&regs->prog->platform),
		     &value, sizeof(value), HOST_LITTLE_ENDIAN);
	drgn_register_state_set_register_known(regs, regno);
}

/**
 * Like @ref drgn_register_state_set_u64_internal() but takes the register
 * identifier.
 *
 * @param[in] reg Identifier of register to set.
 */
#define drgn_register_state_set_u64_id(regs, reg, value)			\
	drgn_register_state_set_u64_internal(regs, DRGN_REGISTER_NUMBER(reg),	\
					     DRGN_REGISTER_OFFSET(reg),		\
					     DRGN_REGISTER_SIZE(reg), value)

/**
 * Like @ref drgn_register_state_set_raw() but takes the register number and
 * layout, doesn't check whether the state is frozen, and requires that the
 * register was already reserved.
 */
static inline void
drgn_register_state_set_raw_internal(struct drgn_register_state *regs,
				     drgn_register_number regno,
				     size_t reg_offset, size_t reg_size,
				     const void *buf)
{
	assert(reg_offset + reg_size <= regs->buf_capacity);
	memcpy(&regs->buf[reg_offset], buf, reg_size);
	drgn_register_state_set_register_known(regs, regno);
}

/**
 * Like @ref drgn_register_state_set_raw_internal() but takes the register
 * identifier.
 *
 * @param[in] reg Identifier of register to set.
 */
#define drgn_register_state_set_raw_id(regs, reg, buf)				\
	drgn_register_state_set_raw_internal(regs, DRGN_REGISTER_NUMBER(reg),	\
					     DRGN_REGISTER_OFFSET(reg),		\
					     DRGN_REGISTER_SIZE(reg), buf)

static inline void
drgn_register_state_set_raw_range_impl(struct drgn_register_state *regs,
				       drgn_register_number first_regno,
				       drgn_register_number last_regno,
				       size_t first_reg_offset,
				       size_t last_reg_end, const void *buf)
{
	assert(last_reg_end <= regs->buf_capacity);
	memcpy(&regs->buf[first_reg_offset], buf,
	       last_reg_end - first_reg_offset);
	drgn_register_state_set_register_range_known(regs, first_regno,
						     last_regno);
}

/**
 * Set the values of a range of adjacent registers in a @ref drgn_register_state
 * from a buffer.
 *
 * Doesn't check whether the state is frozen and requires that the registers
 * were already reserved.
 *
 * @param[in] first_reg Identifier of first register to set (inclusive).
 * @param[in] last_reg Identifier of last register to set (inclusive).
 */
#define drgn_register_state_set_raw_range(regs, first_reg, last_reg, buf)	\
	drgn_register_state_set_raw_range_impl(regs,				\
					       DRGN_REGISTER_NUMBER(first_reg),	\
					       DRGN_REGISTER_NUMBER(last_reg),	\
					       DRGN_REGISTER_OFFSET(first_reg),	\
					       DRGN_REGISTER_END(last_reg), buf)

/**
 * Like @ref drgn_register_state_unset() but takes the register number and
 * doesn't check whether the state is frozen.
 */
static inline void
drgn_register_state_unset_internal(struct drgn_register_state *regs,
				   drgn_register_number regno)
{
	drgn_register_state_unset_known(regs, regno + 2);
}

/**
 * Like @ref drgn_register_state_unset_internal() but takes the register
 * identifier.
 */
#define drgn_register_state_unset_id(regs, reg)	\
	drgn_register_state_unset_internal(regs, DRGN_REGISTER_NUMBER(reg))

/**
 * Get the @ref drgn_module containing the program counter in a register state.
 */
struct drgn_module *
drgn_register_state_module(struct drgn_register_state *regs);

static inline void drgn_register_state_freeze(struct drgn_register_state *regs)
{
	// It may or may not be worth it to shrink the register buffer to fit in
	// the future.
	regs->frozen = true;
}

/** @} */

#endif /* DRGN_REGISTER_STATE_H */
