// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file
 *
 * Call frame information
 *
 * See @ref CallFrameInformation.
 */

#ifndef DRGN_CFI_H
#define DRGN_CFI_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * @ingroup Internals
 *
 * @defgroup CallFrameInformation Call frame information
 *
 * Call frame information for stack unwinding.
 *
 * This defines a generic representation for Call Frame Information (CFI), which
 * describes how to determine the Canonical Frame Address (CFA) and previous
 * register values while unwinding a stack trace.
 *
 * @{
 */

/**
 * Numeric identifier for a register.
 *
 * These are only unique within an architecture, and they are not necessarily
 * the same as the register numbers used by DWARF.
 */
typedef uint16_t drgn_register_number;

/** Maximum valid register number. */
#define DRGN_MAX_REGISTER_NUMBER ((drgn_register_number)-3)
/** Placeholder number for unknown register. */
#define DRGN_REGISTER_NUMBER_UNKNOWN ((drgn_register_number)-1)

/** Kinds of CFI rules. */
enum drgn_cfi_rule_kind {
	/** Register value in the caller is not known. */
	DRGN_CFI_RULE_UNDEFINED,
	/**
	 * Register value in the caller is stored at the CFA in the current
	 * frame plus an offset: `*(cfa + offset)`.
	 */
	DRGN_CFI_RULE_AT_CFA_PLUS_OFFSET,
	/**
	 * Register value in the caller is the CFA in the current frame plus an
	 * offset: `cfa + offset`.
	 */
	DRGN_CFI_RULE_CFA_PLUS_OFFSET,
	/**
	 * Register value in the caller is stored at the value of a register in
	 * the current frame plus an offset: `*(reg + offset)`.
	 */
	DRGN_CFI_RULE_AT_REGISTER_PLUS_OFFSET,
	/**
	 * Register value in the caller is an offset plus the value stored at
	 * the value of a register in the current frame: `(*reg) + offset`.
	 */
	DRGN_CFI_RULE_AT_REGISTER_ADD_OFFSET,
	/**
	 * Register value in the caller is the value of a register in the
	 * current frame plus an offset: `reg + offset`.
	 *
	 * Note that this can also be used to represent DWARF's "same value"
	 * rule by using the same register with an offset of 0.
	 */
	DRGN_CFI_RULE_REGISTER_PLUS_OFFSET,
	/**
	 * Register value in the caller is stored at the address given by a
	 * DWARF expression.
	 */
	DRGN_CFI_RULE_AT_DWARF_EXPRESSION,
	/** Register value in the caller is given by a DWARF expression. */
	DRGN_CFI_RULE_DWARF_EXPRESSION,
} __attribute__((__packed__));

/** Rule for determining a single register value or CFA. */
struct drgn_cfi_rule {
	/** Rule kind. */
	enum drgn_cfi_rule_kind kind;
	/**
	 * Whether to push the CFA before evaluating the DWARF
	 * expression for @ref DRGN_CFI_RULE_AT_DWARF_EXPRESSION or @ref
	 * DRGN_CFI_RULE_DWARF_EXPRESSION.
	 */
	bool push_cfa;
	/** Register number for @ref DRGN_CFI_RULE_REGISTER_PLUS_OFFSET. */
	drgn_register_number regno;
	union {
		/**
		 * Offset for @ref DRGN_CFI_RULE_AT_CFA_PLUS_OFFSET, @ref
		 * DRGN_CFI_RULE_CFA_PLUS_OFFSET, @ref
		 * DRGN_CFI_RULE_AT_REGISTER_PLUS_OFFSET, and @ref
		 * DRGN_CFI_RULE_AT_REGISTER_ADD_OFFSET,
		 * DRGN_CFI_RULE_REGISTER_PLUS_OFFSET, @ref
		 */
		int64_t offset;
		/**
		 * DWARF expression for @ref DRGN_CFI_RULE_AT_DWARF_EXPRESSION
		 * and @ref DRGN_CFI_RULE_DWARF_EXPRESSION.
		 */
		struct {
			/** Pointer to expression data. */
			const char *expr;
			/** Size of @ref drgn_cfi_rule::expr. */
			size_t expr_size;
		};
	};
};

/**
 * "Row" of call frame information, i.e., how to get the CFA and the previous
 * value of each register at a single location in the program.
 *
 * A row may be allocated statically or on the heap. Static rows are created
 * with @ref DRGN_CFI_ROW(). The first time a static row would be modified (with
 * @ref drgn_cfi_row_copy(), @ref drgn_cfi_row_set_cfa(), or @ref
 * drgn_cfi_row_set_register()), it is first copied to the heap. Subsequent
 * modifications reuse the heap allocation, growing it if necessary. The
 * allocation must be freed with @ref drgn_cfi_row_destroy().
 */
struct drgn_cfi_row {
	/**
	 * Number of rules allocated, including the CFA rule.
	 *
	 * If the row is statically allocated, then this is zero, even if
	 * `num_regs` is non-zero. Otherwise, it is at least `num_regs + 1`.
	 */
	uint16_t allocated_rules;
	/** Number of initialized elements in `reg_rules`. */
	uint16_t num_regs;
	/** Canonical Frame Address rule. */
	struct drgn_cfi_rule cfa_rule;
	/** Register rules. */
	struct drgn_cfi_rule reg_rules[];
};

/**
 * Initializer for a static @ref drgn_cfi_row given initializers for @ref
 * drgn_cfi_row::reg_rules.
 */
#define DRGN_CFI_ROW(...) {						\
	.num_regs = (sizeof((struct drgn_cfi_rule []){ __VA_ARGS__ })	\
		     / sizeof(struct drgn_cfi_rule)),			\
	.reg_rules = { __VA_ARGS__ },					\
}

/**
 * Initializer for a rule in @ref drgn_cfi_row::reg_rules specifying that the
 * register with the given number has the same value in the caller.
 */
#define DRGN_CFI_SAME_VALUE_INIT(number)			\
	[(number)] = {						\
		.kind = DRGN_CFI_RULE_REGISTER_PLUS_OFFSET,	\
		.regno = (number),				\
	}

extern const struct drgn_cfi_row drgn_empty_cfi_row_impl;
/**
 * Static @ref drgn_cfi_row with all rules set to @ref DRGN_CFI_RULE_UNDEFINED.
 */
#define drgn_empty_cfi_row ((struct drgn_cfi_row *)&drgn_empty_cfi_row_impl)

/** Free a @ref drgn_cfi_row. */
static inline void drgn_cfi_row_destroy(struct drgn_cfi_row *row)
{
	if (row->allocated_rules > 0)
		free(row);
}

/** Copy the rules from one @ref drgn_cfi_row to another. */
bool drgn_cfi_row_copy(struct drgn_cfi_row **dst,
		       const struct drgn_cfi_row *src);

/**
 * Get the rule for the Canonical Frame Address in a @ref drgn_cfi_row.
 *
 * @param[out] ret Returned rule.
 */
static inline void drgn_cfi_row_get_cfa(const struct drgn_cfi_row *row,
					struct drgn_cfi_rule *ret)
{
	*ret = row->cfa_rule;
}

/**
 * Set the rule for the Canonical Frame Address in a @ref drgn_cfi_row.
 *
 * @param[in] rule Rule to set to.
 * @return @c true on success, @c false on failure to allocate memory.
 */
bool drgn_cfi_row_set_cfa(struct drgn_cfi_row **row,
			  const struct drgn_cfi_rule *rule);

/**
 * Get the rule for a register in a @ref drgn_cfi_row.
 *
 * @param[in] regno Register number.
 */
void drgn_cfi_row_get_register(const struct drgn_cfi_row *row,
			       drgn_register_number regno,
			       struct drgn_cfi_rule *ret);

/**
 * Set the rule for a register in a @ref drgn_cfi_row.
 *
 * @param[in] regno Register number.
 * @param[in] rule Rule to set to.
 * @return @c true on success, @c false on failure to allocate memory.
 */
bool drgn_cfi_row_set_register(struct drgn_cfi_row **row,
			       drgn_register_number regno,
			       const struct drgn_cfi_rule *rule);

/** @} */

#endif /* DRGN_CFI_H */
