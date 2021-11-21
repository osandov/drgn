// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file
 *
 * Architecture register layout definitions.
 *
 * This file generates the definitions of @ref DRGN_REGISTER_NUMBER(), @ref
 * DRGN_REGISTER_OFFSET(), @ref DRGN_REGISTER_SIZE(), @ref DRGN_REGISTER_END(),
 * @ref register_layout, and @ref dwarf_regno_to_internal() for an architecture.
 *
 * This file is included by `arch_foo.inc`, so it doesn't need to be included
 * directly.
 */

#include <stddef.h>

#ifdef DOXYGEN

/**
 * Architecture definition of register layout in a @ref drgn_register_state.
 *
 * Before including `arch_register_layout.h`, this should be defined as a list
 * of calls to @ref DRGN_REGISTER_LAYOUT(). The defined registers are laid out
 * sequentially. To minimize memory usage, registers can be ordered by how
 * commonly they are saved (typically, the program counter/return address
 * register first, then the stack pointer register, then callee-saved registers,
 * and last caller-saved registers). They can also be ordered to match the
 * format in, e.g., `NT_PRSTATUS`.
 */
#define DRGN_ARCH_REGISTER_LAYOUT	\
	DRGN_REGISTER_LAYOUT(pc, 8, 32)	\
	DRGN_REGISTER_LAYOUT(sp, 8, 33)	\
	DRGN_REGISTER_LAYOUT(r0, 8, 0)	\
	DRGN_REGISTER_LAYOUT(r1, 8, 1)	\
	...

/**
 * Definition of a register in @ref DRGN_ARCH_REGISTER_LAYOUT.
 *
 * @param[in] id Register identifier.
 * @param[in] size Size of register in bytes.
 * @param[in] dwarf_number DWARF register number defined by ABI.
 */
#define DRGN_REGISTER_LAYOUT(id, size, dwarf_number)

#else

enum {
#define DRGN_REGISTER_LAYOUT(id, size, dwarf_number) DRGN_REGISTER_NUMBER__##id,
DRGN_ARCH_REGISTER_LAYOUT
#undef DRGN_REGISTER_LAYOUT
};

struct drgn_arch_register_layout {
#define DRGN_REGISTER_LAYOUT(id, size, dwarf_number) char id[size];
DRGN_ARCH_REGISTER_LAYOUT
#undef DRGN_REGISTER_LAYOUT
};

#endif

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

/** Register layouts indexed by internal register number. */
static const struct drgn_register_layout register_layout[]
#ifndef DOXYGEN
= {
#define DRGN_REGISTER_LAYOUT(id, size, dwarf_number)	\
	{ DRGN_REGISTER_OFFSET(id), DRGN_REGISTER_SIZE(id) },
DRGN_ARCH_REGISTER_LAYOUT
#undef DRGN_REGISTER_LAYOUT
}
#endif
;

/**
 * Return the internal register number for the given DWARF register number, or
 * @ref DRGN_REGISTER_NUMBER_UNKNOWN if it is not recognized.
 */
static drgn_register_number dwarf_regno_to_internal(uint64_t dwarf_regno)
{
#ifndef DOXYGEN
	switch (dwarf_regno) {
#define DRGN_REGISTER_LAYOUT(id, size, dwarf_number)	\
	case dwarf_number: return DRGN_REGISTER_NUMBER(id);
DRGN_ARCH_REGISTER_LAYOUT
#undef DRGN_REGISTER_LAYOUT
	default:
		return DRGN_REGISTER_NUMBER_UNKNOWN;
	}
#endif
}
