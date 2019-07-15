// Copyright 2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * ELF relocator.
 *
 * See @ref ElfRelocator.
 */

#ifndef DRGN_ELF_RELOCATOR_H
#define DRGN_ELF_RELOCATOR_H

#include <libelf.h>

#include "vector.h"

/**
 * @ingroup Internals.
 *
 * @defgroup ElfRelocator ELF relocator
 *
 * Fast ELF relocations.
 *
 * Before the debugging information in a relocatable ELF file (e.g., Linux
 * kernel module) can be used, it must have ELF relocations applied. This is
 * usually done by libdwfl. However, libdwfl is relatively slow at it. @ref
 * drgn_elf_relocator is a much faster, parallelized implementation of ELF
 * relocation. It is only implemented for x86-64; for other architectures, we
 * can fall back to libdwfl.
 */

DEFINE_VECTOR_TYPE(elf_vector, Elf *)

/**
 * ELF relocation interface.
 *
 * This interface is used to apply ELF relocations to debug sections in ELF
 * files.
 *
 * A relocator is initialized with @ref drgn_elf_relocator_init(). Files to be
 * relocated are added with @ref drgn_elf_relocator_add_elf(). Once all files
 * have been added, relocations are applied with @ref
 * drgn_elf_relocator_apply(). Finally, the relocator must be cleaned up with
 * @ref drgn_elf_relocator_deinit().
 */
struct drgn_elf_relocator {
	struct elf_vector elfs;
};

/** Initialize a @ref drgn_elf_relocator. */
void drgn_elf_relocator_init(struct drgn_elf_relocator *relocator);

/** Deinitialize a @ref drgn_elf_relocator. */
void drgn_elf_relocator_deinit(struct drgn_elf_relocator *relocator);

/**
 * Add an ELF file to be relocated by a @ref drgn_elf_relocator.
 *
 * If the ELF file is not relocatable or has an unsupported architecture, this
 * does nothing.
 */
struct drgn_error *
drgn_elf_relocator_add_elf(struct drgn_elf_relocator *relocator, Elf *elf);

/** Apply ELF relocations to all files added to a @ref drgn_elf_relocator. */
struct drgn_error *
drgn_elf_relocator_apply(struct drgn_elf_relocator *relocator);

#endif /* DRGN_ELF_RELOCATOR_H */
