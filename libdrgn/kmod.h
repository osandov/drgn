// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#ifndef DRGN_KMOD_H
#define DRGN_KMOD_H

#include "drgn.h"

struct kernel_module_iterator {
	char *name;
	FILE *file;
	union {
		size_t name_capacity;
		struct {
			struct drgn_qualified_type module_type;
			struct drgn_object mod, node, mod_name;
			uint64_t head;
		};
	};
};

struct drgn_error *
kernel_module_iterator_init(struct kernel_module_iterator *it,
			    struct drgn_program *prog);

void kernel_module_iterator_deinit(struct kernel_module_iterator *it);

/**
 * Get the name of the next loaded kernel module.
 *
 * After this is called, @c it->name is set to the name of the kernel module; it
 * is valid until the next time this is called or the iterator is destroyed.
 *
 * @return @c NULL on success, non-@c NULL on error. In particular, when there
 * are no more modules, a @ref DRGN_ERROR_STOP error is returned.
 */
struct drgn_error *
kernel_module_iterator_next(struct kernel_module_iterator *it);

struct drgn_error *kernel_module_section_address(struct drgn_program *prog,
						 const char *module_name,
						 const char *section_name,
						 uint64_t *ret);

#endif /* DRGN_KMOD_H */
