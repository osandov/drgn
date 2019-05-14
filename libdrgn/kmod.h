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

struct kmod_index {
	const char *ptr, *end;
};

struct depmod_index {
	struct kmod_index modules_dep;
};

struct drgn_error *depmod_index_init(struct depmod_index *depmod,
				     const char *osrelease);

void depmod_index_deinit(struct depmod_index *depmod);

/*
 * Look up the path of the kernel module with the given name.
 *
 * @param[in] name Name of the kernel module.
 * @param[out] path_ret Returned path of the kernel module, relative to
 * /lib/modules/$(uname -r). This is @em not null-terminated.
 * @param[out] len_ret Returned length of @p path_ret.
 * @return Whether the module was found.
 */
bool depmod_index_find(struct depmod_index *depmod, const char *name,
		       const char **path_ret, size_t *len_ret);

#endif /* DRGN_KMOD_H */
