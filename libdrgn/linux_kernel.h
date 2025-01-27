// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef DRGN_LINUX_KERNEL_H
#define DRGN_LINUX_KERNEL_H

#include "drgn_internal.h"

struct drgn_debug_info_options;
struct drgn_standard_debug_info_find_state;

struct drgn_error *drgn_program_finish_set_kernel(struct drgn_program *prog);

struct drgn_error *read_memory_via_pgtable(void *buf, uint64_t address,
					   size_t count, uint64_t offset,
					   void *arg, bool physical);

struct drgn_error *drgn_program_parse_vmcoreinfo(struct drgn_program *prog,
						 const char *desc,
						 size_t descsz);

struct drgn_error *proc_kallsyms_symbol_addr(const char *name,
					     unsigned long *ret);

struct drgn_error *read_vmcoreinfo_fallback(struct drgn_program *prog);

struct drgn_error *
linux_kernel_loaded_module_iterator_create(struct drgn_program *prog,
					   struct drgn_module_iterator **ret);

struct drgn_error *
drgn_module_try_vmlinux_files(struct drgn_module *module,
			      const struct drgn_debug_info_options *options);

struct drgn_error *
drgn_module_try_linux_kmod_files(struct drgn_module *module,
				 const struct drgn_debug_info_options *options,
				 struct drgn_standard_debug_info_find_state *state);

#define KDUMP_SIGNATURE "KDUMP   "
#define KDUMP_SIG_LEN (sizeof(KDUMP_SIGNATURE) - 1)

#define FLATTENED_SIGNATURE "makedumpfile"
#define FLATTENED_SIG_LEN (sizeof(FLATTENED_SIGNATURE) - 1)

#ifdef WITH_LIBKDUMPFILE
struct drgn_error *drgn_program_cache_kdump_threads(struct drgn_program *prog);
struct drgn_error *drgn_program_set_kdump(struct drgn_program *prog);
#else
static inline struct drgn_error *
drgn_program_set_kdump(struct drgn_program *prog)
{
        return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
				 "drgn was built without libkdumpfile support");
}
#endif

#endif /* DRGN_LINUX_KERNEL_H */
