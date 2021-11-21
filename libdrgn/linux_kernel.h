// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DRGN_LINUX_KERNEL_H
#define DRGN_LINUX_KERNEL_H

#include "drgn.h"

struct drgn_debug_info_load_state;
struct vmcoreinfo;

struct drgn_error *read_memory_via_pgtable(void *buf, uint64_t address,
					   size_t count, uint64_t offset,
					   void *arg, bool physical);

struct drgn_error *parse_vmcoreinfo(const char *desc, size_t descsz,
				    struct vmcoreinfo *ret);

struct drgn_error *proc_kallsyms_symbol_addr(const char *name,
					     unsigned long *ret);

struct drgn_error *read_vmcoreinfo_fallback(struct drgn_program *prog);

struct drgn_error *linux_kernel_object_find(const char *name, size_t name_len,
					    const char *filename,
					    enum drgn_find_object_flags flags,
					    void *arg, struct drgn_object *ret);

struct drgn_error *
linux_kernel_report_debug_info(struct drgn_debug_info_load_state *load);

#define KDUMP_SIGNATURE "KDUMP   "
#define KDUMP_SIG_LEN (sizeof(KDUMP_SIGNATURE) - 1)

#ifdef WITH_LIBKDUMPFILE
struct drgn_error *drgn_program_cache_prstatus_kdump(struct drgn_program *prog);
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
