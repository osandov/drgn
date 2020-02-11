// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#ifndef DRGN_LINUX_KERNEL_H
#define DRGN_LINUX_KERNEL_H

#include <elfutils/libdwfl.h>

#include "drgn.h"

struct drgn_dwarf_index;
struct drgn_memory_reader;
struct vmcoreinfo;

struct drgn_error *parse_vmcoreinfo(const char *desc, size_t descsz,
				    struct vmcoreinfo *ret);

struct drgn_error *read_vmcoreinfo_fallback(struct drgn_memory_reader *reader,
					    bool have_non_zero_phys_addr,
					    struct vmcoreinfo *ret);

struct drgn_error *
vmcoreinfo_object_find(const char *name, size_t name_len, const char *filename,
		       enum drgn_find_object_flags flags, void *arg,
		       struct drgn_object *ret);

struct drgn_error *
linux_kernel_report_debug_info(struct drgn_program *prog,
			       struct drgn_dwarf_index *dindex,
			       const char **paths, size_t n,
			       bool report_default, bool report_main);

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
