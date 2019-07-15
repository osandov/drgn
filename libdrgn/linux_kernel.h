// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#ifndef DRGN_LINUX_KERNEL_H
#define DRGN_LINUX_KERNEL_H

#include <elfutils/libdwfl.h>

#include "drgn.h"

struct drgn_memory_reader;
struct vmcoreinfo;

struct drgn_error *parse_vmcoreinfo(const char *desc, size_t descsz,
				    struct vmcoreinfo *ret);

struct drgn_error *read_vmcoreinfo_fallback(struct drgn_memory_reader *reader,
					    bool have_non_zero_phys_addr,
					    struct vmcoreinfo *ret);

struct drgn_error *
linux_kernel_load_debug_info(struct drgn_program *prog, const char **paths,
			     size_t n);

struct drgn_error *
linux_kernel_load_default_debug_info(struct drgn_program *prog);

#endif /* DRGN_LINUX_KERNEL_H */
