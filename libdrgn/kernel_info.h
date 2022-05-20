// Copyright (c) 2022 Oracle and/or its affiliates
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DRGN_KERNEL_INFO_H
#define DRGN_KERNEL_INFO_H

struct kallsyms_registry;
struct drgn_program;

/**
 * @ingroup Internals
 *
 * @defgroup KernelInfo Linux Kernel specific debug info
 *
 * @{
 */

/**
 * Holds kernel internal debug information
 *
 * This structure contains any internal information for the Linux kernel which
 * can be used to provide similar information as DWARF info. It can be used when
 * no DWARF info is available to provide symbol information.
 */
struct kernel_info {
	struct kallsyms_registry *kallsyms;
};

/**
 * Load debugging information from within the program itself (Linux only)
 *
 * The Linux kernel can contain enough information to do some simple debugging
 * tasks. If other sources of debug info fail, we can try to find this info
 * and load it.
 */
struct drgn_error *drgn_program_load_kernel_info(struct drgn_program *prog);

/** @} */

#endif // DRGN_KERNEL_INFO_H
