// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef DRGN_DEBUG_INFO_OPTIONS_H
#define DRGN_DEBUG_INFO_OPTIONS_H

#include "drgn_internal.h"

// X macro expanding to all debug info options.
#define DRGN_DEBUG_INFO_OPTIONS				\
	LIST_OPTION(directories)			\
	BOOL_OPTION(try_module_name, true)		\
	BOOL_OPTION(try_build_id, true)			\
	BOOL_OPTION(try_debug_link, true)		\
	BOOL_OPTION(try_procfs, true)			\
	BOOL_OPTION(try_embedded_vdso, true)		\
	BOOL_OPTION(try_reuse, true)			\
	BOOL_OPTION(try_supplementary, true)

struct drgn_debug_info_options {
#define LIST_OPTION(name) const char * const *name;
#define BOOL_OPTION(name, default_value) bool name;
#define ENUM_OPTION(name, type, default_value) enum type name;
	DRGN_DEBUG_INFO_OPTIONS
#undef ENUM_OPTION
#undef BOOL_OPTION
#undef LIST_OPTION
};

void drgn_debug_info_options_init(struct drgn_debug_info_options *options);
void drgn_debug_info_options_deinit(struct drgn_debug_info_options *options);

char *drgn_format_debug_info_options(struct drgn_debug_info_options *options);

#endif /* DRGN_DEBUG_INFO_OPTIONS_H */
