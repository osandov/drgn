// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

// Fallback implementations for builds without Python support.

#include "plugins.h"
#include "program.h"

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_create(const struct drgn_platform *platform,
		    struct drgn_program **ret)
{
	struct drgn_program *prog = malloc(sizeof(*prog));
	if (!prog)
		return &drgn_enomem;
	drgn_program_init(prog, platform);
	*ret = prog;
	return NULL;
}

LIBDRGN_PUBLIC void drgn_program_destroy(struct drgn_program *prog)
{
	if (prog) {
		drgn_program_deinit(prog);
		free(prog);
	}
}

void drgn_call_plugins_prog(const char *name, struct drgn_program *prog)
{
}

void *drgn_begin_blocking(void)
{
	return NULL;
}

void drgn_end_blocking(void *state)
{
}
