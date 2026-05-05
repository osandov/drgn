// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

// Fallback implementations for builds without Python support.

#include "drgn_internal.h"
#include "plugins.h"
#include "program.h"
#include "register_state.h"
#include "thread.h"
#include "util.h"

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

drgn_blocking_state drgn_begin_blocking(void)
{
	return NULL;
}

void drgn_end_blocking(drgn_blocking_state state)
{
}

struct drgn_error *
drgn_blocking_check_signals(drgn_blocking_state *statep)
{
	return NULL;
}

// Define fallback reference counting functions for the given type for builds
// without Python support.
#define DEFINE_REFCOUNT_WRAPPER(type)						\
struct type##_refcount {							\
	/* Saturates and leaks at SIZE_MAX. */					\
	size_t refcount;							\
	struct type x;								\
};										\
										\
struct type *type##_alloc(struct drgn_program *prog)				\
{										\
	struct type##_refcount *rc = calloc(1, sizeof(*rc));			\
	if (!rc)								\
		return NULL;							\
	rc->refcount = 1;							\
	type##_init(&rc->x, prog);						\
	return &rc->x;								\
}										\
										\
LIBDRGN_PUBLIC void type##_incref(struct type *x)				\
{										\
	struct type##_refcount *rc = container_of(x, struct type##_refcount, x);\
	if (rc->refcount < SIZE_MAX)						\
		rc->refcount++;							\
}										\
										\
LIBDRGN_PUBLIC void type##_decref(struct type *x)				\
{										\
	if (!x)									\
		return;								\
	struct type##_refcount *rc = container_of(x, struct type##_refcount, x);\
	if (rc->refcount == SIZE_MAX || --rc->refcount > 0)			\
		return;								\
	type##_deinit(x);							\
	free(rc);								\
}

DEFINE_REFCOUNT_WRAPPER(drgn_register_state)
DEFINE_REFCOUNT_WRAPPER(drgn_thread)
