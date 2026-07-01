// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

// Fallback implementations for builds without Python support.

#include "breakpoint.h"
#include "drgn_internal.h"
#include "error.h"
#include "plugins.h"
#include "program.h"
#include "register_state.h"
#include "thread.h"
#include "util.h"

void drgn_error_resolve(struct drgn_error *err)
{
}

void drgn_error_python_exc_decref(void *python_exc)
{
}

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

struct drgn_error *
drgn_end_blocking_and_check_signals(drgn_blocking_state state) // TODO
{
	return NULL;
}

// drgn_program is currently only reference-counted in Python builds.
void drgn_program_incref(struct drgn_program *prog) {}
void drgn_program_decref(struct drgn_program *prog) {}

struct drgn_refcount {
	// Saturates and leaks at SIZE_MAX.
	size_t counter;
};

static inline void drgn_refcount_init(struct drgn_refcount *rc)
{
	rc->counter = 1;
}

static inline void drgn_refcount_inc(struct drgn_refcount *rc)
{
	if (rc->counter < SIZE_MAX)
		rc->counter++;
}

static inline bool drgn_refcount_dec(struct drgn_refcount *rc)
{
	return rc->counter != SIZE_MAX && --rc->counter == 0;
}

// Define fallback reference counting functions for the given type for builds
// without Python support.
#define DEFINE_REFCOUNT_WRAPPER(type)						\
DEFINE_REFCOUNT_WRAPPER_ALLOC(type)					\
										\
LIBDRGN_PUBLIC void type##_incref(struct type *x)				\
{										\
	struct type##_refcount *rc = container_of(x, struct type##_refcount, x);\
	drgn_refcount_inc(&rc->refcount);					\
}										\
										\
LIBDRGN_PUBLIC void type##_decref(struct type *x)				\
{										\
	if (!x)									\
		return;								\
	struct type##_refcount *rc = container_of(x, struct type##_refcount, x);\
	if (!drgn_refcount_dec(&rc->refcount))					\
		return;								\
	type##_deinit(x);							\
	free(rc);								\
}

// TODO: this doesn't need to be separate anymore.
#define DEFINE_REFCOUNT_WRAPPER_ALLOC(type)			\
struct type##_refcount {					\
	struct drgn_refcount refcount;				\
	struct type x;						\
};								\
								\
struct type *type##_alloc(void)					\
{								\
	struct type##_refcount *rc = calloc(1, sizeof(*rc));	\
	if (!rc)						\
		return NULL;					\
	drgn_refcount_init(&rc->refcount);			\
	return &rc->x;						\
}

DEFINE_REFCOUNT_WRAPPER(drgn_breakpoint)
DEFINE_REFCOUNT_WRAPPER(drgn_breakpoint_site)
DEFINE_REFCOUNT_WRAPPER(drgn_register_state)
DEFINE_REFCOUNT_WRAPPER(drgn_thread)
