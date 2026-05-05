// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef DRGN_THREAD_H
#define DRGN_THREAD_H

#include "drgn_internal.h"
#include "handler.h"
#include "hash_table.h"

#define _cleanup_thread_	\
	__attribute__((__cleanup__(drgn_thread_decrefp)))

static inline void drgn_thread_decrefp(struct drgn_thread **threadp)
{
	drgn_thread_decref(*threadp);
}

struct drgn_thread *drgn_thread_alloc(struct drgn_program *prog);

static inline void drgn_thread_init(struct drgn_thread *thread,
				    struct drgn_program *prog)
{
	drgn_object_init(&thread->object, prog);
}

void drgn_thread_deinit(struct drgn_thread *thread);

struct drgn_register_state_finder {
	struct drgn_handler handler;
	struct drgn_register_state_finder_ops ops;
	void *arg;
};

struct drgn_error *
drgn_register_state_finder_init(struct drgn_program *prog,
				struct drgn_register_state_finder *finder);

static inline void
drgn_register_state_finder_deinit(struct drgn_register_state_finder *finder) {}

DEFINE_HASH_TABLE_TYPE(drgn_thread_set, struct drgn_thread *);

struct drgn_thread_cache {
	struct drgn_program *prog;
	struct drgn_thread_set threads;
};

struct drgn_thread_finder {
	struct drgn_handler handler;
	struct drgn_thread_finder_ops ops;
	void *arg;
	struct drgn_thread_cache cache;
};

struct drgn_thread_iterator {
	struct drgn_thread_finder *finder;
	void *data;
};

struct drgn_error *drgn_thread_finder_init(struct drgn_program *prog,
					   struct drgn_thread_finder *finder);

void drgn_thread_finder_deinit(struct drgn_thread_finder *finder);

#endif /* DRGN_THREAD_H */
