// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef DRGN_BREAKPOINT_H
#define DRGN_BREAKPOINT_H

#include "drgn_internal.h"
#include "vector.h"

// One breakpoint per site is the common case, so pass inline_size as 1.
DEFINE_VECTOR_TYPE(drgn_breakpoint_vector, struct drgn_breakpoint *, 1);

struct drgn_breakpoint_site_node {
	// Node on site->enabled_breakpoints (if bp->enabled is true) or
	// site->disabled_breakpoints (if bp->enabled is false). Empty iff
	// breakpoint has been removed.
	struct list_head node;
	// Strong reference to breakpoint site.
	struct drgn_breakpoint_site *site;
	// Back pointer to breakpoint.
	struct drgn_breakpoint *bp;
};

struct drgn_breakpoint {
	struct drgn_program *prog;
	bool enabled;
	// Sites where this breakpoint is set. Immutable after creation. Even
	// when the breakpoint is removed, it holds references to its sites.
	struct drgn_breakpoint_site_node *site_nodes;
	size_t num_sites;
	// Node on prog->breakpoints. Empty iff breakpoint has been removed.
	struct list_head prog_node;
	void *data;
	void (*destroy_data)(void *);
};

struct drgn_breakpoint *drgn_breakpoint_alloc(void);

void drgn_breakpoint_deinit(struct drgn_breakpoint *bp);

struct drgn_breakpoint_site {
	struct drgn_program *prog;
	uint64_t address;
	bool hardware;
	// Lists of enabled and disabled breakpoints. References are borrowed
	// from prog->breakpoints. Both are empty iff all associated breakpoints
	// have been removed, at which point this site is also removed from
	// prog->breakpoint_sites.
	struct list_head enabled_breakpoints;
	struct list_head disabled_breakpoints;
	uint64_t lists_generation;
	void *controller_data;
	void (*destroy_controller_data)(void *);
};

struct drgn_breakpoint_site *drgn_breakpoint_site_alloc(void);

void drgn_breakpoint_site_deinit(struct drgn_breakpoint_site *site);

#define _cleanup_breakpoint_site_	\
	__attribute__((__cleanup__(drgn_breakpoint_site_decrefp)))

static inline void drgn_breakpoint_site_decrefp(struct drgn_breakpoint_site **sitep)
{
	drgn_breakpoint_site_decref(*sitep);
}

#endif /* DRGN_BREAKPOINT_H */
