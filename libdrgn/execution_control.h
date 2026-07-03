// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef DRGN_EXECUTION_CONTROL_H
#define DRGN_EXECUTION_CONTROL_H

#include "drgn_internal.h"
#include "handler.h"

void drgn_program_init_execution_control(struct drgn_program *prog);
void drgn_program_deinit_execution_control(struct drgn_program *prog);
void drgn_program_clear_execution_control(struct drgn_program *prog);
int drgn_program_traverse_execution_control(struct drgn_program *prog,
	    int (*visit_thread)(struct drgn_thread *, void *),
	    int (*visit_breakpoint)(struct drgn_breakpoint *, void *),
	    int (*visit_breakpoint_site)(struct drgn_breakpoint_site *, void *),
	    void *arg);

struct drgn_error *drgn_program_ensure_epoll_fd(struct drgn_program *prog);

struct drgn_execution_controller {
	struct drgn_handler handler;
	struct drgn_execution_controller_ops ops;
	void *arg;
};

struct drgn_error *
drgn_execution_controller_init(struct drgn_program *prog,
			       struct drgn_execution_controller *controller);

static inline void
drgn_execution_controller_deinit(struct drgn_execution_controller *controller)
{
}

struct drgn_error *
drgn_execution_controller_check_change_enabled(struct drgn_program *prog,
					       bool multiple);

#endif /* DRGN_EXECUTION_CONTROL_H */
