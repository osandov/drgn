// Copyright 2019-2020 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#ifndef DRGN_STACK_TRACE_H
#define DRGN_STACK_TRACE_H

#include <elfutils/libdwfl.h>

struct drgn_stack_frame {
	Dwfl_Frame *state;
};

struct drgn_stack_trace {
	struct drgn_program *prog;
	union {
		Dwfl_Thread *thread;
		/* Used during creation. */
		int capacity;
	};
	int num_frames;
	struct drgn_stack_frame frames[];
};

#endif /* DRGN_STACK_TRACE_H */
