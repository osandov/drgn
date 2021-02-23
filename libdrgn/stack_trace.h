// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * Stack trace internals
 *
 * See @ref StackTraceInternals.
 */

#ifndef DRGN_STACK_TRACE_H
#define DRGN_STACK_TRACE_H

#include <elfutils/libdwfl.h>
#include <stddef.h>

/**
 * @ingroup Internals
 *
 * @defgroup StackTraceInternals Stack traces
 *
 * Stack trace internals.
 *
 * This provides the internal data structures used for stack traces.
 *
 * @{
 */

struct drgn_stack_trace {
	struct drgn_program *prog;
	union {
		Dwfl_Thread *thread;
		/* Used during creation. */
		size_t capacity;
	};
	size_t num_frames;
	Dwfl_Frame *frames[];
};

/** @} */

#endif /* DRGN_STACK_TRACE_H */
