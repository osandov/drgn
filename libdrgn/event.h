// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef DRGN_EVENT_H
#define DRGN_EVENT_H

#include "drgn_internal.h"

struct drgn_event {
	enum drgn_event_type type;
};

struct drgn_thread_event {
	struct drgn_event event;
	struct drgn_thread *thread;
};

struct drgn_program_exit_event {
	struct drgn_event event;
	int status;
};

struct drgn_thread_exit_event {
	struct drgn_thread_event thread_event;
	int status;
};

struct drgn_thread_signal_event {
	struct drgn_thread_event thread_event;
	int signal;
};

struct drgn_breakpoint_event {
	struct drgn_thread_signal_event signal_event;
	struct drgn_breakpoint_site *site;
};

#define DRGN_EVENT_TYPES				\
	X(program_exit, PROGRAM_EXIT, ProgramExit)	\
	X(thread_exit, THREAD_EXIT, ThreadExit)		\
	X(thread_signal, THREAD_SIGNAL, ThreadSignal)	\
	X(breakpoint, BREAKPOINT, Breakpoint)

#define X(type_, TYPE, Type)						\
struct drgn_##type_##_event *drgn_##type_##_event_alloc(void);		\
void drgn_##type_##_event_deinit(struct drgn_##type_##_event *event);
DRGN_EVENT_TYPES
#undef X

#endif /* DRGN_EVENT_H */
