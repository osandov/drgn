// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <stdlib.h>

#include "event.h"
#include "util.h"

LIBDRGN_PUBLIC
enum drgn_event_type drgn_event_type(const struct drgn_event *event)
{
	return event->type;
}

static inline struct drgn_thread *
drgn_thread_event_thread(const struct drgn_thread_event *event)
{
	return event->thread;
}

static void drgn_thread_event_deinit(struct drgn_thread_event *event)
{
	drgn_thread_decref(event->thread);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_exit_event_create(int status, struct drgn_program_exit_event **ret)
{
	struct drgn_program_exit_event *event = drgn_program_exit_event_alloc();
	if (!event)
		return &drgn_enomem;
	event->event.type = DRGN_EVENT_PROGRAM_EXIT;
	event->status = status;
	*ret = event;
	return NULL;
}

void drgn_program_exit_event_deinit(struct drgn_program_exit_event *event)
{
}

LIBDRGN_PUBLIC int
drgn_program_exit_event_status(const struct drgn_program_exit_event *event)
{
	return event->status;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_thread_exit_event_create(struct drgn_thread *thread, int status,
			      struct drgn_thread_exit_event **ret)
{
	struct drgn_thread_exit_event *event = drgn_thread_exit_event_alloc();
	if (!event)
		return &drgn_enomem;
	event->thread_event.event.type = DRGN_EVENT_THREAD_EXIT;
	drgn_thread_incref(thread);
	event->thread_event.thread = thread;
	event->status = status;
	*ret = event;
	return NULL;
}

void drgn_thread_exit_event_deinit(struct drgn_thread_exit_event *event)
{
	drgn_thread_event_deinit(&event->thread_event);
}

LIBDRGN_PUBLIC struct drgn_thread *
drgn_thread_exit_event_thread(const struct drgn_thread_exit_event *event)
{
	return drgn_thread_event_thread(&event->thread_event);
}

LIBDRGN_PUBLIC int
drgn_thread_exit_event_status(const struct drgn_thread_exit_event *event)
{
	return event->status;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_thread_signal_event_create(struct drgn_thread *thread, int signal,
				struct drgn_thread_signal_event **ret)
{
	if (signal <= 0) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "signal number must be positive");
	}
	struct drgn_thread_signal_event *event =
		drgn_thread_signal_event_alloc();
	if (!event)
		return &drgn_enomem;
	event->thread_event.event.type = DRGN_EVENT_THREAD_SIGNAL;
	drgn_thread_incref(thread);
	event->thread_event.thread = thread;
	event->signal = signal;
	*ret = event;
	return NULL;
}

void drgn_thread_signal_event_deinit(struct drgn_thread_signal_event *event)
{
	drgn_thread_event_deinit(&event->thread_event);
}

LIBDRGN_PUBLIC struct drgn_thread *
drgn_thread_signal_event_thread(const struct drgn_thread_signal_event *event)
{
	return drgn_thread_event_thread(&event->thread_event);
}

LIBDRGN_PUBLIC int
drgn_thread_signal_event_signal(const struct drgn_thread_signal_event *event)
{
	return event->signal;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_breakpoint_event_create(struct drgn_thread *thread, int signal,
			     struct drgn_breakpoint_site *site,
			     struct drgn_breakpoint_event **ret)
{
	if (signal <= 0) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "signal number must be positive");
	}
	struct drgn_breakpoint_event *event = drgn_breakpoint_event_alloc();
	if (!event)
		return &drgn_enomem;
	event->signal_event.thread_event.event.type = DRGN_EVENT_BREAKPOINT;
	drgn_thread_incref(thread);
	event->signal_event.thread_event.thread = thread;
	event->signal_event.signal = signal;
	drgn_breakpoint_site_incref(site);
	event->site = site;
	*ret = event;
	return NULL;
}

void drgn_breakpoint_event_deinit(struct drgn_breakpoint_event *event)
{
	drgn_thread_signal_event_deinit(&event->signal_event);
	drgn_breakpoint_site_decref(event->site);
}

LIBDRGN_PUBLIC struct drgn_thread *
drgn_breakpoint_event_thread(const struct drgn_breakpoint_event *event)
{
	return drgn_thread_event_thread(&event->signal_event.thread_event);
}

LIBDRGN_PUBLIC
int drgn_breakpoint_event_signal(const struct drgn_breakpoint_event *event)
{
	return drgn_thread_signal_event_signal(&event->signal_event);
}

LIBDRGN_PUBLIC struct drgn_breakpoint_site *
drgn_breakpoint_event_site(const struct drgn_breakpoint_event *event)
{
	return event->site;
}
