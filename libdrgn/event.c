// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "event.h"
#include "util.h"

LIBDRGN_PUBLIC enum drgn_event_type drgn_event_type(struct drgn_event *event)
{
	return event->type;
}

static const char *drgn_event_type_name(enum drgn_event_type type)
{
	SWITCH_ENUM(type) {
	case DRGN_EVENT_PROGRAM_EXIT:
		return "program exit";
	case DRGN_EVENT_THREAD_EXIT:
		return "thread exit";
	case DRGN_EVENT_THREAD_STOP:
		return "thread stop";
	default:
		UNREACHABLE();
	}
}

#define CHECK_EVENT_MEMBER(member, member_name)					\
do {										\
	if (!drgn_event_type_has_##member(event->type)) {			\
		return drgn_error_format(DRGN_ERROR_TYPE,			\
					 "%s event does not have " member_name,	\
					 drgn_event_type_name(event->type));	\
	}									\
} while (0)

LIBDRGN_PUBLIC
struct drgn_error *drgn_event_exit_status(struct drgn_event *event, int *ret)
{
	CHECK_EVENT_MEMBER(exit_status, "exit status");
	*ret = event->exit_status;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_event_thread(struct drgn_event *event, struct drgn_thread **ret)
{
	CHECK_EVENT_MEMBER(thread, "thread");
	*ret = event->thread;
	return NULL;
}
