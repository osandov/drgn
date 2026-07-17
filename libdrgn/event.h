// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef DRGN_EVENT_H
#define DRGN_EVENT_H

#include "drgn_internal.h"

struct drgn_event {
	enum drgn_event_type type;
	int exit_status;
	union {
		struct drgn_thread *thread;
		struct drgn_error *err;
	};
};

#endif /* DRGN_EVENT_H */
