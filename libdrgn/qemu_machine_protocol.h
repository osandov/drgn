// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * QEMU Machine Protocol (QMP) support.
 */

#ifndef DRGN_QEMU_MACHINE_PROTOCOL_H
#define DRGN_QEMU_MACHINE_PROTOCOL_H

#include <stddef.h>

#include "string_builder.h"

#ifdef WITH_JSON_C
struct drgn_qmp_conn {
	int fd;
	struct string_builder read_buf;
	struct string_builder write_buf;
	struct json_tokener *json_tok;
	struct drgn_qemu_process_mem_segment *process_mem_segments;
};

static inline void drgn_qmp_conn_init(struct drgn_qmp_conn *conn)
{
	conn->fd = -1;
	conn->read_buf = (struct string_builder)STRING_BUILDER_INIT;
	conn->write_buf = (struct string_builder)STRING_BUILDER_INIT;
	conn->json_tok = NULL;
	conn->process_mem_segments = NULL;
}

void drgn_qmp_conn_deinit(struct drgn_qmp_conn *conn);
#else
struct drgn_qmp_conn {};

static inline void drgn_qmp_conn_init(struct drgn_qmp_conn *conn) {}
static inline void drgn_qmp_conn_deinit(struct drgn_qmp_conn *conn) {}
#endif

#endif /* DRGN_QEMU_MACHINE_PROTOCOL_H */
