// Copyright (c) Daniel Thompson <daniel@redfelineninja.org.uk>
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * gdbremote protocol implementation.
 *
 * See @ref GdbRemote.
 */

#ifndef DRGN_GDBREMOTE_H
#define DRGN_GDBREMOTE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * @ingroup Internals
 *
 * @defgroup GdbRemote gdbremote protocol
 *
 * gdbremote protocol implementation.
 *
 * @{
 */

/**
 * Connect to a gdbremote server or debug stub.
 *
 * Supported connecting strings include:
 *
 *  * 127.0.0.1:2345
 *
 * @param[in] conn gdb connection string
 * @param[out] ret File descriptor for the gdbremote connection
 */
struct drgn_error *drgn_gdbremote_connect(const char *conn, int *ret);

/** @ref drgn_memory_read_fn which reads using the gdbremote protocol. */
struct drgn_error *drgn_gdbremote_read_memory(void *buf, uint64_t address,
					      size_t count, uint64_t offset,
					      void *arg, bool physical);

/**
 * Fetch the register set from the gdbremote.
 *
 * The buffer provided in ret is formatted in an architecture specific manner
 * and, because it is dynamically allocated, must be freed by the caller.
 *
 * @param[in] conn_fd File descriptor for the gdbremote connection
 * @param[in] tid Thread identifier of the desired register set
 * @param[out] ret Allocated buffer containing decoded register values.
 */
struct drgn_error *drgn_gdbremote_get_registers(int conn_fd, uint32_t tid,
						void **regs_ret,
						size_t *reglen_ret);

/** @} */

#endif // DRGN_GDBREMOTE_H
