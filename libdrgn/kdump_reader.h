// Copyright 2019 - Serapheim Dimitropoulos
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * Makedumpfile format reader that implements the MemoryReader interface.
 *
 * Other implementation references:
 * - sourceforge.net/p/makedumpfile/code/ci/master/tree/IMPLEMENTATION
 * - github.com/ptesarik/libkdumpfile
 *
 * Note that this is only really used when --with-libkdumpfile=yes is
 * configured.
 *
 * See @ref KdumpReader.
 */

#ifndef DRGN_KDUMP_READER_H
#define DRGN_KDUMP_READER_H

#ifdef LIBKDUMPFILE
#include <stdbool.h>
#include <stdint.h>
#include <libkdumpfile/kdumpfile.h>

#include "internal.h"

/**
 * @ingroup Internals
 *
 * @defgroup KdumpReader kdump reader
 *
 * kdump reader implementation of the MemoryReader interface.
 *
 * @{
 */

#define	KDUMP_SIGNATURE	"KDUMP   "
#define	SIG_LEN	(sizeof (KDUMP_SIGNATURE) - 1)

/** Check contents from the file descriptor start with the KDUMP signature */
struct drgn_error *has_kdump_signature(int fd, bool *ret);

/** Create a kdump-context from the given file descriptor */
struct drgn_error *drgn_kdump_init(kdump_ctx_t **ctx, int fd);

/** Clean up all kdump-related metadata. */
void drgn_kdump_close(kdump_ctx_t *ctx);

/**
 * Get all the vmcoreinfo from the kdump in a single string.
 *
 * @param[in] ctx Kdump context.
 * @param[out] ret vmcore info.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_kdump_get_raw_vmcoreinfo(kdump_ctx_t *ctx,
                                                 const char **ret);

/**
 * Get the expected architecture flags from the kdump file.
 *
 * @param[in] ctx Kdump context.
 * @param[out] arch architecture flags.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_kdump_get_arch(kdump_ctx_t *ctx,
                                       enum drgn_architecture_flags *arch);

/** @ref drgn_memory_read_fn which reads from a kdump file. */
struct drgn_error *drgn_read_kdump(void *buf, uint64_t address, size_t count,
                                   uint64_t offset, void *arg, bool physical);

/** @} */
#endif /* LIBKDUMPFILE */

#endif /* DRGN_KDUMP_READER_H */
