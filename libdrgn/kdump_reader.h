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
 * See @ref KdumpReader.
 */

#ifndef DRGN_KDUMP_READER_H
#define DRGN_KDUMP_READER_H

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
bool has_kdump_signature(int fd, struct drgn_error **err);

/** Create a kdump-context from the given file descriptor */
struct drgn_error *drgn_kdump_init(kdump_ctx_t **ctx, int fd);

/** Clean up all kdump-related metadata. */
void drgn_kdump_close(kdump_ctx_t *ctx);

/**
 * Get the offset of the kernel binary from the kdump file.
 *
 * @param[in] ctx Kdump context.
 * @param[out] offset kernel offset within the image.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_kdump_get_kernel_offset(kdump_ctx_t *ctx,
                                                uint64_t *offset);

/**
 * Get the osrelease attribute (e.g. `uname -r`) from the kdump file.
 *
 * @param[in] ctx Kdump context.
 * @param[out] osrelease (e.g. "4.15.0-50-generic").
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_kdump_get_osrelease(kdump_ctx_t *ctx,
                                            char *osrelease);

/**
 * Get the page size for contents of the given kdump file.
 *
 * @param[in] ctx Kdump context.
 * @param[out] page_size Page size.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_kdump_get_page_size(kdump_ctx_t *ctx,
                                            uint64_t *page_size);

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

#endif /* DRGN_KDUMP_READER_H */
