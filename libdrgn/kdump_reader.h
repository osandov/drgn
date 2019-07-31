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

#include <stdbool.h>
#include <stdint.h>

#include "internal.h"

/**
 * @ingroup Internals
 *
 * @defgroup KdumpReader kdump reader
 *
 * Logic for setting up drgn for reading kdump crash dumps.
 *
 * @{
 */

#define	KDUMP_SIGNATURE	"KDUMP   "
#define	KDUMP_SIG_LEN	(sizeof (KDUMP_SIGNATURE) - 1)

#ifndef LIBKDUMPFILE

static inline struct drgn_error *
drgn_program_set_kdump(const struct drgn_program *prog)
{
        return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
	                         "drgn configured without libkdumpfile");
}

#else /* LIBKDUMPFILE */

/**
 * Setup program-related context leveraging libkdumpfile so
 * we are able to read from makedumpfile program dumps.
 *
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_set_kdump(struct drgn_program *prog);

#endif /* LIBKDUMPFILE */

/** @} */

#endif /* DRGN_KDUMP_READER_H */
