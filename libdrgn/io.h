// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * Input/output helpers.
 */

#ifndef DRGN_IO_H
#define DRGN_IO_H

#include <sys/types.h>

/**
 * Wrapper around \manpage{read,2} that never returns less bytes than requested unless it
 * hits end-of-file.
 */
ssize_t read_all(int fd, void *buf, size_t count);

/**
 * Wrapper around \manpage{pread,2} that never returns less bytes than requested unless
 * it hits end-of-file.
 */
ssize_t pread_all(int fd, void *buf, size_t count, off_t offset);

#endif /* DRGN_IO_H */
