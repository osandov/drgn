// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * Input/output helpers.
 */

#ifndef DRGN_IO_H
#define DRGN_IO_H

#include <stddef.h>
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

/**
 * Get the canonical path of a file descriptor.
 *
 * This returns the first of the following that succeeds:
 *
 * 1. `readlink("/proc/self/fd/{fd}")`
 * 2. `realpath(path)` if @p path is not @c NULL
 * 3. `"/proc/self/fd/{fd}"` if @p path is @c NULL, `path` otherwise
 *
 * @return Returned path, or @c NULL if memory could not be allocated. On
 * success, must be freed with @c free().
 */
char *fd_canonical_path(int fd, const char *path);

#endif /* DRGN_IO_H */
