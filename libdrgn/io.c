// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <errno.h>
#include <limits.h>
#include <unistd.h>

#include "cleanup.h"
#include "io.h"
#include "util.h"

ssize_t read_all(int fd, void *buf, size_t count)
{
	if (count > SSIZE_MAX) {
		errno = EINVAL;
		return -1;
	}
	size_t n = 0;
	while (n < count) {
		ssize_t r = read(fd, (char *)buf + n, count - n);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return r;
		} else if (r == 0) {
			break;
		}
		n += r;
	}
	return n;
}

ssize_t pread_all(int fd, void *buf, size_t count, off_t offset)
{
	if (count > SSIZE_MAX) {
		errno = EINVAL;
		return -1;
	}
	size_t n = 0;
	while (n < count) {
		ssize_t r = pread(fd, (char *)buf + n, count - n, offset + n);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return r;
		} else if (r == 0) {
			break;
		}
		n += r;
	}
	return n;
}

char *fd_canonical_path(int fd, const char *path)
{
#define FORMAT "/proc/self/fd/%d"
	char fd_path[sizeof(FORMAT)
		     - (sizeof("%d") - 1)
		     + max_decimal_length(int)];
	snprintf(fd_path, sizeof(fd_path), FORMAT, fd);
#undef FORMAT

	size_t buf_size = PATH_MAX;
	_cleanup_free_ char *buf = malloc(buf_size);
	if (!buf)
		return NULL;

	for (;;) {
		ssize_t r = readlink(fd_path, buf, buf_size);
		if (r < 0) {
			if (!path)
				return strdup(fd_path);
			char *real = realpath(path, NULL);
			if (real)
				return real;
			return strdup(path);
		}

		if (r < buf_size) {
			buf[r] = '\0';
			// The path is likely to be much smaller than PATH_MAX,
			// so try shrinking it.
			if (r + 1 < buf_size) {
				char *tmp = realloc(buf, r + 1);
				if (tmp)
					buf = tmp;
			}
			return_ptr(buf);
		}

		if (__builtin_mul_overflow(buf_size, 2U, &buf_size))
			return NULL;
		free(buf);
		buf = malloc(buf_size);
		if (!buf)
			return NULL;
	}
}
