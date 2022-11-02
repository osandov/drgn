// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <errno.h>
#include <limits.h>
#include <unistd.h>

#include "io.h"

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
