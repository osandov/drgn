// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * QEMU's 9pfs server passes through O_NOATIME from the client. If the server
 * process doesn't have permission to use O_NOATIME (e.g., because it's being
 * run without privileges and it doesn't own the file), then the open will fail.
 * Overlayfs uses O_NOATIME, so overlayfs on top of 9pfs doesn't work. We work
 * around this with this LD_PRELOAD hack to remove O_NOATIME from open() and
 * fcntl() calls.
 *
 * As of QEMU 5.1.0, the 9pfs server falls back to removing O_NOATIME, so this
 * isn't necessary on newer versions.
 */

#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#define ORIG(name) ({						\
	static typeof(&name) orig;				\
								\
	if (!orig) {						\
		void *tmp;					\
								\
		tmp = dlsym(RTLD_NEXT, #name);			\
		if (!tmp) {					\
			fprintf(stderr, "%s\n", dlerror());	\
			abort();				\
		}						\
		orig = tmp;					\
	}							\
	orig;							\
})

#ifndef __OPEN_NEEDS_MODE
/* From glibc fnctl.h. */
#ifdef __O_TMPFILE
# define __OPEN_NEEDS_MODE(oflag) \
  (((oflag) & O_CREAT) != 0 || ((oflag) & __O_TMPFILE) == __O_TMPFILE)
#else
# define __OPEN_NEEDS_MODE(oflag) (((oflag) & O_CREAT) != 0)
#endif
#endif

#define OPEN_MODE(flags) ({			\
	mode_t mode = 0;			\
						\
	if (__OPEN_NEEDS_MODE(flags)) {		\
		va_list ap;			\
						\
		va_start(ap, flags);		\
		mode = va_arg(ap, mode_t);	\
		va_end(ap);			\
	}					\
	mode;					\
})

int open(const char *pathname, int flags, ...)
{
	flags &= ~O_NOATIME;
	return ORIG(open)(pathname, flags, OPEN_MODE(flags));
}

int open64(const char *pathname, int flags, ...)
{
	flags &= ~O_NOATIME;
	return ORIG(open64)(pathname, flags, OPEN_MODE(flags));
}

int openat(int dirfd, const char *pathname, int flags, ...)
{
	flags &= ~O_NOATIME;
	return ORIG(openat)(dirfd, pathname, flags, OPEN_MODE(flags));
}

int openat64(int dirfd, const char *pathname, int flags, ...)
{
	flags &= ~O_NOATIME;
	return ORIG(openat64)(dirfd, pathname, flags, OPEN_MODE(flags));
}

#define FCNTL_ARG(cmd) ({					\
	va_list ap;						\
	void *arg;						\
								\
	va_start(ap, cmd);					\
	arg = va_arg(ap, void *);				\
	va_end(ap);						\
	if (cmd == F_SETFL)					\
		arg = (void *)((uintptr_t)arg & ~O_NOATIME);	\
	arg;							\
})

int fcntl(int fd, int cmd, ...)
{
	return ORIG(fcntl)(fd, cmd, FCNTL_ARG(cmd));
}

int fcntl64(int fd, int cmd, ...)
{
	return ORIG(fcntl64)(fd, cmd, FCNTL_ARG(cmd));
}
