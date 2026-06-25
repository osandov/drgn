// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <elfutils/libdw.h>
#include <errno.h>
#include <inttypes.h>
#include <libelf.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "drgn_internal.h"
#include "error.h"
#include "string_builder.h"
#include "util.h"

LIBDRGN_PUBLIC struct drgn_error drgn_enomem =
	DRGN_ERROR_INIT(DRGN_ERROR_NO_MEMORY, "cannot allocate memory");

LIBDRGN_PUBLIC struct drgn_error drgn_not_found =
	DRGN_ERROR_INIT(DRGN_ERROR_LOOKUP, "not found");

struct drgn_error drgn_stop =
	DRGN_ERROR_INIT(DRGN_ERROR_STOP, "stop iteration");

struct drgn_error drgn_error_object_absent =
	DRGN_ERROR_INIT(DRGN_ERROR_OBJECT_ABSENT, "object absent");

LIBDRGN_PUBLIC enum drgn_error_code drgn_error_code(struct drgn_error *err)
{
	return err->_code;
}

LIBDRGN_PUBLIC const char *drgn_error_message(struct drgn_error *err)
{
	return err->_message;
}

LIBDRGN_PUBLIC int drgn_error_os_errno(struct drgn_error *err)
{
	return err->_errno;
}

LIBDRGN_PUBLIC const char *drgn_error_os_path(struct drgn_error *err)
{
	return err->_path;
}

LIBDRGN_PUBLIC uint64_t drgn_error_fault_address(struct drgn_error *err)
{
	return err->_address;
}

static struct drgn_error *drgn_error_create_nodup(enum drgn_error_code code,
						  char *message)
{
	struct drgn_error *err;

	err = malloc(sizeof(*err));
	if (!err) {
		free(message);
		return &drgn_enomem;
	}

	err->_code = code;
	err->_needs_destroy = true;
	err->_errno = 0;
	err->_path = NULL;
	err->_address = 0;
	err->_message = message;
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *drgn_error_create(enum drgn_error_code code,
						    const char *message)
{
	char *message_copy;

	message_copy = strdup(message);
	if (!message_copy)
		return &drgn_enomem;
	return drgn_error_create_nodup(code, message_copy);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_error_format_os(const char *message, int errnum, const char *path_format,
		     ...)
{
	struct drgn_error *err;
	va_list ap;
	int ret;

	err = malloc(sizeof(*err));
	if (!err)
		return &drgn_enomem;

	err->_code = DRGN_ERROR_OS;
	err->_needs_destroy = true;
	err->_errno = errnum;
	if (path_format) {
		va_start(ap, path_format);
		ret = vasprintf(&err->_path, path_format, ap);
		va_end(ap);
		if (ret == -1) {
			free(err);
			return &drgn_enomem;
		}
	} else {
		err->_path = NULL;
	}
	err->_address = 0;
	err->_message = strdup(message);
	if (!err->_message) {
		free(err->_path);
		free(err);
		return &drgn_enomem;
	}
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *drgn_error_create_os(const char *message,
						       int errnum,
						       const char *path)
{
	if (path)
		return drgn_error_format_os(message, errnum, "%s", path);
	else
		return drgn_error_format_os(message, errnum, NULL);
}

LIBDRGN_PUBLIC struct drgn_error *drgn_error_format(enum drgn_error_code code,
						    const char *format, ...)
{
	char *message;
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = vasprintf(&message, format, ap);
	va_end(ap);
	if (ret == -1)
                return &drgn_enomem;
	return drgn_error_create_nodup(code, message);
}

LIBDRGN_PUBLIC struct drgn_error *drgn_error_create_fault(const char *message,
							  uint64_t address)
{
	struct drgn_error *err;

	err = drgn_error_create(DRGN_ERROR_FAULT, message);
	if (err != &drgn_enomem)
		err->_address = address;
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_error_format_fault(uint64_t address, const char *format, ...)
{
	struct drgn_error *err;
	va_list ap;
	char *message;
	int ret;

	va_start(ap, format);
	ret = vasprintf(&message, format, ap);
	va_end(ap);
	if (ret == -1)
                return &drgn_enomem;
	err = drgn_error_create_nodup(DRGN_ERROR_FAULT, message);
	if (err != &drgn_enomem)
		err->_address = address;
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *drgn_error_copy(struct drgn_error *src)
{
	if (!src->_needs_destroy)
		return src;
	struct drgn_error *dst = malloc(sizeof(*dst));
	if (!dst)
		return &drgn_enomem;
	dst->_code = src->_code;
	dst->_needs_destroy = true;
	dst->_errno = src->_errno;
	if (src->_path) {
		dst->_path = strdup(src->_path);
		if (!dst->_path) {
			free(dst);
			return &drgn_enomem;
		}
	} else {
		dst->_path = NULL;
	}
	dst->_address = src->_address;
	if (src->_message) {
		dst->_message = strdup(src->_message);
		if (!dst->_message) {
			free(dst->_path);
			free(dst);
			return &drgn_enomem;
		}
	} else {
		dst->_message = NULL;
	}
	return dst;
}

#define emit_error(err) (							\
	err->_code == DRGN_ERROR_OS ?						\
		/* This is easier than dealing with strerror_r(). */		\
		(errno = err->_errno,						\
		 err->_message[0] && err->_path ?				\
		 emit_error_format("%s: %s: %m", err->_message, err->_path) :	\
		 err->_message[0] || err->_path ?				\
		 emit_error_format("%s: %m",					\
				   err->_message[0]				\
				   ? err->_message : err->_path) :		\
		 emit_error_format("%m"))					\
	: err->_code == DRGN_ERROR_FAULT ?					\
		emit_error_format("%s: 0x%" PRIx64, err->_message,		\
				  err->_address)				\
	:									\
		emit_error_string(err->_message)				\
)

bool string_builder_append_error(struct string_builder *sb,
				 struct drgn_error *err)
{
#define emit_error_format(...) string_builder_appendf(sb, ##__VA_ARGS__)
#define emit_error_string(s) string_builder_append(sb, s)
	return emit_error(err);
#undef emit_error_string
#undef emit_error_format
}

LIBDRGN_PUBLIC char *drgn_error_string(struct drgn_error *err)
{
	char *tmp;
#define emit_error_format(...) (asprintf(&tmp, ##__VA_ARGS__) < 0 ? NULL : tmp)
#define emit_error_string(s) strdup(s)
	return emit_error(err);
#undef emit_error_string
#undef emit_error_format
}

LIBDRGN_PUBLIC int drgn_error_fwrite(FILE *file, struct drgn_error *err)
{
#define emit_error_format(format, ...) fprintf(file, format "\n", ##__VA_ARGS__)
#define emit_error_string(s) fprintf(file, "%s\n", s)
	return emit_error(err);
#undef emit_error_string
#undef emit_error_format
}

LIBDRGN_PUBLIC int drgn_error_dwrite(int fd, struct drgn_error *err)
{
#define emit_error_format(format, ...) dprintf(fd, format "\n", ##__VA_ARGS__)
#define emit_error_string(s) dprintf(fd, "%s\n", s)
	return emit_error(err);
#undef emit_error_string
#undef emit_error_format
}

#undef emit_error

LIBDRGN_PUBLIC void drgn_error_destroy(struct drgn_error *err)
{
	if (err && err->_needs_destroy) {
		free(err->_path);
		free(err->_message);
		free(err);
	}
}

struct drgn_error *drgn_error_libelf(void)
{
	return drgn_error_format(DRGN_ERROR_OTHER, "libelf error: %s",
				 elf_errmsg(-1));
}

struct drgn_error *drgn_error_libdw(void)
{
	return drgn_error_format(DRGN_ERROR_OTHER, "libdw error: %s",
				 dwarf_errmsg(-1));
}
