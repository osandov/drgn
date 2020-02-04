// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <errno.h>
#include <elfutils/libdwfl.h>
#include <inttypes.h>
#include <libelf.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "string_builder.h"

LIBDRGN_PUBLIC struct drgn_error drgn_enomem = {
	.code = DRGN_ERROR_NO_MEMORY,
	.message = "cannot allocate memory",
};

LIBDRGN_PUBLIC struct drgn_error drgn_not_found = {
	.code = DRGN_ERROR_LOOKUP,
	.message = "not found",
};

struct drgn_error drgn_stop = {
	.code = DRGN_ERROR_STOP,
	.message = "stop iteration",
};

static struct drgn_error *drgn_error_create_nodup(enum drgn_error_code code,
						  char *message)
{
	struct drgn_error *err;

	err = malloc(sizeof(*err));
	if (!err) {
		free(message);
		return &drgn_enomem;
	}

	err->code = code;
	err->needs_destroy = true;
	err->errnum = 0;
	err->path = NULL;
	err->address = 0;
	err->message = message;
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

	err->code = DRGN_ERROR_OS;
	err->needs_destroy = true;
	err->errnum = errnum;
	if (path_format) {
		va_start(ap, path_format);
		ret = vasprintf(&err->path, path_format, ap);
		va_end(ap);
		if (ret == -1) {
			free(err);
			return &drgn_enomem;
		}
	} else {
		err->path = NULL;
	}
	err->address = 0;
	err->message = strdup(message);
	if (!err->message) {
		free(err->path);
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
		err->address = address;
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
		err->address = address;
	return err;
}

struct drgn_error *drgn_error_from_string_builder(enum drgn_error_code code,
						  struct string_builder *sb)
{
	char *message;

	if (!string_builder_finalize(sb, &message)) {
		free(sb->str);
		return &drgn_enomem;
	}
	return drgn_error_create_nodup(code, message);
}

bool string_builder_append_error(struct string_builder *sb,
				 struct drgn_error *err)
{
	bool ret;

	if (err->code == DRGN_ERROR_OS) {
		/* This is easier than dealing with strerror_r(). */
		errno = err->errnum;
		if (err->path) {
			ret = string_builder_appendf(sb, "%s: %s: %m",
						     err->message, err->path);
		} else {
			ret = string_builder_appendf(sb, "%s: %m",
						     err->message);
		}
	} else if (err->code == DRGN_ERROR_FAULT) {
		ret = string_builder_appendf(sb, "%s: 0x%" PRIx64,
					     err->message,
					     err->address);
	} else {
		ret = string_builder_append(sb, err->message);
	}
	return ret;
}

LIBDRGN_PUBLIC int drgn_error_fwrite(FILE *file, struct drgn_error *err)
{
	struct string_builder sb = {};
	char *message;
	int ret;

	if (err->code == DRGN_ERROR_OS) {
		if (!string_builder_append_error(&sb, err) ||
		    !string_builder_finalize(&sb, &message)) {
			free(sb.str);
			errno = ENOMEM;
			return EOF;
		}
		ret = fputs(message, file);
		free(message);
		if (ret == EOF)
			return EOF;
	} else {
		if (fputs(err->message, file) == EOF)
			return EOF;
	}
	return fputc('\n', file);
}

LIBDRGN_PUBLIC void drgn_error_destroy(struct drgn_error *err)
{
	if (err && err->needs_destroy) {
		free(err->path);
		free(err->message);
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

struct drgn_error *drgn_error_libdwfl(void)
{
	return drgn_error_format(DRGN_ERROR_OTHER, "libdwfl error: %s",
				 dwfl_errmsg(-1));
}
