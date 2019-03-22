// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <errno.h>
#include <elfutils/libdw.h>
#include <libelf.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

LIBDRGN_PUBLIC struct drgn_error drgn_enomem = {
	.code = DRGN_ERROR_NO_MEMORY,
	.message = "cannot allocate memory",
};

struct drgn_error drgn_stop = {
	.code = DRGN_ERROR_STOP,
	.message = "stop iteration",
};

struct drgn_error drgn_not_elf = {
	.code = DRGN_ERROR_ELF_FORMAT,
	.message = "not an ELF file",
};

static struct drgn_error *drgn_error_create_internal(int code, int errnum,
						     const char *path,
						     const char *message)
{
	struct drgn_error *err;

	err = malloc(sizeof(*err));
	if (!err)
		return &drgn_enomem;

	err->code = code;
	err->needs_destroy = true;
	err->errnum = errnum;
	if (path) {
		err->path = strdup(path);
		if (!err->path) {
			free(err);
			return &drgn_enomem;
		}
	} else {
		err->path = NULL;
	}
	err->message = strdup(message);
	if (!err->message) {
		free(err->path);
		free(err);
		return &drgn_enomem;
	}
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *drgn_error_create(int code,
						    const char *message)
{
	return drgn_error_create_internal(code, 0, NULL, message);
}

LIBDRGN_PUBLIC struct drgn_error *drgn_error_create_os(int errnum,
						       const char *path,
						       const char *message)
{
	return drgn_error_create_internal(DRGN_ERROR_OS, errnum, path, message);
}

static struct drgn_error *drgn_error_format_internal(int code, int errnum,
                                                     const char *path,
                                                     const char *format,
                                                     va_list ap)
{
        struct drgn_error *err;

        err = malloc(sizeof(*err));
        if (!err)
                return &drgn_enomem;

        err->code = code;
	err->needs_destroy = true;
        err->errnum = errnum;
        if (path) {
                err->path = strdup(path);
                if (!err->path) {
                        free(err);
                        return &drgn_enomem;
                }
        } else {
                err->path = NULL;
        }
        if (vasprintf(&err->message, format, ap) == -1) {
                free(err->path);
                free(err);
                return &drgn_enomem;
        }
        return err;
}

LIBDRGN_PUBLIC struct drgn_error *drgn_error_format(int code,
						    const char *format, ...)
{
	struct drgn_error *err;
	va_list ap;

	va_start(ap, format);
	err = drgn_error_format_internal(code, 0, NULL, format, ap);
	va_end(ap);
	return err;
}

LIBDRGN_PUBLIC void drgn_error_fwrite(FILE *file, struct drgn_error *err)
{
	if (err->code == DRGN_ERROR_OS) {
		/* This is easier than dealing with strerror_r(). */
		errno = err->errnum;
		if (err->path)
			fprintf(file, "%s: %s: %m\n", err->message, err->path);
		else
			fprintf(file, "%s: %m\n", err->message);
	} else {
		fprintf(file, "%s\n", err->message);
	}
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
	return drgn_error_format(DRGN_ERROR_ELF_FORMAT, "libelf error: %s",
				 elf_errmsg(-1));
}

struct drgn_error *drgn_error_libdw(void)
{
	return drgn_error_format(DRGN_ERROR_DWARF_FORMAT, "libdw error: %s",
				 dwarf_errmsg(-1));
}
