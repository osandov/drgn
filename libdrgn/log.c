// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include "log.h"
#include "program.h"
#include "util.h"

LIBDRGN_PUBLIC void drgn_program_set_log_level(struct drgn_program *prog,
					       int level)
{
	prog->log_level = level;
}

LIBDRGN_PUBLIC int drgn_program_get_log_level(struct drgn_program *prog)
{
	return prog->log_level;
}

static void drgn_file_log_fn(struct drgn_program *prog, void *arg,
			     enum drgn_log_level level, const char *format,
			     va_list ap, struct drgn_error *err)
{
	FILE *file = arg;
	flockfile(file);

	static const char * const prefix[] = {
		[DRGN_LOG_DEBUG] = "debug: ",
		[DRGN_LOG_INFO] = "info: ",
		[DRGN_LOG_WARNING] = "warning: ",
		[DRGN_LOG_ERROR] = "error: ",
		[DRGN_LOG_CRITICAL] = "critical: ",
	};
	fputs(prefix[level], file);
	vfprintf(file, format, ap);
	if (err)
		drgn_error_fwrite(file, err);
	else
		putc('\n', file);

	funlockfile(file);
}

LIBDRGN_PUBLIC void drgn_program_set_log_file(struct drgn_program *prog,
					      FILE *file)
{
	drgn_program_set_log_callback(prog, drgn_file_log_fn, file);
}

LIBDRGN_PUBLIC void drgn_program_set_log_callback(struct drgn_program *prog,
						  drgn_log_fn *callback,
						  void *callback_arg)
{
	prog->log_fn = callback;
	prog->log_arg = callback_arg;
}

LIBDRGN_PUBLIC void drgn_program_get_log_callback(struct drgn_program *prog,
						  drgn_log_fn **callback_ret,
						  void **callback_arg_ret)
{
	*callback_ret = prog->log_fn;
	*callback_arg_ret = prog->log_arg;
}

bool drgn_log_is_enabled(struct drgn_program *prog, enum drgn_log_level level)
{
	return level >= prog->log_level;
}

void drgn_error_log(enum drgn_log_level level, struct drgn_program *prog,
		    struct drgn_error *err, const char *format, ...)
{
	if (!drgn_log_is_enabled(prog, level))
		return;

	va_list ap;
	va_start(ap, format);
	prog->log_fn(prog, prog->log_arg, level, format, ap, err);
	va_end(ap);
}
