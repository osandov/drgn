// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "binary_buffer.h"
#include "drgn.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

static struct drgn_error *binary_buffer_error_vat(struct binary_buffer *bb,
						  const char *pos,
						  const char *format,
						  va_list ap)
{
	char *message;
	int ret = vasprintf(&message, format, ap);
	if (ret == -1)
		return &drgn_enomem;
	struct drgn_error *err = bb->error_fn(bb, pos, message);
	free(message);
	return err;
}

struct drgn_error *binary_buffer_error(struct binary_buffer *bb,
				       const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	struct drgn_error *err = binary_buffer_error_vat(bb, bb->prev, format,
							 ap);
	va_end(ap);
	return err;
}

struct drgn_error *binary_buffer_error_at(struct binary_buffer *bb,
					  const char *pos, const char *format,
					  ...)
{
	va_list ap;
	va_start(ap, format);
	struct drgn_error *err = binary_buffer_error_vat(bb, pos, format, ap);
	va_end(ap);
	return err;
}
