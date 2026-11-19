// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef DRGN_LANGUAGE_RUST_H
#define DRGN_LANGUAGE_RUST_H

#include "drgn.h"

struct string_builder;

struct drgn_error *drgn_rust_append_type_name(struct drgn_qualified_type qualified_type, struct string_builder *sb);

struct drgn_error *drgn_rust_format_type_name(struct drgn_qualified_type qualified_type, char **ret);

struct drgn_error *drgn_rust_format_type(struct drgn_qualified_type qualified_type, char **ret);

struct drgn_error *drgn_rust_format_variable_declaration(struct drgn_qualified_type qualified_type, const char *name,
							 char **ret);

struct drgn_error *drgn_rust_find_type(const struct drgn_language *lang, struct drgn_program *prog, const char *name,
				       const char *filename, struct drgn_qualified_type *ret);

#endif /* DRGN_LANGUAGE_RUST_H */
