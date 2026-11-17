// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef DRGN_LANGUAGE_RUST_H
#define DRGN_LANGUAGE_RUST_H

#include "drgn.h"

struct string_builder;

struct drgn_error *drgn_rust_append_type_name(struct drgn_qualified_type qualified_type, struct string_builder *sb);

struct drgn_error *drgn_rust_format_type_name(struct drgn_qualified_type qualified_type, char **ret);

#endif /* DRGN_LANGUAGE_RUST_H */
