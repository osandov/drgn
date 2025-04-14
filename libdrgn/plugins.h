// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef DRGN_PLUGINS_H
#define DRGN_PLUGINS_H

struct drgn_program;

void drgn_call_plugins_prog(const char *name, struct drgn_program *prog);

#endif /* DRGN_PLUGINS_H */
