// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef DRGN_PLUGINS_H
#define DRGN_PLUGINS_H

#include <stdbool.h>

struct drgn_program;

#if ENABLE_PYTHON
void drgn_call_plugins_prog(const char *name, struct drgn_program *prog);
#else
static inline void drgn_call_plugins_prog(const char *name, struct drgn_program *prog) {}
#endif

#endif /* DRGN_PLUGINS_H */
