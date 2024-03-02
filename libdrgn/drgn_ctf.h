// Copyright (c) 2024 Oracle and/or its affiliates
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * CTF type format integration
 */

#ifndef DRGN_CTF_H
#define DRGN_CTF_H

struct drgn_error;
struct drgn_program;

struct drgn_error *
drgn_program_load_ctf(struct drgn_program *prog, const char *file);

#endif // DRGN_CTF_H
