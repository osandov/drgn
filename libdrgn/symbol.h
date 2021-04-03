// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DRGN_SYMBOL_H
#define DRGN_SYMBOL_H

#include <stdint.h>

struct drgn_symbol {
	const char *name;
	uint64_t address;
	uint64_t size;
};

#endif /* DRGN_SYMBOL_H */
