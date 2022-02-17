// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <assert.h>

#include "array.h"
#include "language.h"
#include "util.h"

const struct drgn_language * const drgn_languages[] = {
	[DRGN_LANGUAGE_C] = &drgn_language_c,
	[DRGN_LANGUAGE_CPP] = &drgn_language_cpp,
};
static_assert(array_size(drgn_languages) == DRGN_NUM_LANGUAGES,
	      "missing language in drgn_languages");

LIBDRGN_PUBLIC const char *drgn_language_name(const struct drgn_language *lang)
{
	return lang->name;
}
