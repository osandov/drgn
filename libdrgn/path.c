// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <string.h>

#include "internal.h"

bool path_iterator_next(struct path_iterator *it, const char **component,
			size_t *component_len)
{
	if (!it->len) {
empty:
		if (it->dot_dot) {
			/*
			 * Leftover ".." components must be above the current
			 * directory.
			 */
			it->dot_dot--;
			*component = "..";
			*component_len = 2;
			return true;
		}
		return false;
	}

	while (it->len) {
		/* Skip slashes. */
		if (it->path[it->len - 1] == '/') {
			it->len--;
			continue;
		}

		/* Skip "." components. */
		if (it->len == 1 && it->path[0] == '.') {
			it->len--;
			break;
		}
		if (it->len >= 2 && it->path[it->len - 2] == '/' &&
		    it->path[it->len - 1] == '.') {
			it->len -= 2;
			continue;
		}

		/* Count ".." components. */
		if (it->len == 2 && it->path[0] == '.' && it->path[1] == '.') {
			it->len -= 2;
			it->dot_dot++;
			break;
		}
		if (it->len >= 3 && it->path[it->len - 3] == '/' &&
		    it->path[it->len - 2] == '.' &&
		    it->path[it->len - 1] == '.') {
			it->len -= 3;
			it->dot_dot++;
			continue;
		}

		/* Emit or skip other components. */
		*component_len = 0;
		while (it->path[it->len - 1] != '/') {
			it->len--;
			(*component_len)++;
			if (!it->len)
				break;
		}
		if (it->dot_dot) {
			it->dot_dot--;
			continue;
		}

		*component = &it->path[it->len];
		return true;
	}

	if (it->path[0] == '/') {
		/*
		 * This is an absolute path. Emit an empty component. ".."
		 * components above this path are not meaningful.
		 */
		it->dot_dot = 0;
		*component = "";
		*component_len = 0;
		return true;
	}
	goto empty;
}

bool normalized_path_eq(const char *path1, const char *path2)
{
	struct path_iterator it = {
		.path = path1,
		.len = strlen(path1),
	};
	struct path_iterator it2 = {
		.path = path2,
		.len = strlen(path2),
	};

	for (;;) {
		const char *component1, *component2;
		size_t component_len1, component_len2;
		bool more1, more2;

		more1 = path_iterator_next(&it, &component1, &component_len1);
		more2 = path_iterator_next(&it2, &component2, &component_len2);

		if (!more1 && !more2)
			return true;
		else if (!more1 || !more2)
			return false;

		if (component_len1 != component_len2 ||
		    memcmp(component1, component2, component_len1) != 0)
			return false;
	}
}

bool die_matches_filename(Dwarf_Die *die, const char *filename)
{
	const char *die_filename;

	if (!filename)
		return true;

	die_filename = dwarf_decl_file(die);
	return die_filename && normalized_path_eq(die_filename, filename);
}
