// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <dwarf.h>
#include <stdbool.h>
#include <string.h>

#include "path.h"
#include "util.h"

bool path_iterator_next(struct path_iterator *it, const char **component_ret,
			size_t *component_len_ret)
{
	while (it->num_components) {
		struct nstring *cur = &it->components[it->num_components - 1];
		while (cur->len > 0) {
			if (cur->str[cur->len - 1] == '/') {
				if (cur->len == 1) {
					/*
					 * This is an absolute path. Emit an
					 * empty component. Components joined
					 * before this one and remaining ".."
					 * components are not meaningful.
					 */
					it->num_components = 0;
					it->dot_dot = 0;
					*component_ret = "";
					*component_len_ret = 0;
					return true;
				}
				/* Skip redundant slashes. */
				cur->len--;
				continue;
			}

			size_t component_start = cur->len - 1;
			while (component_start > 0 &&
			       cur->str[component_start - 1] != '/')
				component_start--;
			size_t component_len = cur->len - component_start;
			cur->len = component_start;
			if (component_len == 1 &&
			    cur->str[component_start] == '.') {
				/* Skip "." components. */
			} else if (component_len == 2 &&
				   cur->str[component_start] == '.' &&
				   cur->str[component_start + 1] == '.') {
				/* Count ".." components. */
				it->dot_dot++;
			} else if (it->dot_dot) {
				it->dot_dot--;
			} else {
				*component_ret = &cur->str[component_start];
				*component_len_ret = component_len;
				return true;
			}
		}
		it->num_components--;
	}

	if (it->dot_dot) {
		/*
		 * Leftover ".." components must be above the current
		 * directory.
		 */
		it->dot_dot--;
		*component_ret = "..";
		*component_len_ret = 2;
		return true;
	}
	return false;
}

bool path_ends_with(struct path_iterator *haystack,
		    struct path_iterator *needle)
{
	for (;;) {
		const char *h_component, *n_component;
		size_t h_component_len, n_component_len;

		if (!path_iterator_next(needle, &n_component, &n_component_len))
			return true;

		if (!path_iterator_next(haystack, &h_component,
					&h_component_len))
			return false;

		if (h_component_len != n_component_len ||
		    memcmp(h_component, n_component, h_component_len) != 0)
			return false;
	}
}

bool die_matches_filename(Dwarf_Die *die, const char *filename)
{
	if (!filename || !filename[0])
		return true;

	struct nstring die_components[2];
	struct path_iterator die_path = {
		.components = die_components,
	};

	Dwarf_Die cu_die;
	Dwarf_Attribute attr_mem, *attr;
	attr = dwarf_attr_integrate(dwarf_diecu(die, &cu_die, NULL, NULL),
				    DW_AT_comp_dir, &attr_mem);
	const char *path = dwarf_formstring(attr);
	if (path) {
		die_path.components[die_path.num_components].str = path;
		die_path.components[die_path.num_components].len = strlen(path);
		die_path.num_components++;
	}

	path = dwarf_decl_file(die);
	if (!path)
		return false;
	/*
	 * If the declaration file name is absolute, the compilation directory
	 * component will be ignored.
	 */
	die_path.components[die_path.num_components].str = path;
	die_path.components[die_path.num_components].len = strlen(path);
	die_path.num_components++;

	struct path_iterator needle = {
		.components = (struct nstring []){
			{ filename, strlen(filename) }
		},
		.num_components = 1,
	};

	return path_ends_with(&die_path, &needle);
}

LIBDRGN_PUBLIC bool drgn_filename_matches(const char *haystack,
					  const char *needle)
{
	struct path_iterator haystack_path = {
		.components = (struct nstring []){
			{ haystack, strlen(haystack) }
		},
		.num_components = 1,
	};
	struct path_iterator needle_path = {
		.components = (struct nstring []){
			{ needle, strlen(needle) }
		},
		.num_components = 1,
	};
	return path_ends_with(&haystack_path, &needle_path);
}
