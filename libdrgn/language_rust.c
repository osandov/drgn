// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <inttypes.h>

#include "error.h"
#include "language_rust.h"
#include "string_builder.h"
#include "type.h"
#include "util.h"

static struct drgn_error *rust_append_function_type_name(struct drgn_type *type, struct string_builder *sb)
{
	struct drgn_error *err;

	if (!string_builder_append(sb, "fn("))
		return &drgn_enomem;
	struct drgn_type_parameter *parameters = drgn_type_parameters(type);
	size_t num_parameters = drgn_type_num_parameters(type);
	for (size_t i = 0; i < num_parameters; i++) {
		if (i > 0 && !string_builder_append(sb, ", "))
			return &drgn_enomem;
		struct drgn_qualified_type parameter_type;
		err = drgn_parameter_type(&parameters[i], &parameter_type);
		if (err)
			return err;
		err = drgn_rust_append_type_name(parameter_type, sb);
		if (err)
			return err;
	}
	if (drgn_type_is_variadic(type) && !string_builder_append(sb, num_parameters ? ", ..." : "..."))
		return &drgn_enomem;
	if (!string_builder_appendc(sb, ')'))
		return &drgn_enomem;

	struct drgn_qualified_type return_type = drgn_type_type(type);
	if (drgn_type_kind(return_type.type) == DRGN_TYPE_VOID)
		return NULL;
	if (!string_builder_append(sb, " -> "))
		return &drgn_enomem;
	return drgn_rust_append_type_name(return_type, sb);
}

static struct drgn_error *rust_append_tagged_name(struct drgn_type *type, const char *keyword,
						  struct string_builder *sb)
{
	if (drgn_type_is_anonymous(type)) {
		if (!string_builder_append(sb, keyword) || !string_builder_append(sb, " <anonymous>"))
			return &drgn_enomem;
		return NULL;
	}
	if (!string_builder_append(sb, drgn_type_tag(type)))
		return &drgn_enomem;
	return NULL;
}

struct drgn_error *drgn_rust_append_type_name(struct drgn_qualified_type qualified_type, struct string_builder *sb)
{
	struct drgn_error *err;
	struct drgn_type *type = qualified_type.type;

	drgn_recursion_guard(1000, "maximum type depth exceeded");

	SWITCH_ENUM(drgn_type_kind(type)) {
	case DRGN_TYPE_VOID:
		if (!string_builder_append(sb, "()"))
			return &drgn_enomem;
		return NULL;
	case DRGN_TYPE_INT:
	case DRGN_TYPE_BOOL:
	case DRGN_TYPE_FLOAT:
	case DRGN_TYPE_TYPEDEF:
		if (!string_builder_append(sb, drgn_type_name(type)))
			return &drgn_enomem;
		return NULL;
	case DRGN_TYPE_STRUCT:
		return rust_append_tagged_name(type, "struct", sb);
	case DRGN_TYPE_UNION:
		return rust_append_tagged_name(type, "union", sb);
	case DRGN_TYPE_CLASS:
		return rust_append_tagged_name(type, "class", sb);
	case DRGN_TYPE_ENUM:
		return rust_append_tagged_name(type, "enum", sb);
	case DRGN_TYPE_POINTER: {
		if (drgn_type_has_name(type)) {
			if (!string_builder_append(sb, drgn_type_name(type)))
				return &drgn_enomem;
			return NULL;
		}
		struct drgn_qualified_type referenced_type = drgn_type_type(type);
		if (drgn_type_kind(referenced_type.type) == DRGN_TYPE_FUNCTION)
			return rust_append_function_type_name(referenced_type.type, sb);
		if (!string_builder_append(sb, referenced_type.qualifiers & DRGN_QUALIFIER_CONST ? "*const " : "*mut "))
			return &drgn_enomem;
		return drgn_rust_append_type_name(referenced_type, sb);
	}
	case DRGN_TYPE_ARRAY:
		if (!string_builder_appendc(sb, '['))
			return &drgn_enomem;
		err = drgn_rust_append_type_name(drgn_type_type(type), sb);
		if (err)
			return err;
		if (drgn_type_is_complete(type)) {
			if (!string_builder_appendf(sb, "; %" PRIu64 "]", drgn_type_length(type)))
				return &drgn_enomem;
		} else if (!string_builder_appendc(sb, ']')) {
			return &drgn_enomem;
		}
		return NULL;
	case DRGN_TYPE_FUNCTION:
		return rust_append_function_type_name(type, sb);
	default:
		UNREACHABLE();
	}
}

struct drgn_error *drgn_rust_format_type_name(struct drgn_qualified_type qualified_type, char **ret)
{
	struct drgn_error *err;
	STRING_BUILDER(sb);

	err = drgn_rust_append_type_name(qualified_type, &sb);
	if (err)
		return err;
	if (!string_builder_null_terminate(&sb))
		return &drgn_enomem;
	*ret = string_builder_steal(&sb);
	return NULL;
}
