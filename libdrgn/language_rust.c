// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

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

static bool rust_is_tuple_like(struct drgn_type *type)
{
	struct drgn_type_member *members = drgn_type_members(type);
	size_t num_members = drgn_type_num_members(type);

	if (num_members == 0)
		return false;
	for (size_t i = 0; i < num_members; i++) {
		char name[sizeof("__") + 20];
		snprintf(name, sizeof(name), "__%zu", i);
		if (!members[i].name || strcmp(members[i].name, name) != 0)
			return false;
	}
	return true;
}

static struct drgn_error *rust_append_member_type(struct drgn_type_member *member, struct string_builder *sb)
{
	struct drgn_error *err;
	struct drgn_qualified_type member_type;
	uint64_t bit_field_size;

	err = drgn_member_type(member, &member_type, &bit_field_size);
	if (err)
		return err;
	err = drgn_rust_append_type_name(member_type, sb);
	if (err)
		return err;
	if (bit_field_size && !string_builder_appendf(sb, " /* : %" PRIu64 " */", bit_field_size))
		return &drgn_enomem;
	return NULL;
}

static struct drgn_error *rust_append_field(struct drgn_type_member *member, struct string_builder *sb)
{
	if (member->name && member->name[0] &&
	    (!string_builder_append(sb, member->name) || !string_builder_append(sb, ": ")))
		return &drgn_enomem;
	return rust_append_member_type(member, sb);
}

static struct drgn_error *rust_append_inline_fields(struct drgn_type *type, struct string_builder *sb)
{
	struct drgn_error *err;
	struct drgn_type_member *members = drgn_type_members(type);
	size_t num_members = drgn_type_num_members(type);

	if (num_members == 0)
		return NULL;
	bool tuple = rust_is_tuple_like(type);
	if (!string_builder_append(sb, tuple ? "(" : " { "))
		return &drgn_enomem;
	for (size_t i = 0; i < num_members; i++) {
		if (i > 0 && !string_builder_append(sb, ", "))
			return &drgn_enomem;
		if (tuple)
			err = rust_append_member_type(&members[i], sb);
		else
			err = rust_append_field(&members[i], sb);
		if (err)
			return err;
	}
	if (!string_builder_append(sb, tuple ? ")" : " }"))
		return &drgn_enomem;
	return NULL;
}

static bool rust_append_keyword_and_tag(struct drgn_type *type, const char *keyword, struct string_builder *sb)
{
	const char *tag = drgn_type_tag(type);

	if (!string_builder_append(sb, keyword))
		return false;
	return !tag || (string_builder_appendc(sb, ' ') && string_builder_append(sb, tag));
}

static struct drgn_error *rust_define_compound(struct drgn_type *type, const char *keyword, struct string_builder *sb)
{
	struct drgn_error *err;
	struct drgn_type_member *members = drgn_type_members(type);
	size_t num_members = drgn_type_num_members(type);

	if (!rust_append_keyword_and_tag(type, keyword, sb))
		return &drgn_enomem;
	if (drgn_type_kind(type) != DRGN_TYPE_UNION && (num_members == 0 || rust_is_tuple_like(type))) {
		err = rust_append_inline_fields(type, sb);
		if (err)
			return err;
		if (!string_builder_appendc(sb, ';'))
			return &drgn_enomem;
		return NULL;
	}
	if (num_members == 0) {
		if (!string_builder_append(sb, " {}"))
			return &drgn_enomem;
		return NULL;
	}

	if (!string_builder_append(sb, " {\n"))
		return &drgn_enomem;
	for (size_t i = 0; i < num_members; i++) {
		if (!string_builder_appendc(sb, '\t'))
			return &drgn_enomem;
		err = rust_append_field(&members[i], sb);
		if (err)
			return err;
		if (!string_builder_append(sb, ",\n"))
			return &drgn_enomem;
	}
	if (!string_builder_appendc(sb, '}'))
		return &drgn_enomem;
	return NULL;
}

static bool rust_append_discr_comment(struct drgn_type *type, size_t i, struct string_builder *sb)
{
	if (i == drgn_type_default_discr(type))
		return string_builder_append(sb, " /* default */");
	union drgn_type_discr *discr = &drgn_type_discrs(type)[i - 1];
	if (drgn_type_discr_is_signed(type))
		return string_builder_appendf(sb, " /* %" PRId64 " */", discr->svalue);
	return string_builder_appendf(sb, " /* %" PRIu64 " */", discr->uvalue);
}

static struct drgn_error *rust_define_discr_union(struct drgn_type *type, struct string_builder *sb)
{
	struct drgn_error *err;
	struct drgn_type_member *members = drgn_type_members(type);
	size_t num_members = drgn_type_num_members(type);

	if (!rust_append_keyword_and_tag(type, "enum", sb) || !string_builder_append(sb, " {\n\t/* discriminant: "))
		return &drgn_enomem;
	err = rust_append_member_type(&members[0], sb);
	if (err)
		return err;
	if (!string_builder_append(sb, " */\n"))
		return &drgn_enomem;

	for (size_t i = 1; i < num_members; i++) {
		if (!string_builder_appendc(sb, '\t') || !string_builder_append(sb, members[i].name ?: ""))
			return &drgn_enomem;
		struct drgn_qualified_type variant_type;
		err = drgn_member_type(&members[i], &variant_type, NULL);
		if (err)
			return err;
		struct drgn_type *underlying_type = drgn_underlying_type(variant_type.type);
		if (drgn_type_kind(underlying_type) == DRGN_TYPE_STRUCT && drgn_type_is_complete(underlying_type)) {
			err = rust_append_inline_fields(underlying_type, sb);
		} else {
			if (!string_builder_appendc(sb, '('))
				return &drgn_enomem;
			err = drgn_rust_append_type_name(variant_type, sb);
			if (!err && !string_builder_appendc(sb, ')'))
				return &drgn_enomem;
		}
		if (err)
			return err;
		if (!string_builder_appendc(sb, ',') || !rust_append_discr_comment(type, i, sb) ||
		    !string_builder_appendc(sb, '\n'))
			return &drgn_enomem;
	}
	if (!string_builder_appendc(sb, '}'))
		return &drgn_enomem;
	return NULL;
}

static struct drgn_error *rust_define_enum(struct drgn_type *type, struct string_builder *sb)
{
	struct drgn_type_enumerator *enumerators = drgn_type_enumerators(type);
	size_t num_enumerators = drgn_type_num_enumerators(type);
	bool is_signed = drgn_enum_type_is_signed(type);

	if (!rust_append_keyword_and_tag(type, "enum", sb))
		return &drgn_enomem;
	if (num_enumerators == 0) {
		if (!string_builder_append(sb, " {}"))
			return &drgn_enomem;
		return NULL;
	}
	if (!string_builder_append(sb, " {\n"))
		return &drgn_enomem;
	for (size_t i = 0; i < num_enumerators; i++) {
		if (!string_builder_appendc(sb, '\t') || !string_builder_append(sb, enumerators[i].name))
			return &drgn_enomem;
		if (is_signed) {
			if (!string_builder_appendf(sb, " = %" PRId64 ",\n", enumerators[i].svalue))
				return &drgn_enomem;
		} else if (!string_builder_appendf(sb, " = %" PRIu64 ",\n", enumerators[i].uvalue)) {
			return &drgn_enomem;
		}
	}
	if (!string_builder_appendc(sb, '}'))
		return &drgn_enomem;
	return NULL;
}

static struct drgn_error *rust_define_typedef(struct drgn_type *type, struct string_builder *sb)
{
	struct drgn_error *err;

	if (!string_builder_append(sb, "type ") || !string_builder_append(sb, drgn_type_name(type)) ||
	    !string_builder_append(sb, " = "))
		return &drgn_enomem;
	err = drgn_rust_append_type_name(drgn_type_type(type), sb);
	if (err)
		return err;
	if (!string_builder_appendc(sb, ';'))
		return &drgn_enomem;
	return NULL;
}

static struct drgn_error *rust_define_type(struct drgn_qualified_type qualified_type, struct string_builder *sb)
{
	struct drgn_type *type = qualified_type.type;

	switch (drgn_type_kind(type)) {
	case DRGN_TYPE_STRUCT:
	case DRGN_TYPE_UNION:
	case DRGN_TYPE_CLASS: {
		const char *tag = drgn_type_tag(type);
		if (!drgn_type_is_complete(type) || (tag && tag[0] == '('))
			break;
		if (drgn_type_is_discr_union(type))
			return rust_define_discr_union(type, sb);
		const char *keyword;
		if (drgn_type_kind(type) == DRGN_TYPE_STRUCT)
			keyword = "struct";
		else if (drgn_type_kind(type) == DRGN_TYPE_UNION)
			keyword = "union";
		else
			keyword = "class";
		return rust_define_compound(type, keyword, sb);
	}
	case DRGN_TYPE_ENUM:
		if (!drgn_type_is_complete(type))
			break;
		return rust_define_enum(type, sb);
	case DRGN_TYPE_TYPEDEF:
		return rust_define_typedef(type, sb);
	default:
		break;
	}
	return drgn_rust_append_type_name(qualified_type, sb);
}

struct drgn_error *drgn_rust_format_type(struct drgn_qualified_type qualified_type, char **ret)
{
	struct drgn_error *err;
	STRING_BUILDER(sb);

	err = rust_define_type(qualified_type, &sb);
	if (err)
		return err;
	if (!string_builder_null_terminate(&sb))
		return &drgn_enomem;
	*ret = string_builder_steal(&sb);
	return NULL;
}

struct drgn_error *drgn_rust_format_variable_declaration(struct drgn_qualified_type qualified_type, const char *name,
							 char **ret)
{
	struct drgn_error *err;
	STRING_BUILDER(sb);

	if (!string_builder_append(&sb, name) || !string_builder_append(&sb, ": "))
		return &drgn_enomem;
	err = drgn_rust_append_type_name(qualified_type, &sb);
	if (err)
		return err;
	if (!string_builder_null_terminate(&sb))
		return &drgn_enomem;
	*ret = string_builder_steal(&sb);
	return NULL;
}
