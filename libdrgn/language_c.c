// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <assert.h>
#include <ctype.h>
#include <float.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "array.h"
#include "bitops.h"
#include "error.h"
#include "hash_table.h"
#include "language.h" // IWYU pragma: associated
#include "lexer.h"
#include "minmax.h"
#include "object.h"
#include "program.h"
#include "string_builder.h"
#include "symbol.h"
#include "type.h"
#include "util.h"
#include "vector.h"

static struct drgn_error *
c_declare_variable(struct drgn_qualified_type qualified_type,
		   struct string_callback *name, size_t indent,
		   bool define_anonymous_type, struct string_builder *sb);

static struct drgn_error *
c_define_type(struct drgn_qualified_type qualified_type, size_t indent,
	      struct string_builder *sb);

static bool append_tabs(int n, struct string_builder *sb)
{
	while (n-- > 0) {
		if (!string_builder_appendc(sb, '\t'))
			return false;
	}
	return true;
}

static struct drgn_error *c_variable_name(struct string_callback *name,
					  void *arg, struct string_builder *sb)
{
	if (!string_builder_append(sb, arg))
		return &drgn_enomem;
	return NULL;
}

static struct drgn_error *c_append_qualifiers(enum drgn_qualifiers qualifiers,
					      struct string_builder *sb)
{
	static const char *qualifier_names[] = {
		"const", "volatile", "restrict", "_Atomic",
	};
	bool first = true;
	unsigned int i;

	static_assert((1 << array_size(qualifier_names)) - 1 ==
		      DRGN_ALL_QUALIFIERS, "missing C qualifier name");

	for (i = 0; (1U << i) & DRGN_ALL_QUALIFIERS; i++) {
		if (!(qualifiers & (1U << i)))
			continue;
		if (!first) {
			if (!string_builder_appendc(sb, ' '))
				return &drgn_enomem;
		}
		if (!string_builder_append(sb, qualifier_names[i]))
			return &drgn_enomem;
		first = false;
	}
	return NULL;
}

static struct drgn_error *
c_declare_basic(struct drgn_qualified_type qualified_type,
		struct string_callback *name, size_t indent,
		struct string_builder *sb)
{
	struct drgn_error *err;

	if (!append_tabs(indent, sb))
		return &drgn_enomem;
	if (qualified_type.qualifiers) {
		err = c_append_qualifiers(qualified_type.qualifiers, sb);
		if (err)
			return err;
		if (!string_builder_appendc(sb, ' '))
			return &drgn_enomem;
	}
	if (!string_builder_append(sb,
				   drgn_type_kind(qualified_type.type) == DRGN_TYPE_VOID ?
				   "void" : drgn_type_name(qualified_type.type)))
		return &drgn_enomem;
	if (name) {
		if (!string_builder_appendc(sb, ' '))
			return &drgn_enomem;
		err = string_callback_call(name, sb);
		if (err)
			return err;
	}
	return NULL;
}

static struct drgn_error *
c_append_tagged_name(struct drgn_qualified_type qualified_type, size_t indent,
		     struct string_builder *sb)
{
	struct drgn_error *err;
	const char *keyword, *tag;

	switch (drgn_type_kind(qualified_type.type)) {
	case DRGN_TYPE_STRUCT:
		keyword = "struct";
		break;
	case DRGN_TYPE_UNION:
		keyword = "union";
		break;
	case DRGN_TYPE_CLASS:
		keyword = "class";
		break;
	case DRGN_TYPE_ENUM:
		keyword = "enum";
		break;
	default:
		UNREACHABLE();
	}

	if (!append_tabs(indent, sb))
		return &drgn_enomem;
	if (qualified_type.qualifiers) {
		err = c_append_qualifiers(qualified_type.qualifiers, sb);
		if (err)
			return err;
		if (!string_builder_appendc(sb, ' '))
			return &drgn_enomem;
	}
	if (!string_builder_append(sb, keyword))
		return &drgn_enomem;

	tag = drgn_type_tag(qualified_type.type);
	if (tag) {
		if (!string_builder_appendc(sb, ' ') ||
		    !string_builder_append(sb, tag))
			return &drgn_enomem;
	}

	return NULL;
}

static struct drgn_error *
c_declare_tagged(struct drgn_qualified_type qualified_type,
		 struct string_callback *name, size_t indent,
		 bool define_anonymous_type, struct string_builder *sb)
{
	struct drgn_error *err;

	bool anonymous = drgn_type_is_anonymous(qualified_type.type);
	if (anonymous && define_anonymous_type)
		err = c_define_type(qualified_type, indent, sb);
	else
		err = c_append_tagged_name(qualified_type, indent, sb);
	if (err)
		return err;
	if (anonymous && !define_anonymous_type &&
	    !string_builder_append(sb, " <anonymous>"))
		return &drgn_enomem;

	if (name) {
		if (!string_builder_appendc(sb, ' '))
			return &drgn_enomem;
		err = string_callback_call(name, sb);
		if (err)
			return err;
	}
	return NULL;
}

static struct drgn_error *c_pointer_name(struct string_callback *name,
					 void *arg, struct string_builder *sb)
{
	struct drgn_error *err;
	struct drgn_qualified_type *qualified_type = arg;
	struct drgn_qualified_type referenced_type;
	enum drgn_type_kind referenced_kind;
	bool parenthesize;

	referenced_type = drgn_type_type(qualified_type->type);
	referenced_kind = drgn_type_kind(referenced_type.type);
	parenthesize = (referenced_kind == DRGN_TYPE_ARRAY ||
			referenced_kind == DRGN_TYPE_FUNCTION);
	if (parenthesize && !string_builder_appendc(sb, '('))
		return &drgn_enomem;

	if (!string_builder_appendc(sb, '*'))
		return &drgn_enomem;
	if (qualified_type->qualifiers) {
		if (!string_builder_appendc(sb, ' '))
			return &drgn_enomem;
		err = c_append_qualifiers(qualified_type->qualifiers, sb);
		if (err)
			return err;
		if (name) {
			if (!string_builder_appendc(sb, ' '))
				return &drgn_enomem;
		}
	}

	err = string_callback_call(name, sb);
	if (err)
		return err;

	if (parenthesize && !string_builder_appendc(sb, ')'))
		return &drgn_enomem;
	return NULL;
}

static struct drgn_error *
c_declare_pointer(struct drgn_qualified_type qualified_type,
		  struct string_callback *name, size_t indent,
		  struct string_builder *sb)
{
	struct string_callback pointer_name = {
		.fn = c_pointer_name,
		.str = name,
		.arg = &qualified_type,
	};
	struct drgn_qualified_type referenced_type;

	referenced_type = drgn_type_type(qualified_type.type);
	return c_declare_variable(referenced_type, &pointer_name, indent, false,
				  sb);
}

static struct drgn_error *c_array_name(struct string_callback *name, void *arg,
				       struct string_builder *sb)
{
	struct drgn_error *err;
	struct drgn_qualified_type *qualified_type = arg;

	err = string_callback_call(name, sb);
	if (err)
		return err;

	if (drgn_type_is_complete(qualified_type->type)) {
		uint64_t length = drgn_type_length(qualified_type->type);

		if (!string_builder_appendf(sb, "[%" PRIu64 "]", length))
			return &drgn_enomem;
	} else {
		if (!string_builder_append(sb, "[]"))
			return &drgn_enomem;
	}
	return NULL;
}

static struct drgn_error *
c_declare_array(struct drgn_qualified_type qualified_type,
		struct string_callback *name, size_t indent,
		struct string_builder *sb)
{
	struct string_callback array_name = {
		.fn = c_array_name,
		.str = name,
		.arg = &qualified_type,
	};
	struct drgn_qualified_type element_type;

	element_type = drgn_type_type(qualified_type.type);
	return c_declare_variable(element_type, &array_name, indent, false, sb);
}

static struct drgn_error *
c_declare_function(struct drgn_qualified_type qualified_type,
		   struct string_callback *name, size_t indent,
		   struct string_builder *sb)
{
	struct drgn_error *err;
	struct drgn_type_parameter *parameters;
	size_t num_parameters, i;
	struct drgn_qualified_type return_type;

	if (!name) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "function must have name");
	}

	parameters = drgn_type_parameters(qualified_type.type);
	num_parameters = drgn_type_num_parameters(qualified_type.type);

	return_type = drgn_type_type(qualified_type.type);
	err = c_declare_variable(return_type, name, indent, false, sb);
	if (err)
		return err;

	if (!string_builder_appendc(sb, '('))
		return &drgn_enomem;

	for (i = 0; i < num_parameters; i++) {
		const char *parameter_name = parameters[i].name;
		struct drgn_qualified_type parameter_type;
		struct string_callback name_cb = {
			.fn = c_variable_name,
			.arg = (void *)parameter_name,
		};

		err = drgn_parameter_type(&parameters[i], &parameter_type);
		if (err)
			return err;

		if (i > 0)  {
			if (!string_builder_append(sb, ", "))
				return &drgn_enomem;
		}
		err = c_declare_variable(parameter_type,
					 parameter_name && parameter_name[0] ?
					 &name_cb : NULL, 0, false, sb);
		if (err)
			return err;
	}
	if (num_parameters && drgn_type_is_variadic(qualified_type.type)) {
		if (!string_builder_append(sb, ", ..."))
			return &drgn_enomem;
	} else if (!num_parameters &&
		   !drgn_type_is_variadic(qualified_type.type)) {
		if (!string_builder_append(sb, "void"))
			return &drgn_enomem;
	}

	if (!string_builder_appendc(sb, ')'))
		return &drgn_enomem;
	return NULL;
}

static struct drgn_error *
c_declare_variable(struct drgn_qualified_type qualified_type,
		   struct string_callback *name, size_t indent,
		   bool define_anonymous_type, struct string_builder *sb)
{
	SWITCH_ENUM(drgn_type_kind(qualified_type.type),
	case DRGN_TYPE_VOID:
	case DRGN_TYPE_INT:
	case DRGN_TYPE_BOOL:
	case DRGN_TYPE_FLOAT:
	case DRGN_TYPE_TYPEDEF:
		return c_declare_basic(qualified_type, name, indent, sb);
	case DRGN_TYPE_STRUCT:
	case DRGN_TYPE_UNION:
	case DRGN_TYPE_CLASS:
	case DRGN_TYPE_ENUM:
		return c_declare_tagged(qualified_type, name, indent,
					define_anonymous_type, sb);
	case DRGN_TYPE_POINTER:
		return c_declare_pointer(qualified_type, name, indent, sb);
	case DRGN_TYPE_ARRAY:
		return c_declare_array(qualified_type, name, indent, sb);
	case DRGN_TYPE_FUNCTION:
		return c_declare_function(qualified_type, name, indent, sb);
	)
}

static struct drgn_error *
c_define_compound(struct drgn_qualified_type qualified_type, size_t indent,
		  struct string_builder *sb)
{
	struct drgn_error *err;
	struct drgn_type_member *members;
	size_t num_members, i;

	if (!drgn_type_is_complete(qualified_type.type)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "cannot get definition of incomplete compound type");
	}

	members = drgn_type_members(qualified_type.type);
	num_members = drgn_type_num_members(qualified_type.type);

	err = c_append_tagged_name(qualified_type, indent, sb);
	if (err)
		return err;
	if (!string_builder_append(sb, " {\n"))
		return &drgn_enomem;

	for (i = 0; i < num_members; i++) {
		struct drgn_qualified_type member_type;
		uint64_t member_bit_field_size;
		err = drgn_member_type(&members[i], &member_type,
				       &member_bit_field_size);
		if (err)
			return err;

		const char *member_name = members[i].name;
		struct string_callback name_cb = {
			.fn = c_variable_name,
			.arg = (void *)member_name,
		};
		err = c_declare_variable(member_type,
					 member_name && member_name[0] ?
					 &name_cb : NULL, indent + 1, true, sb);
		if (err)
			return err;
		if (member_bit_field_size &&
		    !string_builder_appendf(sb, " : %" PRIu64,
					    member_bit_field_size))
				return &drgn_enomem;
		if (!string_builder_append(sb, ";\n"))
			return &drgn_enomem;
	}

	if (!append_tabs(indent, sb) || !string_builder_appendc(sb, '}'))
		return &drgn_enomem;
	return NULL;
}

static struct drgn_error *
c_define_enum(struct drgn_qualified_type qualified_type, size_t indent,
	      struct string_builder *sb)
{
	struct drgn_error *err;
	const struct drgn_type_enumerator *enumerators;
	size_t num_enumerators, i;
	bool is_signed;

	if (!drgn_type_is_complete(qualified_type.type)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "cannot get definition of incomplete enum type");
	}

	enumerators = drgn_type_enumerators(qualified_type.type);
	num_enumerators = drgn_type_num_enumerators(qualified_type.type);

	err = c_append_tagged_name(qualified_type, indent, sb);
	if (err)
		return err;
	if (!string_builder_append(sb, " {\n"))
		return &drgn_enomem;

	is_signed = drgn_enum_type_is_signed(qualified_type.type);
	for (i = 0; i < num_enumerators; i++) {
		if (!append_tabs(indent + 1, sb) ||
		    !string_builder_append(sb, enumerators[i].name) ||
		    !string_builder_append(sb, " = "))
			return &drgn_enomem;
		if (is_signed) {
			if (!string_builder_appendf(sb, "%" PRId64 ",\n",
						    enumerators[i].svalue))
				return &drgn_enomem;
		} else {
			if (!string_builder_appendf(sb, "%" PRIu64 ",\n",
						    enumerators[i].uvalue))
				return &drgn_enomem;
		}
	}

	if (!append_tabs(indent, sb) || !string_builder_appendc(sb, '}'))
		return &drgn_enomem;
	return NULL;
}

static struct drgn_error *
c_define_typedef(struct drgn_qualified_type qualified_type, size_t indent,
		 struct string_builder *sb)
{
	struct string_callback typedef_name = {
		.fn = c_variable_name,
		.arg = (char *)drgn_type_name(qualified_type.type),
	};
	struct drgn_qualified_type aliased_type;
	struct drgn_error *err;

	if (!append_tabs(indent, sb))
		return &drgn_enomem;
	if (qualified_type.qualifiers) {
		err = c_append_qualifiers(qualified_type.qualifiers, sb);
		if (err)
			return err;
		if (!string_builder_appendc(sb, ' '))
			return &drgn_enomem;
	}
	if (!string_builder_append(sb, "typedef "))
		return &drgn_enomem;

	aliased_type = drgn_type_type(qualified_type.type);
	return c_declare_variable(aliased_type, &typedef_name, 0, true, sb);
}

static struct drgn_error *
c_define_type(struct drgn_qualified_type qualified_type, size_t indent,
	      struct string_builder *sb)
{
	SWITCH_ENUM(drgn_type_kind(qualified_type.type),
	case DRGN_TYPE_VOID:
	case DRGN_TYPE_INT:
	case DRGN_TYPE_BOOL:
	case DRGN_TYPE_FLOAT:
		return c_declare_basic(qualified_type, NULL, indent, sb);
	case DRGN_TYPE_STRUCT:
	case DRGN_TYPE_UNION:
	case DRGN_TYPE_CLASS:
		return c_define_compound(qualified_type, indent, sb);
	case DRGN_TYPE_ENUM:
		return c_define_enum(qualified_type, indent, sb);
	case DRGN_TYPE_TYPEDEF:
		return c_define_typedef(qualified_type, indent, sb);
	case DRGN_TYPE_POINTER:
		return c_declare_pointer(qualified_type, NULL, indent, sb);
	case DRGN_TYPE_ARRAY:
		return c_declare_array(qualified_type, NULL, indent, sb);
	case DRGN_TYPE_FUNCTION:
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "function type cannot be formatted");
	)
}

static struct drgn_error *
c_format_type_name_impl(struct drgn_qualified_type qualified_type,
			struct string_builder *sb)
{
	if (drgn_type_kind(qualified_type.type) == DRGN_TYPE_FUNCTION) {
		struct string_callback name_cb = {
			.fn = c_variable_name,
			.arg = (void *)"",
		};

		return c_declare_function(qualified_type, &name_cb, 0, sb);
	} else {
		return c_declare_variable(qualified_type, NULL, 0, false, sb);
	}
}

struct drgn_error *c_format_type_name(struct drgn_qualified_type qualified_type,
				      char **ret)
{
	struct drgn_error *err;
	struct string_builder sb = {};

	err = c_format_type_name_impl(qualified_type, &sb);
	if (err) {
		free(sb.str);
		return err;
	}
	if (!string_builder_finalize(&sb, ret))
		return &drgn_enomem;
	return NULL;
}

struct drgn_error *c_format_type(struct drgn_qualified_type qualified_type,
				 char **ret)
{
	struct drgn_error *err;
	struct string_builder sb = {};

	if (drgn_type_is_complete(qualified_type.type))
		err = c_define_type(qualified_type, 0, &sb);
	else
		err = c_format_type_name_impl(qualified_type, &sb);
	if (err) {
		free(sb.str);
		return err;
	}
	if (!string_builder_finalize(&sb, ret))
		return &drgn_enomem;
	return NULL;
}

static struct drgn_error *
c_format_object_impl(const struct drgn_object *obj, size_t indent,
		     size_t one_line_columns, size_t multi_line_columns,
		     enum drgn_format_object_flags flags,
		     struct string_builder *sb);

static bool is_character_type(struct drgn_type *type)
{
	switch (drgn_type_primitive(type)) {
	case DRGN_C_TYPE_CHAR:
	case DRGN_C_TYPE_SIGNED_CHAR:
	case DRGN_C_TYPE_UNSIGNED_CHAR:
		return true;
	default:
		return false;
	}
}

static struct drgn_error *
c_format_character(unsigned char c, bool escape_single_quote,
		   bool escape_double_quote, struct string_builder *sb)
{
	bool ret;

	switch (c) {
	case '\0':
		ret = string_builder_append(sb, "\\0");
		break;
	case '\a':
		ret = string_builder_append(sb, "\\a");
		break;
	case '\b':
		ret = string_builder_append(sb, "\\b");
		break;
	case '\t':
		ret = string_builder_append(sb, "\\t");
		break;
	case '\n':
		ret = string_builder_append(sb, "\\n");
		break;
	case '\v':
		ret = string_builder_append(sb, "\\v");
		break;
	case '\f':
		ret = string_builder_append(sb, "\\f");
		break;
	case '\r':
		ret = string_builder_append(sb, "\\r");
		break;
	case '"':
		if (!escape_double_quote)
			goto no_escape;
		ret = string_builder_append(sb, "\\\"");
		break;
	case '\'':
		if (!escape_single_quote)
			goto no_escape;
		ret = string_builder_append(sb, "\\'");
		break;
	case '\\':
		ret = string_builder_append(sb, "\\\\");
		break;
	default:
		if (c <= '\x1f' || c >= '\x7f') {
			ret = string_builder_appendf(sb, "\\x%02x", c);
		} else {
no_escape:
			ret = string_builder_appendc(sb, c);
		}
		break;
	}
	return ret ? NULL : &drgn_enomem;
}

static struct drgn_error *
c_format_string(struct drgn_program *prog, uint64_t address, uint64_t length,
		struct string_builder *sb)
{
	struct drgn_error *err;

	if (!string_builder_appendc(sb, '"'))
		return &drgn_enomem;
	while (length) {
		unsigned char c;
		err = drgn_program_read_memory(prog, &c, address++, 1, false);
		if (err)
			return err;

		if (c == '\0') {
			break;
		} else {
			err = c_format_character(c, false, true, sb);
			if (err)
				return err;
		}
		length--;
	}
	if (!string_builder_appendc(sb, '"'))
		return &drgn_enomem;
	return NULL;
}

static struct drgn_error *
c_format_int_object(const struct drgn_object *obj,
		    enum drgn_format_object_flags flags,
		    struct string_builder *sb)
{
	struct drgn_error *err;

	if ((flags & DRGN_FORMAT_OBJECT_CHAR) && is_character_type(obj->type)) {
		union drgn_value value;

		if (!string_builder_appendc(sb, '\''))
			return &drgn_enomem;
		err = drgn_object_read_integer(obj, &value);
		if (err)
			return err;
		err = c_format_character(value.uvalue, true, false, sb);
		if (err)
			return err;
		if (!string_builder_appendc(sb, '\''))
			return &drgn_enomem;
		return NULL;
	}

	switch (obj->encoding) {
	case DRGN_OBJECT_ENCODING_SIGNED: {
		int64_t svalue;

		err = drgn_object_read_signed(obj, &svalue);
		if (err)
			return err;
		if (!string_builder_appendf(sb, "%" PRId64, svalue))
			return &drgn_enomem;
		return NULL;
	}
	case DRGN_OBJECT_ENCODING_UNSIGNED: {
		uint64_t uvalue;

		err = drgn_object_read_unsigned(obj, &uvalue);
		if (err)
			return err;
		if (!string_builder_appendf(sb, "%" PRIu64, uvalue))
			return &drgn_enomem;
		return NULL;
	}
	default:
		UNREACHABLE();
	}
}

static struct drgn_error *
c_format_float_object(const struct drgn_object *obj, struct string_builder *sb)
{
	struct drgn_error *err;
	double fvalue;

	err = drgn_object_read_float(obj, &fvalue);
	if (err)
		return err;
	if (rint(fvalue) == fvalue) {
		if (!string_builder_appendf(sb, "%.1f", fvalue))
			return &drgn_enomem;
	} else {
		if (!string_builder_appendf(sb, "%.*g", DBL_DECIMAL_DIG,
					    fvalue))
			return &drgn_enomem;
	}
	return NULL;
}

static struct drgn_error drgn_line_wrap = {
	.code = DRGN_ERROR_STOP,
	.message = "needs line wrap",
};

struct initializer_iter {
	struct drgn_error *(*next)(struct initializer_iter *,
				   struct drgn_object *,
				   enum drgn_format_object_flags *);
	void (*reset)(struct initializer_iter *);
	struct drgn_error *(*append_designation)(struct initializer_iter *,
						 struct string_builder *);
};

static struct drgn_error *c_format_initializer(struct drgn_program *prog,
					       struct initializer_iter *iter,
					       size_t indent,
					       size_t one_line_columns,
					       size_t multi_line_columns,
					       bool same_line,
					       struct string_builder *sb)
{
	struct drgn_error *err;
	struct drgn_object obj;
	enum drgn_format_object_flags initializer_flags;
	size_t brace, remaining_columns, start_columns;

	drgn_object_init(&obj, prog);

	/* First, try to fit everything on one line. */
	brace = sb->len;
	if (!string_builder_appendc(sb, '{')) {
		err = &drgn_enomem;
		goto out;
	}
	if (__builtin_sub_overflow(one_line_columns, 1, &remaining_columns))
		remaining_columns = 0;
	for (;;) {
		size_t initializer_start;

		err = iter->next(iter, &obj, &initializer_flags);
		if (err == &drgn_stop)
			break;
		else if (err)
			goto out;

		if (!same_line) {
			err = &drgn_line_wrap;
			break;
		} else if (sb->len == brace + 1) {
			if (remaining_columns < 3) {
				/*
				 * The preceding space and closing space and
				 * brace don't fit.
				 */
				err = &drgn_line_wrap;
				break;
			}
			if (!string_builder_appendc(sb, ' ')) {
				err = &drgn_enomem;
				goto out;
			}
			remaining_columns--;
		} else {
			if (remaining_columns < 4) {
				/*
				 * The preceding comma and space and closing
				 * space and brace don't fit.
				 */
				err = &drgn_line_wrap;
				break;
			}
			if (!string_builder_append(sb, ", ")) {
				err = &drgn_enomem;
				goto out;
			}
			remaining_columns -= 2;
		}

		if (iter->append_designation) {
			size_t designation_start = sb->len;

			err = iter->append_designation(iter, sb);
			if (err)
				goto out;
			if (__builtin_sub_overflow(remaining_columns,
						   sb->len - designation_start,
						   &remaining_columns)) {
				err = &drgn_line_wrap;
				break;
			}
		}

		initializer_start = sb->len;
		err = c_format_object_impl(&obj, indent + 1,
					   remaining_columns - 2, 0,
					   initializer_flags, sb);
		if (err == &drgn_line_wrap)
			break;
		else if (err)
			goto out;

		if (__builtin_sub_overflow(remaining_columns,
					   sb->len - initializer_start,
					   &remaining_columns)) {
			err = &drgn_line_wrap;
			break;
		}
	}
	if (err != &drgn_line_wrap) {
		/* All of the initializers fit. */
		if (sb->len == brace + 1) {
			/* There were no initializers. */
			if (string_builder_appendc(sb, '}'))
				err = NULL;
			else
				err = &drgn_enomem;
			goto out;
		} else if (remaining_columns >= 2) {
			if (string_builder_append(sb, " }"))
				err = NULL;
			else
				err = &drgn_enomem;
			goto out;
		}
		/* The final space and closing brace didn't fit. */
	}

	/* It didn't fit on one line. Try multiple lines. */

	if (multi_line_columns == 0) {
		/* We were asked to stay on one line. */
		err = &drgn_line_wrap;
		goto out;
	}

	sb->len = brace + 1;
	if (__builtin_sub_overflow(multi_line_columns, 8 * (indent + 1),
				   &start_columns))
		start_columns = 0;
	remaining_columns = 0;
	iter->reset(iter);
	for (;;) {
		size_t newline, designation_start, line_columns;

		err = iter->next(iter, &obj, &initializer_flags);
		if (err == &drgn_stop)
			break;
		else if (err)
			goto out;

		newline = sb->len;
		if (!string_builder_appendc(sb, '\n') ||
		    !append_tabs(indent + 1, sb)) {
			err = &drgn_enomem;
			goto out;
		}

		designation_start = sb->len;
		line_columns = start_columns;
		if (iter->append_designation) {
			err = iter->append_designation(iter, sb);
			if (err)
				goto out;
			if (__builtin_sub_overflow(line_columns,
						   sb->len - designation_start,
						   &line_columns))
				line_columns = 0;
		}

		if (line_columns > 1) {
			size_t initializer_start = sb->len;

			err = c_format_object_impl(&obj, 0, line_columns - 1,
						   0, initializer_flags, sb);
			if (!err) {
				size_t len = sb->len - designation_start;

				if (same_line && len + 2 <= remaining_columns) {
					/*
					 * It would've fit on the previous line.
					 * Move it over.
					 */
					sb->str[newline] = ' ';
					memmove(&sb->str[newline + 1],
						&sb->str[designation_start],
						len);
					sb->len = newline + 1 + len;
					if (!string_builder_appendc(sb, ',')) {
						err = &drgn_enomem;
						goto out;
					}
					remaining_columns -= len + 2;
					continue;
				}
				if (len < start_columns) {
					/* It fit on the new line. */
					if (!string_builder_appendc(sb, ',')) {
						err = &drgn_enomem;
						goto out;
					}
					remaining_columns =
						start_columns - len - 1;
					continue;
				}
			} else if (err != &drgn_line_wrap) {
				goto out;
			}
			/* It didn't fit. */
			sb->len = initializer_start;
		}

		err = c_format_object_impl(&obj, indent + 1, 0,
					   multi_line_columns,
					   initializer_flags, sb);
		if (err)
			goto out;
		if (!string_builder_appendc(sb, ',')) {
			err = &drgn_enomem;
			goto out;
		}
		remaining_columns = 0;
	}

	if (!string_builder_appendc(sb, '\n') || !append_tabs(indent, sb) ||
	    !string_builder_appendc(sb, '}')) {
		err = &drgn_enomem;
		goto out;
	}
	err = NULL;
out:
	drgn_object_deinit(&obj);
	return err;
}

struct compound_initializer_state {
	struct drgn_type_member *member, *end;
	uint64_t bit_offset;
};

DEFINE_VECTOR(compound_initializer_stack, struct compound_initializer_state)

struct compound_initializer_iter {
	struct initializer_iter iter;
	const struct drgn_object *obj;
	struct compound_initializer_stack stack;
	enum drgn_format_object_flags flags, member_flags;
};

static struct drgn_error *
compound_initializer_iter_next(struct initializer_iter *iter_,
			       struct drgn_object *obj_ret,
			       enum drgn_format_object_flags *flags_ret)
{
	struct drgn_error *err;
	struct compound_initializer_iter *iter =
		container_of(iter_, struct compound_initializer_iter, iter);

	for (;;) {
		if (!iter->stack.size)
			return &drgn_stop;

		struct compound_initializer_state *top =
			&iter->stack.data[iter->stack.size - 1];
		if (top->member == top->end) {
			iter->stack.size--;
			continue;
		}

		uint64_t bit_offset = top->bit_offset;
		struct drgn_type_member *member = top->member++;
		struct drgn_qualified_type member_type;
		uint64_t member_bit_field_size;
		err = drgn_member_type(member, &member_type,
				       &member_bit_field_size);
		if (err)
			return err;

		/*
		 * If the member is named or we are not including names, return
		 * it. Otherwise, if it has members, descend into it. If it
		 * doesn't, then this isn't valid C, but let's return it
		 * anyways.
		 */
		if (member->name ||
		    !(iter->flags & DRGN_FORMAT_OBJECT_MEMBER_NAMES) ||
		    !drgn_type_has_members(member_type.type)) {
			err = drgn_object_slice(obj_ret, iter->obj, member_type,
						bit_offset + member->bit_offset,
						member_bit_field_size);
			if (err)
				return err;

			/* If we're including names, we can skip zeroes. */
			if ((iter->flags & (DRGN_FORMAT_OBJECT_MEMBER_NAMES |
					    DRGN_FORMAT_OBJECT_IMPLICIT_MEMBERS)) ==
			     DRGN_FORMAT_OBJECT_MEMBER_NAMES) {
				bool zero;

				err = drgn_object_is_zero(obj_ret, &zero);
				if (err)
					return err;
				if (zero)
					continue;
			}
			break;
		}

		struct compound_initializer_state *new =
			compound_initializer_stack_append_entry(&iter->stack);
		if (!new)
			return &drgn_enomem;
		new->member = drgn_type_members(member_type.type);
		new->end = new->member + drgn_type_num_members(member_type.type);
		new->bit_offset = bit_offset + member->bit_offset;
	}

	*flags_ret = iter->member_flags;
	return NULL;
}

static void compound_initializer_iter_reset(struct initializer_iter *iter_)
{
	struct compound_initializer_iter *iter =
		container_of(iter_, struct compound_initializer_iter, iter);
	struct drgn_type *underlying_type =
		drgn_underlying_type(iter->obj->type);

	iter->stack.size = 1;
	iter->stack.data[0].member = drgn_type_members(underlying_type);
}

static struct drgn_error *
compound_initializer_append_designation(struct initializer_iter *iter_,
				       struct string_builder *sb)
{
	struct compound_initializer_iter *iter =
		container_of(iter_, struct compound_initializer_iter, iter);
	struct compound_initializer_state *top =
		&iter->stack.data[iter->stack.size - 1];
	const char *name = top->member[-1].name;

	if (name && !string_builder_appendf(sb, ".%s = ", name))
		return &drgn_enomem;
	return NULL;
}

static struct drgn_error *
c_format_compound_object(const struct drgn_object *obj,
			 struct drgn_type *underlying_type, size_t indent,
			 size_t one_line_columns, size_t multi_line_columns,
			 enum drgn_format_object_flags flags,
			 struct string_builder *sb)
{
	struct drgn_error *err;

	if (!drgn_type_is_complete(underlying_type)) {
		const char *keyword;

		switch (drgn_type_kind(underlying_type)) {
		case DRGN_TYPE_STRUCT:
			keyword = "struct";
			break;
		case DRGN_TYPE_UNION:
			keyword = "union";
			break;
		case DRGN_TYPE_CLASS:
			keyword = "class";
			break;
		default:
			UNREACHABLE();
		}
		return drgn_error_format(DRGN_ERROR_TYPE,
					 "cannot format incomplete %s object",
					 keyword);
	}

	struct compound_initializer_iter iter = {
		.iter = {
			.next = compound_initializer_iter_next,
			.reset = compound_initializer_iter_reset,
			.append_designation =
				flags & DRGN_FORMAT_OBJECT_MEMBER_NAMES ?
				compound_initializer_append_designation : NULL,
		},
		.obj = obj,
		.stack = VECTOR_INIT,
		.flags = flags,
		.member_flags = drgn_member_format_object_flags(flags),
	};
	struct compound_initializer_state *new =
		compound_initializer_stack_append_entry(&iter.stack);
	if (!new) {
		err = &drgn_enomem;
		goto out;
	}
	new->member = drgn_type_members(underlying_type);
	new->end = add_to_possibly_null_pointer(new->member,
						drgn_type_num_members(underlying_type));
	new->bit_offset = 0;

	/*
	 * If we don't want zero members, ignore any at the end. If we're
	 * including member names, then we'll skip past zero members as we
	 * iterate, so we don't need to do this.
	 */
	if (!(flags & (DRGN_FORMAT_OBJECT_MEMBER_NAMES |
		       DRGN_FORMAT_OBJECT_IMPLICIT_MEMBERS)) &&
	    new->member < new->end) {
		struct drgn_object member;
		drgn_object_init(&member, drgn_object_program(obj));
		do {
			struct drgn_qualified_type member_type;
			uint64_t member_bit_field_size;
			err = drgn_member_type(&new->end[-1], &member_type,
					       &member_bit_field_size);
			if (err)
				break;

			err = drgn_object_slice(&member, obj, member_type,
						new->end[-1].bit_offset,
						member_bit_field_size);
			if (err)
				break;

			bool zero;
			err = drgn_object_is_zero(&member, &zero);
			if (err)
				break;
			if (zero)
				new->end--;
			else
				break;
		} while (new->member < new->end);
		drgn_object_deinit(&member);
		if (err)
			return err;
	}

	err = c_format_initializer(drgn_object_program(obj), &iter.iter, indent,
				   one_line_columns, multi_line_columns,
				   flags & DRGN_FORMAT_OBJECT_MEMBERS_SAME_LINE,
				   sb);
out:
	compound_initializer_stack_deinit(&iter.stack);
	return err;
}

static struct drgn_error *
c_format_enum_object(const struct drgn_object *obj,
		     struct drgn_type *underlying_type,
		     struct string_builder *sb)
{
	struct drgn_error *err;
	struct drgn_type_enumerator *enumerators;
	size_t num_enumerators, i;

	if (!drgn_type_is_complete(underlying_type)) {
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "cannot format incomplete enum object");
	}

	enumerators = drgn_type_enumerators(underlying_type);
	num_enumerators = drgn_type_num_enumerators(underlying_type);
	if (drgn_enum_type_is_signed(underlying_type)) {
		int64_t svalue;

		err = drgn_object_read_signed(obj, &svalue);
		if (err)
			return err;
		for (i = 0; i < num_enumerators; i++) {
			if (enumerators[i].svalue == svalue) {
				if (!string_builder_append(sb,
							   enumerators[i].name))
					return &drgn_enomem;
				return NULL;
			}
		}
		if (!string_builder_appendf(sb, "%" PRId64, svalue))
			return &drgn_enomem;
		return NULL;
	} else {
		uint64_t uvalue;

		err = drgn_object_read_unsigned(obj, &uvalue);
		if (err)
			return err;
		for (i = 0; i < num_enumerators; i++) {
			if (enumerators[i].uvalue == uvalue) {
				if (!string_builder_append(sb,
							   enumerators[i].name))
					return &drgn_enomem;
				return NULL;
			}
		}
		if (!string_builder_appendf(sb, "%" PRIu64, uvalue))
			return &drgn_enomem;
		return NULL;
	}
}

static struct drgn_error *
c_format_pointer_object(const struct drgn_object *obj,
			struct drgn_type *underlying_type,
			size_t indent, size_t one_line_columns,
			size_t multi_line_columns,
			enum drgn_format_object_flags flags,
			struct string_builder *sb)
{
	struct drgn_error *err;
	enum drgn_format_object_flags passthrough_flags =
		drgn_passthrough_format_object_flags(flags);
	bool dereference = flags & DRGN_FORMAT_OBJECT_DEREFERENCE;
	bool c_string =
		((flags & DRGN_FORMAT_OBJECT_STRING) &&
		 is_character_type(drgn_type_type(underlying_type).type));
	bool have_symbol;
	uint64_t uvalue;
	struct drgn_symbol sym;
	size_t start, type_start, type_end, value_start, value_end;

	start = sb->len;
	if (dereference && !c_string && !string_builder_appendc(sb, '*'))
		return &drgn_enomem;
	type_start = sb->len;
	if (flags & DRGN_FORMAT_OBJECT_TYPE_NAME) {
		if (!string_builder_appendc(sb, '('))
			return &drgn_enomem;
		err = c_format_type_name_impl(drgn_object_qualified_type(obj),
					      sb);
		if (err)
			return err;
		if (!string_builder_appendc(sb, ')'))
			return &drgn_enomem;

	}
	type_end = sb->len;

	err = drgn_object_read_unsigned(obj, &uvalue);
	if (err)
		return err;

	have_symbol = ((flags & DRGN_FORMAT_OBJECT_SYMBOLIZE) &&
		       drgn_program_find_symbol_by_address_internal(drgn_object_program(obj),
								    uvalue,
								    NULL,
								    &sym));
	if (have_symbol && dereference && !c_string &&
	    !string_builder_appendc(sb, '('))
		return &drgn_enomem;
	value_start = sb->len;
	if (have_symbol &&
	     !string_builder_appendf(sb, "%s+0x%" PRIx64 " = ", sym.name,
				     uvalue - sym.address))
		return &drgn_enomem;

	if (!string_builder_appendf(sb, "0x%" PRIx64, uvalue))
		return &drgn_enomem;
	if (!dereference && !c_string)
		return NULL;
	value_end = sb->len;

	if ((have_symbol && dereference && !c_string &&
	     !string_builder_appendc(sb, ')')) ||
	    !string_builder_append(sb, " = "))
		return &drgn_enomem;

	if (c_string) {
		err = c_format_string(drgn_object_program(obj), uvalue,
				      UINT64_MAX, sb);
	} else {
		struct drgn_object dereferenced;

		drgn_object_init(&dereferenced, drgn_object_program(obj));
		err = drgn_object_dereference(&dereferenced, obj);
		if (err) {
			drgn_object_deinit(&dereferenced);
			if (err->code == DRGN_ERROR_TYPE)
				goto no_dereference;
			return err;
		}
		if (__builtin_sub_overflow(one_line_columns, sb->len - start,
					   &one_line_columns))
			one_line_columns = 0;
		err = c_format_object_impl(&dereferenced, indent,
					   one_line_columns, multi_line_columns,
					   passthrough_flags, sb);
		drgn_object_deinit(&dereferenced);
	}
	if (!err || (err->code != DRGN_ERROR_FAULT && err->code != DRGN_ERROR_OUT_OF_BOUNDS)) {
		/* We either succeeded or hit a fatal error. */
		return err;
	}

no_dereference:
	/*
	 * We hit a non-fatal error. Delete the asterisk and symbol parentheses
	 * and truncate everything after the address.
	 */
	drgn_error_destroy(err);
	if (type_start != start) {
		memmove(&sb->str[start], &sb->str[type_start],
			type_end - type_start);
	}
	if (start + type_end - type_start != value_start) {
		memmove(&sb->str[start + type_end - type_start],
			&sb->str[value_start], value_end - value_start);
	}
	sb->len = start + type_end - type_start + value_end - value_start;
	return NULL;
}

struct array_initializer_iter {
	struct initializer_iter iter;
	const struct drgn_object *obj;
	struct drgn_qualified_type element_type;
	uint64_t element_bit_size;
	uint64_t length, i;
	enum drgn_format_object_flags flags, element_flags;
};

static struct drgn_error *
array_initializer_iter_next(struct initializer_iter *iter_,
			    struct drgn_object *obj_ret,
			    enum drgn_format_object_flags *flags_ret)
{
	struct drgn_error *err;
	struct array_initializer_iter *iter =
		container_of(iter_, struct array_initializer_iter, iter);

	for (;;) {
		bool zero;

		if (iter->i >= iter->length)
			return &drgn_stop;
		err = drgn_object_slice(obj_ret, iter->obj, iter->element_type,
					iter->i * iter->element_bit_size, 0);
		if (err)
			return err;
		iter->i++;

		/* If we're including indices, we can skip zeroes. */
		if ((iter->flags & (DRGN_FORMAT_OBJECT_ELEMENT_INDICES |
				    DRGN_FORMAT_OBJECT_IMPLICIT_ELEMENTS)) !=
		    DRGN_FORMAT_OBJECT_ELEMENT_INDICES)
			break;

		err = drgn_object_is_zero(obj_ret, &zero);
		if (err)
			return err;
		if (!zero)
			break;
	}
	*flags_ret = iter->element_flags;
	return NULL;
}

static void array_initializer_iter_reset(struct initializer_iter *iter_)
{
	struct array_initializer_iter *iter =
		container_of(iter_, struct array_initializer_iter, iter);

	iter->i = 0;
}

static struct drgn_error *
array_initializer_append_designation(struct initializer_iter *iter_,
				     struct string_builder *sb)
{
	struct array_initializer_iter *iter =
		container_of(iter_, struct array_initializer_iter, iter);

	if (!string_builder_appendf(sb, "[%" PRIu64 "] = ", iter->i - 1))
		return &drgn_enomem;
	return NULL;
}

static struct drgn_error *
c_format_array_object(const struct drgn_object *obj,
		      struct drgn_type *underlying_type, size_t indent,
		      size_t one_line_columns, size_t multi_line_columns,
		      enum drgn_format_object_flags flags,
		      struct string_builder *sb)
{
	struct drgn_error *err;
	struct array_initializer_iter iter = {
		.iter = {
			.next = array_initializer_iter_next,
			.reset = array_initializer_iter_reset,
			.append_designation =
				flags & DRGN_FORMAT_OBJECT_ELEMENT_INDICES ?
				array_initializer_append_designation : NULL,
		},
		.obj = obj,
		.element_type = drgn_type_type(underlying_type),
		.length = drgn_type_length(underlying_type),
		.flags = flags,
		.element_flags = drgn_element_format_object_flags(flags),
	};

	if ((flags & DRGN_FORMAT_OBJECT_STRING) && iter.length &&
	    is_character_type(iter.element_type.type)) {
		SWITCH_ENUM(obj->kind,
		case DRGN_OBJECT_VALUE: {
			const unsigned char *buf;
			uint64_t size, i;

			if (!string_builder_appendc(sb, '"'))
				return &drgn_enomem;
			buf = (const unsigned char *)drgn_object_buffer(obj);
			size = drgn_object_size(obj);
			for (i = 0; i < size; i++) {
				if (buf[i] == '\0')
					break;
				err = c_format_character(buf[i], false, true,
							 sb);
				if (err)
					return err;
			}
			if (!string_builder_appendc(sb, '"'))
				return &drgn_enomem;
			return NULL;
		}
		case DRGN_OBJECT_REFERENCE:
			return c_format_string(drgn_object_program(obj),
					       obj->address, iter.length, sb);
		case DRGN_OBJECT_ABSENT:
		)
	}

	err = drgn_type_bit_size(iter.element_type.type,
				 &iter.element_bit_size);
	if (err)
		return err;

	/*
	 * If we don't want zero elements, ignore any at the end. If we're
	 * including indices, then we'll skip past zeroes as we iterate, so we
	 * don't need to do this.
	 */
	if (!(flags & (DRGN_FORMAT_OBJECT_ELEMENT_INDICES |
		       DRGN_FORMAT_OBJECT_IMPLICIT_ELEMENTS)) &&
	    iter.length) {
		struct drgn_object element;

		drgn_object_init(&element, drgn_object_program(obj));
		do {
			bool zero;

			err = drgn_object_slice(&element, obj,
						iter.element_type,
						(iter.length - 1) *
						iter.element_bit_size,
						0);
			if (err)
				break;

			err = drgn_object_is_zero(&element, &zero);
			if (err)
				break;
			if (zero)
				iter.length--;
			else
				break;
		} while (iter.length);
		drgn_object_deinit(&element);
		if (err)
			return err;
	}
	return c_format_initializer(drgn_object_program(obj), &iter.iter,
				    indent, one_line_columns,
				    multi_line_columns,
				    flags & DRGN_FORMAT_OBJECT_ELEMENTS_SAME_LINE,
				    sb);
}

static struct drgn_error *
c_format_function_object(const struct drgn_object *obj,
			 struct string_builder *sb)
{
	assert(obj->kind == DRGN_OBJECT_REFERENCE);
	if (!string_builder_appendf(sb, "0x%" PRIx64, obj->address))
		return &drgn_enomem;
	return NULL;
}

static struct drgn_error *
c_format_object_impl(const struct drgn_object *obj, size_t indent,
		     size_t one_line_columns, size_t multi_line_columns,
		     enum drgn_format_object_flags flags,
		     struct string_builder *sb)
{
	struct drgn_error *err;
	struct drgn_type *underlying_type = drgn_underlying_type(obj->type);

	if (drgn_type_kind(underlying_type) == DRGN_TYPE_VOID) {
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "cannot format void object");
	}

	/*
	 * Pointers are special because they can have an asterisk prefix if
	 * we're dereferencing them.
	 */
	if (drgn_type_kind(underlying_type) == DRGN_TYPE_POINTER &&
	    obj->kind != DRGN_OBJECT_ABSENT) {
		return c_format_pointer_object(obj, underlying_type, indent,
					       one_line_columns,
					       multi_line_columns, flags, sb);
	}

	if (flags & DRGN_FORMAT_OBJECT_TYPE_NAME) {
		size_t old_len = sb->len;

		if (!string_builder_appendc(sb, '('))
			return &drgn_enomem;
		err = c_format_type_name_impl(drgn_object_qualified_type(obj),
					      sb);
		if (err)
			return err;
		if (!string_builder_appendc(sb, ')'))
			return &drgn_enomem;

		if (__builtin_sub_overflow(one_line_columns, sb->len - old_len,
					   &one_line_columns))
		    one_line_columns = 0;
	}

	if (obj->kind == DRGN_OBJECT_ABSENT) {
		if (!string_builder_append(sb, "<absent>"))
			return &drgn_enomem;
		return NULL;
	}

	SWITCH_ENUM(drgn_type_kind(underlying_type),
	case DRGN_TYPE_INT:
	case DRGN_TYPE_BOOL:
		return c_format_int_object(obj, flags, sb);
	case DRGN_TYPE_FLOAT:
		return c_format_float_object(obj, sb);
	case DRGN_TYPE_STRUCT:
	case DRGN_TYPE_UNION:
	case DRGN_TYPE_CLASS:
		return c_format_compound_object(obj, underlying_type, indent,
						one_line_columns,
						multi_line_columns, flags, sb);
	case DRGN_TYPE_ENUM:
		return c_format_enum_object(obj, underlying_type, sb);
	case DRGN_TYPE_ARRAY:
		return c_format_array_object(obj, underlying_type, indent,
					     one_line_columns,
					     multi_line_columns, flags, sb);
	case DRGN_TYPE_FUNCTION:
		return c_format_function_object(obj, sb);
	case DRGN_TYPE_VOID:
	case DRGN_TYPE_TYPEDEF:
	case DRGN_TYPE_POINTER:
	)
}

struct drgn_error *c_format_object(const struct drgn_object *obj,
				   size_t columns,
				   enum drgn_format_object_flags flags,
				   char **ret)
{
	struct drgn_error *err;
	struct string_builder sb = {};

	err = c_format_object_impl(obj, 0, columns, max(columns, (size_t)1),
				   flags, &sb);
	if (err) {
		free(sb.str);
		return err;
	}
	if (!string_builder_finalize(&sb, ret))
		return &drgn_enomem;
	return NULL;
}

/* This obviously incomplete since we only handle the tokens we care about. */
enum {
	C_TOKEN_EOF = -1,
	MIN_KEYWORD_TOKEN,
	MIN_SPECIFIER_TOKEN = MIN_KEYWORD_TOKEN,
	C_TOKEN_VOID = MIN_SPECIFIER_TOKEN,
	C_TOKEN_CHAR,
	C_TOKEN_SHORT,
	C_TOKEN_INT,
	C_TOKEN_LONG,
	C_TOKEN_SIGNED,
	C_TOKEN_UNSIGNED,
	C_TOKEN_BOOL,
	C_TOKEN_FLOAT,
	C_TOKEN_DOUBLE,
	C_TOKEN_COMPLEX,
	MAX_SPECIFIER_TOKEN = C_TOKEN_COMPLEX,
	MIN_QUALIFIER_TOKEN,
	C_TOKEN_CONST = MIN_QUALIFIER_TOKEN,
	C_TOKEN_RESTRICT,
	C_TOKEN_VOLATILE,
	C_TOKEN_ATOMIC,
	MAX_QUALIFIER_TOKEN = C_TOKEN_ATOMIC,
	C_TOKEN_STRUCT,
	C_TOKEN_UNION,
	C_TOKEN_ENUM,
	MAX_KEYWORD_TOKEN = C_TOKEN_ENUM,
	C_TOKEN_LPAREN,
	C_TOKEN_RPAREN,
	C_TOKEN_LBRACKET,
	C_TOKEN_RBRACKET,
	C_TOKEN_ASTERISK,
	C_TOKEN_DOT,
	C_TOKEN_NUMBER,
	C_TOKEN_IDENTIFIER,
};

static const char *token_spelling[] = {
	[C_TOKEN_VOID] = "void",
	[C_TOKEN_CHAR] = "char",
	[C_TOKEN_SHORT] = "short",
	[C_TOKEN_INT] = "int",
	[C_TOKEN_LONG] = "long",
	[C_TOKEN_SIGNED] = "signed",
	[C_TOKEN_UNSIGNED] = "unsigned",
	[C_TOKEN_BOOL] = "_Bool",
	[C_TOKEN_FLOAT] = "float",
	[C_TOKEN_DOUBLE] = "double",
	[C_TOKEN_COMPLEX] = "_Complex",
	[C_TOKEN_CONST] = "const",
	[C_TOKEN_RESTRICT] = "restrict",
	[C_TOKEN_VOLATILE] = "volatile",
	[C_TOKEN_ATOMIC] = "_Atomic",
	[C_TOKEN_STRUCT] = "struct",
	[C_TOKEN_UNION] = "union",
	[C_TOKEN_ENUM] = "enum",
};

DEFINE_HASH_MAP(c_keyword_map, struct nstring, int, nstring_hash_pair,
		nstring_eq)

static struct c_keyword_map c_keywords = HASH_TABLE_INIT;

__attribute__((__constructor__(101)))
static void c_keywords_init(void)
{
	for (int i = MIN_KEYWORD_TOKEN; i <= MAX_KEYWORD_TOKEN; i++) {
		struct c_keyword_map_entry entry = {
			.key = {
				.str = token_spelling[i],
				.len = strlen(token_spelling[i]),
			},
			.value = i,
		};
		if (c_keyword_map_insert(&c_keywords, &entry, NULL) != 1)
			abort();
	}
}

__attribute__((__destructor__(101)))
static void c_keywords_deinit(void)
{
	c_keyword_map_deinit(&c_keywords);
}

struct drgn_error *drgn_lexer_c(struct drgn_lexer *lexer,
				struct drgn_token *token) {
	const char *p = lexer->p;

	while (isspace(*p))
		p++;

	token->value = p;
	switch (*p) {
	case '\0':
		token->kind = C_TOKEN_EOF;
		break;
	case '(':
		token->kind = C_TOKEN_LPAREN;
		p++;
		break;
	case ')':
		token->kind = C_TOKEN_RPAREN;
		p++;
		break;
	case '[':
		token->kind = C_TOKEN_LBRACKET;
		p++;
		break;
	case ']':
		token->kind = C_TOKEN_RBRACKET;
		p++;
		break;
	case '*':
		token->kind = C_TOKEN_ASTERISK;
		p++;
		break;
	case '.':
		token->kind = C_TOKEN_DOT;
		p++;
		break;
	default:
		if (isalpha(*p) || *p == '_') {
			struct nstring key;
			struct c_keyword_map_iterator it;

			do {
				p++;
			} while (isalnum(*p) || *p == '_');

			key.str = token->value;
			key.len = p - token->value;
			it = c_keyword_map_search(&c_keywords, &key);
			token->kind = (it.entry ? it.entry->value :
				       C_TOKEN_IDENTIFIER);
		} else if ('0' <= *p && *p <= '9') {
			token->kind = C_TOKEN_NUMBER;
			if (*p++ == '0' && *p == 'x') {
				p++;
				while (('0' <= *p && *p <= '9') ||
				       ('a' <= *p && *p <= 'f') ||
				       ('A' <= *p && *p <= 'F')) {
					p++;
				}
				if (p - token->value <= 2) {
					return drgn_error_create(DRGN_ERROR_SYNTAX,
								 "invalid number");
				}
			} else {
				while ('0' <= *p && *p <= '9')
					p++;
			}
			if (isalpha(*p) || *p == '_') {
				return drgn_error_create(DRGN_ERROR_SYNTAX,
							 "invalid number");
			}
		} else {
			return drgn_error_format(DRGN_ERROR_SYNTAX,
						 "invalid character \\x%02x", (unsigned char)*p);
		}
		break;
	}

	token->len = p - token->value;
	lexer->p = p;
	return NULL;
}

static struct drgn_error *c_token_to_u64(const struct drgn_token *token,
					 uint64_t *ret)
{
	uint64_t x = 0;
	size_t i;

	assert(token->kind == C_TOKEN_NUMBER);
	if (token->len > 2 && token->value[0] == '0' &&
	    token->value[1] == 'x') {
		for (i = 2; i < token->len; i++) {
			char c = token->value[i];
			int digit;

			if ('0' <= c && c <= '9')
				digit = c - '0';
			else if ('a' <= c && c <= 'f')
				digit = c - 'a';
			else /* ('A' <= c && c <= 'F') */
				digit = c - 'A';
			if (x > UINT64_MAX / 16)
				goto overflow;
			x *= 16;
			if (x > UINT64_MAX - digit)
				goto overflow;
			x += digit;
		}
	} else if (token->value[0] == '0') {
		for (i = 1; i < token->len; i++) {
			int digit;

			digit = token->value[i] - '0';
			if (x > UINT64_MAX / 8)
				goto overflow;
			x *= 8;
			if (x > UINT64_MAX - digit)
				goto overflow;
			x += digit;
		}
	} else {
		for (i = 0; i < token->len; i++) {
			int digit;

			digit = token->value[i] - '0';
			if (x > UINT64_MAX / 10)
				goto overflow;
			x *= 10;
			if (x > UINT64_MAX - digit)
				goto overflow;
			x += digit;
		}
	}
	*ret = x;
	return NULL;

overflow:
	return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
				 "number is too large");
}

enum c_type_specifier {
	SPECIFIER_ERROR,
	SPECIFIER_VOID,
	SPECIFIER_CHAR,
	SPECIFIER_SIGNED_CHAR,
	SPECIFIER_UNSIGNED_CHAR,
	SPECIFIER_SHORT,
	SPECIFIER_SHORT_INT,
	SPECIFIER_SIGNED_SHORT_INT,
	SPECIFIER_UNSIGNED_SHORT_INT,
	SPECIFIER_SIGNED_SHORT,
	SPECIFIER_UNSIGNED_SHORT,
	SPECIFIER_INT,
	SPECIFIER_SIGNED_INT,
	SPECIFIER_UNSIGNED_INT,
	SPECIFIER_LONG,
	SPECIFIER_LONG_INT,
	SPECIFIER_SIGNED_LONG,
	SPECIFIER_UNSIGNED_LONG,
	SPECIFIER_SIGNED_LONG_INT,
	SPECIFIER_UNSIGNED_LONG_INT,
	SPECIFIER_LONG_LONG,
	SPECIFIER_LONG_LONG_INT,
	SPECIFIER_SIGNED_LONG_LONG_INT,
	SPECIFIER_UNSIGNED_LONG_LONG_INT,
	SPECIFIER_SIGNED_LONG_LONG,
	SPECIFIER_UNSIGNED_LONG_LONG,
	SPECIFIER_SIGNED,
	SPECIFIER_UNSIGNED,
	SPECIFIER_BOOL,
	SPECIFIER_FLOAT,
	SPECIFIER_DOUBLE,
	SPECIFIER_LONG_DOUBLE,
	SPECIFIER_NONE,
	NUM_SPECIFIER_STATES,
};

static const char *specifier_spelling[NUM_SPECIFIER_STATES] = {
	[SPECIFIER_VOID] = "void",
	[SPECIFIER_CHAR] = "char",
	[SPECIFIER_SIGNED_CHAR] = "signed char",
	[SPECIFIER_UNSIGNED_CHAR] = "unsigned char",
	[SPECIFIER_SHORT] = "short",
	[SPECIFIER_SHORT_INT] = "short int",
	[SPECIFIER_SIGNED_SHORT_INT] = "signed short int",
	[SPECIFIER_UNSIGNED_SHORT_INT] = "unsigned short int",
	[SPECIFIER_SIGNED_SHORT] = "signed short",
	[SPECIFIER_UNSIGNED_SHORT] = "unsigned short",
	[SPECIFIER_INT] = "int",
	[SPECIFIER_SIGNED_INT] = "signed int",
	[SPECIFIER_UNSIGNED_INT] = "unsigned int",
	[SPECIFIER_LONG] = "long",
	[SPECIFIER_LONG_INT] = "long int",
	[SPECIFIER_SIGNED_LONG] = "signed long",
	[SPECIFIER_UNSIGNED_LONG] = "unsigned long",
	[SPECIFIER_SIGNED_LONG_INT] = "signed long int",
	[SPECIFIER_UNSIGNED_LONG_INT] = "unsigned long int",
	[SPECIFIER_LONG_LONG] = "long long",
	[SPECIFIER_LONG_LONG_INT] = "long long int",
	[SPECIFIER_SIGNED_LONG_LONG_INT] = "signed long long int",
	[SPECIFIER_UNSIGNED_LONG_LONG_INT] = "unsigned long long int",
	[SPECIFIER_SIGNED_LONG_LONG] = "signed long long",
	[SPECIFIER_UNSIGNED_LONG_LONG] = "unsigned long long",
	[SPECIFIER_SIGNED] = "signed",
	[SPECIFIER_UNSIGNED] = "unsigned",
	[SPECIFIER_BOOL] = "_Bool",
	[SPECIFIER_FLOAT] = "float",
	[SPECIFIER_DOUBLE] = "double",
	[SPECIFIER_LONG_DOUBLE] = "long double",
};

static const enum drgn_qualifiers qualifier_from_token[MAX_QUALIFIER_TOKEN + 1] = {
	[C_TOKEN_CONST] = DRGN_QUALIFIER_CONST,
	[C_TOKEN_RESTRICT] = DRGN_QUALIFIER_RESTRICT,
	[C_TOKEN_VOLATILE] = DRGN_QUALIFIER_VOLATILE,
	[C_TOKEN_ATOMIC] = DRGN_QUALIFIER_ATOMIC,
};

static const enum c_type_specifier
specifier_transition[NUM_SPECIFIER_STATES][MAX_SPECIFIER_TOKEN + 1] = {
	[SPECIFIER_NONE] = {
		[C_TOKEN_VOID] = SPECIFIER_VOID,
		[C_TOKEN_CHAR] = SPECIFIER_CHAR,
		[C_TOKEN_SHORT] = SPECIFIER_SHORT,
		[C_TOKEN_INT] = SPECIFIER_INT,
		[C_TOKEN_LONG] = SPECIFIER_LONG,
		[C_TOKEN_SIGNED] = SPECIFIER_SIGNED,
		[C_TOKEN_UNSIGNED] = SPECIFIER_UNSIGNED,
		[C_TOKEN_BOOL] = SPECIFIER_BOOL,
		[C_TOKEN_FLOAT] = SPECIFIER_FLOAT,
		[C_TOKEN_DOUBLE] = SPECIFIER_DOUBLE,
	},
	[SPECIFIER_VOID] = {},
	[SPECIFIER_CHAR] = {
		[C_TOKEN_SIGNED] = SPECIFIER_SIGNED_CHAR,
		[C_TOKEN_UNSIGNED] = SPECIFIER_UNSIGNED_CHAR,
	},
	[SPECIFIER_SIGNED_CHAR] = {},
	[SPECIFIER_UNSIGNED_CHAR] = {},
	[SPECIFIER_SHORT] = {
		[C_TOKEN_INT] = SPECIFIER_SHORT_INT,
		[C_TOKEN_SIGNED] = SPECIFIER_SIGNED_SHORT,
		[C_TOKEN_UNSIGNED] = SPECIFIER_UNSIGNED_SHORT,
	},
	[SPECIFIER_SHORT_INT] = {
		[C_TOKEN_SIGNED] = SPECIFIER_SIGNED_SHORT_INT,
		[C_TOKEN_UNSIGNED] = SPECIFIER_UNSIGNED_SHORT_INT,
	},
	[SPECIFIER_SIGNED_SHORT_INT] = {},
	[SPECIFIER_UNSIGNED_SHORT_INT] = {},
	[SPECIFIER_SIGNED_SHORT] = {
		[C_TOKEN_INT] = SPECIFIER_SIGNED_SHORT_INT,
	},
	[SPECIFIER_UNSIGNED_SHORT] = {
		[C_TOKEN_INT] = SPECIFIER_UNSIGNED_SHORT_INT,
	},
	[SPECIFIER_INT] = {
		[C_TOKEN_SHORT] = SPECIFIER_SHORT_INT,
		[C_TOKEN_LONG] = SPECIFIER_LONG_INT,
		[C_TOKEN_SIGNED] = SPECIFIER_SIGNED_INT,
		[C_TOKEN_UNSIGNED] = SPECIFIER_UNSIGNED_INT,
	},
	[SPECIFIER_SIGNED_INT] = {
		[C_TOKEN_SHORT] = SPECIFIER_SIGNED_SHORT_INT,
		[C_TOKEN_LONG] = SPECIFIER_SIGNED_LONG_INT,
	},
	[SPECIFIER_UNSIGNED_INT] = {
		[C_TOKEN_SHORT] = SPECIFIER_UNSIGNED_SHORT_INT,
		[C_TOKEN_LONG] = SPECIFIER_UNSIGNED_LONG_INT,
	},
	[SPECIFIER_LONG] = {
		[C_TOKEN_INT] = SPECIFIER_LONG_INT,
		[C_TOKEN_LONG] = SPECIFIER_LONG_LONG,
		[C_TOKEN_SIGNED] = SPECIFIER_SIGNED_LONG,
		[C_TOKEN_UNSIGNED] = SPECIFIER_UNSIGNED_LONG,
		[C_TOKEN_DOUBLE] = SPECIFIER_LONG_DOUBLE,
	},
	[SPECIFIER_LONG_INT] = {
		[C_TOKEN_LONG] = SPECIFIER_LONG_LONG_INT,
		[C_TOKEN_SIGNED] = SPECIFIER_SIGNED_LONG_INT,
		[C_TOKEN_UNSIGNED] = SPECIFIER_UNSIGNED_LONG_INT,
	},
	[SPECIFIER_SIGNED_LONG] = {
		[C_TOKEN_LONG] = SPECIFIER_SIGNED_LONG_LONG,
		[C_TOKEN_INT] = SPECIFIER_SIGNED_LONG_INT,
	},
	[SPECIFIER_UNSIGNED_LONG] = {
		[C_TOKEN_LONG] = SPECIFIER_UNSIGNED_LONG_LONG,
		[C_TOKEN_INT] = SPECIFIER_UNSIGNED_LONG_INT,
	},
	[SPECIFIER_SIGNED_LONG_INT] = {
		[C_TOKEN_LONG] = SPECIFIER_SIGNED_LONG_LONG_INT,
	},
	[SPECIFIER_UNSIGNED_LONG_INT] = {
		[C_TOKEN_LONG] = SPECIFIER_UNSIGNED_LONG_LONG_INT,
	},
	[SPECIFIER_LONG_LONG] = {
		[C_TOKEN_INT] = SPECIFIER_LONG_LONG_INT,
		[C_TOKEN_SIGNED] = SPECIFIER_SIGNED_LONG_LONG,
		[C_TOKEN_UNSIGNED] = SPECIFIER_UNSIGNED_LONG_LONG,
	},
	[SPECIFIER_LONG_LONG_INT] = {
		[C_TOKEN_SIGNED] = SPECIFIER_SIGNED_LONG_LONG_INT,
		[C_TOKEN_UNSIGNED] = SPECIFIER_UNSIGNED_LONG_LONG_INT,
	},
	[SPECIFIER_SIGNED_LONG_LONG_INT] = {},
	[SPECIFIER_UNSIGNED_LONG_LONG_INT] = {},
	[SPECIFIER_SIGNED_LONG_LONG] = {
		[C_TOKEN_INT] = SPECIFIER_SIGNED_LONG_LONG_INT,
	},
	[SPECIFIER_UNSIGNED_LONG_LONG] = {
		[C_TOKEN_INT] = SPECIFIER_UNSIGNED_LONG_LONG_INT,
	},
	[SPECIFIER_SIGNED] = {
		[C_TOKEN_CHAR] = SPECIFIER_SIGNED_CHAR,
		[C_TOKEN_SHORT] = SPECIFIER_SIGNED_SHORT,
		[C_TOKEN_INT] = SPECIFIER_SIGNED_INT,
		[C_TOKEN_LONG] = SPECIFIER_SIGNED_LONG,
	},
	[SPECIFIER_UNSIGNED] = {
		[C_TOKEN_CHAR] = SPECIFIER_UNSIGNED_CHAR,
		[C_TOKEN_SHORT] = SPECIFIER_UNSIGNED_SHORT,
		[C_TOKEN_INT] = SPECIFIER_UNSIGNED_INT,
		[C_TOKEN_LONG] = SPECIFIER_UNSIGNED_LONG,
	},
	[SPECIFIER_BOOL] = {},
	[SPECIFIER_FLOAT] = {},
	[SPECIFIER_DOUBLE] = {
		[C_TOKEN_LONG] = SPECIFIER_LONG_DOUBLE,
	},
	[SPECIFIER_LONG_DOUBLE] = {},
};

static const enum drgn_primitive_type specifier_kind[NUM_SPECIFIER_STATES] = {
	[SPECIFIER_VOID] = DRGN_C_TYPE_VOID,
	[SPECIFIER_CHAR] = DRGN_C_TYPE_CHAR,
	[SPECIFIER_SIGNED_CHAR] = DRGN_C_TYPE_SIGNED_CHAR,
	[SPECIFIER_UNSIGNED_CHAR] = DRGN_C_TYPE_UNSIGNED_CHAR,
	[SPECIFIER_SHORT] = DRGN_C_TYPE_SHORT,
	[SPECIFIER_SHORT_INT] = DRGN_C_TYPE_SHORT,
	[SPECIFIER_SIGNED_SHORT_INT] = DRGN_C_TYPE_SHORT,
	[SPECIFIER_UNSIGNED_SHORT_INT] = DRGN_C_TYPE_UNSIGNED_SHORT,
	[SPECIFIER_SIGNED_SHORT] = DRGN_C_TYPE_SHORT,
	[SPECIFIER_UNSIGNED_SHORT] = DRGN_C_TYPE_UNSIGNED_SHORT,
	[SPECIFIER_INT] = DRGN_C_TYPE_INT,
	[SPECIFIER_SIGNED_INT] = DRGN_C_TYPE_INT,
	[SPECIFIER_UNSIGNED_INT] = DRGN_C_TYPE_UNSIGNED_INT,
	[SPECIFIER_LONG] = DRGN_C_TYPE_LONG,
	[SPECIFIER_LONG_INT] = DRGN_C_TYPE_LONG,
	[SPECIFIER_SIGNED_LONG] = DRGN_C_TYPE_LONG,
	[SPECIFIER_UNSIGNED_LONG] = DRGN_C_TYPE_UNSIGNED_LONG,
	[SPECIFIER_SIGNED_LONG_INT] = DRGN_C_TYPE_LONG,
	[SPECIFIER_UNSIGNED_LONG_INT] = DRGN_C_TYPE_UNSIGNED_LONG,
	[SPECIFIER_LONG_LONG] = DRGN_C_TYPE_LONG_LONG,
	[SPECIFIER_LONG_LONG_INT] = DRGN_C_TYPE_LONG_LONG,
	[SPECIFIER_SIGNED_LONG_LONG_INT] = DRGN_C_TYPE_LONG_LONG,
	[SPECIFIER_UNSIGNED_LONG_LONG_INT] = DRGN_C_TYPE_UNSIGNED_LONG_LONG,
	[SPECIFIER_SIGNED_LONG_LONG] = DRGN_C_TYPE_LONG_LONG,
	[SPECIFIER_UNSIGNED_LONG_LONG] = DRGN_C_TYPE_UNSIGNED_LONG_LONG,
	[SPECIFIER_SIGNED] = DRGN_C_TYPE_INT,
	[SPECIFIER_UNSIGNED] = DRGN_C_TYPE_UNSIGNED_INT,
	[SPECIFIER_BOOL] = DRGN_C_TYPE_BOOL,
	[SPECIFIER_FLOAT] = DRGN_C_TYPE_FLOAT,
	[SPECIFIER_DOUBLE] = DRGN_C_TYPE_DOUBLE,
	[SPECIFIER_LONG_DOUBLE] = DRGN_C_TYPE_LONG_DOUBLE,
};

enum drgn_primitive_type c_parse_specifier_list(const char *s)
{
	struct drgn_error *err;
	struct drgn_lexer lexer;
	enum c_type_specifier specifier = SPECIFIER_NONE;
	enum drgn_primitive_type primitive = DRGN_NOT_PRIMITIVE_TYPE;

	drgn_lexer_init(&lexer, drgn_lexer_c, s);

	for (;;) {
		struct drgn_token token;

		err = drgn_lexer_pop(&lexer, &token);
		if (err) {
			drgn_error_destroy(err);
			goto out;
		}

		if (MIN_SPECIFIER_TOKEN <= token.kind &&
		    token.kind <= MAX_SPECIFIER_TOKEN)
			specifier = specifier_transition[specifier][token.kind];
		else if (token.kind == C_TOKEN_EOF)
			break;
		else
			specifier = SPECIFIER_ERROR;
		if (specifier == SPECIFIER_ERROR)
			goto out;
	}

	primitive = specifier_kind[specifier];
out:
	drgn_lexer_deinit(&lexer);
	return primitive;
}

static struct drgn_error *
c_parse_specifier_qualifier_list(struct drgn_program *prog,
				 struct drgn_lexer *lexer, const char *filename,
				 struct drgn_qualified_type *ret)
{
	struct drgn_error *err;
	enum c_type_specifier specifier = SPECIFIER_NONE;
	enum drgn_qualifiers qualifiers = 0;
	const char *identifier = NULL;
	size_t identifier_len = 0;
	int tag_token = C_TOKEN_EOF;

	for (;;) {
		struct drgn_token token;

		err = drgn_lexer_pop(lexer, &token);
		if (err)
			return err;

		/* type-qualifier */
		if (MIN_QUALIFIER_TOKEN <= token.kind &&
		    token.kind <= MAX_QUALIFIER_TOKEN) {
			qualifiers |= qualifier_from_token[token.kind];
		/* type-specifier */
		} else if (MIN_SPECIFIER_TOKEN <= token.kind &&
			   token.kind <= MAX_SPECIFIER_TOKEN) {
			enum c_type_specifier prev_specifier;

			if (tag_token != C_TOKEN_EOF) {
				return drgn_error_format(DRGN_ERROR_SYNTAX,
							 "cannot combine '%s' with '%s'",
							 token_spelling[token.kind],
							 token_spelling[tag_token]);
			}
			if (identifier) {
				return drgn_error_format(DRGN_ERROR_SYNTAX,
							 "cannot combine '%s' with identifier",
							 token_spelling[token.kind]);
			}
			prev_specifier = specifier;
			specifier = specifier_transition[specifier][token.kind];
			if (specifier == SPECIFIER_ERROR) {
				return drgn_error_format(DRGN_ERROR_SYNTAX,
							 "cannot combine '%s' with '%s'",
							 token_spelling[token.kind],
							 specifier_spelling[prev_specifier]);
			}
		} else if (token.kind == C_TOKEN_IDENTIFIER &&
			   specifier == SPECIFIER_NONE && !identifier) {
			identifier = token.value;
			identifier_len = token.len;
		} else if (token.kind == C_TOKEN_STRUCT ||
			   token.kind == C_TOKEN_UNION ||
			   token.kind == C_TOKEN_ENUM) {
			if (identifier) {
				return drgn_error_format(DRGN_ERROR_SYNTAX,
							 "cannot combine '%s' with identifier",
							 token_spelling[token.kind]);
			}
			if (specifier != SPECIFIER_NONE) {
				return drgn_error_format(DRGN_ERROR_SYNTAX,
							 "cannot combine '%s' with '%s'",
							 token_spelling[token.kind],
							 specifier_spelling[specifier]);
			}
			tag_token = token.kind;
			err = drgn_lexer_pop(lexer, &token);
			if (err)
				return err;
			if (token.kind != C_TOKEN_IDENTIFIER) {
				return drgn_error_format(DRGN_ERROR_SYNTAX,
							 "expected identifier after '%s'",
							 token_spelling[tag_token]);

			}
			identifier = token.value;
			identifier_len = token.len;
		} else {
			err = drgn_lexer_push(lexer, &token);
			if (err)
				return err;
			break;
		}
	}

	if (specifier == SPECIFIER_NONE) {
		enum drgn_type_kind kind;

		if (tag_token == C_TOKEN_STRUCT) {
			kind = DRGN_TYPE_STRUCT;
		} else if (tag_token == C_TOKEN_UNION) {
			kind = DRGN_TYPE_UNION;
		} else if (tag_token == C_TOKEN_ENUM) {
			kind = DRGN_TYPE_ENUM;
		} else if (identifier) {
			if (strstartswith(identifier, "size_t")) {
				err = drgn_program_find_primitive_type(prog,
								       DRGN_C_TYPE_SIZE_T,
								       &ret->type);
				if (err)
					return err;
				ret->qualifiers = 0;
				goto out;
			} else if (strstartswith(identifier, "ptrdiff_t")) {
				err = drgn_program_find_primitive_type(prog,
								       DRGN_C_TYPE_PTRDIFF_T,
								       &ret->type);
				if (err)
					return err;
				ret->qualifiers = 0;
				goto out;
			} else {
				kind = DRGN_TYPE_TYPEDEF;
			}
		} else {
			return drgn_error_create(DRGN_ERROR_SYNTAX,
						 "expected type specifier");
		}

		err = drgn_program_find_type_impl(prog, kind, identifier,
						  identifier_len, filename,
						  ret);
		if (err)
			return err;
	} else {
		err = drgn_program_find_primitive_type(prog,
						       specifier_kind[specifier],
						       &ret->type);
		if (err)
			return err;
		ret->qualifiers = 0;
	}
out:
	ret->qualifiers |= qualifiers;
	return NULL;
}

struct c_declarator {
	/* C_TOKEN_ASTERISK or C_TOKEN_LBRACKET. */
	int kind;
	enum drgn_qualifiers qualifiers;
	/* Only for C_TOKEN_LBRACKET. */
	bool is_complete;
	uint64_t length;
	struct c_declarator *next;
};

/* These functions don't free the declarator list on error. */
static struct drgn_error *
c_parse_abstract_declarator(struct drgn_program *prog,
			    struct drgn_lexer *lexer,
			    struct c_declarator **outer,
			    struct c_declarator **inner);

static struct drgn_error *
c_parse_optional_type_qualifier_list(struct drgn_lexer *lexer,
				     enum drgn_qualifiers *qualifiers)
{
	struct drgn_error *err;
	struct drgn_token token;

	*qualifiers = 0;
	for (;;) {
		err = drgn_lexer_pop(lexer, &token);
		if (err)
			return err;

		if (token.kind < MIN_QUALIFIER_TOKEN ||
		    token.kind > MAX_QUALIFIER_TOKEN) {
			err = drgn_lexer_push(lexer, &token);
			if (err)
				return err;
			return NULL;
		}
		*qualifiers |= qualifier_from_token[token.kind];
	}
}

static struct drgn_error *
c_parse_pointer(struct drgn_program *prog, struct drgn_lexer *lexer,
		struct c_declarator **outer, struct c_declarator **inner)
{
	struct drgn_error *err;
	struct drgn_token token;

	err = drgn_lexer_pop(lexer, &token);
	if (err)
		return err;
	if (token.kind != C_TOKEN_ASTERISK)
		return drgn_error_create(DRGN_ERROR_SYNTAX, "expected '*'");

	*inner = NULL;
	for (;;) {
		struct c_declarator *tmp;

		tmp = malloc(sizeof(*tmp));
		if (!tmp)
			return &drgn_enomem;

		tmp->kind = C_TOKEN_ASTERISK;
		tmp->next = *outer;
		*outer = tmp;

		err = c_parse_optional_type_qualifier_list(lexer,
							   &(*outer)->qualifiers);
		if (err)
			return err;
		if (!*inner)
			*inner = *outer;

		err = drgn_lexer_pop(lexer, &token);
		if (err)
			return err;
		if (token.kind != C_TOKEN_ASTERISK)
			return drgn_lexer_push(lexer, &token);
	}
}

static struct drgn_error *
c_parse_direct_abstract_declarator(struct drgn_program *prog,
				   struct drgn_lexer *lexer,
				   struct c_declarator **outer,
				   struct c_declarator **inner)
{
	struct drgn_error *err;
	struct drgn_token token;

	*inner = NULL;

	err = drgn_lexer_pop(lexer, &token);
	if (err)
		return err;
	if (token.kind == C_TOKEN_LPAREN) {
		struct drgn_token token2;

		err = drgn_lexer_peek(lexer, &token2);
		if (err)
			return err;
		if (token2.kind == C_TOKEN_ASTERISK ||
		    token2.kind == C_TOKEN_LPAREN ||
		    token2.kind == C_TOKEN_LBRACKET) {
			err = c_parse_abstract_declarator(prog, lexer, outer,
							  inner);
			if (err)
				return err;
			err = drgn_lexer_pop(lexer, &token2);
			if (err)
				return err;
			if (token2.kind != C_TOKEN_RPAREN) {
				return drgn_error_create(DRGN_ERROR_SYNTAX,
							 "expected ')'");
			}
			err = drgn_lexer_pop(lexer, &token);
			if (err)
				return err;
		}
	}

	for (;;) {
		if (token.kind == C_TOKEN_LBRACKET) {
			struct c_declarator *tmp;

			err = drgn_lexer_pop(lexer, &token);
			if (err)
				return err;

			tmp = malloc(sizeof(*tmp));
			if (!tmp)
				return &drgn_enomem;

			tmp->kind = C_TOKEN_LBRACKET;
			tmp->qualifiers = 0;
			if (token.kind == C_TOKEN_NUMBER) {
				tmp->is_complete = true;
				err = c_token_to_u64(&token, &tmp->length);
				if (err) {
					free(tmp);
					return err;
				}
				err = drgn_lexer_pop(lexer, &token);
				if (err) {
					free(tmp);
					return err;
				}
			} else {
				tmp->is_complete = false;
			}

			if (*inner) {
				tmp->next = (*inner)->next;
				*inner = (*inner)->next = tmp;
			} else {
				tmp->next = *outer;
				*outer = *inner = tmp;
			}
			if (token.kind != C_TOKEN_RBRACKET) {
				return drgn_error_create(DRGN_ERROR_SYNTAX,
							 "expected ']'");
			}
		} else if (token.kind == C_TOKEN_LPAREN) {
			return drgn_error_create(DRGN_ERROR_SYNTAX,
						 "function pointer types are not implemented");
		} else {
			err = drgn_lexer_push(lexer, &token);
			if (err)
				return err;

			if (!*inner) {
				return drgn_error_create(DRGN_ERROR_SYNTAX,
							 "expected abstract declarator");
			}
			return NULL;
		}

		err = drgn_lexer_pop(lexer, &token);
		if (err)
			return err;
	}
}

static struct drgn_error *
c_parse_abstract_declarator(struct drgn_program *prog,
			    struct drgn_lexer *lexer,
			    struct c_declarator **outer,
			    struct c_declarator **inner)
{
	struct drgn_error *err;
	struct drgn_token token;

	err = drgn_lexer_peek(lexer, &token);
	if (err)
		return err;
	if (token.kind == C_TOKEN_ASTERISK) {
		err = c_parse_pointer(prog, lexer, outer, inner);
		if (err)
			return err;

		err = drgn_lexer_peek(lexer, &token);
		if (err)
			return err;
		if (token.kind == C_TOKEN_LPAREN ||
		    token.kind == C_TOKEN_LBRACKET) {
			struct c_declarator *tmp;

			err = c_parse_direct_abstract_declarator(prog, lexer,
								 outer, &tmp);
			if (err)
				return err;
		}
		return NULL;
	} else {
		return c_parse_direct_abstract_declarator(prog, lexer, outer,
							  inner);
	}
}

/* This always frees the declarator list regardless of success or failure. */
static struct drgn_error *
c_type_from_declarator(struct drgn_program *prog,
		       struct c_declarator *declarator,
		       struct drgn_qualified_type *ret)
{
	struct drgn_error *err;

	if (!declarator)
		return NULL;

	err = c_type_from_declarator(prog, declarator->next, ret);
	if (err) {
		free(declarator);
		return err;
	}

	if (declarator->kind == C_TOKEN_ASTERISK) {
		uint8_t address_size;
		err = drgn_program_address_size(prog, &address_size);
		if (!err) {
			err = drgn_pointer_type_create(prog, *ret, address_size,
						       DRGN_PROGRAM_ENDIAN,
						       drgn_type_language(ret->type),
						       &ret->type);
		}
	} else if (declarator->is_complete) {
		err = drgn_array_type_create(prog, *ret, declarator->length,
					     drgn_type_language(ret->type),
					     &ret->type);
	} else {
		err = drgn_incomplete_array_type_create(prog, *ret,
							drgn_type_language(ret->type),
							&ret->type);
	}

	if (!err)
		ret->qualifiers = declarator->qualifiers;
	free(declarator);
	return err;
}

struct drgn_error *c_find_type(struct drgn_program *prog, const char *name,
			       const char *filename,
			       struct drgn_qualified_type *ret)
{
	struct drgn_error *err;
	struct drgn_lexer lexer;
	struct drgn_token token;

	drgn_lexer_init(&lexer, drgn_lexer_c, name);

	err = c_parse_specifier_qualifier_list(prog, &lexer, filename, ret);
	if (err)
		goto out;

	err = drgn_lexer_pop(&lexer, &token);
	if (err)
		goto out;
	if (token.kind != C_TOKEN_EOF) {
		struct c_declarator *outer = NULL, *inner;

		err = drgn_lexer_push(&lexer, &token);
		if (err)
			return err;

		err = c_parse_abstract_declarator(prog, &lexer, &outer, &inner);
		if (err) {
			while (outer) {
				struct c_declarator *next;

				next = outer->next;
				free(outer);
				outer = next;
			}
			goto out;
		}

		err = c_type_from_declarator(prog, outer, ret);
		if (err)
			goto out;

		err = drgn_lexer_pop(&lexer, &token);
		if (err)
			goto out;
		if (token.kind != C_TOKEN_EOF) {
			err = drgn_error_create(DRGN_ERROR_SYNTAX,
						"extra tokens after type name");
			goto out;
		}
	}

	err = NULL;
out:
	drgn_lexer_deinit(&lexer);
	return err;
}

struct drgn_error *c_bit_offset(struct drgn_program *prog,
				struct drgn_type *type,
				const char *member_designator, uint64_t *ret)
{
	struct drgn_error *err;
	struct drgn_lexer lexer;
	int state = INT_MIN;
	uint64_t bit_offset = 0;

	drgn_lexer_init(&lexer, drgn_lexer_c, member_designator);

	for (;;) {
		struct drgn_token token;

		err = drgn_lexer_pop(&lexer, &token);
		if (err)
			goto out;

		switch (state) {
		case INT_MIN:
		case C_TOKEN_DOT:
			if (token.kind == C_TOKEN_IDENTIFIER) {
				struct drgn_type_member *member;
				uint64_t member_bit_offset;
				err = drgn_type_find_member_len(type,
								token.value,
								token.len,
								&member,
								&member_bit_offset);
				if (err)
					goto out;
				if (__builtin_add_overflow(bit_offset,
							   member_bit_offset,
							   &bit_offset)) {
					err = drgn_error_create(DRGN_ERROR_OVERFLOW,
								"offset is too large");
					goto out;
				}
				struct drgn_qualified_type member_type;
				err = drgn_member_type(member, &member_type,
						       NULL);
				if (err)
					goto out;
				type = member_type.type;
			} else if (state == C_TOKEN_DOT) {
				err = drgn_error_create(DRGN_ERROR_SYNTAX,
							"expected identifier after '.'");
				goto out;
			} else {
				err = drgn_error_create(DRGN_ERROR_SYNTAX,
							"expected identifier");
				goto out;
			}
			break;
		case C_TOKEN_IDENTIFIER:
		case C_TOKEN_RBRACKET:
			switch (token.kind) {
			case C_TOKEN_EOF:
				*ret = bit_offset;
				err = NULL;
				goto out;
			case C_TOKEN_DOT:
			case C_TOKEN_LBRACKET:
				break;
			default:
				if (state == C_TOKEN_IDENTIFIER) {
					err = drgn_error_create(DRGN_ERROR_SYNTAX,
								"expected '.' or '[' after identifier");
					goto out;
				} else {
					err = drgn_error_create(DRGN_ERROR_SYNTAX,
								"expected '.' or '[' after ']'");
					goto out;
				}
			}
			break;
		case C_TOKEN_LBRACKET:
			if (token.kind == C_TOKEN_NUMBER) {
				struct drgn_type *underlying_type;
				struct drgn_type *element_type;
				uint64_t index, bit_size, element_offset;

				err = c_token_to_u64(&token, &index);
				if (err)
					goto out;

				underlying_type = drgn_underlying_type(type);
				if (drgn_type_kind(underlying_type) != DRGN_TYPE_ARRAY) {
					err = drgn_type_error("'%s' is not an array",
							      type);
					goto out;
				}
				element_type =
					drgn_type_type(underlying_type).type;
				err = drgn_type_bit_size(element_type,
							 &bit_size);
				if (err)
					goto out;
				if (__builtin_mul_overflow(index, bit_size,
							   &element_offset) ||
				    __builtin_add_overflow(bit_offset,
							   element_offset,
							   &bit_offset)) {
					err = drgn_error_create(DRGN_ERROR_OVERFLOW,
								"offset is too large");
					goto out;
				}
				type = element_type;
			} else {
				err = drgn_error_create(DRGN_ERROR_SYNTAX,
							"expected number after '['");
				goto out;
			}
			break;
		case C_TOKEN_NUMBER:
			if (token.kind != C_TOKEN_RBRACKET) {
				err = drgn_error_create(DRGN_ERROR_SYNTAX,
							"expected ']' after number");
				goto out;
			}
			break;
		default:
			UNREACHABLE();
		}
		state = token.kind;
	}

out:
	drgn_lexer_deinit(&lexer);
	return err;
}

struct drgn_error *c_integer_literal(struct drgn_object *res, uint64_t uvalue)
{
	static const enum drgn_primitive_type types[] = {
		DRGN_C_TYPE_INT,
		DRGN_C_TYPE_LONG,
		DRGN_C_TYPE_LONG_LONG,
		DRGN_C_TYPE_UNSIGNED_LONG_LONG,
	};
	struct drgn_error *err;

	unsigned int bits = fls(uvalue);
	struct drgn_qualified_type qualified_type;
	qualified_type.qualifiers = 0;
	array_for_each(type, types) {
		err = drgn_program_find_primitive_type(drgn_object_program(res),
						       *type,
						       &qualified_type.type);
		if (err)
			return err;

		if (drgn_type_is_signed(qualified_type.type) &&
		    bits < 8 * drgn_type_size(qualified_type.type)) {
			return drgn_object_set_signed(res,
						      qualified_type,
						      uvalue, 0);
		} else if (!drgn_type_is_signed(qualified_type.type) &&
			   bits <= 8 * drgn_type_size(qualified_type.type)) {
			return drgn_object_set_unsigned(res, qualified_type,
							uvalue, 0);
		}
	}
	return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
				 "integer literal is too large");
}

struct drgn_error *c_bool_literal(struct drgn_object *res, bool bvalue)
{
	struct drgn_error *err;
	struct drgn_qualified_type qualified_type;

	err = drgn_program_find_primitive_type(drgn_object_program(res),
					       DRGN_C_TYPE_INT,
					       &qualified_type.type);
	if (err)
		return err;
	qualified_type.qualifiers = 0;
	return drgn_object_set_signed(res, qualified_type, bvalue, 0);
}

struct drgn_error *c_float_literal(struct drgn_object *res, double fvalue)
{
	struct drgn_error *err;
	struct drgn_qualified_type qualified_type;

	err = drgn_program_find_primitive_type(drgn_object_program(res),
					       DRGN_C_TYPE_DOUBLE,
					       &qualified_type.type);
	if (err)
		return err;
	qualified_type.qualifiers = 0;
	return drgn_object_set_float(res, qualified_type, fvalue);
}

static const int c_integer_conversion_rank[] = {
	[DRGN_C_TYPE_BOOL] = 0,
	[DRGN_C_TYPE_CHAR] = 1,
	[DRGN_C_TYPE_SIGNED_CHAR] = 1,
	[DRGN_C_TYPE_UNSIGNED_CHAR] = 1,
	[DRGN_C_TYPE_SHORT] = 2,
	[DRGN_C_TYPE_UNSIGNED_SHORT] = 2,
	[DRGN_C_TYPE_INT] = 3,
	[DRGN_C_TYPE_UNSIGNED_INT] = 3,
	[DRGN_C_TYPE_LONG] = 4,
	[DRGN_C_TYPE_UNSIGNED_LONG] = 4,
	[DRGN_C_TYPE_LONG_LONG] = 5,
	[DRGN_C_TYPE_UNSIGNED_LONG_LONG] = 5,
};

static bool c_can_represent_all_values(struct drgn_type *type1,
				       uint64_t bit_field_size1,
				       struct drgn_type *type2,
				       uint64_t bit_field_size2)
{
	uint64_t width1, width2;
	bool is_signed1, is_signed2;

	if (drgn_type_kind(type1) == DRGN_TYPE_BOOL) {
		width1 = 1;
		is_signed1 = false;
	} else {
		width1 = (bit_field_size1 ? bit_field_size1 :
			  8 * drgn_type_size(type1));
		is_signed1 = drgn_type_is_signed(type1);
	}
	if (drgn_type_kind(type2) == DRGN_TYPE_BOOL) {
		width2 = 1;
		is_signed2 = false;
	} else {
		width2 = (bit_field_size2 ? bit_field_size2 :
			  8 * drgn_type_size(type2));
		is_signed2 = drgn_type_is_signed(type2);
	}

	if (is_signed1 == is_signed2)
		return width1 >= width2;
	else if (is_signed1 && !is_signed2)
		return width1 > width2;
	else
		return false;
}

static struct drgn_error *c_integer_promotions(struct drgn_program *prog,
					       struct drgn_operand_type *type)
{
	struct drgn_error *err;
	enum drgn_primitive_type primitive;
	struct drgn_type *int_type;

	switch (drgn_type_kind(type->underlying_type)) {
	case DRGN_TYPE_ENUM:
		/* Convert the enum to its compatible type. */
		type->type = type->underlying_type =
			drgn_type_type(type->underlying_type).type;
		if (!type->type) {
			return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
						 "operand cannot have incomplete enum type");
		}
		break;
	case DRGN_TYPE_INT:
	case DRGN_TYPE_BOOL:
		break;
	default:
		return NULL;
	}

	primitive = drgn_type_primitive(type->underlying_type);
	/*
	 * Integer promotions are performed on types whose integer conversion
	 * rank is less than or equal to the rank of int and unsigned int.
	 *
	 * If this isn't a standard integer type, then we don't know the rank,
	 * so we may need to promote it. According to the C standard, "the rank
	 * of a signed integer type shall be greater than the rank of any signed
	 * integer type with less precision", and "the rank of any standard
	 * integer type shall be greater than the rank of any extended integer
	 * type with the same width". If an extended signed integer type has
	 * less precision than int, or the same width as int, then all of its
	 * values can be represented by int (and likewise for an extended
	 * unsigned integer type and unsigned int). Therefore, an extended
	 * integer type should be promoted iff all of its values can be
	 * represented by int or unsigned int.
	 *
	 * Integer promotions are also performed on bit fields. The C standard
	 * only requires that bit fields of type _Bool, int, or unsigned int are
	 * supported, so it does not define how integer promotions should affect
	 * a bit field which cannot be represented by int or unsigned int. Clang
	 * promotes it to the full width, but GCC does not. We implement the GCC
	 * behavior of preserving the width.
	 */
	if (primitive >= array_size(c_integer_conversion_rank) ||
	    type->bit_field_size) {
		err = drgn_program_find_primitive_type(prog, DRGN_C_TYPE_INT,
						       &int_type);
		if (err)
			return err;
		if (c_can_represent_all_values(int_type, 0,
					       type->underlying_type,
					       type->bit_field_size)) {
			type->type = type->underlying_type = int_type;
			type->bit_field_size = 0;
			return NULL;
		}

		err = drgn_program_find_primitive_type(prog,
						       DRGN_C_TYPE_UNSIGNED_INT,
						       &int_type);
		if (err)
			return err;
		if (c_can_represent_all_values(int_type, 0,
					       type->underlying_type,
					       type->bit_field_size)) {
			type->type = type->underlying_type = int_type;
			type->bit_field_size = 0;
		}
		return NULL;
	}

	if (primitive == DRGN_C_TYPE_INT ||
	    primitive == DRGN_C_TYPE_UNSIGNED_INT ||
	    c_integer_conversion_rank[primitive] >
	    c_integer_conversion_rank[DRGN_C_TYPE_INT])
		return NULL;

	/*
	 * If int can represent all values of the original type, then the result
	 * is int. Otherwise, the result is unsigned int.
	 */
	err = drgn_program_find_primitive_type(prog, DRGN_C_TYPE_INT,
					       &int_type);
	if (err)
		return err;
	if (c_can_represent_all_values(int_type, 0, type->underlying_type, 0)) {
		type->type = int_type;
	} else {
		err = drgn_program_find_primitive_type(prog,
						       DRGN_C_TYPE_UNSIGNED_INT,
						       &type->type);
		if (err)
			return err;
	}
	type->underlying_type = type->type;
	return NULL;
}

static struct drgn_error *
c_corresponding_unsigned_type(struct drgn_program *prog,
			      enum drgn_primitive_type type,
			      struct drgn_type **ret)
{
	switch (type) {
	/*
	 * char, signed char, and short are promoted to int, so we don't need to
	 * handle them here.
	 */
	case DRGN_C_TYPE_INT:
		return drgn_program_find_primitive_type(prog,
							DRGN_C_TYPE_UNSIGNED_INT,
							ret);
	case DRGN_C_TYPE_LONG:
		return drgn_program_find_primitive_type(prog,
							DRGN_C_TYPE_UNSIGNED_LONG,
							ret);
	case DRGN_C_TYPE_LONG_LONG:
		return drgn_program_find_primitive_type(prog,
							DRGN_C_TYPE_UNSIGNED_LONG_LONG,
							ret);
	default:
		UNREACHABLE();
	}
}

static struct drgn_error *c_common_real_type(struct drgn_program *prog,
					     struct drgn_operand_type *type1,
					     struct drgn_operand_type *type2,
					     struct drgn_operand_type *ret)
{
	struct drgn_error *err;
	enum drgn_primitive_type primitive1, primitive2;
	bool is_float1, is_float2;
	bool is_signed1, is_signed2;
	int rank_cmp;

	ret->qualifiers = 0;

	/*
	 * Strictly, the rules are:
	 *
	 * If either operand is long double, then the result is long double.
	 * Otherwise, if either operand is double, then the result is double.
	 * Otherwise, if either operand is float, then the result is float.
	 *
	 * However, we also have to handle other floating types not in the
	 * standard. Thus, the result is always the larger type, with ties
	 * broken in the order unknown > long double > double > float.
	 */
	is_float1 = drgn_type_kind(type1->underlying_type) == DRGN_TYPE_FLOAT;
	is_float2 = drgn_type_kind(type2->underlying_type) == DRGN_TYPE_FLOAT;
	if (is_float1 && is_float2) {
		uint64_t size1, size2;

		size1 = drgn_type_size(type1->underlying_type);
		size2 = drgn_type_size(type2->underlying_type);
		if (size1 > size2)
			goto ret1;
		else if (size2 > size1)
			goto ret2;
		else if (drgn_type_primitive(type1->underlying_type) >
			 drgn_type_primitive(type2->underlying_type))
			goto ret1;
		else
			goto ret2;
	} else if (is_float1) {
		goto ret1;
	} else if (is_float2) {
		goto ret2;
	}

	/*
	 * Otherwise, the integer promotions are performed before applying the
	 * following rules.
	 */
	err = c_integer_promotions(prog, type1);
	if (err)
		return err;
	err = c_integer_promotions(prog, type2);
	if (err)
		return err;

	is_signed1 = drgn_type_is_signed(type1->underlying_type);
	is_signed2 = drgn_type_is_signed(type2->underlying_type);

	/*
	 * The C standard only requires that bit fields of type _Bool, int, or
	 * unsigned int are supported, which are always promoted to int or
	 * unsigned int, so it does not define how to find the common real type
	 * when one or both of the operands are bit fields. GCC seems to use the
	 * wider operand, or the unsigned operand if they have equal width. As
	 * usual, we pick type2 if the two types are equivalent.
	 */
	if (type1->bit_field_size || type2->bit_field_size) {
		uint64_t width1, width2;

		width1 = (type1->bit_field_size ? type1->bit_field_size :
			  8 * drgn_type_size(type1->type));
		width2 = (type2->bit_field_size ? type2->bit_field_size :
			  8 * drgn_type_size(type2->type));
		if (width1 < width2 ||
		    (width1 == width2 && (!is_signed2 || is_signed1)))
			goto ret2;
		else
			goto ret1;
	}

	primitive1 = drgn_type_primitive(type1->underlying_type);
	primitive2 = drgn_type_primitive(type2->underlying_type);

	if (primitive1 != DRGN_NOT_PRIMITIVE_TYPE &&
	    primitive2 != DRGN_NOT_PRIMITIVE_TYPE) {
		/*
		 * If both operands have the same type, then no further
		 * conversions are needed.
		 *
		 * We can return either type1 or type2 here; it only makes a
		 * difference for typedefs. Arbitrarily pick type2 because
		 * that's what GCC seems to do (Clang always throws away the
		 * typedef).
		 */
		if (primitive1 == primitive2)
			goto ret2;

		/* Ranks are small, so this won't overflow. */
		rank_cmp = (c_integer_conversion_rank[primitive1] -
			    c_integer_conversion_rank[primitive2]);
	} else {
		/*
		 * We don't know the rank of non-standard integer types.
		 * However, we can usually compare their ranks, because
		 * according to the C standard, "the rank of a signed integer
		 * type shall be greater than the rank of any signed integer
		 * type with less precision", "the rank of any unsigned integer
		 * type shall equal the rank of the corresponding signed integer
		 * type", and "the rank of any standard integer type shall be
		 * greater than the rank of any extended integer type with the
		 * same width". The only case where we can't is if both types
		 * are non-standard and have the same size; we treat them as
		 * having equal rank in this case.
		 */
		uint64_t size1, size2;

		size1 = drgn_type_size(type1->underlying_type);
		size2 = drgn_type_size(type2->underlying_type);
		if (size1 == size2 && primitive1 == DRGN_NOT_PRIMITIVE_TYPE &&
		    primitive2 == DRGN_NOT_PRIMITIVE_TYPE)
			rank_cmp = 0;
		else if ((size1 == size2 && primitive2 != DRGN_NOT_PRIMITIVE_TYPE) ||
			 size1 < size2)
			rank_cmp = -1;
		else
			rank_cmp = 1;
	}

	/*
	 * Otherwise, if both operands have signed integer types or both have
	 * unsigned integer types, then the result is the type of the operand
	 * with the greater rank.
	 */
	if (is_signed1 == is_signed2) {
		if (rank_cmp > 0)
			goto ret1;
		else
			goto ret2;
	}

        /*
	 * Otherwise, if the operand that has unsigned integer type has rank
	 * greater or equal to the rank of the type of the other operand, then
	 * the result is the unsigned integer type.
	 */
	if (!is_signed1 && rank_cmp >= 0)
		goto ret1;
	else if (!is_signed2 && rank_cmp <= 0)
		goto ret2;

	/*
	 * Otherwise, if the type of the operand with signed integer type can
	 * represent all of the values of the type of the operand with unsigned
	 * integer type, then the result is the signed integer type.
	 */
	if (is_signed1 && c_can_represent_all_values(type1->underlying_type, 0,
						     type2->underlying_type, 0))
		goto ret1;
	if (is_signed2 && c_can_represent_all_values(type2->underlying_type, 0,
						     type1->underlying_type, 0))
		goto ret2;

	/*
	 * Otherwise, the result is the unsigned integer type corresponding to
	 * the type of the operand with signed integer type.
	 *
	 * Note that this case is not reached for non-standard types: if the
	 * types have different signs and the signed integer type has greater
	 * rank, then it must have greater size and thus be able to represent
	 * all values of the unsigned integer type.
	 */
	err = c_corresponding_unsigned_type(prog,
					    is_signed1 ? primitive1 : primitive2,
					    &ret->type);
	if (err)
		return err;
	ret->underlying_type = ret->type;
	ret->bit_field_size = 0;
	return NULL;

ret1:
	*ret = *type1;
	return NULL;
ret2:
	*ret = *type2;
	return NULL;
}

static struct drgn_error *c_operand_type(const struct drgn_object *obj,
					 struct drgn_operand_type *type_ret,
					 bool *is_pointer_ret,
					 uint64_t *referenced_size_ret)
{
	struct drgn_error *err;

	*type_ret = drgn_object_operand_type(obj);
	switch (drgn_type_kind(type_ret->underlying_type)) {
	case DRGN_TYPE_ARRAY: {
		uint8_t address_size;
		err = drgn_program_address_size(drgn_object_program(obj),
						&address_size);
		if (err)
			return err;
		err = drgn_pointer_type_create(drgn_object_program(obj),
					       drgn_type_type(type_ret->underlying_type),
					       address_size,
					       DRGN_PROGRAM_ENDIAN,
					       drgn_type_language(type_ret->underlying_type),
					       &type_ret->type);
		if (err)
			return err;
		type_ret->underlying_type = type_ret->type;
		break;
	}
	case DRGN_TYPE_FUNCTION: {
		struct drgn_qualified_type function_type = {
			.type = type_ret->underlying_type,
			.qualifiers = type_ret->qualifiers,
		};
		uint8_t address_size;
		err = drgn_program_address_size(drgn_object_program(obj),
						&address_size);
		if (err)
			return err;
		err = drgn_pointer_type_create(drgn_object_program(obj),
					       function_type, address_size,
					       DRGN_PROGRAM_ENDIAN,
					       drgn_type_language(type_ret->underlying_type),
					       &type_ret->type);
		if (err)
			return err;
		type_ret->underlying_type = type_ret->type;
		break;
	}
	default:
		err = drgn_type_with_byte_order(&type_ret->type,
						&type_ret->underlying_type,
						DRGN_PROGRAM_ENDIAN);
		if (err)
			return err;
		break;
	}
	type_ret->qualifiers = 0;

	if (is_pointer_ret) {
		struct drgn_type *type = type_ret->underlying_type;
		*is_pointer_ret = drgn_type_kind(type) == DRGN_TYPE_POINTER;
		if (*is_pointer_ret && referenced_size_ret) {
			struct drgn_type *referenced_type =
				drgn_underlying_type(drgn_type_type(type).type);
			if (drgn_type_kind(referenced_type) == DRGN_TYPE_VOID) {
				*referenced_size_ret = 1;
			} else {
				err = drgn_type_sizeof(referenced_type,
						       referenced_size_ret);
				if (err)
					return err;
			}
		}
	}
	return NULL;
}

struct drgn_error *c_op_cast(struct drgn_object *res,
			     struct drgn_qualified_type qualified_type,
			     const struct drgn_object *obj)
{
	struct drgn_error *err;
	struct drgn_operand_type type;
	err = c_operand_type(obj, &type, NULL, NULL);
	if (err)
		return err;
	return drgn_op_cast(res, qualified_type, obj, &type);
}

/*
 * It's too expensive to check that two pointer types are compatible, so we just
 * check that they refer to the same kind of type with equal size.
 */
static bool c_pointers_similar(const struct drgn_operand_type *lhs_type,
			       const struct drgn_operand_type *rhs_type,
			       uint64_t lhs_size, uint64_t rhs_size)
{
	struct drgn_type *lhs_referenced_type, *rhs_referenced_type;

	lhs_referenced_type = drgn_type_type(lhs_type->underlying_type).type;
	rhs_referenced_type = drgn_type_type(rhs_type->underlying_type).type;
	return (drgn_type_kind(lhs_referenced_type) ==
		drgn_type_kind(rhs_referenced_type) && lhs_size == rhs_size);
}

struct drgn_error *c_op_bool(const struct drgn_object *obj, bool *ret)
{
	struct drgn_error *err;
	struct drgn_type *underlying_type;

	underlying_type = drgn_underlying_type(obj->type);
	if (drgn_type_kind(underlying_type) == DRGN_TYPE_ARRAY) {
		*ret = true;
		return NULL;
	}

	if (!drgn_type_is_scalar(underlying_type)) {
		return drgn_qualified_type_error("cannot convert '%s' to bool",
						 drgn_object_qualified_type(obj));
	}

	err = drgn_object_is_zero(obj, ret);
	if (err)
		return err;
	*ret = !*ret;
	return NULL;
}

struct drgn_error *c_op_cmp(const struct drgn_object *lhs,
			    const struct drgn_object *rhs, int *ret)
{
	struct drgn_error *err;

	struct drgn_operand_type lhs_type, rhs_type;
	bool lhs_pointer, rhs_pointer;
	err = c_operand_type(lhs, &lhs_type, &lhs_pointer, NULL);
	if (err)
		return err;
	err = c_operand_type(rhs, &rhs_type, &rhs_pointer, NULL);
	if (err)
		return err;

	if (lhs_pointer && rhs_pointer) {
		return drgn_op_cmp_pointers(lhs, rhs, ret);
	} else if (lhs_pointer || rhs_pointer) {
		goto type_error;
	} else {
		struct drgn_operand_type type;
		if (!drgn_type_is_arithmetic(lhs_type.underlying_type) ||
		    !drgn_type_is_arithmetic(rhs_type.underlying_type))
			goto type_error;
		err = c_common_real_type(drgn_object_program(lhs), &lhs_type,
					 &rhs_type, &type);
		if (err)
			return err;

		return drgn_op_cmp_impl(lhs, rhs, &type, ret);
	}

type_error:
	return drgn_error_binary_op("comparison", &lhs_type, &rhs_type);
}

struct drgn_error *c_op_add(struct drgn_object *res,
			    const struct drgn_object *lhs,
			    const struct drgn_object *rhs)
{
	struct drgn_error *err;

	struct drgn_operand_type lhs_type, rhs_type;
	bool lhs_pointer, rhs_pointer;
	uint64_t lhs_size, rhs_size;
	err = c_operand_type(lhs, &lhs_type, &lhs_pointer, &lhs_size);
	if (err)
		return err;
	err = c_operand_type(rhs, &rhs_type, &rhs_pointer, &rhs_size);
	if (err)
		return err;

	if (lhs_pointer) {
		if (!drgn_type_is_integer(rhs_type.underlying_type))
			goto type_error;
		return drgn_op_add_to_pointer(res, &lhs_type, lhs_size, false, lhs, rhs);
	} else if (rhs_pointer) {
		if (!drgn_type_is_integer(lhs_type.underlying_type))
			goto type_error;
		return drgn_op_add_to_pointer(res, &rhs_type, rhs_size, false, rhs, lhs);
	} else {
		struct drgn_operand_type type;
		if (!drgn_type_is_arithmetic(lhs_type.underlying_type) ||
		    !drgn_type_is_arithmetic(rhs_type.underlying_type))
			goto type_error;
		err = c_common_real_type(drgn_object_program(lhs), &lhs_type,
					 &rhs_type, &type);
		if (err)
			return err;

		return drgn_op_add_impl(res, &type, lhs, rhs);
	}

type_error:
	return drgn_error_binary_op("binary +", &lhs_type, &rhs_type);
}

struct drgn_error *c_op_sub(struct drgn_object *res,
			    const struct drgn_object *lhs,
			    const struct drgn_object *rhs)
{
	struct drgn_error *err;

	struct drgn_operand_type lhs_type, rhs_type;
	bool lhs_pointer, rhs_pointer;
	uint64_t lhs_size, rhs_size;
	err = c_operand_type(lhs, &lhs_type, &lhs_pointer, &lhs_size);
	if (err)
		return err;
	err = c_operand_type(rhs, &rhs_type, &rhs_pointer, &rhs_size);
	if (err)
		return err;

	if (lhs_pointer && rhs_pointer) {
		struct drgn_operand_type type = {};
		err = drgn_program_find_primitive_type(drgn_object_program(lhs),
						       DRGN_C_TYPE_PTRDIFF_T,
						       &type.type);
		if (err)
			return err;
		type.underlying_type = drgn_underlying_type(type.type);
		if (!c_pointers_similar(&lhs_type, &rhs_type, lhs_size,
					rhs_size))
			goto type_error;
		return drgn_op_sub_pointers(res, &type, lhs_size, lhs, rhs);
	} else if (lhs_pointer) {
		if (!drgn_type_is_integer(rhs_type.underlying_type))
			goto type_error;
		return drgn_op_add_to_pointer(res, &lhs_type, lhs_size, true,
					      lhs, rhs);
	} else {
		struct drgn_operand_type type;
		if (!drgn_type_is_arithmetic(lhs_type.underlying_type) ||
		    !drgn_type_is_arithmetic(rhs_type.underlying_type))
			goto type_error;
		err = c_common_real_type(drgn_object_program(lhs), &lhs_type,
					 &rhs_type, &type);
		if (err)
			return err;

		return drgn_op_sub_impl(res, &type, lhs, rhs);
	}

type_error:
	return drgn_error_binary_op("binary -", &lhs_type, &rhs_type);
}

#define BINARY_OP(op_name, op, check)						\
struct drgn_error *c_op_##op_name(struct drgn_object *res,			\
				  const struct drgn_object *lhs,		\
				  const struct drgn_object *rhs)		\
{										\
	struct drgn_error *err;							\
										\
	struct drgn_operand_type lhs_type, rhs_type, type;			\
	err = c_operand_type(lhs, &lhs_type, NULL, NULL);			\
	if (err)								\
		return err;							\
	err = c_operand_type(rhs, &rhs_type, NULL, NULL);			\
	if (err)								\
		return err;							\
	if (!drgn_type_is_##check(lhs_type.underlying_type) ||			\
	    !drgn_type_is_##check(rhs_type.underlying_type))			\
		return drgn_error_binary_op("binary "#op, &lhs_type,		\
					    &rhs_type);				\
										\
	err = c_common_real_type(drgn_object_program(lhs), &lhs_type,		\
				 &rhs_type, &type);				\
	if (err)								\
		return err;							\
										\
	return drgn_op_##op_name##_impl(res, &type, lhs, rhs);			\
}
BINARY_OP(mul, *, arithmetic)
BINARY_OP(div, /, arithmetic)
BINARY_OP(mod, %, integer)
BINARY_OP(and, &, integer)
BINARY_OP(or, |, integer)
BINARY_OP(xor, ^, integer)
#undef BINARY_OP

#define SHIFT_OP(op_name, op)							\
struct drgn_error *c_op_##op_name(struct drgn_object *res,			\
					 const struct drgn_object *lhs,		\
					 const struct drgn_object *rhs)		\
{										\
	struct drgn_error *err;							\
										\
	struct drgn_operand_type lhs_type, rhs_type;				\
	err = c_operand_type(lhs, &lhs_type, NULL, NULL);			\
	if (err)								\
		return err;							\
	err = c_operand_type(rhs, &rhs_type, NULL, NULL);			\
	if (err)								\
		return err;							\
	if (!drgn_type_is_integer(lhs_type.underlying_type) ||			\
	    !drgn_type_is_integer(rhs_type.underlying_type))			\
		return drgn_error_binary_op("binary " #op, &lhs_type,		\
					    &rhs_type);				\
										\
	err = c_integer_promotions(drgn_object_program(lhs), &lhs_type);	\
	if (err)								\
		return err;							\
	err = c_integer_promotions(drgn_object_program(lhs), &rhs_type);	\
	if (err)								\
		return err;							\
										\
	return drgn_op_##op_name##_impl(res, lhs, &lhs_type, rhs, &rhs_type);	\
}
SHIFT_OP(lshift, <<)
SHIFT_OP(rshift, >>)
#undef SHIFT_OP

#define UNARY_OP(op_name, op, check)					\
struct drgn_error *c_op_##op_name(struct drgn_object *res,		\
					 const struct drgn_object *obj)	\
{									\
	struct drgn_error *err;						\
									\
	struct drgn_operand_type type;					\
	err = c_operand_type(obj, &type, NULL, NULL);			\
	if (err)							\
		return err;						\
	if (!drgn_type_is_##check(type.underlying_type))		\
		return drgn_error_unary_op("unary " #op, &type);	\
									\
	err = c_integer_promotions(drgn_object_program(obj), &type);	\
	if (err)							\
		return err;						\
									\
	return drgn_op_##op_name##_impl(res, &type, obj);		\
}
UNARY_OP(pos, +, arithmetic)
UNARY_OP(neg, -, arithmetic)
UNARY_OP(not, ~, integer)
#undef UNARY_OP
