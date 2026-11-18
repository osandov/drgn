// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "array.h"
#include "cleanup.h"
#include "error.h"
#include "language.h"
#include "language_rust.h"
#include "lexer.h"
#include "program.h"
#include "string_builder.h"
#include "type.h"
#include "util.h"
#include "vector.h"

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

enum {
	RUST_TOKEN_EOF = -1,
	// Single-character punctuation tokens are their character.
	RUST_TOKEN_IDENTIFIER = 256,
	RUST_TOKEN_NUMBER,
	RUST_TOKEN_STRING,
	RUST_TOKEN_SEGMENT,
	RUST_TOKEN_LIFETIME,
	RUST_TOKEN_COLON_COLON,
	RUST_TOKEN_ARROW,
	RUST_TOKEN_ELLIPSIS,
};

static struct drgn_error *rust_lexer_func(struct drgn_lexer *lexer, struct drgn_token *token)
{
	const char *p = lexer->p;

	while (isspace((unsigned char)*p))
		p++;
	token->value = p;
	switch (*p) {
	case '\0':
		token->kind = RUST_TOKEN_EOF;
		break;
	case '&':
	case '*':
	case '[':
	case ']':
	case '(':
	case ')':
	case '<':
	case '>':
	case ',':
	case ';':
	case '!':
	case '+':
	case '=':
		token->kind = *p++;
		break;
	case ':':
		if (p[1] != ':')
			return drgn_error_create(DRGN_ERROR_SYNTAX, "expected '::'");
		token->kind = RUST_TOKEN_COLON_COLON;
		p += 2;
		break;
	case '-':
		if (p[1] != '>')
			return drgn_error_create(DRGN_ERROR_SYNTAX, "expected '->'");
		token->kind = RUST_TOKEN_ARROW;
		p += 2;
		break;
	case '.':
		if (p[1] != '.' || p[2] != '.')
			return drgn_error_create(DRGN_ERROR_SYNTAX, "expected '...'");
		token->kind = RUST_TOKEN_ELLIPSIS;
		p += 3;
		break;
	case '{':
		token->kind = RUST_TOKEN_SEGMENT;
		p = strchr(p, '}');
		if (!p)
			return drgn_error_create(DRGN_ERROR_SYNTAX, "expected '}'");
		p++;
		break;
	case '"':
		token->kind = RUST_TOKEN_STRING;
		p = strchr(p + 1, '"');
		if (!p)
			return drgn_error_create(DRGN_ERROR_SYNTAX, "expected '\"'");
		p++;
		break;
	case '\'':
		token->kind = RUST_TOKEN_LIFETIME;
		do {
			p++;
		} while (isalnum((unsigned char)*p) || *p == '_');
		break;
	default:
		if (isalpha((unsigned char)*p) || *p == '_') {
			token->kind = RUST_TOKEN_IDENTIFIER;
			do {
				p++;
			} while (isalnum((unsigned char)*p) || *p == '_');
		} else if (isdigit((unsigned char)*p)) {
			token->kind = RUST_TOKEN_NUMBER;
			do {
				p++;
			} while (isalnum((unsigned char)*p) || *p == '_');
		} else {
			return drgn_error_format(DRGN_ERROR_SYNTAX, "invalid character '%c'", *p);
		}
		break;
	}
	token->len = p - token->value;
	lexer->p = p;
	return NULL;
}

static bool rust_token_is_keyword(const struct drgn_token *token, const char *keyword)
{
	return token->kind == RUST_TOKEN_IDENTIFIER && token->len == strlen(keyword) &&
	       memcmp(token->value, keyword, token->len) == 0;
}

enum rust_type_expr_kind {
	// Looked up by its canonical name.
	RUST_TYPE_EXPR_NAMED,
	// &T, &mut T, *const T, or *mut T.
	RUST_TYPE_EXPR_POINTER,
	// [T; N].
	RUST_TYPE_EXPR_ARRAY,
	// [T].
	RUST_TYPE_EXPR_SLICE,
	// (T).
	RUST_TYPE_EXPR_PAREN,
};

struct rust_type_expr {
	enum rust_type_expr_kind kind;
	// Range of the canonical name in rust_type_parser::canonical.
	size_t start, end;
	// For RUST_TYPE_EXPR_NAMED: kinds of types to look up.
	uint64_t kinds;
	// For RUST_TYPE_EXPR_NAMED: whether this is a single identifier.
	bool is_identifier;
	// Whether this is a dynamically sized type: str, [T], or dyn T.
	bool is_unsized;
	// For RUST_TYPE_EXPR_ARRAY: length.
	uint64_t length;
	// For RUST_TYPE_EXPR_POINTER, RUST_TYPE_EXPR_ARRAY,
	// RUST_TYPE_EXPR_SLICE, and RUST_TYPE_EXPR_PAREN: index of operand.
	size_t operand;
};

DEFINE_VECTOR(rust_type_expr_vector, struct rust_type_expr);

struct rust_type_parser {
	struct drgn_lexer lexer;
	struct string_builder canonical;
	struct rust_type_expr_vector exprs;
};

static void rust_type_parser_deinit(struct rust_type_parser *parser)
{
	rust_type_expr_vector_deinit(&parser->exprs);
	string_builder_deinit(&parser->canonical);
	drgn_lexer_deinit(&parser->lexer);
}

#define RUST_NOMINAL_TYPE_KINDS							\
	((UINT64_C(1) << DRGN_TYPE_STRUCT) | (UINT64_C(1) << DRGN_TYPE_UNION) |	\
	 (UINT64_C(1) << DRGN_TYPE_CLASS) | (UINT64_C(1) << DRGN_TYPE_ENUM) | (UINT64_C(1) << DRGN_TYPE_TYPEDEF))

#define RUST_BASE_TYPE_KINDS							\
	((UINT64_C(1) << DRGN_TYPE_INT) | (UINT64_C(1) << DRGN_TYPE_BOOL) | (UINT64_C(1) << DRGN_TYPE_FLOAT))

// rustc represents tuples, trait objects, and fat pointers as structures, and
// (), !, and other zero-sized base types are represented as empty structures.
#define RUST_STRUCTURAL_TYPE_KINDS ((UINT64_C(1) << DRGN_TYPE_STRUCT) | RUST_BASE_TYPE_KINDS)

static struct drgn_error *rust_expect(struct rust_type_parser *parser, int kind, const char *what)
{
	struct drgn_error *err;
	struct drgn_token token;

	err = drgn_lexer_pop(&parser->lexer, &token);
	if (err)
		return err;
	if (token.kind != kind)
		return drgn_error_format(DRGN_ERROR_SYNTAX, "expected %s", what);
	return NULL;
}

static struct drgn_error *rust_append_token(struct rust_type_parser *parser, const struct drgn_token *token)
{
	if (!string_builder_appendn(&parser->canonical, token->value, token->len))
		return &drgn_enomem;
	return NULL;
}

static struct drgn_error *rust_append(struct rust_type_parser *parser, const char *str)
{
	if (!string_builder_append(&parser->canonical, str))
		return &drgn_enomem;
	return NULL;
}

static struct drgn_error *rust_parse_type(struct rust_type_parser *parser, size_t *ret);

static struct drgn_error *rust_parse_generic_args(struct rust_type_parser *parser)
{
	struct drgn_error *err;
	struct drgn_token token;
	bool first = true;

	err = rust_append(parser, "<");
	if (err)
		return err;
	for (;;) {
		err = drgn_lexer_pop(&parser->lexer, &token);
		if (err)
			return err;
		if (token.kind == '>')
			break;
		if (token.kind == RUST_TOKEN_LIFETIME) {
			err = drgn_lexer_pop(&parser->lexer, &token);
			if (err)
				return err;
			if (token.kind == '>')
				break;
			if (token.kind != ',')
				return drgn_error_create(DRGN_ERROR_SYNTAX, "expected ',' or '>'");
			continue;
		}

		if (!first) {
			err = rust_append(parser, ", ");
			if (err)
				return err;
		}
		first = false;

		if (token.kind == RUST_TOKEN_NUMBER) {
			err = rust_append_token(parser, &token);
			if (err)
				return err;
		} else {
			struct drgn_token next;
			if (token.kind == RUST_TOKEN_IDENTIFIER) {
				err = drgn_lexer_peek(&parser->lexer, &next);
				if (err)
					return err;
			} else {
				next.kind = RUST_TOKEN_EOF;
			}
			if (next.kind == '=') {
				err = drgn_lexer_pop(&parser->lexer, &next);
				if (!err)
					err = rust_append_token(parser, &token);
				if (!err)
					err = rust_append(parser, "=");
				if (err)
					return err;
			} else {
				err = drgn_lexer_push(&parser->lexer, &token);
				if (err)
					return err;
			}
			size_t unused;
			err = rust_parse_type(parser, &unused);
			if (err)
				return err;
		}

		err = drgn_lexer_pop(&parser->lexer, &token);
		if (err)
			return err;
		if (token.kind == '>')
			break;
		if (token.kind != ',')
			return drgn_error_create(DRGN_ERROR_SYNTAX, "expected ',' or '>'");
	}
	return rust_append(parser, ">");
}

static struct drgn_error *rust_parse_path(struct rust_type_parser *parser, bool *is_identifier_ret)
{
	struct drgn_error *err;
	struct drgn_token token;
	bool is_identifier = true;

	err = drgn_lexer_peek(&parser->lexer, &token);
	if (err)
		return err;
	if (token.kind == RUST_TOKEN_COLON_COLON) {
		err = drgn_lexer_pop(&parser->lexer, &token);
		if (!err)
			err = rust_append(parser, "::");
		if (err)
			return err;
		is_identifier = false;
	}

	for (;;) {
		err = drgn_lexer_pop(&parser->lexer, &token);
		if (err)
			return err;
		if (token.kind != RUST_TOKEN_IDENTIFIER && token.kind != RUST_TOKEN_SEGMENT)
			return drgn_error_create(DRGN_ERROR_SYNTAX, "expected identifier");
		err = rust_append_token(parser, &token);
		if (err)
			return err;

		err = drgn_lexer_peek(&parser->lexer, &token);
		if (err)
			return err;
		if (token.kind == '<') {
			err = drgn_lexer_pop(&parser->lexer, &token);
			if (!err)
				err = rust_parse_generic_args(parser);
			if (err)
				return err;
			is_identifier = false;
			err = drgn_lexer_peek(&parser->lexer, &token);
			if (err)
				return err;
		}
		if (token.kind != RUST_TOKEN_COLON_COLON)
			break;
		err = drgn_lexer_pop(&parser->lexer, &token);
		if (!err)
			err = rust_append(parser, "::");
		if (err)
			return err;
		is_identifier = false;
	}
	if (is_identifier_ret)
		*is_identifier_ret = is_identifier;
	return NULL;
}

static struct drgn_error *rust_parse_qualified_path(struct rust_type_parser *parser)
{
	struct drgn_error *err;
	struct drgn_token token;

	err = rust_append(parser, "<");
	if (err)
		return err;
	size_t unused;
	err = rust_parse_type(parser, &unused);
	if (err)
		return err;
	err = drgn_lexer_pop(&parser->lexer, &token);
	if (err)
		return err;
	if (!rust_token_is_keyword(&token, "as"))
		return drgn_error_create(DRGN_ERROR_SYNTAX, "expected 'as'");
	err = rust_append(parser, " as ");
	if (!err)
		err = rust_parse_path(parser, NULL);
	if (!err)
		err = rust_expect(parser, '>', "'>'");
	if (!err)
		err = rust_append(parser, ">");
	if (!err)
		err = rust_expect(parser, RUST_TOKEN_COLON_COLON, "'::'");
	if (!err)
		err = rust_append(parser, "::");
	if (!err)
		err = rust_parse_path(parser, NULL);
	return err;
}

static struct drgn_error *rust_parse_dyn(struct rust_type_parser *parser)
{
	struct drgn_error *err;
	struct drgn_token token;
	bool first = true;

	err = rust_append(parser, "dyn ");
	if (err)
		return err;
	for (;;) {
		err = drgn_lexer_peek(&parser->lexer, &token);
		if (err)
			return err;
		if (token.kind == RUST_TOKEN_LIFETIME) {
			err = drgn_lexer_pop(&parser->lexer, &token);
		} else {
			if (!first)
				err = rust_append(parser, " + ");
			if (!err)
				err = rust_parse_path(parser, NULL);
			first = false;
		}
		if (err)
			return err;
		err = drgn_lexer_peek(&parser->lexer, &token);
		if (err)
			return err;
		if (token.kind != '+')
			break;
		err = drgn_lexer_pop(&parser->lexer, &token);
		if (err)
			return err;
	}
	return NULL;
}

static struct drgn_error *rust_parse_parenthesized(struct rust_type_parser *parser, struct rust_type_expr *expr)
{
	struct drgn_error *err;
	struct drgn_token token;

	err = rust_append(parser, "(");
	if (err)
		return err;
	err = drgn_lexer_peek(&parser->lexer, &token);
	if (err)
		return err;
	if (token.kind == ')') {
		err = drgn_lexer_pop(&parser->lexer, &token);
		if (!err)
			err = rust_append(parser, ")");
		expr->kind = RUST_TYPE_EXPR_NAMED;
		expr->kinds = RUST_STRUCTURAL_TYPE_KINDS;
		return err;
	}

	err = rust_parse_type(parser, &expr->operand);
	if (err)
		return err;
	err = drgn_lexer_pop(&parser->lexer, &token);
	if (err)
		return err;
	if (token.kind == ')') {
		expr->kind = RUST_TYPE_EXPR_PAREN;
		return rust_append(parser, ")");
	}

	expr->kind = RUST_TYPE_EXPR_NAMED;
	expr->kinds = RUST_STRUCTURAL_TYPE_KINDS;
	for (size_t num_elements = 1;; num_elements++) {
		if (token.kind != ',')
			return drgn_error_create(DRGN_ERROR_SYNTAX, "expected ',' or ')'");
		err = drgn_lexer_peek(&parser->lexer, &token);
		if (err)
			return err;
		if (token.kind == ')') {
			err = drgn_lexer_pop(&parser->lexer, &token);
			if (!err)
				err = rust_append(parser, num_elements == 1 ? ",)" : ")");
			return err;
		}
		err = rust_append(parser, ", ");
		if (err)
			return err;
		size_t unused;
		err = rust_parse_type(parser, &unused);
		if (err)
			return err;
		err = drgn_lexer_pop(&parser->lexer, &token);
		if (err)
			return err;
		if (token.kind == ')')
			return rust_append(parser, ")");
	}
}

static struct drgn_error *rust_parse_array_length(const struct drgn_token *token, uint64_t *ret)
{
	char buf[32];

	if (token->kind != RUST_TOKEN_NUMBER || token->len >= sizeof(buf))
		return drgn_error_create(DRGN_ERROR_SYNTAX, "expected array length");
	memcpy(buf, token->value, token->len);
	buf[token->len] = '\0';
	char *end;
	errno = 0;
	*ret = strtoull(buf, &end, 0);
	if (errno == ERANGE)
		return drgn_error_create(DRGN_ERROR_OVERFLOW, "array length is too large");
	if (*end)
		return drgn_error_create(DRGN_ERROR_SYNTAX, "invalid array length");
	return NULL;
}

static struct drgn_error *rust_parse_type(struct rust_type_parser *parser, size_t *ret)
{
	struct drgn_error *err;
	struct drgn_token token;
	struct rust_type_expr expr = { .start = parser->canonical.len };

	drgn_recursion_guard(1000, "maximum type name depth exceeded");

	err = drgn_lexer_pop(&parser->lexer, &token);
	if (err)
		return err;
	switch (token.kind) {
	case '&': {
		err = drgn_lexer_peek(&parser->lexer, &token);
		if (err)
			return err;
		if (token.kind == RUST_TOKEN_LIFETIME) {
			err = drgn_lexer_pop(&parser->lexer, &token);
			if (!err)
				err = drgn_lexer_peek(&parser->lexer, &token);
			if (err)
				return err;
		}
		bool is_mut = rust_token_is_keyword(&token, "mut");
		if (is_mut) {
			err = drgn_lexer_pop(&parser->lexer, &token);
			if (err)
				return err;
		}
		err = rust_append(parser, is_mut ? "&mut " : "&");
		if (err)
			return err;
		expr.kind = RUST_TYPE_EXPR_POINTER;
		err = rust_parse_type(parser, &expr.operand);
		break;
	}
	case '*':
		err = drgn_lexer_pop(&parser->lexer, &token);
		if (err)
			return err;
		if (rust_token_is_keyword(&token, "const"))
			err = rust_append(parser, "*const ");
		else if (rust_token_is_keyword(&token, "mut"))
			err = rust_append(parser, "*mut ");
		else
			return drgn_error_create(DRGN_ERROR_SYNTAX, "expected 'const' or 'mut' after '*'");
		if (err)
			return err;
		expr.kind = RUST_TYPE_EXPR_POINTER;
		err = rust_parse_type(parser, &expr.operand);
		break;
	case '[':
		err = rust_append(parser, "[");
		if (!err)
			err = rust_parse_type(parser, &expr.operand);
		if (!err)
			err = drgn_lexer_pop(&parser->lexer, &token);
		if (err)
			return err;
		if (token.kind == ';') {
			err = drgn_lexer_pop(&parser->lexer, &token);
			if (!err)
				err = rust_parse_array_length(&token, &expr.length);
			if (err)
				return err;
			if (!string_builder_appendf(&parser->canonical, "; %" PRIu64 "]", expr.length))
				return &drgn_enomem;
			expr.kind = RUST_TYPE_EXPR_ARRAY;
			err = rust_expect(parser, ']', "']'");
		} else if (token.kind == ']') {
			expr.kind = RUST_TYPE_EXPR_SLICE;
			expr.is_unsized = true;
			err = rust_append(parser, "]");
		} else {
			return drgn_error_create(DRGN_ERROR_SYNTAX, "expected ';' or ']'");
		}
		break;
	case '(':
		err = rust_parse_parenthesized(parser, &expr);
		break;
	case '!':
		expr.kind = RUST_TYPE_EXPR_NAMED;
		expr.kinds = RUST_STRUCTURAL_TYPE_KINDS;
		err = rust_append(parser, "!");
		break;
	case '<':
		expr.kind = RUST_TYPE_EXPR_NAMED;
		expr.kinds = RUST_NOMINAL_TYPE_KINDS;
		err = rust_parse_qualified_path(parser);
		break;
	case RUST_TOKEN_IDENTIFIER:
		if (rust_token_is_keyword(&token, "dyn")) {
			expr.kind = RUST_TYPE_EXPR_NAMED;
			expr.kinds = RUST_STRUCTURAL_TYPE_KINDS;
			expr.is_unsized = true;
			err = rust_parse_dyn(parser);
			break;
		}
		if (rust_token_is_keyword(&token, "fn") || rust_token_is_keyword(&token, "unsafe") ||
		    rust_token_is_keyword(&token, "extern")) {
			return drgn_error_create(DRGN_ERROR_NOT_IMPLEMENTED,
						 "function pointer types are not implemented");
		}
		fallthrough;
	case RUST_TOKEN_SEGMENT:
	case RUST_TOKEN_COLON_COLON:
		err = drgn_lexer_push(&parser->lexer, &token);
		if (err)
			return err;
		expr.kind = RUST_TYPE_EXPR_NAMED;
		expr.kinds = RUST_NOMINAL_TYPE_KINDS;
		err = rust_parse_path(parser, &expr.is_identifier);
		expr.is_unsized = rust_token_is_keyword(&token, "str") && expr.is_identifier;
		break;
	default:
		return drgn_error_create(DRGN_ERROR_SYNTAX, "expected type");
	}
	if (err)
		return err;

	if (expr.kind == RUST_TYPE_EXPR_PAREN)
		expr.is_unsized = rust_type_expr_vector_at(&parser->exprs, expr.operand)->is_unsized;
	expr.end = parser->canonical.len;
	*ret = rust_type_expr_vector_size(&parser->exprs);
	if (!rust_type_expr_vector_append(&parser->exprs, &expr))
		return &drgn_enomem;
	return NULL;
}

static const struct {
	const char *name;
	enum drgn_type_kind kind;
	// 0 means the size of a pointer.
	uint8_t size;
	bool is_signed;
} rust_primitive_types[] = {
	{ "bool", DRGN_TYPE_BOOL, 1 },
	{ "char", DRGN_TYPE_INT, 4, false },
	{ "i8", DRGN_TYPE_INT, 1, true },
	{ "i16", DRGN_TYPE_INT, 2, true },
	{ "i32", DRGN_TYPE_INT, 4, true },
	{ "i64", DRGN_TYPE_INT, 8, true },
	{ "i128", DRGN_TYPE_INT, 16, true },
	{ "isize", DRGN_TYPE_INT, 0, true },
	{ "u8", DRGN_TYPE_INT, 1, false },
	{ "u16", DRGN_TYPE_INT, 2, false },
	{ "u32", DRGN_TYPE_INT, 4, false },
	{ "u64", DRGN_TYPE_INT, 8, false },
	{ "u128", DRGN_TYPE_INT, 16, false },
	{ "usize", DRGN_TYPE_INT, 0, false },
	{ "f32", DRGN_TYPE_FLOAT, 4 },
	{ "f64", DRGN_TYPE_FLOAT, 8 },
};

static struct drgn_error *rust_find_primitive_type(struct drgn_program *prog, const char *name, size_t name_len,
						   const char *filename, struct drgn_qualified_type *ret)
{
	struct drgn_error *err;

	for (size_t i = 0; i < array_size(rust_primitive_types); i++) {
		if (strlen(rust_primitive_types[i].name) != name_len ||
		    memcmp(rust_primitive_types[i].name, name, name_len) != 0)
			continue;

		err = drgn_program_find_type_impl(prog, RUST_BASE_TYPE_KINDS, name, name_len, filename, ret);
		if (err != &drgn_not_found)
			return err;

		uint64_t size = rust_primitive_types[i].size;
		if (size == 0) {
			err = drgn_program_address_size(prog, &size);
			if (err)
				return err;
		}
		ret->qualifiers = 0;
		switch (rust_primitive_types[i].kind) {
		case DRGN_TYPE_BOOL:
			return drgn_bool_type_create(prog, rust_primitive_types[i].name, size, DRGN_PROGRAM_ENDIAN,
						     &drgn_language_rust, &ret->type);
		case DRGN_TYPE_FLOAT:
			return drgn_float_type_create(prog, rust_primitive_types[i].name, size, DRGN_PROGRAM_ENDIAN,
						      &drgn_language_rust, &ret->type);
		default:
			return drgn_int_type_create(prog, rust_primitive_types[i].name, size,
						    rust_primitive_types[i].is_signed, DRGN_PROGRAM_ENDIAN,
						    &drgn_language_rust, &ret->type);
		}
	}
	return &drgn_not_found;
}

static struct drgn_error *rust_resolve_type(struct rust_type_parser *parser, struct drgn_program *prog,
					    const char *filename, size_t index, struct drgn_qualified_type *ret)
{
	struct drgn_error *err;
	struct rust_type_expr *expr = rust_type_expr_vector_at(&parser->exprs, index);
	const char *name = parser->canonical.str + expr->start;
	size_t name_len = expr->end - expr->start;
	struct drgn_qualified_type operand_type;

	SWITCH_ENUM(expr->kind) {
	case RUST_TYPE_EXPR_NAMED:
		if (expr->is_identifier) {
			err = rust_find_primitive_type(prog, name, name_len, filename, ret);
			if (err != &drgn_not_found)
				return err;
		}
		return drgn_program_find_type_impl(prog, expr->kinds, name, name_len, filename, ret);
	case RUST_TYPE_EXPR_POINTER: {
		err = drgn_program_find_type_impl(prog, UINT64_C(1) << DRGN_TYPE_STRUCT, name, name_len, filename, ret);
		if (err != &drgn_not_found || rust_type_expr_vector_at(&parser->exprs, expr->operand)->is_unsized)
			return err;
		err = rust_resolve_type(parser, prog, filename, expr->operand, &operand_type);
		if (err)
			return err;
		const char *interned_name;
		err = drgn_program_intern_type_name(prog, name, name_len, &interned_name);
		if (err)
			return err;
		uint64_t size;
		err = drgn_program_address_size(prog, &size);
		if (err)
			return err;
		ret->qualifiers = 0;
		return drgn_pointer_type_create(prog, operand_type, size, DRGN_PROGRAM_ENDIAN, interned_name,
						&drgn_language_rust, &ret->type);
	}
	case RUST_TYPE_EXPR_ARRAY:
	case RUST_TYPE_EXPR_SLICE: {
		uint64_t length = expr->length;
		bool is_array = expr->kind == RUST_TYPE_EXPR_ARRAY;
		err = rust_resolve_type(parser, prog, filename, expr->operand, &operand_type);
		if (err)
			return err;
		ret->qualifiers = 0;
		if (is_array)
			return drgn_array_type_create(prog, operand_type, length, &drgn_language_rust, &ret->type);
		return drgn_incomplete_array_type_create(prog, operand_type, &drgn_language_rust, &ret->type);
	}
	case RUST_TYPE_EXPR_PAREN:
		return rust_resolve_type(parser, prog, filename, expr->operand, ret);
	default:
		UNREACHABLE();
	}
}

struct drgn_error *drgn_rust_find_type(const struct drgn_language *lang, struct drgn_program *prog, const char *name,
				       const char *filename, struct drgn_qualified_type *ret)
{
	struct drgn_error *err;
	_cleanup_(rust_type_parser_deinit) struct rust_type_parser parser = {
		.lexer = DRGN_LEXER_INIT(rust_lexer_func, name),
		.canonical = STRING_BUILDER_INIT,
		.exprs = VECTOR_INIT,
	};

	size_t index;
	err = rust_parse_type(&parser, &index);
	if (err)
		return err;
	err = rust_expect(&parser, RUST_TOKEN_EOF, "end of type name");
	if (err)
		return err;
	return rust_resolve_type(&parser, prog, filename, index, ret);
}
