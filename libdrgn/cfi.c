// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "cfi.h"

const struct drgn_cfi_row drgn_empty_cfi_row_impl;

bool drgn_cfi_row_copy(struct drgn_cfi_row **dst,
		       const struct drgn_cfi_row *src)
{
	if (src->num_regs + 1 > (*dst)->allocated_rules) {
		if ((*dst)->allocated_rules == 0 && src->allocated_rules == 0) {
			*dst = (struct drgn_cfi_row *)src;
			return true;
		}
		struct drgn_cfi_row *tmp =
			malloc(sizeof(struct drgn_cfi_row) +
			       src->num_regs * sizeof(struct drgn_cfi_rule));
		if (!tmp)
			return false;
		tmp->allocated_rules = src->num_regs + 1;
		drgn_cfi_row_destroy(*dst);
		*dst = tmp;
	}
	(*dst)->num_regs = src->num_regs;
	(*dst)->cfa_rule = src->cfa_rule;
	memcpy((*dst)->reg_rules, src->reg_rules,
	       (*dst)->num_regs * sizeof((*dst)->reg_rules[0]));
	return true;
}

static bool drgn_cfi_row_reserve(struct drgn_cfi_row **row, uint16_t num_rules)
{
	if ((*row)->allocated_rules < num_rules) {
		if (num_rules < (*row)->num_regs + 1)
			num_rules = (*row)->num_regs + 1;
		size_t size;
		if (__builtin_mul_overflow((uint16_t)(num_rules - 1),
					   sizeof(struct drgn_cfi_rule),
					   &size) ||
		    __builtin_add_overflow(sizeof(struct drgn_cfi_row), size,
					   &size))
			return false;
		struct drgn_cfi_row *tmp;
		if ((*row)->allocated_rules == 0) {
			tmp = malloc(size);
			if (!tmp)
				return false;
			tmp->num_regs = (*row)->num_regs;
			tmp->cfa_rule = (*row)->cfa_rule;
			memcpy(tmp->reg_rules, (*row)->reg_rules,
			       tmp->num_regs * sizeof(tmp->reg_rules[0]));
		} else {
			tmp = realloc(*row, size);
			if (!tmp)
				return false;
		}
		tmp->allocated_rules = num_rules;
		*row = tmp;
	}
	return true;
}

bool drgn_cfi_row_set_cfa(struct drgn_cfi_row **row,
			  const struct drgn_cfi_rule *rule)
{
	assert(rule->kind != DRGN_CFI_RULE_AT_CFA_PLUS_OFFSET);
	assert(rule->kind != DRGN_CFI_RULE_CFA_PLUS_OFFSET);
	if (!drgn_cfi_row_reserve(row, 1))
		return false;
	(*row)->cfa_rule = *rule;
	return true;
}

void drgn_cfi_row_get_register(const struct drgn_cfi_row *row,
			       drgn_register_number regno,
			       struct drgn_cfi_rule *ret)
{
	if (regno < row->num_regs)
		*ret = row->reg_rules[regno];
	else
		ret->kind = DRGN_CFI_RULE_UNDEFINED;
}

bool drgn_cfi_row_set_register(struct drgn_cfi_row **row,
			       drgn_register_number regno,
			       const struct drgn_cfi_rule *rule)
{
	assert(regno <= DRGN_MAX_REGISTER_NUMBER);
	if (!drgn_cfi_row_reserve(row, regno + 2))
		return false;
	if (regno >= (*row)->num_regs) {
		static_assert(DRGN_CFI_RULE_UNDEFINED == 0,
			      "DRGN_CFI_RULE_UNDEFINED must be zero");
		memset(&(*row)->reg_rules[(*row)->num_regs], 0,
		       (regno - (*row)->num_regs) *
		       sizeof((*row)->reg_rules[0]));
		(*row)->num_regs = regno + 1;
	}
	(*row)->reg_rules[regno] = *rule;
	return true;
}
