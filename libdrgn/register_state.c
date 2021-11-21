// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <elfutils/libdwfl.h>
#include <limits.h>

#include "debug_info.h"
#include "drgn.h"
#include "register_state.h"

#define drgn_register_state_known_bitset(regs) ({	\
	__auto_type _state = (regs);			\
	&_state->buf[_state->regs_size];		\
})

struct drgn_register_state *drgn_register_state_create_impl(uint32_t regs_size,
							    uint16_t num_regs,
							    bool interrupted)
{
	uint32_t bitset_size = ((uint32_t)num_regs + CHAR_BIT + 1) / CHAR_BIT;
	size_t size;
	struct drgn_register_state *regs;
	if (__builtin_add_overflow(regs_size, bitset_size, &size) ||
	    __builtin_add_overflow(size, sizeof(*regs), &size) ||
	    !(regs = malloc(size)))
		return NULL;
	regs->module = NULL;
	regs->regs_size = regs_size;
	regs->num_regs = num_regs;
	regs->interrupted = interrupted;
	memset(drgn_register_state_known_bitset(regs), 0, bitset_size);
	return regs;
}

static bool
drgn_register_state_is_known(const struct drgn_register_state *regs, uint32_t i)
{
	const unsigned char *bitset = drgn_register_state_known_bitset(regs);
	return (bitset[i / CHAR_BIT] & (1 << (i % CHAR_BIT))) != 0;
}

static void drgn_register_state_set_known(struct drgn_register_state *regs,
					  uint32_t i)
{
	unsigned char *bitset = drgn_register_state_known_bitset(regs);
	bitset[i / CHAR_BIT] |= 1 << (i % CHAR_BIT);
}

bool drgn_register_state_has_register(const struct drgn_register_state *regs,
				      drgn_register_number regno)
{
	return (regno < regs->num_regs &&
		drgn_register_state_is_known(regs, (uint32_t)regno + 2));
}

void drgn_register_state_set_has_register(struct drgn_register_state *regs,
					  drgn_register_number regno)
{
	assert(regno < regs->num_regs);
	drgn_register_state_set_known(regs, (uint32_t)regno + 2);
}

void
drgn_register_state_set_has_register_range(struct drgn_register_state *regs,
					   drgn_register_number first_regno,
					   drgn_register_number last_regno)
{
	assert(first_regno <= last_regno);
	assert(last_regno < regs->num_regs);
	for (uint32_t regno = first_regno; regno <= last_regno; regno++)
		drgn_register_state_set_known(regs, regno + 2);
}

struct optional_uint64
drgn_register_state_get_pc(const struct drgn_register_state *regs)
{
	return (struct optional_uint64){
		regs->_pc,
		drgn_register_state_is_known(regs, 0),
	};
}

void drgn_register_state_set_pc(struct drgn_program *prog,
				struct drgn_register_state *regs, uint64_t pc)
{
	pc &= drgn_platform_address_mask(&prog->platform);
	regs->_pc = pc;
	drgn_register_state_set_known(regs, 0);
	if (prog->dbinfo) {
		Dwfl_Module *dwfl_module = dwfl_addrmodule(prog->dbinfo->dwfl,
							   pc - !regs->interrupted);
		if (dwfl_module) {
			void **userdatap;
			dwfl_module_info(dwfl_module, &userdatap, NULL, NULL,
					 NULL, NULL, NULL, NULL);
			struct drgn_debug_info_module *module = *userdatap;
			static const enum drgn_platform_flags check_flags =
				(DRGN_PLATFORM_IS_64_BIT |
				 DRGN_PLATFORM_IS_LITTLE_ENDIAN);
			if (module->platform.arch == prog->platform.arch &&
			    (module->platform.flags & check_flags) ==
			    (prog->platform.flags & check_flags))
				regs->module = module;
		}
	}
}

struct optional_uint64
drgn_register_state_get_cfa(const struct drgn_register_state *regs)
{
	return (struct optional_uint64){
		regs->_cfa,
		drgn_register_state_is_known(regs, 1),
	};
}

void drgn_register_state_set_cfa(struct drgn_program *prog,
				 struct drgn_register_state *regs, uint64_t cfa)
{
	regs->_cfa = cfa & drgn_platform_address_mask(&prog->platform);
	drgn_register_state_set_known(regs, 1);
}
