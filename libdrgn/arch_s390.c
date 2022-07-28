// SPDX-License-Identifier: GPL-3.0-or-later

#include "platform.h" // IWYU pragma: associated

/*
 * The ABI specification can be found at:
 * https://github.com/IBM/s390x-abi
 */

static struct drgn_error drgn_invalid_rel = {
	.code = DRGN_ERROR_OTHER,
	.message = "invalid relocation entry",
};

static struct drgn_error *
apply_rela_bits(char *dest, uint64_t loc, uint64_t val,
			   int sign, int bits, int shift)
{
	unsigned long umax;
	long min, max;

	if (val & ((1UL << shift) - 1))
		return &drgn_invalid_rel;
	if (sign) {
		val = (uint64_t)(((long) val) >> shift);
		min = -(1L << (bits - 1));
		max = (1L << (bits - 1)) - 1;
		if ((long) val < min || (long) val > max)
			return &drgn_invalid_rel;
	} else {
		val >>= shift;
		umax = ((1UL << (bits - 1)) << 1) - 1;
		if ((unsigned long) val > umax)
			return &drgn_invalid_rel;
	}

	if (bits == 8) {
		unsigned char tmp = val;
		memcpy(dest + loc, &tmp, 1);
	} else if (bits == 12) {
		unsigned short tmp = (val & 0xfff) |
			(*(unsigned short *) loc & 0xf000);
		memcpy(dest + loc, &tmp, 2);
	} else if (bits == 16) {
		unsigned short tmp = val;
		memcpy(dest + loc, &tmp, 2);
	} else if (bits == 20) {
		unsigned int tmp = (val & 0xfff) << 16 |
			(val & 0xff000) >> 4 | (*(unsigned int *) loc & 0xf00000ff);
		memcpy(dest + loc, &tmp, 4);
	} else if (bits == 32) {
		unsigned int tmp = val;
		memcpy(dest + loc, &tmp, 4);
	} else if (bits == 64) {
		unsigned long tmp = val;
		memcpy(dest + loc, &tmp, 8);
	}
	return 0;
}

static struct drgn_error *
apply_elf_reloc_s390(const struct drgn_relocating_section *relocating,
			uint64_t r_offset, uint32_t r_type, const int64_t *r_addend,
			uint64_t sym_value)
{
	struct drgn_error *err = NULL;

	switch (r_type) {
	case R_390_NONE:
		break;
	case R_390_8:		/* Direct 8 bit.   */
		err = apply_rela_bits(relocating->buf, r_offset, *r_addend, 0, 8, 0);
		break;
	case R_390_12:		/* Direct 12 bit.  */
		err = apply_rela_bits(relocating->buf, r_offset, *r_addend, 0, 12, 0);
		break;
	case R_390_16:		/* Direct 16 bit.  */
		err = apply_rela_bits(relocating->buf, r_offset, *r_addend, 0, 16, 0);
		break;
	case R_390_20:		/* Direct 20 bit.  */
		err = apply_rela_bits(relocating->buf, r_offset, *r_addend, 1, 20, 0);
		break;
	case R_390_32:		/* Direct 32 bit.  */
		err = apply_rela_bits(relocating->buf, r_offset, *r_addend, 0, 32, 0);
		break;
	case R_390_64:		/* Direct 64 bit.  */
		err = apply_rela_bits(relocating->buf, r_offset, *r_addend, 0, 64, 0);
		break;
	case R_390_PC16:	/* PC relative 16 bit.  */
		err = apply_rela_bits(relocating->buf, r_offset, *r_addend - r_offset, 1, 16, 0);
		break;
	case R_390_PC16DBL:	/* PC relative 16 bit shifted by 1.  */
		err = apply_rela_bits(relocating->buf, r_offset, *r_addend - r_offset, 1, 16, 1);
		break;
	case R_390_PC32DBL:	/* PC relative 32 bit shifted by 1.  */
		err = apply_rela_bits(relocating->buf, r_offset, *r_addend - r_offset, 1, 32, 1);
		break;
	case R_390_PC32:	/* PC relative 32 bit.  */
		err = apply_rela_bits(relocating->buf, r_offset, *r_addend - r_offset, 1, 32, 0);
		break;
	case R_390_PC64:	/* PC relative 64 bit.	*/
		err = apply_rela_bits(relocating->buf, r_offset, *r_addend - r_offset, 1, 64, 0);
		break;
	default:
		err = DRGN_UNKNOWN_RELOCATION_TYPE(r_type);
		break;
	}
	return err;
}

const struct drgn_architecture_info arch_info_s390 = {
	.name = "s390",
	.arch = DRGN_ARCH_S390,
	.default_flags = DRGN_PLATFORM_IS_64_BIT,
	.register_by_name = drgn_register_by_name_unknown,
	.apply_elf_reloc = apply_elf_reloc_s390,
};
