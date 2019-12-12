/* Manage address space lookup table for libdwfl.
   Copyright (C) 2008, 2009, 2010, 2013, 2015 Red Hat, Inc.
   This file is part of elfutils.

   This file is free software; you can redistribute it and/or modify
   it under the terms of either

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at
       your option) any later version

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at
       your option) any later version

   or both in parallel, as here.

   elfutils is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see <http://www.gnu.org/licenses/>.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "libdwflP.h"

GElf_Addr
internal_function
__libdwfl_segment_start (Dwfl *dwfl, GElf_Addr start)
{
  if (dwfl->segment_align > 1)
    start &= -dwfl->segment_align;
  return start;
}

GElf_Addr
internal_function
__libdwfl_segment_end (Dwfl *dwfl, GElf_Addr end)
{
  if (dwfl->segment_align > 1)
    end = (end + dwfl->segment_align - 1) & -dwfl->segment_align;
  return end;
}

static bool
insert (Dwfl *dwfl, size_t i, GElf_Addr start, GElf_Addr end, int segndx)
{
  bool need_start = (i == 0 || dwfl->lookup_addr[i - 1] != start);
  bool need_end = (i + 1 >= dwfl->lookup_elts
		   || dwfl->lookup_addr[i + 1] != end);
  size_t need = need_start + need_end;
  if (need == 0)
    return false;

  if (dwfl->lookup_alloc - dwfl->lookup_elts < need)
    {
      size_t n = dwfl->lookup_alloc == 0 ? 16 : dwfl->lookup_alloc * 2;
      GElf_Addr *naddr = realloc (dwfl->lookup_addr, sizeof naddr[0] * n);
      if (unlikely (naddr == NULL))
	return true;
      int *nsegndx = realloc (dwfl->lookup_segndx, sizeof nsegndx[0] * n);
      if (unlikely (nsegndx == NULL))
	{
	  if (naddr != dwfl->lookup_addr)
	    free (naddr);
	  return true;
	}
      dwfl->lookup_alloc = n;
      dwfl->lookup_addr = naddr;
      dwfl->lookup_segndx = nsegndx;
    }

  if (unlikely (i < dwfl->lookup_elts))
    {
      const size_t move = dwfl->lookup_elts - i;
      memmove (&dwfl->lookup_addr[i + need], &dwfl->lookup_addr[i],
	       move * sizeof dwfl->lookup_addr[0]);
      memmove (&dwfl->lookup_segndx[i + need], &dwfl->lookup_segndx[i],
	       move * sizeof dwfl->lookup_segndx[0]);
    }

  if (need_start)
    {
      dwfl->lookup_addr[i] = start;
      dwfl->lookup_segndx[i] = segndx;
      ++i;
    }
  else
    dwfl->lookup_segndx[i - 1] = segndx;

  if (need_end)
    {
      dwfl->lookup_addr[i] = end;
      dwfl->lookup_segndx[i] = -1;
    }

  dwfl->lookup_elts += need;

  return false;
}

static int
lookup (Dwfl *dwfl, GElf_Addr address, int hint)
{
  if (hint >= 0
      && address >= dwfl->lookup_addr[hint]
      && ((size_t) hint + 1 == dwfl->lookup_elts
	  || address < dwfl->lookup_addr[hint + 1]))
    return hint;

  /* Do binary search on the array indexed by module load address.  */
  size_t l = 0, u = dwfl->lookup_elts;
  while (l < u)
    {
      size_t idx = (l + u) / 2;
      if (address < dwfl->lookup_addr[idx])
	u = idx;
      else
	{
	  l = idx + 1;
	  if (l == dwfl->lookup_elts || address < dwfl->lookup_addr[l])
	    return idx;
	}
    }

  return -1;
}

int
dwfl_addrsegment (Dwfl *dwfl, Dwarf_Addr address, Dwfl_Module **mod)
{
  if (unlikely (dwfl == NULL))
    return -1;

  int idx = lookup (dwfl, address, -1);
  if (likely (idx >= 0))
    /* Translate internal segment table index to user segment index.  */
    idx = dwfl->lookup_segndx[idx];

  if (mod != NULL)
    *mod = INTUSE(dwfl_addrmodule) (dwfl, address);

  return idx;
}
INTDEF (dwfl_addrsegment)

int
dwfl_report_segment (Dwfl *dwfl, int ndx, const GElf_Phdr *phdr, GElf_Addr bias,
		     const void *ident)
{
  /* This was previously used for coalescing segments, but it was buggy since
     day one.  We don't use it anymore.  */
  (void)ident;

  if (dwfl == NULL)
    return -1;

  if (ndx < 0)
    ndx = dwfl->next_segndx;

  if (phdr->p_align > 1 && (dwfl->segment_align <= 1 ||
			    phdr->p_align < dwfl->segment_align))
    dwfl->segment_align = phdr->p_align;

  GElf_Addr start = __libdwfl_segment_start (dwfl, bias + phdr->p_vaddr);
  GElf_Addr end = __libdwfl_segment_end (dwfl,
					 bias + phdr->p_vaddr + phdr->p_memsz);

  /* Normally just appending keeps us sorted.  */

  size_t i = dwfl->lookup_elts;
  while (i > 0 && unlikely (start < dwfl->lookup_addr[i - 1]))
    --i;

  if (unlikely (insert (dwfl, i, start, end, ndx)))
    {
      __libdwfl_seterrno (DWFL_E_NOMEM);
      return -1;
    }

  dwfl->next_segndx = ndx + 1;

  return ndx;
}
INTDEF (dwfl_report_segment)
