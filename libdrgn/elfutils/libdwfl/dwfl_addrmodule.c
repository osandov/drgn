/* Find module containing address.
   Copyright (C) 2005, 2006, 2007, 2008 Red Hat, Inc.
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

static bool append_lookup_module (Dwfl *dwfl, Dwfl_Module *mod, GElf_Addr start,
				  GElf_Addr end)
{
  if (dwfl->lookup_module_elts >= dwfl->lookup_module_alloc)
    {
      size_t n = dwfl->lookup_module_alloc;
      n = n == 0 ? 16 : n * 2;
      struct dwfl_module_segment *tmp;
      tmp = realloc (dwfl->lookup_module, n * sizeof (tmp[0]));
      if (tmp == NULL)
	{
	  __libdwfl_seterrno (DWFL_E_NOMEM);
	  return true;
	}
      dwfl->lookup_module = tmp;
      dwfl->lookup_module_alloc = n;
    }
  size_t i = dwfl->lookup_module_elts++;
  dwfl->lookup_module[i].start = start;
  dwfl->lookup_module[i].end = end;
  dwfl->lookup_module[i].mod = mod;
  return false;
}

static int compare_dwfl_module_segment (const void *a, const void *b)
{
  const struct dwfl_module_segment *seg1 = a;
  const struct dwfl_module_segment *seg2 = b;
  if (seg1->start < seg2->start)
    return -1;
  else if (seg1->start > seg2->start)
    return 1;
  else
    return 0;
}

static bool
create_lookup_module (Dwfl *dwfl)
{
  for (Dwfl_Module *mod = dwfl->modulelist; mod != NULL; mod = mod->next)
    if (! mod->gc)
      {
	Dwarf_Addr bias;
	if (mod->dwfl->callbacks->find_elf
	    && dwfl_module_getdwarf(mod, &bias)
	    && mod->e_type == ET_REL)
	  {
	    if (__libdwfl_cache_sections (mod) < 0)
	      return true;

	    struct dwfl_relocation *sections = mod->reloc_info;
	    for (size_t i = 0; i < sections->count; i++)
	      if (append_lookup_module(dwfl, mod, sections->refs[i].start,
				       sections->refs[i].end))
		return true;
	  }
	else
	  {
	    GElf_Addr start = __libdwfl_segment_start(dwfl, mod->low_addr);
	    GElf_Addr end = __libdwfl_segment_end(dwfl, mod->high_addr);
	    if (append_lookup_module(dwfl, mod, start, end))
	      return true;
	  }
      }

  qsort (dwfl->lookup_module, dwfl->lookup_module_elts,
	 sizeof (dwfl->lookup_module[0]), compare_dwfl_module_segment);
  for (size_t i = 0; i < dwfl->lookup_module_elts; i++)
    {
      dwfl->lookup_module[i].mod->lookup = i;
      /* If the upper boundary of the segment isn't part of the next segment,
	 treat it as part of the segment.  */
      if (i == dwfl->lookup_module_elts - 1
	  || dwfl->lookup_module[i].end < dwfl->lookup_module[i + 1].start)
	dwfl->lookup_module[i].end++;
    }
  return false;
}

static int search_dwfl_module_segment (const void *key, const void *elt)
{
  Dwarf_Addr address = *(Dwarf_Addr *)key;
  const struct dwfl_module_segment *seg = elt;
  if (address < seg->start)
    return -1;
  else if (address >= seg->end)
    return 1;
  else
    return 0;
}

Dwfl_Module *
dwfl_addrmodule (Dwfl *dwfl, Dwarf_Addr address)
{
  if (unlikely (dwfl == NULL)
      || (unlikely (dwfl->lookup_module_elts == 0)
	  && unlikely (create_lookup_module (dwfl))))
    return NULL;

  struct dwfl_module_segment *seg = bsearch (&address, dwfl->lookup_module,
					     dwfl->lookup_module_elts,
					     sizeof (dwfl->lookup_module[0]),
					     search_dwfl_module_segment);
  if (seg == NULL)
    return NULL;
  return seg->mod;
}
INTDEF (dwfl_addrmodule)
