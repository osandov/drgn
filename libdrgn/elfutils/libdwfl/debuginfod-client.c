/* Try to get an ELF or debug file through the debuginfod.
   Copyright (C) 2019 Red Hat, Inc.
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
#include <dlfcn.h>

static __typeof__ (debuginfod_begin) *fp_debuginfod_begin;
static __typeof__ (debuginfod_find_executable) *fp_debuginfod_find_executable;
static __typeof__ (debuginfod_find_debuginfo) *fp_debuginfod_find_debuginfo;
static __typeof__ (debuginfod_end) *fp_debuginfod_end;

/* NB: this is slightly thread-unsafe */

static debuginfod_client *
get_client (Dwfl *dwfl)
{
  if (dwfl->debuginfod != NULL)
    return dwfl->debuginfod;

  if (fp_debuginfod_begin != NULL)
    {
      dwfl->debuginfod = (*fp_debuginfod_begin) ();
      return dwfl->debuginfod;
    }

  return NULL;
}

int
__libdwfl_debuginfod_find_executable (Dwfl *dwfl,
				      const unsigned char *build_id_bits,
				      size_t build_id_len)
{
  int fd = -1;
  if (build_id_len > 0)
    {
      debuginfod_client *c = get_client (dwfl);
      if (c != NULL)
	fd = (*fp_debuginfod_find_executable) (c, build_id_bits,
					       build_id_len, NULL);
    }

  return fd;
}

int
__libdwfl_debuginfod_find_debuginfo (Dwfl *dwfl,
				     const unsigned char *build_id_bits,
				     size_t build_id_len)
{
  int fd = -1;
  if (build_id_len > 0)
    {
      debuginfod_client *c = get_client (dwfl);
      if (c != NULL)
	fd = (*fp_debuginfod_find_debuginfo) (c, build_id_bits,
					      build_id_len, NULL);
    }

  return fd;
}

void
__libdwfl_debuginfod_end (debuginfod_client *c)
{
  if (c != NULL)
    (*fp_debuginfod_end) (c);
}

/* Try to get the libdebuginfod library functions to make sure
   everything is initialized early.  */
void __attribute__ ((constructor))
__libdwfl_debuginfod_init (void)
{
  void *debuginfod_so = dlopen("libdebuginfod-" VERSION ".so", RTLD_LAZY);

  if (debuginfod_so == NULL)
    debuginfod_so = dlopen("libdebuginfod.so", RTLD_LAZY);

  if (debuginfod_so != NULL)
    {
      fp_debuginfod_begin = dlsym (debuginfod_so, "debuginfod_begin");
      fp_debuginfod_find_executable = dlsym (debuginfod_so,
					     "debuginfod_find_executable");
      fp_debuginfod_find_debuginfo = dlsym (debuginfod_so,
					    "debuginfod_find_debuginfo");
      fp_debuginfod_end = dlsym (debuginfod_so, "debuginfod_end");

      /* We either get them all, or we get none.  */
      if (fp_debuginfod_begin == NULL
	  || fp_debuginfod_find_executable == NULL
	  || fp_debuginfod_find_debuginfo == NULL
	  || fp_debuginfod_end == NULL)
	{
	  fp_debuginfod_begin = NULL;
	  fp_debuginfod_find_executable = NULL;
	  fp_debuginfod_find_debuginfo = NULL;
	  fp_debuginfod_end = NULL;
	  dlclose (debuginfod_so);
	}
    }
}
