/* Sniff out modules from ELF headers visible in memory segments.
   Copyright (C) 2008-2012, 2014, 2015, 2018 Red Hat, Inc.
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

#include <config.h>
#include "../libelf/libelfP.h"	/* For NOTE_ALIGN4 and NOTE_ALIGN8.  */
#undef	_
#include "libdwflP.h"
#include "common.h"

#include <elf.h>
#include <gelf.h>
#include <inttypes.h>
#include <endian.h>
#include <unistd.h>
#include <fcntl.h>

#include <system.h>


/* A good size for the initial read from memory, if it's not too costly.
   This more than covers the phdrs and note segment in the average 64-bit
   binary.  */

#define INITIAL_READ	1024

#if __BYTE_ORDER == __LITTLE_ENDIAN
# define MY_ELFDATA	ELFDATA2LSB
#else
# define MY_ELFDATA	ELFDATA2MSB
#endif


/* Return user segment index closest to ADDR but not above it.
   If NEXT, return the closest to ADDR but not below it.  */
static int
addr_segndx (Dwfl *dwfl, size_t segment, GElf_Addr addr, bool next)
{
  int ndx = -1;
  do
    {
      if (dwfl->lookup_segndx[segment] >= 0)
	ndx = dwfl->lookup_segndx[segment];
      if (++segment >= dwfl->lookup_elts - 1)
	return next ? ndx + 1 : ndx;
    }
  while (dwfl->lookup_addr[segment] < addr);

  if (next)
    {
      while (dwfl->lookup_segndx[segment] < 0)
	if (++segment >= dwfl->lookup_elts - 1)
	  return ndx + 1;
      ndx = dwfl->lookup_segndx[segment];
    }

  return ndx;
}

/* Return whether there is SZ bytes available at PTR till END.  */

static bool
buf_has_data (const void *ptr, const void *end, size_t sz)
{
  return ptr < end && (size_t) (end - ptr) >= sz;
}

/* Read SZ bytes into *RETP from *PTRP (limited by END) in format EI_DATA.
   Function comes from src/readelf.c .  */

static bool
buf_read_ulong (unsigned char ei_data, size_t sz,
		const void **ptrp, const void *end, uint64_t *retp)
{
  if (! buf_has_data (*ptrp, end, sz))
    return false;

  union
  {
    uint64_t u64;
    uint32_t u32;
  } u;

  memcpy (&u, *ptrp, sz);
  (*ptrp) += sz;

  if (retp == NULL)
    return true;

  if (MY_ELFDATA != ei_data)
    {
      if (sz == 4)
	CONVERT (u.u32);
      else
	CONVERT (u.u64);
    }
  if (sz == 4)
    *retp = u.u32;
  else
    *retp = u.u64;
  return true;
}

/* Try to find matching entry for module from address MODULE_START to
   MODULE_END in NT_FILE note located at NOTE_FILE of NOTE_FILE_SIZE
   bytes in format EI_CLASS and EI_DATA.  */

static const char *
handle_file_note (GElf_Addr module_start, GElf_Addr module_end,
		  unsigned char ei_class, unsigned char ei_data,
		  const void *note_file, size_t note_file_size)
{
  if (note_file == NULL)
    return NULL;

  size_t sz;
  switch (ei_class)
    {
    case ELFCLASS32:
      sz = 4;
      break;
    case ELFCLASS64:
      sz = 8;
      break;
    default:
      return NULL;
    }

  const void *ptr = note_file;
  const void *end = note_file + note_file_size;
  uint64_t count;
  if (! buf_read_ulong (ei_data, sz, &ptr, end, &count))
    return NULL;
  if (! buf_read_ulong (ei_data, sz, &ptr, end, NULL)) // page_size
    return NULL;

  uint64_t maxcount = (size_t) (end - ptr) / (3 * sz);
  if (count > maxcount)
    return NULL;

  /* Where file names are stored.  */
  const char *fptr = ptr + 3 * count * sz;

  ssize_t firstix = -1;
  ssize_t lastix = -1;
  for (size_t mix = 0; mix < count; mix++)
    {
      uint64_t mstart, mend, moffset;
      if (! buf_read_ulong (ei_data, sz, &ptr, fptr, &mstart)
	  || ! buf_read_ulong (ei_data, sz, &ptr, fptr, &mend)
	  || ! buf_read_ulong (ei_data, sz, &ptr, fptr, &moffset))
	return NULL;
      if (mstart == module_start && moffset == 0)
	firstix = lastix = mix;
      if (firstix != -1 && mstart < module_end)
	lastix = mix;
      if (mend >= module_end)
	break;
    }
  if (firstix == -1)
    return NULL;

  const char *retval = NULL;
  for (ssize_t mix = 0; mix <= lastix; mix++)
    {
      const char *fnext = memchr (fptr, 0, (const char *) end - fptr);
      if (fnext == NULL)
	return NULL;
      if (mix == firstix)
	retval = fptr;
      if (firstix < mix && mix <= lastix && strcmp (fptr, retval) != 0)
	return NULL;
      fptr = fnext + 1;
    }
  return retval;
}

/* Return true iff we are certain ELF cannot match BUILD_ID of
   BUILD_ID_LEN bytes.  Pass DISK_FILE_HAS_BUILD_ID as false if it is
   certain ELF does not contain build-id (it is only a performance hit
   to pass it always as true).  */

static bool
invalid_elf (Elf *elf, bool disk_file_has_build_id,
	     const void *build_id, size_t build_id_len)
{
  if (! disk_file_has_build_id && build_id_len > 0)
    {
      /* Module found in segments with build-id is more reliable
	 than a module found via DT_DEBUG on disk without any
	 build-id.   */
      return true;
    }
  if (disk_file_has_build_id && build_id_len > 0)
    {
      const void *elf_build_id;
      ssize_t elf_build_id_len;

      /* If there is a build id in the elf file, check it.  */
      elf_build_id_len = INTUSE(dwelf_elf_gnu_build_id) (elf, &elf_build_id);
      if (elf_build_id_len > 0)
	{
	  if (build_id_len != (size_t) elf_build_id_len
	      || memcmp (build_id, elf_build_id, build_id_len) != 0)
	    return true;
	}
    }
  return false;
}

int
dwfl_segment_report_module (Dwfl *dwfl, int ndx, const char *name,
			    Dwfl_Memory_Callback *memory_callback,
			    void *memory_callback_arg,
			    Dwfl_Module_Callback *read_eagerly,
			    void *read_eagerly_arg,
			    const void *note_file, size_t note_file_size,
			    const struct r_debug_info *r_debug_info)
{
  size_t segment = ndx;

  if (segment >= dwfl->lookup_elts)
    segment = dwfl->lookup_elts - 1;

  while (segment > 0
	 && (dwfl->lookup_segndx[segment] > ndx
	     || dwfl->lookup_segndx[segment] == -1))
    --segment;

  while (dwfl->lookup_segndx[segment] < ndx)
    if (++segment == dwfl->lookup_elts)
      return 0;

  GElf_Addr start = dwfl->lookup_addr[segment];

  inline bool segment_read (int segndx,
			    void **buffer, size_t *buffer_available,
			    GElf_Addr addr, size_t minread)
  {
    return ! (*memory_callback) (dwfl, segndx, buffer, buffer_available,
				 addr, minread, memory_callback_arg);
  }

  inline void release_buffer (void **buffer, size_t *buffer_available)
  {
    if (*buffer != NULL)
      (void) segment_read (-1, buffer, buffer_available, 0, 0);
  }

  /* First read in the file header and check its sanity.  */

  void *buffer = NULL;
  size_t buffer_available = INITIAL_READ;
  Elf *elf = NULL;
  int fd = -1;

  /* We might have to reserve some memory for the phdrs.  Set to NULL
     here so we can always safely free it.  */
  void *phdrsp = NULL;

  inline int finish (void)
  {
    free (phdrsp);
    release_buffer (&buffer, &buffer_available);
    if (elf != NULL)
      elf_end (elf);
    if (fd != -1)
      close (fd);
    return ndx;
  }

  if (segment_read (ndx, &buffer, &buffer_available,
		    start, sizeof (Elf64_Ehdr))
      || memcmp (buffer, ELFMAG, SELFMAG) != 0)
    return finish ();

  inline bool read_portion (void **data, size_t *data_size,
			    GElf_Addr vaddr, size_t filesz)
  {
    /* Check whether we will have to read the segment data, or if it
       can be returned from the existing buffer.  */
    if (filesz > buffer_available
	|| vaddr - start > buffer_available - filesz
	/* If we're in string mode, then don't consider the buffer we have
	   sufficient unless it contains the terminator of the string.  */
	|| (filesz == 0 && memchr (vaddr - start + buffer, '\0',
				   buffer_available - (vaddr - start)) == NULL))
      {
	*data = NULL;
	*data_size = filesz;
	return segment_read (addr_segndx (dwfl, segment, vaddr, false),
			     data, data_size, vaddr, filesz);
      }

    /* We already have this whole note segment from our initial read.  */
    *data = vaddr - start + buffer;
    *data_size = 0;
    return false;
  }

  inline void finish_portion (void **data, size_t *data_size)
  {
    if (*data_size != 0)
      release_buffer (data, data_size);
  }

  /* Extract the information we need from the file header.  */
  const unsigned char *e_ident;
  unsigned char ei_class;
  unsigned char ei_data;
  uint16_t e_type;
  union
  {
    Elf32_Ehdr e32;
    Elf64_Ehdr e64;
  } ehdr;
  GElf_Off phoff;
  uint_fast16_t phnum;
  uint_fast16_t phentsize;
  GElf_Off shdrs_end;
  Elf_Data xlatefrom =
    {
      .d_type = ELF_T_EHDR,
      .d_buf = (void *) buffer,
      .d_version = EV_CURRENT,
    };
  Elf_Data xlateto =
    {
      .d_type = ELF_T_EHDR,
      .d_buf = &ehdr,
      .d_size = sizeof ehdr,
      .d_version = EV_CURRENT,
    };
  e_ident = ((const unsigned char *) buffer);
  ei_class = e_ident[EI_CLASS];
  ei_data = e_ident[EI_DATA];
  switch (ei_class)
    {
    case ELFCLASS32:
      xlatefrom.d_size = sizeof (Elf32_Ehdr);
      if (elf32_xlatetom (&xlateto, &xlatefrom, ei_data) == NULL)
	return finish ();
      e_type = ehdr.e32.e_type;
      phoff = ehdr.e32.e_phoff;
      phnum = ehdr.e32.e_phnum;
      phentsize = ehdr.e32.e_phentsize;
      if (phentsize != sizeof (Elf32_Phdr))
	return finish ();
      /* NOTE if the number of sections is > 0xff00 then e_shnum
	 is zero and the actual number would come from the section
	 zero sh_size field. We ignore this here because getting shdrs
	 is just a nice bonus (see below in consider_phdr PT_LOAD
	 where we trim the last segment).  */
      shdrs_end = ehdr.e32.e_shoff + ehdr.e32.e_shnum * ehdr.e32.e_shentsize;
      break;

    case ELFCLASS64:
      xlatefrom.d_size = sizeof (Elf64_Ehdr);
      if (elf64_xlatetom (&xlateto, &xlatefrom, ei_data) == NULL)
	return finish ();
      e_type = ehdr.e64.e_type;
      phoff = ehdr.e64.e_phoff;
      phnum = ehdr.e64.e_phnum;
      phentsize = ehdr.e64.e_phentsize;
      if (phentsize != sizeof (Elf64_Phdr))
	return finish ();
      /* See the NOTE above for shdrs_end and ehdr.e32.e_shnum.  */
      shdrs_end = ehdr.e64.e_shoff + ehdr.e64.e_shnum * ehdr.e64.e_shentsize;
      break;

    default:
      return finish ();
    }

  /* The file header tells where to find the program headers.
     These are what we need to find the boundaries of the module.
     Without them, we don't have a module to report.  */

  if (phnum == 0)
    return finish ();

  xlatefrom.d_type = xlateto.d_type = ELF_T_PHDR;
  xlatefrom.d_size = phnum * phentsize;

  void *ph_buffer = NULL;
  size_t ph_buffer_size = 0;
  if (read_portion (&ph_buffer, &ph_buffer_size,
		    start + phoff, xlatefrom.d_size))
    return finish ();

  /* ph_buffer_size will be zero if we got everything from the initial
     buffer, otherwise it will be the size of the new buffer that
     could be read.  */
  if (ph_buffer_size != 0)
    xlatefrom.d_size = ph_buffer_size;

  xlatefrom.d_buf = ph_buffer;

  bool class32 = ei_class == ELFCLASS32;
  size_t phdr_size = class32 ? sizeof (Elf32_Phdr) : sizeof (Elf64_Phdr);
  if (unlikely (phnum > SIZE_MAX / phdr_size))
    return finish ();
  const size_t phdrsp_bytes = phnum * phdr_size;
  phdrsp = malloc (phdrsp_bytes);
  if (unlikely (phdrsp == NULL))
    return finish ();

  xlateto.d_buf = phdrsp;
  xlateto.d_size = phdrsp_bytes;

  /* Track the bounds of the file visible in memory.  */
  GElf_Off file_trimmed_end = 0; /* Proper p_vaddr + p_filesz end.  */
  GElf_Off file_end = 0;	 /* Rounded up to effective page size.  */
  GElf_Off contiguous = 0;	 /* Visible as contiguous file from START.  */
  GElf_Off total_filesz = 0;	 /* Total size of data to read.  */

  /* Collect the bias between START and the containing PT_LOAD's p_vaddr.  */
  GElf_Addr bias = 0;
  bool found_bias = false;

  /* Collect the unbiased bounds of the module here.  */
  GElf_Addr module_start = -1l;
  GElf_Addr module_end = 0;
  GElf_Addr module_address_sync = 0;

  /* If we see PT_DYNAMIC, record it here.  */
  GElf_Addr dyn_vaddr = 0;
  GElf_Xword dyn_filesz = 0;

  /* Collect the build ID bits here.  */
  void *build_id = NULL;
  size_t build_id_len = 0;
  GElf_Addr build_id_vaddr = 0;

  /* Consider a PT_NOTE we've found in the image.  */
  inline void consider_notes (GElf_Addr vaddr, GElf_Xword filesz,
			      GElf_Xword align)
  {
    /* If we have already seen a build ID, we don't care any more.  */
    if (build_id != NULL || filesz == 0)
      return;

    void *data;
    size_t data_size;
    if (read_portion (&data, &data_size, vaddr, filesz))
      return;

    /* data_size will be zero if we got everything from the initial
       buffer, otherwise it will be the size of the new buffer that
       could be read.  */
    if (data_size != 0)
      filesz = data_size;

    assert (sizeof (Elf32_Nhdr) == sizeof (Elf64_Nhdr));

    void *notes;
    if (ei_data == MY_ELFDATA)
      notes = data;
    else
      {
	notes = malloc (filesz);
	if (unlikely (notes == NULL))
	  return;
	xlatefrom.d_type = xlateto.d_type = (align == 8
					     ? ELF_T_NHDR8 : ELF_T_NHDR);
	xlatefrom.d_buf = (void *) data;
	xlatefrom.d_size = filesz;
	xlateto.d_buf = notes;
	xlateto.d_size = filesz;
	if (elf32_xlatetom (&xlateto, &xlatefrom,
			    ehdr.e32.e_ident[EI_DATA]) == NULL)
	  goto done;
      }

    const GElf_Nhdr *nh = notes;
    size_t len = 0;
    while (filesz > len + sizeof (*nh))
      {
	const void *note_name;
	const void *note_desc;

	len += sizeof (*nh);
	note_name = notes + len;

	len += nh->n_namesz;
	len = align == 8 ? NOTE_ALIGN8 (len) : NOTE_ALIGN4 (len);
	note_desc = notes + len;

	if (unlikely (filesz < len + nh->n_descsz))
	  break;

        if (nh->n_type == NT_GNU_BUILD_ID
	    && nh->n_descsz > 0
	    && nh->n_namesz == sizeof "GNU"
	    && !memcmp (note_name, "GNU", sizeof "GNU"))
	  {
	    build_id_vaddr = note_desc - (const void *) notes + vaddr;
	    build_id_len = nh->n_descsz;
	    build_id = malloc (nh->n_descsz);
	    if (likely (build_id != NULL))
	      memcpy (build_id, note_desc, build_id_len);
	    break;
	  }

	len += nh->n_descsz;
	len = align == 8 ? NOTE_ALIGN8 (len) : NOTE_ALIGN4 (len);
	nh = (void *) notes + len;
      }

  done:
    if (notes != data)
      free (notes);
    finish_portion (&data, &data_size);
  }

  /* Consider each of the program headers we've read from the image.  */
  inline void consider_phdr (GElf_Word type,
			     GElf_Addr vaddr, GElf_Xword memsz,
			     GElf_Off offset, GElf_Xword filesz,
			     GElf_Xword align)
  {
    switch (type)
      {
      case PT_DYNAMIC:
	dyn_vaddr = vaddr;
	dyn_filesz = filesz;
	break;

      case PT_NOTE:
	/* We calculate from the p_offset of the note segment,
	   because we don't yet know the bias for its p_vaddr.  */
	consider_notes (start + offset, filesz, align);
	break;

      case PT_LOAD:
	align = dwfl->segment_align > 1 ? dwfl->segment_align : align ?: 1;

	GElf_Addr vaddr_end = (vaddr + memsz + align - 1) & -align;
	GElf_Addr filesz_vaddr = filesz < memsz ? vaddr + filesz : vaddr_end;
	GElf_Off filesz_offset = filesz_vaddr - vaddr + offset;

	if (file_trimmed_end < offset + filesz)
	  {
	    file_trimmed_end = offset + filesz;

	    /* Trim the last segment so we don't bother with zeros
	       in the last page that are off the end of the file.
	       However, if the extra bit in that page includes the
	       section headers, keep them.  */
	    if (shdrs_end <= filesz_offset && shdrs_end > file_trimmed_end)
	      {
		filesz += shdrs_end - file_trimmed_end;
		file_trimmed_end = shdrs_end;
	      }
	  }

	total_filesz += filesz;

	if (file_end < filesz_offset)
	  {
	    file_end = filesz_offset;
	    if (filesz_vaddr - start == filesz_offset)
	      contiguous = file_end;
	  }

	if (!found_bias && (offset & -align) == 0
	    && likely (filesz_offset >= phoff + phnum * phentsize))
	  {
	    bias = start - vaddr;
	    found_bias = true;
	  }

	if ((vaddr & -align) < module_start)
	  {
	    module_start = vaddr & -align;
	    module_address_sync = vaddr + memsz;
	  }

	if (module_end < vaddr_end)
	  module_end = vaddr_end;
	break;
      }
  }

  Elf32_Phdr (*p32)[phnum] = phdrsp;
  Elf64_Phdr (*p64)[phnum] = phdrsp;
  if (ei_class == ELFCLASS32)
    {
      if (elf32_xlatetom (&xlateto, &xlatefrom, ei_data) == NULL)
	found_bias = false;	/* Trigger error check.  */
      else
	for (uint_fast16_t i = 0; i < phnum; ++i)
	  consider_phdr ((*p32)[i].p_type,
			 (*p32)[i].p_vaddr, (*p32)[i].p_memsz,
			 (*p32)[i].p_offset, (*p32)[i].p_filesz,
			 (*p32)[i].p_align);
    }
  else
    {
      if (elf64_xlatetom (&xlateto, &xlatefrom, ei_data) == NULL)
	found_bias = false;	/* Trigger error check.  */
      else
	for (uint_fast16_t i = 0; i < phnum; ++i)
	  consider_phdr ((*p64)[i].p_type,
			 (*p64)[i].p_vaddr, (*p64)[i].p_memsz,
			 (*p64)[i].p_offset, (*p64)[i].p_filesz,
			 (*p64)[i].p_align);
    }

  finish_portion (&ph_buffer, &ph_buffer_size);

  /* We must have seen the segment covering offset 0, or else the ELF
     header we read at START was not produced by these program headers.  */
  if (unlikely (!found_bias))
    {
      free (build_id);
      return finish ();
    }

  /* Now we know enough to report a module for sure: its bounds.  */
  module_start += bias;
  module_end += bias;

  dyn_vaddr += bias;

  /* NAME found from link map has precedence over DT_SONAME possibly read
     below.  */
  bool name_is_final = false;

  /* Try to match up DYN_VADDR against L_LD as found in link map.
     Segments sniffing may guess invalid address as the first read-only memory
     mapping may not be dumped to the core file (if ELF headers are not dumped)
     and the ELF header is dumped first with the read/write mapping of the same
     file at higher addresses.  */
  if (r_debug_info != NULL)
    for (const struct r_debug_info_module *module = r_debug_info->module;
	 module != NULL; module = module->next)
      if (module_start <= module->l_ld && module->l_ld < module_end)
	{
	  /* L_LD read from link map must be right while DYN_VADDR is unsafe.
	     Therefore subtract DYN_VADDR and add L_LD to get a possibly
	     corrective displacement for all addresses computed so far.  */
	  GElf_Addr fixup = module->l_ld - dyn_vaddr;
	  if ((fixup & (dwfl->segment_align - 1)) == 0
	      && module_start + fixup <= module->l_ld
	      && module->l_ld < module_end + fixup)
	    {
	      module_start += fixup;
	      module_end += fixup;
	      dyn_vaddr += fixup;
	      bias += fixup;
	      if (module->name[0] != '\0')
		{
		  name = basename (module->name);
		  name_is_final = true;
		}
	      break;
	    }
	}

  if (r_debug_info != NULL)
    {
      bool skip_this_module = false;
      for (struct r_debug_info_module *module = r_debug_info->module;
	   module != NULL; module = module->next)
	if ((module_end > module->start && module_start < module->end)
	    || dyn_vaddr == module->l_ld)
	  {
	    if (module->elf != NULL
	        && invalid_elf (module->elf, module->disk_file_has_build_id,
				build_id, build_id_len))
	      {
		elf_end (module->elf);
		close (module->fd);
		module->elf = NULL;
		module->fd = -1;
	      }
	    if (module->elf != NULL)
	      {
		/* Ignore this found module if it would conflict in address
		   space with any already existing module of DWFL.  */
		skip_this_module = true;
	      }
	  }
      if (skip_this_module)
	{
	  free (build_id);
	  return finish ();
	}
    }

  const char *file_note_name = handle_file_note (module_start, module_end,
						 ei_class, ei_data,
						 note_file, note_file_size);
  if (file_note_name)
    {
      name = file_note_name;
      name_is_final = true;
      bool invalid = false;
      fd = open (name, O_RDONLY);
      if (fd >= 0)
	{
	  Dwfl_Error error = __libdw_open_file (&fd, &elf, true, false);
	  if (error == DWFL_E_NOERROR)
	    invalid = invalid_elf (elf, true /* disk_file_has_build_id */,
				   build_id, build_id_len);
	}
      if (invalid)
	{
	  /* The file was there, but the build_id didn't match.  We
	     still want to report the module, but need to get the ELF
	     some other way if possible.  */
	  close (fd);
	  fd = -1;
	  elf_end (elf);
	  elf = NULL;
	}
    }

  /* Our return value now says to skip the segments contained
     within the module.  */
  ndx = addr_segndx (dwfl, segment, module_end, true);

  /* Examine its .dynamic section to get more interesting details.
     If it has DT_SONAME, we'll use that as the module name.
     If it has a DT_DEBUG, then it's actually a PIE rather than a DSO.
     We need its DT_STRTAB and DT_STRSZ to decipher DT_SONAME,
     and they also tell us the essential portion of the file
     for fetching symbols.  */
  GElf_Addr soname_stroff = 0;
  GElf_Addr dynstr_vaddr = 0;
  GElf_Xword dynstrsz = 0;
  bool execlike = false;
  inline bool consider_dyn (GElf_Sxword tag, GElf_Xword val)
  {
    switch (tag)
      {
      default:
	return false;

      case DT_DEBUG:
	execlike = true;
	break;

      case DT_SONAME:
	soname_stroff = val;
	break;

      case DT_STRTAB:
	dynstr_vaddr = val;
	break;

      case DT_STRSZ:
	dynstrsz = val;
	break;
      }

    return soname_stroff != 0 && dynstr_vaddr != 0 && dynstrsz != 0;
  }

  const size_t dyn_entsize = (ei_class == ELFCLASS32
			      ? sizeof (Elf32_Dyn) : sizeof (Elf64_Dyn));
  void *dyn_data = NULL;
  size_t dyn_data_size = 0;
  if (dyn_filesz != 0 && dyn_filesz % dyn_entsize == 0
      && ! read_portion (&dyn_data, &dyn_data_size, dyn_vaddr, dyn_filesz))
    {
      /* dyn_data_size will be zero if we got everything from the initial
         buffer, otherwise it will be the size of the new buffer that
         could be read.  */
      if (dyn_data_size != 0)
	dyn_filesz = dyn_data_size;

      void *dyns = malloc (dyn_filesz);
      Elf32_Dyn (*d32)[dyn_filesz / sizeof (Elf32_Dyn)] = dyns;
      Elf64_Dyn (*d64)[dyn_filesz / sizeof (Elf64_Dyn)] = dyns;
      if (unlikely (dyns == NULL))
	return finish ();

      xlatefrom.d_type = xlateto.d_type = ELF_T_DYN;
      xlatefrom.d_buf = (void *) dyn_data;
      xlatefrom.d_size = dyn_filesz;
      xlateto.d_buf = dyns;
      xlateto.d_size = dyn_filesz;

      if (ei_class == ELFCLASS32)
	{
	  if (elf32_xlatetom (&xlateto, &xlatefrom, ei_data) != NULL)
	    for (size_t i = 0; i < dyn_filesz / sizeof (Elf32_Dyn); ++i)
	      if (consider_dyn ((*d32)[i].d_tag, (*d32)[i].d_un.d_val))
		break;
	}
      else
	{
	  if (elf64_xlatetom (&xlateto, &xlatefrom, ei_data) != NULL)
	    for (size_t i = 0; i < dyn_filesz / sizeof (Elf64_Dyn); ++i)
	      if (consider_dyn ((*d64)[i].d_tag, (*d64)[i].d_un.d_val))
		break;
	}
      free (dyns);
    }
  finish_portion (&dyn_data, &dyn_data_size);

  /* We'll use the name passed in or a stupid default if not DT_SONAME.  */
  if (name == NULL)
    name = e_type == ET_EXEC ? "[exe]" : execlike ? "[pie]" : "[dso]";

  void *soname = NULL;
  size_t soname_size = 0;
  if (! name_is_final && dynstrsz != 0 && dynstr_vaddr != 0)
    {
      /* We know the bounds of the .dynstr section.

	 The DYNSTR_VADDR pointer comes from the .dynamic section
	 (DT_STRTAB, detected above).  Ordinarily the dynamic linker
	 will have adjusted this pointer in place so it's now an
	 absolute address.  But sometimes .dynamic is read-only (in
	 vDSOs and odd architectures), and sometimes the adjustment
	 just hasn't happened yet in the memory image we looked at.
	 So treat DYNSTR_VADDR as an absolute address if it falls
	 within the module bounds, or try applying the phdr bias
	 when that adjusts it to fall within the module bounds.  */

      if ((dynstr_vaddr < module_start || dynstr_vaddr >= module_end)
	  && dynstr_vaddr + bias >= module_start
	  && dynstr_vaddr + bias < module_end)
	dynstr_vaddr += bias;

      if (unlikely (dynstr_vaddr + dynstrsz > module_end))
	dynstrsz = 0;

      /* Try to get the DT_SONAME string.  */
      if (soname_stroff != 0 && soname_stroff + 1 < dynstrsz
	  && ! read_portion (&soname, &soname_size,
			     dynstr_vaddr + soname_stroff, 0))
	name = soname;
    }

  /* Now that we have chosen the module's name and bounds, report it.
     If we found a build ID, report that too.  */

  Dwfl_Module *mod = INTUSE(dwfl_report_module) (dwfl, name,
						 module_start, module_end);

  // !execlike && ET_EXEC is PIE.
  // execlike && !ET_EXEC is a static executable.
  if (mod != NULL && (execlike || ehdr.e32.e_type == ET_EXEC))
    mod->is_executable = true;

  if (likely (mod != NULL) && build_id != NULL
      && unlikely (INTUSE(dwfl_module_report_build_id) (mod,
							build_id,
							build_id_len,
							build_id_vaddr)))
    {
      mod->gc = true;
      mod = NULL;
    }

  /* At this point we do not need BUILD_ID or NAME any more.
     They have been copied.  */
  free (build_id);
  finish_portion (&soname, &soname_size);

  if (unlikely (mod == NULL))
    {
      ndx = -1;
      return finish ();
    }

  /* We have reported the module.  Now let the caller decide whether we
     should read the whole thing in right now.  */

  const GElf_Off cost = (contiguous < file_trimmed_end ? total_filesz
			 : buffer_available >= contiguous ? 0
			 : contiguous - buffer_available);
  const GElf_Off worthwhile = ((dynstr_vaddr == 0 || dynstrsz == 0) ? 0
			       : dynstr_vaddr + dynstrsz - start);
  const GElf_Off whole = MAX (file_trimmed_end, shdrs_end);

  if (elf == NULL
      && (*read_eagerly) (MODCB_ARGS (mod), &buffer, &buffer_available,
			  cost, worthwhile, whole, contiguous,
			  read_eagerly_arg, &elf)
      && elf == NULL)
    {
      /* The caller wants to read the whole file in right now, but hasn't
	 done it for us.  Fill in a local image of the virtual file.  */

      void *contents = calloc (1, file_trimmed_end);
      if (unlikely (contents == NULL))
	return finish ();

      inline void final_read (size_t offset, GElf_Addr vaddr, size_t size)
      {
	void *into = contents + offset;
	size_t read_size = size;
	(void) segment_read (addr_segndx (dwfl, segment, vaddr, false),
			     &into, &read_size, vaddr, size);
      }

      if (contiguous < file_trimmed_end)
	{
	  /* We can't use the memory image verbatim as the file image.
	     So we'll be reading into a local image of the virtual file.  */

	  inline void read_phdr (GElf_Word type, GElf_Addr vaddr,
				 GElf_Off offset, GElf_Xword filesz)
	  {
	    if (type == PT_LOAD)
	      final_read (offset, vaddr + bias, filesz);
	  }

	  if (ei_class == ELFCLASS32)
	    for (uint_fast16_t i = 0; i < phnum; ++i)
	      read_phdr ((*p32)[i].p_type, (*p32)[i].p_vaddr,
			 (*p32)[i].p_offset, (*p32)[i].p_filesz);
	  else
	    for (uint_fast16_t i = 0; i < phnum; ++i)
	      read_phdr ((*p64)[i].p_type, (*p64)[i].p_vaddr,
			 (*p64)[i].p_offset, (*p64)[i].p_filesz);
	}
      else
	{
	  /* The whole file sits contiguous in memory,
	     but the caller didn't want to just do it.  */

	  const size_t have = MIN (buffer_available, file_trimmed_end);
	  memcpy (contents, buffer, have);

	  if (have < file_trimmed_end)
	    final_read (have, start + have, file_trimmed_end - have);
	}

      elf = elf_memory (contents, file_trimmed_end);
      if (unlikely (elf == NULL))
	free (contents);
      else
	elf->flags |= ELF_F_MALLOCED;
    }

  if (elf != NULL)
    {
      /* Install the file in the module.  */
      mod->main.elf = elf;
      mod->main.fd = fd;
      elf = NULL;
      fd = -1;
      mod->main.vaddr = module_start - bias;
      mod->main.address_sync = module_address_sync;
      mod->main_bias = bias;
    }

  return finish ();
}
