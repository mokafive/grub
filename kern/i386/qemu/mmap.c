/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2009  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/machine/init.h>
#include <grub/machine/memory.h>
#include <grub/machine/boot.h>
#include <grub/types.h>
#include <grub/err.h>
#include <grub/misc.h>
#include <grub/cmos.h>

#define QEMU_CMOS_MEMSIZE_HIGH		0x35
#define QEMU_CMOS_MEMSIZE_LOW		0x34

#define QEMU_CMOS_MEMSIZE2_HIGH		0x31
#define QEMU_CMOS_MEMSIZE2_LOW		0x30

#define min(a,b)	((a) > (b) ? (b) : (a))

extern char _start[];
extern char _end[];

static grub_uint64_t mem_size, above_4g;

void
grub_machine_mmap_init ()
{
  mem_size = ((grub_uint64_t) grub_cmos_read (QEMU_CMOS_MEMSIZE_HIGH)) << 24
    | ((grub_uint64_t) grub_cmos_read (QEMU_CMOS_MEMSIZE_LOW)) << 16;
  if (mem_size > 0)
    {
      /* Don't ask... */
      mem_size += (16 * 1024 * 1024);
    }
  else
    {
      mem_size
	= ((((grub_uint64_t) grub_cmos_read (QEMU_CMOS_MEMSIZE2_HIGH)) << 18)
	   | ((grub_uint64_t) (grub_cmos_read (QEMU_CMOS_MEMSIZE2_LOW)) << 10))
	+ 1024 * 1024;
    }

  above_4g = (((grub_uint64_t) grub_cmos_read (0x5b)) << 16)
    | (((grub_uint64_t) grub_cmos_read (0x5c)) << 24)
    | (((grub_uint64_t) grub_cmos_read (0x5d)) << 32);
}

grub_err_t
grub_machine_mmap_iterate (int NESTED_FUNC_ATTR (*hook) (grub_uint64_t, grub_uint64_t, grub_uint32_t))
{
  if (hook (0x0,
	    (grub_addr_t) _start,
	    GRUB_MACHINE_MEMORY_AVAILABLE))
    return 1;

  if (hook (GRUB_MEMORY_MACHINE_UPPER,
	    0x100000 - GRUB_MEMORY_MACHINE_UPPER,
	    GRUB_MACHINE_MEMORY_RESERVED))
    return 1;

  /* Everything else is free.  */
  if (hook (0x100000,
	    min (mem_size, (grub_uint32_t) -GRUB_BOOT_MACHINE_SIZE) - 0x100000,
	    GRUB_MACHINE_MEMORY_AVAILABLE))
    return 1;

  /* Protect boot.img, which contains the gdt.  It is mapped at the top of memory
     (it is also mapped below 0x100000, but we already reserved that area).  */
  if (hook ((grub_uint32_t) -GRUB_BOOT_MACHINE_SIZE,
	    GRUB_BOOT_MACHINE_SIZE,
	    GRUB_MACHINE_MEMORY_RESERVED))
    return 1;

  if (above_4g != 0 && hook (0x100000000ULL, above_4g,
			     GRUB_MACHINE_MEMORY_AVAILABLE))
    return 1;

  return 0;
}
