#ifndef KZ_TEST_H
#define KZ_TEST_H

/* 
 * Copyright (C) 2006-2012, BalaBit IT Ltd.
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <kzorp.h>
#include <kzorp_lookup_internal.h>

// libc:
void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);
int printf(const char *format, ...);
void abort(void);
int atoi(const char *nptr);

// glib/gtestutils.h would redefine some types including time.h:
#define _TIME_H
#define __GLIB_H_INSIDE__
#include <glib/gtestutils.h>

#define KZ_ARRAY(STRUCT, NAME, ELEMENTS...) \
  __typeof__(*((STRUCT *)0)->NAME) array[] = { ELEMENTS }

#define KZ_ALLOC_ARRAY(STRUCT, NAME, ELEMENTS...) \
  ({ KZ_ARRAY(STRUCT, NAME, ELEMENTS); memcpy(calloc(1, sizeof(array)), array, sizeof(array)); })

#define KZ_ARRAY_SIZE(STRUCT, NAME, ELEMENTS...) \
  ({ KZ_ARRAY(STRUCT, NAME, ELEMENTS); sizeof(array) / sizeof(*array); })

#define KZ_STRUCT_ENTRY_INITIALIZER(STRUCT, NAME, ELEMENTS...) \
  .num_##NAME = KZ_ARRAY_SIZE(STRUCT, NAME, ELEMENTS), .NAME = KZ_ALLOC_ARRAY(STRUCT, NAME, ELEMENTS)

#define KZ_RULE_ENTRY_INITIALIZER(NAME, ELEMENTS...) \
  KZ_STRUCT_ENTRY_INITIALIZER(struct kz_dispatcher_n_dimension_rule, NAME, ELEMENTS)

extern unsigned kz_zone_index;

// The zone depth starts with 1, see kz_zone_new in kzorp_core.c:
#define KZ_ZONE_ROOT_INITIALIZER \
  { .depth = 1, .index = kz_zone_index++ }

#define KZ_ZONE_INITIALIZER(PARENT) \
  { .admin_parent = &(PARENT), .depth = PARENT.depth + 1, .index = kz_zone_index++ }

#endif /* KZ_TEST_H */
