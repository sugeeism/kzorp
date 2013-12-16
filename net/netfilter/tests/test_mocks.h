#ifndef TEXT_MOCKZ_H
#define TEXT_MOCKZ_H

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

#define _LINUX_SLUB_DEF_H
#define _LINUX_SLAB_DEF_H

#define __bitwise__

#include <linux/compiler.h>
#ifdef __x86_64__
typedef unsigned long size_t;
#else
typedef unsigned int size_t;
#endif
#define _SIZE_T
typedef unsigned __bitwise__ gfp_t;

struct kmem_cache {
	int objsize;
	int object_size;
};

void *__kmalloc(size_t size, gfp_t flags);
static __always_inline void *kmalloc(size_t size, gfp_t flags) {
	return __kmalloc(size,flags);
}
void *kmalloc_node(size_t size, gfp_t flags, int node);

void *__kmalloc(size_t size, gfp_t flags);
void *kmem_cache_alloc(struct kmem_cache *, gfp_t);

// net/netfilter/kzorp-lookup.c:
static inline struct kz_lookup_ipv6_node *ipv6_node_new(void)
{
	        return kmalloc( 1024/*sizeof(struct kz_lookup_ipv6_node)*/,0);
}

void free(void *ptr);
static inline void ipv6_node_free(struct kz_lookup_ipv6_node *n)
{
	        free(n);
}


int printf(const char *format, ...);
#endif /* TEXT_MOCKZ_H */
