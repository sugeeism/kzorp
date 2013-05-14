
/*
 * Copyright (C) 2006-2012, BalaBit IT Ltd.
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 3 of the License, or
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
#include "test.h"

#define MUST_NOT_CALL (printf("Must not call %s.\n", __func__), abort())

// linux/kernel.h:
int printk(const char *fmt, ...) { return 0; }

// linux/slab.h:
void kfree(const void *mem) { MUST_NOT_CALL; }

// linux/inetdevice.h:
void in_dev_finish_destroy(int idev) {} // MUST_NOT_CALL; }
void in6_dev_finish_destroy(int idev) { MUST_NOT_CALL; }

int nr_cpu_ids = 0;

// linux/slub_def.h:
void *__kmalloc(size_t size, gfp_t flags) { MUST_NOT_CALL; return 0; }
#ifndef SLUB_PAGE_SHIFT
 #define SLUB_PAGE_SHIFT 128

struct cache_sizes malloc_sizes[1];
#endif
struct kmem_cache *kmalloc_caches[SLUB_PAGE_SHIFT] = {};
#ifdef _LINUX_SLUB_DEF_H
void *kmem_cache_alloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size) { MUST_NOT_CALL; return 0; };
#endif
#ifdef _LINUX_SLAB_DEF_H
void *kmem_cache_alloc_trace(size_t size, struct kmem_cache *cachep, gfp_t flags) { MUST_NOT_CALL; return 0; };
#endif


// arch/x86/include/asm/percpu.h:
unsigned long this_cpu_off = 0;

// linux/cpumask.h:
const struct cpumask *const cpu_possible_mask = 0;

// asm-generic/percpu.h:
unsigned long __per_cpu_offset[NR_CPUS] = {};

// linux/bitops.h:
unsigned long find_next_bit(const unsigned long *addr, unsigned long size, unsigned long offset) { MUST_NOT_CALL; return 0; }

// linux/rcupdate.h:
void call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *head)) {}

// linux/netfilter/kzorp.h:
void kz_bind_destroy(struct kz_bind *bind) { MUST_NOT_CALL; }
void kz_dispatcher_destroy(struct kz_dispatcher *_) { MUST_NOT_CALL; }
struct kz_bind *kz_bind_clone(const struct kz_bind const *_bind) { MUST_NOT_CALL; return 0; }
void *kz_big_alloc(size_t size, enum KZ_ALLOC_TYPE *type) { return malloc(size); };
void kz_big_free(void *ptr, enum KZ_ALLOC_TYPE type) { MUST_NOT_CALL; };

// linux/dynamic_debug.h:
int __dynamic_pr_debug(struct _ddebug *descriptor, const char *fmt, ...) { MUST_NOT_CALL; return 0; }

// asm-generic/bug.h:
void warn_slowpath_null(const char *file, const int line) { MUST_NOT_CALL; }

// net/netfilter/kzorp-lookup.c:
inline struct kz_lookup_ipv6_node * ipv6_node_new(void)
{
  return calloc(1, sizeof(struct kz_lookup_ipv6_node));
}

inline void ipv6_node_free(struct kz_lookup_ipv6_node *n)
{
  free(n);
}

unsigned kz_zone_index = 0;

/*
void *kzalloc(size_t size, gfp_t flags)
{
	void *p = malloc(size);
	memset(p,0,size);
}
*/

void kzfree(const void *p) {
	free((void *)p);
}

unsigned int nf_conntrack_hash_rnd = 0xdeadb33f;
