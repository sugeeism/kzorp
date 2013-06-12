/*
 * KZorp "extension" management: the thing which has been a ct ext
 *
 * Copyright (C) 2012, Árpád Magosányi <arpad@magosanyi.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include <linux/hash.h>
#include <linux/bootmem.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include "include/kzorp.h"

#ifdef KZ_USERSPACE

void *malloc(size_t size);
void free(void *ptr);
int printf(const char *format, ...);


#define kzfree(p) free(p)
#define kzalloc(s,d) malloc(s)

#endif

static unsigned int kz_hash_shift = 4;
static unsigned int kz_hash_size;
static struct hlist_nulls_head *kz_hash;

unsigned const int kz_hash_rnd = 0x9e370001UL;	//golden ratio prime

/* the same as in nf_conntrack_core.c */
static u32
hash_conntrack_raw(const struct nf_conntrack_tuple *tuple, u16 zone)
{
	unsigned int n;

	/* The direction must be ignored, so we hash everything up to the
	 * destination ports (which is a multiple of 4) and treat the last
	 * three bytes manually.
	 */
	n = (sizeof(tuple->src) + sizeof(tuple->dst.u3)) / sizeof(u32);
	return jhash2((u32 *) tuple, n, zone ^ kz_hash_rnd ^
		      (((__force __u16) tuple->dst.u.all << 16) |
		       tuple->dst.protonum));
}

static void kz_extension_dealloc(struct nf_conntrack_kzorp *kz)
{
	int i;

	//printf("freeing %p\n",kz);
	for (i = 0; i < IP_CT_DIR_MAX; i++) {
		hlist_nulls_del_rcu(&(kz->tuplehash[i].hnnode));
	}
	kzfree(kz);
}

struct nf_conntrack_kzorp *kz_extension_find(struct nf_conn *ct)
{
	struct hlist_nulls_node *n;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple_hash *th = &(ct->tuplehash[0]);
	unsigned int bucket =
	    hash_conntrack_raw(&(th->tuple),
			       nf_ct_zone(ct)) >> (32 - kz_hash_shift);
	unsigned int zone = nf_ct_zone(ct);

	hlist_nulls_for_each_entry_rcu(h, n, &kz_hash[bucket], hnnode) {
		if (nf_ct_tuple_equal(&(th->tuple), &h->tuple)) {
			struct nf_conntrack_kzorp *kz =
			    container_of((struct nf_conntrack_tuple_hash *)
					 h,
					 struct nf_conntrack_kzorp,
					 tuplehash[((struct
						     nf_conntrack_tuple_hash
						     *) h)->tuple.dst.dir].
					 hnnode);
			if (kz->ct_zone == zone) {
				return kz;
			}
		}
	}
	return NULL;
}

static void kz_extension_timer(unsigned long ctp)
{
	struct nf_conntrack_kzorp *kzorp =
	    kz_extension_find((struct nf_conn *) ctp);
	void (*oldtimer) (unsigned long);

	BUG_ON(!kzorp);
	oldtimer = kzorp->timerfunc_save;
	BUG_ON(!oldtimer);
	// not reinstating ct->timeout.function, we hope no one tries to call it once more.
	kz_extension_dealloc(kzorp);
	(*oldtimer) (ctp);
}

struct nf_conntrack_kzorp *kz_extension_create(struct nf_conn *ct)
{
	int i;
	struct nf_conntrack_kzorp *kzorp;
	kzorp = kzalloc(sizeof(struct nf_conntrack_kzorp), GFP_ATOMIC);
	//printf("kzorp=%p\n",kzorp);
	memcpy(&(kzorp->tuplehash), &(ct->tuplehash),
	       IP_CT_DIR_MAX * sizeof(struct nf_conntrack_tuple_hash));
	for (i = 0; i < IP_CT_DIR_MAX; i++) {
		struct nf_conntrack_tuple_hash *th =
		    &(kzorp->tuplehash[i]);
		//printf("zone=%u\n",nf_ct_zone(ct));
		unsigned int bucket =
		    hash_conntrack_raw(&(th->tuple),
				       nf_ct_zone(ct)) >> (32 -
							   kz_hash_shift);
		//printf("bucket=%u, th = %p, hnnode = %p \n",bucket,th, &(th->hnnode));
		hlist_nulls_add_head(&(th->hnnode), &kz_hash[bucket]);
	}
	kzorp->timerfunc_save = ct->timeout.function;
	ct->timeout.function = kz_extension_timer;
	kzorp->ct_zone = nf_ct_zone(ct);
	return kzorp;
}

int kz_extension_init(void)
{

	int i;

	kz_hash_size = 1 << kz_hash_shift;
	kz_hash =
	    kzalloc(kz_hash_size * sizeof(struct hlist_head *),
		    GFP_KERNEL);
	if (!kz_hash) {
		return -1;
	}

	for (i = 0; i < kz_hash_size; i++) {
		INIT_HLIST_NULLS_HEAD(&kz_hash[i], i);
	}

	return 0;
}

static void kz_extension_dealloc_by_tuplehash(struct hlist_nulls_node *p)
{
	/*
	 * find the kzorp corresponding to the tuplehash
	 * dereference all tuplehashes
	 * free the kzorp
	 */

	struct nf_conntrack_kzorp *kz;
	kz = container_of((struct nf_conntrack_tuple_hash *) p,
			  struct nf_conntrack_kzorp,
			  tuplehash[((struct nf_conntrack_tuple_hash *)
				     p)->tuple.dst.dir].hnnode);
	kz_extension_dealloc(kz);
}

/* deallocate entries in the hashtable */
static void clean_hash(void)
{
	int i;
	struct hlist_nulls_node *p;

	for (i = 0; i < kz_hash_size; i++) {
		while (!hlist_nulls_empty(&kz_hash[i])) {
			p = kz_hash[i].first;
			kz_extension_dealloc_by_tuplehash(p);
		}
	}
	kzfree(kz_hash);
}

void kz_extension_cleanup(void)
{
	clean_hash();
}

void kz_extension_fini(void)
{
	clean_hash();
}
