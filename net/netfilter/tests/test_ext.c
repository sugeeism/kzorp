
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
#include "test.h"

#include <linux/slab.h>
#include <net/netfilter/nf_conntrack_zones.h>

extern unsigned int kz_hash_shift;
extern unsigned int kz_hash_size;
extern struct hlist_nulls_head *kz_hash;

extern struct nf_conntrack_kzorp * kz_get_kzorp_from_node(struct hlist_nulls_node *p);
extern void kz_extension_fill(struct nf_conntrack_kzorp *kzorp, struct nf_conn *ct);
extern void kz_extension_copy_tuplehash(struct nf_conntrack_kzorp *kzorp, struct nf_conn *ct);

void
printhash(char * msg)
{
	printf("%s:kz_hash=%p, size=%u\n", msg,kz_hash, kz_hash_size);
	int i;
	for(i=0;i<kz_hash_size;i++) {
		printf("%u: %p\n",i,kz_hash[i].first);
	}
}

static void
checkhash(int deviations, char * name)
{
	int i;
	int foundDeviations=0;
	for(i=0;i<kz_hash_size;i++)
		if(((long int)kz_hash[i].first) != ((i<<1)+1))
			foundDeviations++;
	if(foundDeviations != deviations) {
		printf("%s: expected deviations=%u, found = %u\n",name,deviations,foundDeviations);
		g_assert_not_reached();
	}
}

static struct nf_conntrack_kzorp *
new_kzorp()
{
	struct nf_conntrack_kzorp *kzorp = (struct nf_conntrack_kzorp *) malloc(sizeof(struct nf_conntrack_kzorp));
	kzorp->timerfunc_save = NULL;
	return kzorp;
}

static struct nf_conn *
new_ct()
{
	struct nf_conn *ct = (struct nf_conn *) malloc(sizeof(struct nf_conn));
	ct -> timeout.function=NULL;
	return ct;
}

static void
test_init(void)
{
	g_assert(0 == kz_extension_init());
	checkhash(0,"init");
	kz_extension_cleanup();
}


static void
test_dealloc()
{
	struct nf_conntrack_kzorp *kzorp = new_kzorp();
	struct nf_conn *ct=new_ct();
	ct->tuplehash[0].tuple.dst.dir = 0;
	ct->tuplehash[1].tuple.dst.dir = 1;
	g_assert(kzorp != ZERO_SIZE_PTR);
	g_assert(0 == kz_extension_init());
	checkhash(0,"dealloc init");
	kz_extension_copy_tuplehash(kzorp,ct);
	kz_extension_fill(kzorp,ct);
	checkhash(2,"dealloc fill");
	kz_extension_cleanup();
	checkhash(0,"fill cleanup");

}

static void
test_fill(void)
{
	struct nf_conntrack_kzorp *kzorp =new_kzorp();
	struct nf_conn *ct=new_ct();
	ct->tuplehash[0].tuple.dst.dir = 0;
	ct->tuplehash[1].tuple.dst.dir = 1;
	g_assert(kzorp != ZERO_SIZE_PTR);
	g_assert(0 == kz_extension_init());
	checkhash(0,"fill init");
	kz_extension_fill(kzorp,ct);
	checkhash(2,"fill fill");
	kz_extension_cleanup();
	checkhash(0,"fill cleanup");
}

static void
test_create(void)
{
	struct nf_conn *ct=new_ct();
	ct->tuplehash[0].tuple.dst.dir = 0;
	ct->tuplehash[1].tuple.dst.dir = 1;
	g_assert(NULL == ct->timeout.function);
	g_assert(0 == nf_ct_zone(ct));
	g_assert(0 == kz_extension_init());
	kz_extension_create(ct);
	checkhash(2,"create create");
	kz_extension_cleanup();
	checkhash(0,"create cleanup");
}

#define IP1 (0xfa520dba)
#define IP2 (0x84dba7a5)

static void
test_find(void)
{

	struct nf_conntrack_kzorp *kzorp1, *kzorp2;
	struct nf_conn *ct1, *ct2;
	ct1=new_ct();
	ct2=new_ct();
	g_assert(0 == kz_extension_init());
	checkhash(0,"find init");
	ct1->tuplehash[0].tuple.dst.dir = 0;
	ct1->tuplehash[0].tuple.dst.u3.ip = IP1;
	ct1->tuplehash[1].tuple.dst.dir = 1;
	ct2->tuplehash[0].tuple.dst.dir = 0;
	ct2->tuplehash[0].tuple.dst.u3.ip = IP2;
	ct2->tuplehash[1].tuple.dst.dir = 1;
	kzorp1 = kz_extension_create(ct1);
	kzorp2 = kz_extension_create(ct2);
	g_assert(kzorp1 == kz_extension_find(ct1));
	g_assert(IP1 == kzorp1->tuplehash[0].tuple.dst.u3.ip);
	g_assert(kzorp2 == kz_extension_find(ct2));
	g_assert(IP2 == kzorp2->tuplehash[0].tuple.dst.u3.ip);
	kz_extension_cleanup();

}

int
main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/ext/init", test_init);
	g_test_add_func("/ext/create", test_create);
	g_test_add_func("/ext/dealloc", test_dealloc);
	g_test_add_func("/ext/fill", test_fill);
	g_test_add_func("/ext/find", test_find);

	g_test_run();

	return 0;
}
