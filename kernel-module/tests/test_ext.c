
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

static void test_init(void)
{

	struct nf_conn ct;
	struct nf_conntrack_kzorp *kzorp;
	ct.tuplehash[0].tuple.dst.dir = 0;
	ct.tuplehash[1].tuple.dst.dir = 1;
	g_assert(0 == kz_extension_init());
	kzorp = kz_extension_create(&ct);
	g_assert(kzorp);
	kz_extension_cleanup();

}

#define IP1 (0xfa520dba)
#define IP2 (0x84dba7a5)
static void test_find(void)
{

	struct nf_conntrack_kzorp *kzorp1, *kzorp2;
	struct nf_conn ct1, ct2;
	g_assert(0 == kz_extension_init());
	ct1.tuplehash[0].tuple.dst.dir = 0;
	ct1.tuplehash[0].tuple.dst.u3.ip = IP1;
	ct1.tuplehash[1].tuple.dst.dir = 1;
	ct2.tuplehash[0].tuple.dst.dir = 0;
	ct2.tuplehash[0].tuple.dst.u3.ip = IP2;
	ct2.tuplehash[1].tuple.dst.dir = 1;
	kzorp1 = kz_extension_create(&ct1);
	kzorp2 = kz_extension_create(&ct2);
	g_assert(kzorp1 == kz_extension_find(&ct1));
	g_assert(IP1 == kzorp1->tuplehash[0].tuple.dst.u3.ip);
	g_assert(kzorp2 == kz_extension_find(&ct2));
	g_assert(IP2 == kzorp2->tuplehash[0].tuple.dst.u3.ip);
	kz_extension_cleanup();

}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/ext/init", test_init);
	g_test_add_func("/ext/find", test_find);

	g_test_run();

	return 0;
}
