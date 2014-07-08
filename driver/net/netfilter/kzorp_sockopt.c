/*
 * KZorp getsockopt() interface
 *
 * Copyright (C) 2010, BalaBit IT Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include <net/inet_sock.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/netfilter/kzorp.h>
#include <linux/netfilter/kzorp_sockopt.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <linux/export.h>
#include <net/netfilter/nf_conntrack_zones.h>

static const char *const kz_log_null = "(NULL)";

#define COPY_NAME_TO_USER(dst, field, string)				\
	if (string != NULL) {						\
		size_t len = strlen(string) + 1;			\
		if (copy_to_user(dst + offsetof(struct kz_lookup_result, field), string, len) != 0) { \
			res = -EFAULT;					\
			goto error_put_ct;				\
		}							\
	}

static int
kzorp_getsockopt_results(u8 family, struct sock *sk, int optval, void __user *user, int *len)
{
	const struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple;

	if (sk->sk_protocol != IPPROTO_TCP && sk->sk_protocol != IPPROTO_UDP) {
		kz_debug("not a TCP or UDP socket; proto='%u'\n", sk->sk_protocol);
		return -ENOPROTOOPT;
	}

	switch (family) {
	case PF_INET:
		kz_debug("getting results; proto='%u', src='%pI4:%hu', dst='%pI4:%hu'\n", sk->sk_protocol,
			 &inet_sk(sk)->inet_rcv_saddr, ntohs(inet_sk(sk)->inet_sport), &inet_sk(sk)->inet_daddr, ntohs(inet_sk(sk)->inet_dport));
		break;
	case PF_INET6:
		kz_debug("getting results; proto='%u', src='%pI6:%hu', dst='%pI6:%hu'\n", sk->sk_protocol,
			 &inet6_sk(sk)->saddr, ntohs(inet_sk(sk)->inet_sport), inet6_sk(sk)->daddr_cache, ntohs(inet_sk(sk)->inet_dport));
		break;
	default:
		BUG();
	}

	if ((unsigned int) *len < sizeof(struct kz_lookup_result)) {
		kz_debug("buffer size is too small for the result; len='%d', required='%lu'\n", *len, sizeof(struct kz_lookup_result));
		return -EINVAL;
	}

	memset(&tuple, 0, sizeof(tuple));
	switch (family) {
	case PF_INET:
		tuple.src.u3.ip = inet_sk(sk)->inet_rcv_saddr;
		tuple.src.u.tcp.port = inet_sk(sk)->inet_sport;
		tuple.dst.u3.ip = inet_sk(sk)->inet_daddr;
		tuple.dst.u.tcp.port = inet_sk(sk)->inet_dport;
		tuple.src.l3num = AF_INET;
		tuple.dst.protonum = sk->sk_protocol;
		break;
	case PF_INET6:
		ipv6_addr_copy(&tuple.src.u3.in6, &inet6_sk(sk)->saddr);
		tuple.src.u.tcp.port = inet_sk(sk)->inet_sport;
		ipv6_addr_copy(&tuple.dst.u3.in6, inet6_sk(sk)->daddr_cache);
		tuple.dst.u.tcp.port = inet_sk(sk)->inet_dport;
		tuple.src.l3num = AF_INET6;
		tuple.dst.protonum = sk->sk_protocol;
		break;
	default:
		BUG();
	}

	h = nf_conntrack_find_get(sock_net(sk), NF_CT_DEFAULT_ZONE, &tuple);
	if (h) {
		struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);
		struct nf_conntrack_kzorp *kzorp = kz_extension_find(ct);
		u_int64_t cookie;
		int res = 0;

		if (kzorp == NULL) {
			kz_debug("no kzorp extension structure found\n");
			res = -ENOENT;
			goto error_put_ct;
		}

		rcu_read_lock();
		{
			/* we could waste space to store the coolie in kzorp but user is really interested
			   whether it is the current one, 0 indicates obsolete  */
			const struct kz_config *cfg = rcu_dereference(kz_config_rcu);
			cookie = kz_generation_valid(cfg, kzorp->generation) ? cfg->cookie : 0;
		}
		rcu_read_unlock();

		kz_debug("found kzorp results; client_zone='%s', server_zone='%s', dispatcher='%s', service='%s'\n",
			 kzorp->czone ? kzorp->czone->unique_name : kz_log_null,
			 kzorp->szone ? kzorp->szone->unique_name : kz_log_null,
			 kzorp->dpt ? kzorp->dpt->name : kz_log_null,
			 kzorp->svc ? kzorp->svc->name : kz_log_null);

		if (copy_to_user(user, &cookie, sizeof(cookie)) != 0) {
			res = -EFAULT;
			goto error_put_ct;
		}

		if (kzorp->czone)
			COPY_NAME_TO_USER(user, czone_name, kzorp->czone->unique_name);
		if (kzorp->szone)
			COPY_NAME_TO_USER(user, szone_name, kzorp->szone->unique_name);
		if (kzorp->dpt)
			COPY_NAME_TO_USER(user, dispatcher_name, kzorp->dpt->name);
		if (kzorp->svc)
			COPY_NAME_TO_USER(user, service_name, kzorp->svc->name);

error_put_ct:
		nf_ct_put(ct);

		return res;
	}

	kz_debug("conntrack entry not found\n");

	return -ENOENT;
}

static int
kzorp_getsockopt_results_v4(struct sock *sk, int optval, void __user *user, int *len)
{
	return kzorp_getsockopt_results(PF_INET, sk, optval, user, len);
}

static int
kzorp_getsockopt_results_v6(struct sock *sk, int optval, void __user *user, int *len)
{
	return kzorp_getsockopt_results(PF_INET6, sk, optval, user, len);
}

static struct nf_sockopt_ops so_kzorpresult[] = {
	{
		.pf		= PF_INET,
		.get_optmin	= SO_KZORP_RESULT,
		.get_optmax	= SO_KZORP_RESULT + 1,
		.get		= &kzorp_getsockopt_results_v4,
		.owner		= THIS_MODULE,
	},
	{
		.pf		= PF_INET6,
		.get_optmin	= SO_KZORP_RESULT,
		.get_optmax	= SO_KZORP_RESULT + 1,
		.get		= &kzorp_getsockopt_results_v6,
		.owner		= THIS_MODULE,
	},
};

int __init
kz_sockopt_init(void)
{
	int res;

	res = nf_register_sockopt(&so_kzorpresult[0]);
	if (res < 0)
		return res;

	res = nf_register_sockopt(&so_kzorpresult[1]);
	if (res < 0)
		nf_unregister_sockopt(&so_kzorpresult[0]);

	return res;
}

void
kz_sockopt_cleanup(void)
{
	nf_unregister_sockopt(&so_kzorpresult[1]);
	nf_unregister_sockopt(&so_kzorpresult[0]);
}
