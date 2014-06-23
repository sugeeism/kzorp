/*
 * KZorp data structure lookup implementation
 *
 * Copyright (C) 2006-2011, BalaBit IT Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

/* TODO:
 *   - FIX transparent vs. non-transparent dispatcher lookups bug #21578 (specification needed before fix)
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/if.h>
#include <linux/list.h>
#include <linux/jhash.h>
#include <linux/percpu.h>
#include <linux/cpumask.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/sort.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/addrconf.h>
#include <net/xfrm.h>

#include <asm/bitops.h>

#include <linux/netfilter/kzorp.h>

#include <net/netfilter/kzorp_lookup_internal.h>

static const char *const kz_log_null = "(NULL)";

/***********************************************************
 * Global lookup structures
 ***********************************************************/

struct zone_lookup_t
{
	u_int16_t index;
	u_int16_t depth;
};

void kz_generate_lookup_data(struct kz_head_d *dispatchers);

static DEFINE_PER_CPU(struct kz_percpu_env *, kz_percpu);

void
kz_lookup_cleanup(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct kz_percpu_env *l = per_cpu(kz_percpu, cpu);

		if (l != NULL) {
			KZ_KFREE(l->src_mask);
			KZ_KFREE(l->dst_mask);
			KZ_KFREE(l->result_rules);
			kfree(l);
		}
	}
}

int __init
kz_lookup_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct kz_percpu_env *l;

		l = (struct kz_percpu_env *) kzalloc(sizeof(*l), GFP_KERNEL);
		if (l == NULL)
			goto cleanup;

		per_cpu(kz_percpu, cpu) = l; /* store early, so cleanup works! */

		l->src_mask = (unsigned long *) kzalloc(KZ_ZONE_BF_SIZE, GFP_KERNEL);
		if (l->src_mask == NULL)
			goto cleanup;

		l->dst_mask = (unsigned long *) kzalloc(KZ_ZONE_BF_SIZE, GFP_KERNEL);
		if (l->dst_mask == NULL)
			goto cleanup;

		l->result_rules = kzalloc(sizeof(*l->result_rules), GFP_KERNEL);
		if (l->result_rules == NULL)
			goto cleanup;

		l->max_result_size = 1;
	}

	return 0;

cleanup:
	kz_lookup_cleanup();

	return -ENOMEM;
}

/***********************************************************
 * Utility functions
 ***********************************************************/

/* Return 1 if the destination address is local on the interface. */
static inline int
match_iface_local(const struct net_device * in, u_int8_t proto, const union nf_inet_addr *addr)
{
	int res = 0;


	if (in == NULL)
		return 0;

	switch (proto) {
	case NFPROTO_IPV4:
		{
			struct in_device *indev;
			indev = in_dev_get(in);
			if (indev == NULL)
				return 0;

			for_ifa(indev) {
				if (ifa->ifa_local == addr->ip) {
					res = 1;
					break;
				}
			}
			endfor_ifa(indev);

			in_dev_put(indev);
		}
		break;
	case NFPROTO_IPV6:
		{
			struct inet6_dev *in6dev;
			struct inet6_ifaddr *ifp;
			in6dev = in6_dev_get(in);
			if (in6dev == NULL)
				return 0;

			list_for_each_entry(ifp, &in6dev->addr_list, if_list) {
				if (ipv6_addr_cmp(&ifp->addr, &addr->in6) == 0) {
					res = 1;
					break;
				}
			}

			in6_dev_put(in6dev);
		}
		break;
	}

	return res;
}

/***********************************************************
 * Dispatchers
 ***********************************************************/

static int
port_range_cmp(const void *_a, const void *_b)
{
	const struct kz_port_range *a = (struct kz_port_range *)_a;
	const struct kz_port_range *b = (struct kz_port_range *)_b;
	int res;

	res = a->from - b->from;
	if (res == 0)
		res = a->to - b->to;

	return res;
}

static void
port_range_swap(void *_a, void *_b, int size)
{
	struct kz_port_range *a = (struct kz_port_range *)_a;
	struct kz_port_range *b = (struct kz_port_range *)_b;

	swap(a->from, b->from);
	swap(a->to, b->to);
}

static int
dpt_ndim_rule_sort_ports(unsigned int n, struct kz_port_range *r)
{
	sort(r, n, sizeof(*r), port_range_cmp, port_range_swap);

	/* FIXME: add check to make sure there are no overlaps in ranges */
	return 0;
}

static int
in_subnet_size_cmp(const void *_a, const void *_b)
{
	const struct kz_in_subnet *a = (struct kz_in_subnet *)_a;
	const struct kz_in_subnet *b = (struct kz_in_subnet *)_b;

	int res;

	/* NOTE: inverted result because we need to sort by the mask
	 * size decreasingly */
	res = mask_to_size_v4(&b->mask) - mask_to_size_v4(&a->mask);

	if (res == 0)
		res = (a->addr.s_addr < b->addr.s_addr) ? -1 :
			((a->addr.s_addr == b->addr.s_addr) ? 0 : 1);

	return res;
}

static void
in_subnet_swap(void *_a, void *_b, int size)
{
	struct kz_in_subnet *a = (struct kz_in_subnet *)_a;
	struct kz_in_subnet *b = (struct kz_in_subnet *)_b;

	swap(a->addr, b->addr);
	swap(a->mask, b->mask);
}

/**
 * ipv6_addr_less - return true if an IPv6 address is less than another address
 * @a1: first address
 * @a2: second address
 *
 * Returns: true if @a1 < @a2 (numerically)
 */
static inline bool
ipv6_addr_less(const struct in6_addr *a1, const struct in6_addr *a2)
{
	int i;

	for (i = 0; i < 4; i++) {
		u32 _a1 = ntohl(a1->s6_addr32[i]);
		u32 _a2 = ntohl(a2->s6_addr32[i]);

		if (_a1 < _a2)
			return true;
		else if (_a1 == _a2)
			continue;
		else
			return false;
	}

	/* equal */
	return false;
}

static int
in6_subnet_size_cmp(const void *_a, const void *_b)
{
	const struct kz_in6_subnet *a = (struct kz_in6_subnet *)_a;
	const struct kz_in6_subnet *b = (struct kz_in6_subnet *)_b;

	int res;

	/* NOTE: inverted result because we need to sort by the mask
	 * size decreasingly */
	res = mask_to_size_v6(&b->mask) - mask_to_size_v6(&a->mask);

	if (res == 0)
		res = ipv6_addr_less(&a->addr, &b->addr) ? -1 :
		       (ipv6_addr_equal(&a->addr, &b->addr) ? 0 : 1);

	return res;
}

static void
in6_subnet_swap(void *_a, void *_b, int size)
{
	struct kz_in6_subnet *a = (struct kz_in6_subnet *)_a;
	struct kz_in6_subnet *b = (struct kz_in6_subnet *)_b;

	swap(a->addr, b->addr);
	swap(a->mask, b->mask);
}

static int
dpt_ndim_rule_sort_in_subnets(unsigned int n, struct kz_in_subnet *r)
{
	sort(r, n, sizeof(*r), in_subnet_size_cmp, in_subnet_swap);

	return 0;
}

static int
dpt_ndim_rule_sort_in6_subnets(unsigned int n, struct kz_in6_subnet *r)
{
	sort(r, n, sizeof(*r), in6_subnet_size_cmp, in6_subnet_swap);

	return 0;
}

static int
zone_depth_cmp(const void *_a, const void *_b)
{
	const struct kz_zone *a = *(const struct kz_zone **)_a;
	const struct kz_zone *b = *(const struct kz_zone **)_b;
	int res;

	/* NOTE: inverted result because we need to sort by the depth
	 * in reverse order */
	res = b->depth - a->depth;
	if (res == 0)
		res = strcmp(a->unique_name, b->unique_name);

	kz_debug("a='%s', b='%s', res='%d'\n", a->unique_name, b->unique_name, res);

	return res;
}

static void
zone_swap(void *_a, void *_b, int size)
{
	struct kz_zone **a = (struct kz_zone **)_a;
	struct kz_zone **b = (struct kz_zone **)_b;

	swap(*a, *b);
}

static int
dpt_ndim_rule_sort_zones(unsigned int n, struct kz_zone **r)
{
	sort(r, n, sizeof(*r), zone_depth_cmp, zone_swap);

	return 0;
}

static int
dpt_ndim_rule_sort(struct kz_dispatcher_n_dimension_rule *rule)
{
	int res;

	kz_debug("sorting rule; id='%u'\n", rule->id);

	res = dpt_ndim_rule_sort_ports(rule->num_src_port, rule->src_port);
	if (res < 0)
		return res;

	res = dpt_ndim_rule_sort_ports(rule->num_dst_port, rule->dst_port);
	if (res < 0)
		return res;

	res = dpt_ndim_rule_sort_in_subnets(rule->num_src_in_subnet, rule->src_in_subnet);
	if (res < 0)
		return res;

	res = dpt_ndim_rule_sort_in6_subnets(rule->num_src_in6_subnet, rule->src_in6_subnet);
	if (res < 0)
		return res;

	res = dpt_ndim_rule_sort_in_subnets(rule->num_dst_in_subnet, rule->dst_in_subnet);
	if (res < 0)
		return res;

	res = dpt_ndim_rule_sort_in6_subnets(rule->num_dst_in6_subnet, rule->dst_in6_subnet);
	if (res < 0)
		return res;

	res = dpt_ndim_rule_sort_zones(rule->num_src_zone, rule->src_zone);
	if (res < 0)
		return res;

	res = dpt_ndim_rule_sort_zones(rule->num_dst_zone, rule->dst_zone);

	return res;
}

static int
dpt_ndim_sort(struct kz_dispatcher *dispatcher)
{
	unsigned int i;
	int res;

	kz_debug("sorting dispatcher; name='%s'\n", dispatcher->name);

	for (i = 0; i < dispatcher->num_rule; i++) {
		res = dpt_ndim_rule_sort(&dispatcher->rule[i]);
		if (res < 0)
			return res;
	}

	return 0;
}

/***********************************************************
 * Dispatcher lookup
 ***********************************************************/

void
kz_head_dispatcher_init(struct kz_head_d *h)
{
	h->lookup_data = NULL;
}
EXPORT_SYMBOL_GPL(kz_head_dispatcher_init);

int
kz_head_dispatcher_build(struct kz_head_d *h)
{
	struct kz_dispatcher *i;
	int res = 0;

	list_for_each_entry(i, &h->head, list) {
		/* n-dim dispatchers do not have a complex
		 * lookup data structure yet, but we still
		 * have to do some preparation for the lookup
		 * here:
		 *
		 *  - port range lists should be sorted by on the 'from' entry
		 *  - subnet lists should be sorted by the subnet size
		 *  - zone lists should be sorted by the zone depth
		 */
		res = dpt_ndim_sort(i);
		if (res < 0)
			goto cleanup;
	}

	kz_generate_lookup_data(h);

	return res;

cleanup:
	kz_debug("problem, cleaning up\n");

	return res;
}
EXPORT_SYMBOL_GPL(kz_head_dispatcher_build);

void
kz_head_dispatcher_destroy(struct kz_head_d *h)
{
	if (h->lookup_data != NULL)
		kz_big_free(h->lookup_data, h->lookup_data_allocator);
}
EXPORT_SYMBOL_GPL(kz_head_dispatcher_destroy);

/***********************************************************
 * Helper functions for weighted zone checks
 ***********************************************************/

/**
 * unmark_zone_path - clear reachable marking for all reachable zone IDs
 * @mask: the bitfield to clear bits in
 * @zone: the zone to start with
 *
 * Undoes what mark_zone_path() did.
 */
static inline void
unmark_zone_path(unsigned long *mask, const struct kz_zone *zone)
{
	while (zone != NULL) {
		clear_bit(zone->index, mask);
		zone = zone->admin_parent;
	}
}

/**
 * zone_score - return the "score" of a given zone
 * @zone: the zone we need to score
 * @mask: bitfield initialized with mark_zone_path()
 *
 * Returns a scrore for the given zone, based on whether or not it is
 * accessible according to the mask and how deep it is in the zone
 * hierarchy.
 *
 * The idea is that the more specific the match is the larger the
 * score is.
 *
 * Returns: -1 if @zone is not accessible
 *	    0 for root zones
 *	    n if @zone is reachable through n links from a root zone
 */
static inline int
zone_score(const struct zone_lookup_t *zone, const unsigned long * const mask)
{
	/* NULL zone == wildcard */
	if (zone == NULL)
		return 0;

	/* check if the zone is reachable */
	if (test_bit(zone->index, mask)) {
		return zone->depth;
	}
	else {
		return -1;
	}
}

/* ipv4_masked_addr_cmp - return wether two addresses are in the same subnet
 * @a1: first address
 * @m: netmask of the subnet
 * @a2: second address
 *
 * Returns: 0 if the addresses are in the same subnet
 *          1 else
 */
static inline int
ipv4_masked_addr_cmp(const struct in_addr *a1, const struct in_addr *m,
		     const struct in_addr *a2)
{
	return !!((a1->s_addr ^ a2->s_addr) & m->s_addr);
}

static inline int
iface_name_cmp(const char *ifname1, const char *ifname2)
{
	return !strncmp(ifname1, ifname2, IFNAMSIZ);
}

/***********************************************************
 * N-dimensional rule lookup
 *
 * This is special: we have to do the rule lookup on an aggregated
 * list of rules in all N-dimension dispatchers.
 ***********************************************************/

#define SCORE_ZONE_BITS 5 /* max. zone->depth + 1 */
#define SCORE_SUBNET_BITS 8 /* /128 IPv6 subnet depth + 1 */
#define SCORE_DST_IFACE_BITS 2 /* Tri-state: 2 iface match, 1 ifgroup match, 0 empty */
#define SCORE_SRC_ADDRESS_BITS (SCORE_ZONE_BITS + SCORE_SUBNET_BITS)
#define SCORE_DST_ADDRESS_BITS (SCORE_ZONE_BITS + SCORE_DST_IFACE_BITS + SCORE_SUBNET_BITS)

/**
 * union kz_ndim_score - structure to store rule evaluation scores
 *
 * NOTE: zero usually means wildcard match (ie. no restriction was
 * specified in the rule). More specific match means higher score.
 *
 * FIXME: This layout depends on the particular bitfield layout GCC
 * uses on x86 and is totally non-portable.
 */
typedef union kz_ndim_score {
	struct {
		unsigned long dst_address : SCORE_DST_ADDRESS_BITS;
		unsigned long src_address : SCORE_SRC_ADDRESS_BITS;
		unsigned long dst_port : 2;		/* 1: matching range, 2: specific match (range of 1 element) */
		unsigned long src_port : 2;		/* 1: matching range, 2: specific match (range of 1 element) */
		unsigned long proto : 1;		/* 1: protocol match */
		unsigned long iface : 3;		/* 1: interface group match, 2: interface match, 4: reqid match */
	} d;
	int64_t all;
} kz_ndim_score;

static int
kz_ndim_eval_reqid_match(const struct kz_reqids * const reqids,
			 const u_int32_t n_reqids, const u_int32_t * const r_reqids)
{
	int reqid_idx, idx;
	if (!reqids || n_reqids == 0)
		return 0;

	for (idx = 0; idx < reqids->len; idx++) {
		const u_int32_t reqid = reqids->vec[idx];
		for (reqid_idx = 0; reqid_idx < n_reqids; reqid_idx++) {
			kz_debug("comparing reqids; id='%d', r_reqid='%d'\n", reqid, r_reqids[reqid_idx]);
			if (reqid == r_reqids[reqid_idx])
				return 1;
		}
	}

	return 0;
}

/**
 * kz_ndim_eval_rule_iface - evaluate if a network interface matches a list of interface names or interface groups
 * @n_ifaces: number of elements in the interface name array
 * @r_ifaces: array of interface names to check
 * @n_ifgroups: number of elements in the interface group array
 * @r_ifgroups: array of interface group IDs to check
 * @iface: pointer to a net_device structure -- we have to check this
 *
 * Returns: -1, if no matching interface name or group ID was found, or there's no interface
 *		and @r_ifaces or @r_ifgroups is not empty
 *	     0, if both @r_ifaces and @r_ifgroups is empty
 *	     1, if a matching interface group ID was found
 *	     2, if a matching interface name was found
 */
static int
kz_ndim_eval_rule_iface(const u_int32_t n_reqids, const u_int32_t * const r_reqids,
			const u_int32_t n_ifaces, ifname_t * r_ifaces,
			const u_int32_t n_ifgroups, const u_int32_t * const r_ifgroups,
			const struct kz_reqids * const reqids,
			const struct net_device * const iface)
{
	unsigned int i;
	int score = 0;

	kz_debug("n_ifaces='%u', n_ifgroups='%u', iface='%s'\n",
		 n_ifaces, n_ifgroups, iface ? iface->name : kz_log_null);

	if (n_reqids == 0 && n_ifaces == 0 && n_ifgroups == 0)
		return score;

	if (iface == NULL)
		return -1;

	for (i = 0; i < n_ifgroups; i++) {
		kz_debug("comparing groups; id='%u', r_id='%u'\n", iface->group, r_ifgroups[i]);
		if (iface->group == r_ifgroups[i]) {
			score = 1;
			break;
		}
	}

	for (i = 0; i < n_ifaces; i++) {
		kz_debug("comparing names; name='%s', r_name='%s'\n", iface->name, (char *) (r_ifaces + i));
		if (iface_name_cmp(iface->name, (char *) (r_ifaces + i))) {
			score |= 2;
			break;
		}
	}

	if (kz_ndim_eval_reqid_match(reqids, n_reqids, r_reqids))
		score |= 4;

	return score ? score : -1;
}

static int
kz_ndim_eval_rule_dst_if(const u_int32_t n_ifaces, ifname_t * r_ifaces,
		    const u_int32_t n_ifgroups, const u_int32_t * const r_ifgroups,
		    const struct net_device * const iface,
		    const u_int8_t proto, const union nf_inet_addr *daddr)
{
	if (n_ifaces == 0 && n_ifgroups == 0)
		return 0;

	if (iface == NULL)
		return -1;

	if (match_iface_local(iface, proto, daddr))
		return kz_ndim_eval_rule_iface(0, NULL, /* We don't have reqid for dst addresses */
					       n_ifaces, r_ifaces,
					       n_ifgroups, r_ifgroups,
					       NULL, iface);
	else
		return -1;
}

/**
 * kz_ndim_eval_rule_proto - evaluate if the protocol ID matches a list of protocols
 * @n_protos: number of elements in the protocol ID array
 * @r_protos: array of protocol IDs to check
 * @proto: protocol ID to look for in the array
 *
 * Returns: -1, if no matching protocol ID was found
 *	     0, if @r_protos is empty
 *	     1, if a match was found
 */
static int
kz_ndim_eval_rule_proto(const u_int32_t n_protos, const u_int8_t * const r_protos,
			const u_int8_t proto)
{
	unsigned int i;

	kz_debug("n_protos='%u', proto='%u'\n", n_protos, proto);

	if (n_protos == 0)
		return 0;

	for (i = 0; i < n_protos; i++) {
		kz_debug("comparing protocol; proto='%u', r_proto='%u'\n", proto, r_protos[i]);
		if (proto == r_protos[i])
			return 1;
	}

	return -1;
}

/**
 * kz_ndim_eval_rule_port - evaluate if a discrete port number matches a list of port ranges
 * @n_ports: number of port ranges on the list
 * @r_ports: array of kz_port_range structures (sorted by the 'from' field)
 * @port: port number to match for
 *
 * Assumptions:
 * @r_ports should be sorted increasingly by the 'from' field of kz_port_range
 *
 * Returns: -1, if no matching port range was found in @r_ports and @r_ports is not empty
 *	     0, if @r_ports is empty
 *	     1, if a matching range of size larger than one was found
 *	     2, if a matching range of size one (iow. one port) was found in the list
 */
static int
kz_ndim_eval_rule_port(const u_int32_t n_ports, const struct kz_port_range * const r_ports,
		       const u_int16_t port)
{
	unsigned int i;

	kz_debug("n_ports='%u', port='%u'\n", n_ports, port);

	if (n_ports == 0)
		return 0;

	for (i = 0; i < n_ports; i++) {
		kz_debug("comparing port range; port='%u', r_from='%u', r_to='%u'\n", port,
			 r_ports[i].from, r_ports[i].to);

		/* if port is less than 'from' we can be sure that
		 * there's no match */
		if (port < r_ports[i].from)
			return -1;

		if (port <= r_ports[i].to) {
			/* match single port: 2; match in real range: 1 */
			return (r_ports[i].from == r_ports[i].to) ? 2 : 1;
		}
	}

	return -1;
}

#define kz_ndim_eval_rule_src_port kz_ndim_eval_rule_port
#define kz_ndim_eval_rule_dst_port kz_ndim_eval_rule_port

/**
 * kz_ndim_eval_rule_subnet - evaluate how an IP address matches an array of subnets
 * @n_subnets: number of IPv4 subnets in the array
 * @r_subnets: array of kz_in_subnet structures
 * @n_subnets6: number of IPv6 subnets in the array
 * @r_subnets6: array of kz_in6_subnet structures
 * @proto: protocol of the address to check
 * @addr: the address to check
 *
 * Assumptions:
 * @r_subnets and @r_subnets6 should be sorted decreasingly by the size
 * of the subnet mask and the ip component of subnet structures should
 * be properly masked with the mask.
 *
 * Returns: -1, if no matching subnet was found in @r_subnets, and @r_subnets is not empty
 *	     0, if @r_subnets is empty
 *           n, (n > 0) for matches, where n is the size of the subnet mask of
 *              the matching subnet + 1
 */
static int
kz_ndim_eval_rule_subnet(const u_int32_t n_subnets, const struct kz_in_subnet *const r_subnets,
                         const u_int32_t n_subnets6, const struct kz_in6_subnet * const r_subnets6,
                         u_int8_t proto, const union nf_inet_addr * addr)
{
	unsigned int i;

	kz_debug("n_subnets='%u', n_subnets6='%u'\n", n_subnets, n_subnets6);

	if (n_subnets == 0 && n_subnets6 == 0)
		return 0;

	switch (proto)
	{
	case NFPROTO_IPV4:
		for (i = 0; i < n_subnets; i++) {
			kz_debug("comparing subnet; ip='%pI4', network='%pI4', mask='%pI4'\n",
				 &addr->in, &r_subnets[i].addr, &r_subnets[i].mask);

			if (!ipv4_masked_addr_cmp(&addr->in, &r_subnets[i].mask, &r_subnets[i].addr))
				return mask_to_size_v4(&r_subnets[i].mask) + 1;
		}
		break;
	case NFPROTO_IPV6:
		for (i = 0; i < n_subnets6; i++) {
			kz_debug("comparing subnet; ip='%pI6', network='%pI6', mask='%pI6'\n",
				 &addr->in6, &r_subnets6[i].addr, &r_subnets6[i].mask);

			if (!ipv6_masked_addr_cmp(&addr->in6, &r_subnets6[i].mask, &r_subnets6[i].addr))
				return mask_to_size_v6(&r_subnets6[i].mask) + 1;
		}
		break;
	default:
		BUG();
	}
	return -1;
}

/**
 * kz_ndim_eval_rule_zone - evaluate how good a list of zones matches our zone
 * @n_zones: number of zones in the list
 * @r_zones: array of zone pointers containint @n_zones elements
 * @zone: zone to check match for
 * @mask: bitmask with the ids of accessible zones marked
 *
 * Assumptions:
 * @r_zones should be sorted decreasingly by the zone depth
 *
 * Returns a score indicating how good a match, if any, was found for @zone in
 * the @r_zones list. Higher scores indicate better match.
 *
 * Returns: -1, if no matching zone was found in @r_zones, or there's no zone specified
 *              and @r_zones is not empty,
 *           0, if @r_zones is empty,
 *           n, (n > 0) for matches, where n is the depth of the matching zone in @r_zones,
 *              the zone depth starts with 1, @see kz_zone_new in kzorp_core.c.
 */
static int
kz_ndim_eval_rule_zone(const u_int32_t n_zones, struct zone_lookup_t * const r_zones,
		        const struct kz_zone * const zone, const unsigned long *mask)
{
	unsigned int i;
	int zscore = -1;

	kz_debug("n_zones='%u', zone='%s'\n", n_zones, zone ? zone->unique_name : kz_log_null);

	if (n_zones == 0)
		return 0;

	if (zone == NULL)
		return -1;

	for (i = 0; i < n_zones; i++) {
		//kz_debug("comparing zone; zone='%s', r_zone='%s'\n", zone->unique_name, r_zones[i]->unique_name);

		zscore = zone_score(&r_zones[i], mask);

		if (zscore < 0)
			continue;

		/* Matching zone, the first match should be the most
		 * specific since @r_zones is ordered on the zone
		 * depth. Stop iterating the list.
		 */
		break;
	}

	return zscore;
}

/**
 * kz_ndim_eval_rule_address - evaluate all address related dimensions (subnets and zones)
 * @n_subnets: number of IPv4 subnets in the array
 * @r_subnets: array of kz_in_subnet structures
 * @n_subnets6: number of IPv6 subnets in the array
 * @r_subnets6: array of kz_in6_subnet structures
 * @n_zones: number of zones in the list
 * @r_zones: array of zone pointers containint @n_zones elements
 * @proto: protocol of the address to check
 * @addr: the address to check
 * @zone: zone to check match for
 * @mask: bitmask with the ids of accessible zones marked
 *
 * Assumptions:
 * @r_subnets and @r_subnets6 should be sorted decreasingly by the size
 * of the subnet mask and the ip component of subnet structures should
 * be properly masked with the mask.
 * @r_zones should be sorted decreasingly by the zone depth
 *
 * Returns a score indicating how good a match, if any, was found for
 * the address related dimensions.
 *
 * Evaluates the dimensions in the following order: subnet, zone.  If
 * no subnet match is found the zone dimension is evaluated.
 *
 * Returns: -1, if no match was found
 *           0, if both the subnets and zone dimensions are empty
 *           n, (n > 0) for matches, where n is the aggregated score from the subnet and
 *              zone evaluation
 */

static int
kz_ndim_eval_rule_address(const u_int32_t n_subnets, const struct kz_in_subnet * const r_subnets,
			   const u_int32_t n_subnets6, const struct kz_in6_subnet * const r_subnets6,
			   const u_int32_t n_zones, struct zone_lookup_t * const r_zones,
			   u_int8_t proto, const union nf_inet_addr *addr,
			   const struct kz_zone * const zone, const unsigned long *mask)
{
	int score = 0;
	int subnet_score = kz_ndim_eval_rule_subnet(n_subnets, r_subnets, n_subnets6, r_subnets6, proto, addr);
	int zone_score = kz_ndim_eval_rule_zone(n_zones, r_zones, zone, mask);

	if (subnet_score > 0)
		score = subnet_score << SCORE_ZONE_BITS;

	if (zone_score > 0)
		score |= zone_score;

	return (score == 0 && (subnet_score < 0 || zone_score < 0)) ? -1 : score;
}

static int
kz_ndim_eval_rule_dst(const u_int32_t n_subnets, const struct kz_in_subnet * const r_subnets,
		      const u_int32_t n_subnets6, const struct kz_in6_subnet * const r_subnets6,
		      const u_int32_t n_zones, struct zone_lookup_t * const r_zones,
		      const u_int32_t n_ifaces, ifname_t * r_ifaces,
		      const u_int32_t n_ifgroups, const u_int32_t * const r_ifgroups,
		      const struct net_device * const iface,
		      u_int8_t proto, const union nf_inet_addr *addr,
		      const struct kz_zone * const zone, const unsigned long *mask)
{
	int score = 0;
	int subnet_score = kz_ndim_eval_rule_subnet(n_subnets, r_subnets, n_subnets6, r_subnets6, proto, addr);
	int iface_score = kz_ndim_eval_rule_dst_if(n_ifaces, r_ifaces, n_ifgroups, r_ifgroups, iface, proto, addr);
	int zone_score = kz_ndim_eval_rule_zone(n_zones, r_zones, zone, mask);

	if (subnet_score > 0)
		score = subnet_score << (SCORE_ZONE_BITS + SCORE_DST_IFACE_BITS);

	if (iface_score > 0)
		score |= iface_score << SCORE_ZONE_BITS;

	if (zone_score > 0)
		score |= zone_score;

	return (score == 0 && (subnet_score < 0 || iface_score < 0 || zone_score < 0)) ? -1 : score;
}


#define EVAL_DIM_RES(name)					\
	if (dim_res < 0)					\
		return -1;					\
	res.d.name = (unsigned) dim_res;			\
	if (equal) {						\
		if ((unsigned) dim_res < best.d.name)		\
			return -1;				\
		else if ((unsigned) dim_res > best.d.name)	\
			equal = false;				\
	}

#define EVAL_DIM(name)							\
	dim_res = rule->num_##name ? kz_ndim_eval_rule_##name(rule->num_##name, rule->name, name) : 0; \
	EVAL_DIM_RES(name);

/* structs used for lookup data to encode dimensions */

KZ_PROTECTED struct kz_rule_lookup_data*
kz_rule_lookup_cursor_next_rule(struct kz_rule_lookup_cursor *cursor)
{
	if (cursor->rule->bytes_to_next == 0)
		return NULL;

	cursor->rule = (void*)(cursor->rule) + cursor->rule->bytes_to_next;
	cursor->pos = sizeof(struct kz_rule_lookup_data);
	return cursor->rule;
}

#define DEFINE_LOOKUP_DATA_TYPE(DIM_NAME, _, __, ___, LOOKUP_TYPE, ...) \
	typedef struct { \
		u_int32_t num; \
		LOOKUP_TYPE data[]; \
	} DIM_NAME##_dim_lookup_data

KZORP_DIM_LIST(DEFINE_LOOKUP_DATA_TYPE, ;);

#undef DEF_LOOKUP_DATA_TYPE

#define SIZEOF_STRUCT_MEMBER(STRUCT, MEMBER) (sizeof((STRUCT *)0)->MEMBER)
#define PAD(value, n) (((value - 1) | (n-1)) + 1)

/* returns the size of a NAME_lookup_data struct filled with COUNT elements,
 * padded to 4 bytes */
#define LOOKUP_DATA_SIZE(NAME, COUNT) PAD(SIZEOF_STRUCT_MEMBER(NAME##_dim_lookup_data, num) + COUNT * SIZEOF_STRUCT_MEMBER(NAME##_dim_lookup_data, data[0]), 4)
#define LOOKUP_DATA_SIZE_OPTIONAL(NAME, COUNT) (COUNT ? LOOKUP_DATA_SIZE(NAME, COUNT) : 0)

/* Each value represents a bit in the bitmap used in lookup data structure.
 * Order must be the same as the order in which dimensions are fetched from
 * lookup data. */
enum KZORP_DIMENSIONS {
#define KZORP_DIM_ENUM(DIM_NAME, ...) KZORP_DIM_##DIM_NAME

	KZORP_DIM_LIST(KZORP_DIM_ENUM, KZORP_COMMA_SEPARATOR)

#undef KZORP_DIM_ENUM
};

#define GENERATE_DIM(map, name) \
	do { \
		if (!!rule->num_##name) { \
			int i; \
			name##_dim_lookup_data *d = pos; \
			pos += LOOKUP_DATA_SIZE(name, rule->num_##name); \
			map = map | (1 << KZORP_DIM_##name); \
			d->num = rule->num_##name; \
			for (i = 0; i < d->num; ++i) \
				d->data[i] = rule->name[i]; \
		} \
	} while (0);

KZ_PROTECTED size_t
kz_generate_lookup_data_rule_size(const struct kz_dispatcher_n_dimension_rule * const rule)
{
	size_t rule_size = sizeof(struct kz_rule_lookup_data);

#define CALL_LOOKUP_DATA_SIZE_OPTIONAL(DIM_NAME, ...) \
	(LOOKUP_DATA_SIZE_OPTIONAL(DIM_NAME, rule->num_##DIM_NAME))

	rule_size += KZORP_DIM_LIST(CALL_LOOKUP_DATA_SIZE_OPTIONAL, +);

#undef CALL_LOOKUP_DATA_SIZE_OPTIONAL

	return PAD(rule_size, 8);
}

KZ_PROTECTED struct kz_rule_lookup_data *
kz_generate_lookup_data_rule(const struct kz_dispatcher_n_dimension_rule * const rule, void *buf)
{
	void *pos = buf;
	int map = 0;
	struct kz_rule_lookup_data *current_rule = buf;

	pos += sizeof(struct kz_rule_lookup_data);
	current_rule->orig = rule;

	GENERATE_DIM(map, reqid);

	if (!!rule->num_ifname) {
		int i;
		ifname_dim_lookup_data *d = pos;

		map = map | (1 << KZORP_DIM_ifname);

		pos += LOOKUP_DATA_SIZE(ifname, rule->num_ifname);
		d->num = rule->num_ifname;
		for (i = 0; i < d->num; ++i)
			memcpy(d->data[i], rule->ifname[i], IFNAMSIZ);
	}
	GENERATE_DIM(map, ifgroup);
	GENERATE_DIM(map, proto);

	GENERATE_DIM(map, src_port);
	GENERATE_DIM(map, dst_port);
	GENERATE_DIM(map, src_in_subnet);
	GENERATE_DIM(map, src_in6_subnet);

	if (!!rule->num_src_zone) {
		int i;
		src_zone_dim_lookup_data *d = pos;
		pos += LOOKUP_DATA_SIZE(src_zone, rule->num_src_zone);
		map = map | (1 << KZORP_DIM_src_zone);
		d->num = rule->num_src_zone;
		for (i = 0; i < d->num; ++i)
		{
			d->data[i].index = rule->src_zone[i]->index;
			d->data[i].depth = rule->src_zone[i]->depth;
		}
	}

	GENERATE_DIM(map, dst_in_subnet);
	GENERATE_DIM(map, dst_in6_subnet);

	if (!!rule->num_dst_zone) {
		int i;
		dst_zone_dim_lookup_data *d = pos;
		pos += LOOKUP_DATA_SIZE(dst_zone, rule->num_dst_zone);
		map = map | (1 << KZORP_DIM_dst_zone);
		d->num = rule->num_dst_zone;
		for (i = 0; i < d->num; ++i)
		{
			d->data[i].index = rule->dst_zone[i]->index;
			d->data[i].depth = rule->dst_zone[i]->depth;
		}
	}

	if (!!rule->num_dst_ifname) {
		int i;
		ifname_dim_lookup_data *d = pos;
		pos += LOOKUP_DATA_SIZE(ifname, rule->num_dst_ifname);
		map = map | (1 << KZORP_DIM_dst_ifname);
		d->num = rule->num_dst_ifname;
		for (i = 0; i < d->num; ++i)
			memcpy(d->data[i], rule->dst_ifname[i], IFNAMSIZ);
	}

	GENERATE_DIM(map, dst_ifgroup);

	pos = (void*)PAD((int64_t)pos, 8);
	current_rule->dimension_map = map;
	current_rule->bytes_to_next = pos - buf;
	current_rule = pos;
	return buf;
}

KZ_PROTECTED void
kz_generate_lookup_data(struct kz_head_d *dispatchers)
{
	struct kz_dispatcher *dispatcher;
	struct kz_rule_lookup_data *lookup_data, *current_rule;
	void *pos;
	u_int32_t rules_data_size = 0;

	/* First pass calculates total size */
        list_for_each_entry(dispatcher, &dispatchers->head, list) {
		unsigned int rule_idx;
		for (rule_idx = 0; rule_idx < dispatcher->num_rule; rule_idx++) {
			rules_data_size += kz_generate_lookup_data_rule_size(&dispatcher->rule[rule_idx]);
		}
	}

	if (rules_data_size > 0) {
		pos = current_rule = lookup_data = kz_big_alloc(rules_data_size, &dispatchers->lookup_data_allocator);

		/* Second pass builds up the lookup data */
		list_for_each_entry(dispatcher, &dispatchers->head, list) {
			unsigned int rule_idx;
			for (rule_idx = 0; rule_idx < dispatcher->num_rule; rule_idx++) {
				current_rule = kz_generate_lookup_data_rule(&dispatcher->rule[rule_idx], pos);
				pos += current_rule->bytes_to_next;
			}
		}

		if (current_rule)
			current_rule->bytes_to_next = 0;

		dispatchers->lookup_data = lookup_data;
	}
}

#define RULE_LOOKUP_GET_TYPE(dimension_name, out_num, out_data) \
	do { \
		int dimension_bit = 1 << KZORP_DIM_##dimension_name; \
		*out_num = 0; \
		*out_data = NULL; \
		if ((cursor->rule->dimension_map & dimension_bit)) \
		{ \
			dimension_name##_dim_lookup_data *s = (void*)cursor->rule + cursor_pos; \
			*out_num = s->num; \
			*out_data = s->data; \
			cursor_pos += LOOKUP_DATA_SIZE(dimension_name, s->num); \
		} \
	} while (0);

/* Assumes a cursor, a num_NAME and a data_NAME variable */
#define RULE_FETCH_DIM(name) RULE_LOOKUP_GET_TYPE(name, &num_##name, &data_##name)

#define EVAL_DIM_LOOKUP(NAME) \
	do { \
		u_int32_t num_##NAME; \
		void *data_##NAME; \
                RULE_LOOKUP_GET_TYPE(NAME, &num_##NAME, &data_##NAME); \
		dim_res = num_##NAME ? kz_ndim_eval_rule_##NAME(num_##NAME, data_##NAME, NAME) : 0; \
		EVAL_DIM_RES(NAME); \
	} while (0);

KZ_PROTECTED int64_t
kz_ndim_eval_rule(struct kz_rule_lookup_cursor * cursor,
		   int64_t best_all,
		   const struct kz_reqids * const reqids,
		   const struct net_device * const iface,
		   u_int8_t l3proto,
		   const union nf_inet_addr * const src_addr,
		   const union nf_inet_addr * const dst_addr,
		   u_int8_t l4proto, u_int16_t src_port, u_int16_t dst_port,
		   const struct kz_zone * const src_zone,
		   const struct kz_zone * const dst_zone,
		   const unsigned long *src_zone_mask,
		   const unsigned long *dst_zone_mask)
{
	kz_ndim_score best, res;
	bool equal = true;
	int dim_res;
	u_int8_t proto = l4proto;

	u_int32_t cursor_pos = cursor->pos;

	/*kz_debug("evaluating rule; id='%u'\n", rule->id);*/

	best.all = best_all;
	res.all = 0;

	{
		u_int32_t num_reqid, num_ifname, num_ifgroup;
		u_int32_t *data_reqid;
		ifname_t *data_ifname;
		u_int32_t *data_ifgroup;

		RULE_FETCH_DIM(reqid);
		RULE_FETCH_DIM(ifname);
		RULE_FETCH_DIM(ifgroup);
		dim_res = kz_ndim_eval_rule_iface(num_reqid, data_reqid,
						  num_ifname, data_ifname,
						  num_ifgroup, data_ifgroup,
						  reqids, iface);
		EVAL_DIM_RES(iface);
	}

	EVAL_DIM_LOOKUP(proto);
	EVAL_DIM_LOOKUP(src_port);
	EVAL_DIM_LOOKUP(dst_port);

	{
	/* source address */
		u_int32_t num_src_in_subnet, num_src_in6_subnet, num_src_zone;
		struct kz_in_subnet *data_src_in_subnet;
		struct kz_in6_subnet *data_src_in6_subnet;
		struct zone_lookup_t *data_src_zone;
		RULE_FETCH_DIM(src_in_subnet);
		RULE_FETCH_DIM(src_in6_subnet);
		RULE_FETCH_DIM(src_zone);

		dim_res = kz_ndim_eval_rule_address(num_src_in_subnet, data_src_in_subnet,
						     num_src_in6_subnet, data_src_in6_subnet,
						     num_src_zone, data_src_zone,
						     l3proto, src_addr, src_zone, src_zone_mask);
		EVAL_DIM_RES(src_address);
	}

	{
		/* destination interface/address */
		u_int32_t num_dst_in_subnet, num_dst_in6_subnet, num_dst_zone, num_dst_ifname, num_dst_ifgroup;
		struct kz_in_subnet *data_dst_in_subnet;
		struct kz_in6_subnet *data_dst_in6_subnet;
		struct zone_lookup_t *data_dst_zone;
		ifname_t *data_dst_ifname;
		u_int32_t *data_dst_ifgroup;
		RULE_FETCH_DIM(dst_in_subnet);
		RULE_FETCH_DIM(dst_in6_subnet);
		RULE_FETCH_DIM(dst_zone);
		RULE_FETCH_DIM(dst_ifname);
		RULE_FETCH_DIM(dst_ifgroup);

		dim_res = kz_ndim_eval_rule_dst(num_dst_in_subnet, data_dst_in_subnet,
						 num_dst_in6_subnet, data_dst_in6_subnet,
						 num_dst_zone, data_dst_zone,
						 num_dst_ifname, data_dst_ifname,
						 num_dst_ifgroup, data_dst_ifgroup,
						 iface, l3proto, dst_addr, dst_zone, dst_zone_mask);
		EVAL_DIM_RES(dst_address);
	}

	cursor->pos = cursor_pos;
	return res.all;
}

/**
 * kz_adjust_zone - return configured zone for any zone
 * @zone: zone to check
 *
 * Returns the parent zone if the zone was generated by Zorp because
 * of multiple subnets configured by the user; or @zone if it's not a
 * pseudo-zone.
 */
static inline const struct kz_zone *
kz_adjust_zone(const struct kz_zone *zone)
{
	if (zone && zone->name != zone->unique_name)
		zone = zone->admin_parent;

	return zone;
}

KZ_PROTECTED u_int32_t
kz_ndim_eval(const struct kz_reqids *reqids, const struct net_device *iface, u_int8_t l3proto,
	      const union nf_inet_addr * const src_addr, const union nf_inet_addr * const dst_addr,
	      u_int8_t l4proto, u_int16_t src_port, u_int16_t dst_port,
	      const struct kz_zone * src_zone,
	      const struct kz_zone * dst_zone,
	      const struct kz_head_d * const dispatchers,
	      struct kz_percpu_env *lenv)
{
	kz_ndim_score best;
	const size_t max_out_idx = lenv->max_result_size;
	size_t out_idx = 0;
	struct kz_rule_lookup_cursor cursor;
	struct kz_rule_lookup_data *rule;

	BUG_ON(!lenv);
	BUG_ON(!lenv->max_result_size);
	BUG_ON(!lenv->result_rules);

	if (!dispatchers || list_empty(&dispatchers->head)) {
		kz_debug("no dispatchers to evaluate\n");
		lenv->result_size = 0;
		return 0;
	}

	src_zone = kz_adjust_zone(src_zone);
	dst_zone = kz_adjust_zone(dst_zone);

	/* set up helper bitmaps */
	mark_zone_path(lenv->src_mask, src_zone);
	mark_zone_path(lenv->dst_mask, dst_zone);

	best.all = 0;

	cursor.rule = dispatchers->lookup_data;
	cursor.pos = sizeof(struct kz_rule_lookup_data);
	rule = dispatchers->lookup_data;

	while (rule) {
		int64_t score;
		prefetch(rule->bytes_to_next + (void*)rule);
		score = kz_ndim_eval_rule(&cursor, best.all, reqids, iface,
					  l3proto, src_addr, dst_addr,
					  l4proto, src_port, dst_port,
					  src_zone, dst_zone,
					  lenv->src_mask, lenv->dst_mask);

		if (score == -1 || best.all > score) {
			/* no match or worse than the current best */
			rule = kz_rule_lookup_cursor_next_rule(&cursor);
			continue;
		} else if (best.all < score) {
			/* better match, so reset result list */
			kz_debug("reset result list\n");
			out_idx = 0;
			best.all = score;
		}
		if (out_idx < max_out_idx) {
			kz_debug("appending rule to result list; id='%u', score='%llu'\n", rule->orig->id, score);
			lenv->result_rules[out_idx] = rule->orig;
		}
		rule = kz_rule_lookup_cursor_next_rule(&cursor);

		out_idx++;
	}

	/* clean up helpers */
	unmark_zone_path(lenv->src_mask, src_zone);
	unmark_zone_path(lenv->dst_mask, dst_zone);

	kz_debug("out_idx='%zu'\n", out_idx);

	return lenv->result_size = out_idx;
}

/**
 * kz_ndim_lookup -- look up service for a session by evaluating n-dimensional rules
 * @iface: input interface
 * @l3proto: L3 protocol number (IPv4/IPv6)
 * @src_addr: source address
 * @dst_addr: destination address
 * @l4proto: L4 protocol number (TCP/UDP/etc.)
 * @src_port: source TCP/UDP port (if meaningful for @proto)
 * @dst_port: destination TCP/UDP port (if meaningful for @proto)
 * @src_zone: the zone @src_addr belongs to
 * @dst_zone: the zone @dst_addr belongs to
 * @dispatcher: pointer to a kz_dispatcher pointer to return the dispatcher in (OUTPUT)
 *
 * Evaluate our n-dimensional rules in all dispatchers and return the
 * resulting service as a result. If no matching rule was found or
 * there were more than one matching rule, we return NULL.
 */
static struct kz_service *
kz_ndim_lookup(const struct kz_config *cfg,
	       const struct kz_reqids *reqids,
	       const struct net_device *iface,
	       u_int8_t l3proto,
	       const union nf_inet_addr * const src_addr, const union nf_inet_addr * const dst_addr,
	       u_int8_t l4proto, u_int16_t src_port, u_int16_t dst_port,
	       const struct kz_zone * src_zone,
	       const struct kz_zone * dst_zone,
	       struct kz_dispatcher **dispatcher)
{
	struct kz_percpu_env *lenv;
	const struct kz_head_d * const d = &cfg->dispatchers;
	struct kz_service *service = NULL;
	u_int32_t num_results;

	kz_debug("src_zone='%s', dst_zone='%s'\n",
		 src_zone ? src_zone->unique_name : kz_log_null,
		 dst_zone ? dst_zone->unique_name : kz_log_null);

	preempt_disable();
	lenv = __get_cpu_var(kz_percpu);

	num_results = kz_ndim_eval(reqids, iface, l3proto, src_addr, dst_addr,
				    l4proto, src_port, dst_port, src_zone, dst_zone,
				    d, lenv);

	kz_debug("num_results='%u'\n", num_results);

	if (num_results == 1) {
		service = lenv->result_rules[0]->service;
		*dispatcher = lenv->result_rules[0]->dispatcher;

		kz_debug("found service; dispatcher='%s', rule_id='%u', name='%s'\n",
			 lenv->result_rules[0]->dispatcher->name,
			 lenv->result_rules[0]->id,
			 service ? service->name : kz_log_null);
	}

	preempt_enable();

	kz_debug("service='%s'\n", service ? service->name : "null");

	return service;
}

/***********************************************************
 * IPv4 zone lookup
 ***********************************************************/

static inline unsigned int
zone_ipv4_hash_fn(const u_int32_t prefix)
{
	return jhash_1word(prefix, 0) % KZ_ZONE_HASH_SIZE;
}

static inline bool
zone_ipv4_cmp(const struct kz_zone * const z, const u_int32_t _mask)
{
	struct in_addr mask = { htonl(_mask) };
	return !ipv4_masked_addr_cmp(&z->addr.in, &z->mask.in, &mask);
}

static inline unsigned int
zone_ipv4_hash_fn_z(const struct kz_zone * const z)
{
	return zone_ipv4_hash_fn(ntohl(z->addr.in.s_addr) & ntohl(z->mask.in.s_addr));
}

static inline unsigned int
zone_ipv4_mask_bits(const struct kz_zone * const z)
{
	return mask_to_size_v4(&z->mask.in);
}

static inline void
zone_ipv4_hash(struct kz_head_z *h, struct kz_zone *z)
{
	const unsigned int b = zone_ipv4_mask_bits(z);
	const unsigned int v = zone_ipv4_hash_fn_z(z);

	kz_debug("mask='%pI4', order='%d', bucket='%d'\n", &z->mask.in, b, v);

	hlist_add_head(&z->hlist, &h->luzone.hash[b][v]);
}

static inline void
zone_ipv4_unhash(struct kz_zone *z)
{
	if (!hlist_unhashed(&z->hlist))
		hlist_del(&z->hlist);
}

#ifdef SHINY_NEW_HLIST_FOR_EACH
static __always_inline struct kz_zone *
kz_find_entry_for_ipv4_zone_in_luzone_hash(const struct hlist_head *hash, const u_int32_t p)
{
	struct kz_zone *i;
	hlist_for_each_entry(i, hash, hlist) {
		if (zone_ipv4_cmp(i, p)) {
			kz_debug("found zone; name='%s'\n", i->name);
			return i;
		}
	}
	return NULL;
}
#else
static __always_inline struct kz_zone *
kz_find_entry_for_ipv4_zone_in_luzone_hash(const struct hlist_head *hash, const u_int32_t p)
{
	struct kz_zone *i;
	struct hlist_node *n;
	hlist_for_each_entry(i, n, hash, hlist) {
		if (zone_ipv4_cmp(i, p)) {
			kz_debug("found zone; name='%s'\n", i->name);
			return i;
		}
	}
	return NULL;
}
#endif

struct kz_zone *
kz_head_zone_ipv4_lookup(const struct kz_head_z *h, const struct in_addr * const addr)
{
	int o;
	u_int32_t m, ip;

	kz_debug("addr='%pI4'\n", addr);

        ip = ntohl(addr->s_addr);
	for (o = 32, m = 0xffffffff; o >= 0; o--, m <<= 1) {
		const u_int32_t p = ip & m;
		const unsigned int v = zone_ipv4_hash_fn(p);

		if (!hlist_empty(&h->luzone.hash[o][v])) {
			struct kz_zone *i = kz_find_entry_for_ipv4_zone_in_luzone_hash(&h->luzone.hash[o][v],p);
			if(NULL != i)
				return i;
		}
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(kz_head_zone_ipv4_lookup);

/***********************************************************
 * IPv6 zone lookup
 ***********************************************************/

#ifndef KZ_USERSPACE
KZ_PROTECTED inline struct kz_lookup_ipv6_node *
ipv6_node_new(void)
{
	return kzalloc(sizeof(struct kz_lookup_ipv6_node), GFP_KERNEL);
}

KZ_PROTECTED inline void
ipv6_node_free(struct kz_lookup_ipv6_node *n)
{
	kfree(n);
}
#endif

static inline __be32
ipv6_addr_bit_set(const void *token, int bit)
{
	const __be32 *addr = token;

	return htonl(1 << ((~bit) & 0x1F)) & addr[bit >> 5];
}

struct kz_lookup_ipv6_node *
ipv6_add(struct kz_lookup_ipv6_node *root, struct in6_addr *addr, int prefix_len)
{
	struct kz_lookup_ipv6_node *n, *parent, *leaf, *intermediate;
	__be32 dir = 0;
	int prefix_match_len;

	n = root;

	do {
		/* prefix is different */
		if (prefix_len < n->prefix_len ||
		    !ipv6_prefix_equal(&n->addr, addr, n->prefix_len))
			goto insert_above;

		/* prefix is the same */
		if (prefix_len == n->prefix_len)
			return n;

		/* more bits to go */
		dir = ipv6_addr_bit_set(addr, n->prefix_len);
		parent = n;
		n = dir ? n->right : n->left;
	} while (n);

	/* add a new leaf node */
	leaf = ipv6_node_new();
	if (leaf == NULL)
		return NULL;

	leaf->prefix_len = prefix_len;
	leaf->parent = parent;
	ipv6_addr_copy(&leaf->addr, addr);

	if (dir)
		parent->right = leaf;
	else
		parent->left = leaf;

	return leaf;

insert_above:
	/* split node, since we have a new key with shorter or different prefix */
	parent = n->parent;

	prefix_match_len = __ipv6_addr_diff(addr, &n->addr, sizeof(*addr));

	if (prefix_len > prefix_match_len) {
		/*
		 *	   +----------------+
		 *	   |  intermediate  |
		 *	   +----------------+
		 *	      /	       	  \
		 * +--------------+  +--------------+
		 * |   new leaf	  |  |   old node   |
		 * +--------------+  +--------------+
		 */
		intermediate = ipv6_node_new();
		leaf = ipv6_node_new();
		if (leaf == NULL || intermediate == NULL) {
			if (leaf)
				ipv6_node_free(leaf);
			if (intermediate)
				ipv6_node_free(intermediate);
			return NULL;
		}

		intermediate->prefix_len = prefix_match_len;
		ipv6_addr_copy(&intermediate->addr, addr);

		if (dir)
			parent->right = intermediate;
		else
			parent->left = intermediate;

		leaf->prefix_len = prefix_len;
		ipv6_addr_copy(&leaf->addr, addr);

		intermediate->parent = parent;
		leaf->parent = intermediate;
		n->parent = intermediate;

		if (ipv6_addr_bit_set(&n->addr, prefix_match_len)) {
			intermediate->right = n;
			intermediate->left = leaf;
		} else {
			intermediate->right = leaf;
			intermediate->left = n;
		}
	} else {
		/* prefix_len <= prefix_match_len
		 *
		 *	 +-------------------+
		 *	 |     new leaf      |
		 *	 +-------------------+
		 *	    /  	       	  \
		 * +--------------+  +--------------+
		 * |   old node   |  |     NULL     |
		 * +--------------+  +--------------+
		 */
		leaf = ipv6_node_new();
		if (leaf == NULL)
			return NULL;

		leaf->prefix_len = prefix_len;
		leaf->parent = parent;
		ipv6_addr_copy(&leaf->addr, addr);

		if (dir)
			parent->right = leaf;
		else
			parent->left = leaf;

		if (ipv6_addr_bit_set(&n->addr, prefix_len))
			leaf->right = n;
		else
			leaf->left = n;

		n->parent = leaf;
	}

	return leaf;
}

KZ_PROTECTED struct kz_lookup_ipv6_node *
ipv6_lookup(struct kz_lookup_ipv6_node *root, const struct in6_addr *addr)
{
	struct kz_lookup_ipv6_node *n = root;
	__be32 dir;

	/* first, descend to a possibly matching node */

	for (;;) {
		struct kz_lookup_ipv6_node *next;

		dir = ipv6_addr_bit_set(addr, n->prefix_len);

		next = dir ? n->right : n->left;

		if (next) {
			n = next;
			continue;
		}

		break;
	}

	/* we're at a node that has a possibility to match: go up the
	 * tree until we find something that is matching exactly */

	while (n) {
		if (n->zone) {
			/* this is not an intermediate node, but a
			 * real one with data associated with it */
			if (ipv6_prefix_equal(&n->addr, addr, n->prefix_len))
				return n;
		}

		n = n->parent;
	}

	return NULL;
}

KZ_PROTECTED void
ipv6_destroy(struct kz_lookup_ipv6_node *node)
{
	if (node->left)
		ipv6_destroy(node->left);

	if (node->right)
		ipv6_destroy(node->right);

	ipv6_node_free(node);
}

static int
zone_ipv6_tree_add(struct kz_head_z *h, struct kz_zone *z)
{
	struct kz_lookup_ipv6_node *node;
	const unsigned int prefix_len = mask_to_size_v6(&z->mask.in6);

	kz_debug("adding zone to radix tree; name='%s', address='%pI6', mask='%pI6', prefix_len='%u'\n", z->name, &z->addr.in6, &z->mask.in6, prefix_len);

        node = ipv6_add(h->luzone.root, &z->addr.in6, prefix_len);
	if (node == NULL) {
		kz_err("error allocating node structure\n");
		return -ENOMEM;
	}

	if (node->zone != NULL) {
		kz_err("duplicate subnet detected; zone1='%s', zone2='%s'\n", z->name, node->zone->name);
		return -EEXIST;
	}

	node->zone = z;

	return 0;
}

struct kz_zone *
kz_head_zone_ipv6_lookup(const struct kz_head_z *h, const struct in6_addr * const addr)
{
	struct kz_lookup_ipv6_node *node;

	kz_debug("addr='%pI6'\n", addr);

	node = ipv6_lookup(h->luzone.root, addr);
	if (node == NULL)
		return NULL;

	/* if ipv6_lookup() returns with an intermediate node we're in
	 * big trouble, because that means that the lookup algorithm
	 * is broken */
	WARN_ON(node->zone == NULL);

	return node->zone;
}

/***********************************************************
 * Generic zones
 ***********************************************************/

/**
 * kz_head_zone_init - initialize zone lookup data structures to an empty state
 * @h: head to set up
 */
void
kz_head_zone_init(struct kz_head_z *h)
{
	unsigned int i, j;

	for (i = 0; i < 33; i++)
		for (j = 0; j < KZ_ZONE_HASH_SIZE; j++)
			INIT_HLIST_HEAD(&h->luzone.hash[i][j]);
	h->luzone.root = ipv6_node_new();
}
EXPORT_SYMBOL_GPL(kz_head_zone_init);

/**
 * kz_head_zone_build - build zone lookup data structures
 */
int
kz_head_zone_build(struct kz_head_z *h)
{
	struct kz_zone *i;
	int res;
	unsigned int index = 0;

	/* we do not get an extra ref for the lookup structure: the
	 * zone is on the linked list of the head anyway and there's
	 * no way of releasing that without the lookup structures
	 * being destroyed first */

	list_for_each_entry(i, &h->head, list) {
		/* put in hash if the zone has a range */
		if (i->flags & KZF_ZONE_HAS_RANGE) {

			switch (i->family) {
			case AF_INET:
				zone_ipv4_hash(h, i);
				break;

			case AF_INET6:
				if ((res = zone_ipv6_tree_add(h, i)) < 0)
					return res;
				break;

			default:
				BUG();
				break;
			}
		}
		/* assign bitmask index */
		i->index = index++;
	}

	if (index > KZ_ZONE_MAX) {
		kz_err("maximum number of zones exceeded; supported='%d', present='%d'\n",
		       KZ_ZONE_MAX, index);
		return -EINVAL;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(kz_head_zone_build);

void
kz_head_zone_destroy(struct kz_head_z *h)
{
	struct kz_zone *i;

	if (h->luzone.root != NULL) {
		ipv6_destroy(h->luzone.root);
		h->luzone.root = NULL;
	}

	list_for_each_entry(i, &h->head, list) {
		if (i->flags & KZF_ZONE_HAS_RANGE) {

			switch (i->family) {
			case AF_INET:
				zone_ipv4_unhash(i);
				break;
			case AF_INET6:
				/* IPv6 lookup structure has already
				 * been destroyed */
				break;
			default:
				BUG();
			}
		}
	}
}
EXPORT_SYMBOL_GPL(kz_head_zone_destroy);

/***********************************************************
 * Per-instance bind addresses
 ***********************************************************/

/**
 * bind_lookup_new() - allocate and initialize a new bind lookup structure
 */
static struct kz_bind_lookup *
bind_lookup_new(void)
{
	struct kz_bind_lookup *bind_lookup;

	bind_lookup = kzalloc(sizeof(struct kz_bind_lookup), GFP_KERNEL);
	if (bind_lookup == NULL)
		return NULL;

	INIT_LIST_HEAD(&bind_lookup->list_bind);

	return bind_lookup;
}

static void
bind_lookup_destroy(struct kz_bind_lookup *bind_lookup)
{
	struct kz_bind *pos_bind, *n_bind;

	list_for_each_entry_safe(pos_bind, n_bind, &bind_lookup->list_bind, list) {
		list_del(&pos_bind->list);
		kz_bind_destroy(pos_bind);
	}

	if (bind_lookup->binds)
		kfree(bind_lookup->binds);

	kfree(bind_lookup);
}

/**
 * bind_lookup_get_l3proto() - convert L3 protocol to lookup index
 * @l3proto: layer 3 protocol (IPv4 or IPv6)
 * Returns: enum value matching @l3proto
 */
static enum kz_bind_l3proto
bind_lookup_get_l3proto(const u8 l3proto)
{
	switch (l3proto) {
	case AF_INET:
		return KZ_BIND_L3PROTO_IPV4;
		break;
	case AF_INET6:
		return KZ_BIND_L3PROTO_IPV6;
		break;
	default:
		break;
	}

	BUG();
}

/**
 * bind_lookup_get_l4proto() - convert L4 protocol to lookup index
 * @l4proto: layer 4 protocol (TCP or UDP)
 * Returns: enum value matching @l4proto
 */
static enum kz_bind_l4proto
bind_lookup_get_l4proto(const u8 l4proto)
{
	switch (l4proto) {
	case IPPROTO_TCP:
		return KZ_BIND_L4PROTO_TCP;
		break;
	case IPPROTO_UDP:
		return KZ_BIND_L4PROTO_UDP;
		break;
	default:
		break;
	}

	BUG();
}

static void
bind_lookup_build(struct kz_bind_lookup *bind_lookup)
{
	const struct kz_bind const *bind;
	unsigned int num_binds;
	enum kz_bind_l3proto l3proto;
	enum kz_bind_l4proto l4proto;
        unsigned int filled_bind_nums[KZ_BIND_L3PROTO_COUNT][KZ_BIND_L4PROTO_COUNT] = { { 0, 0 }, { 0, 0 } };

	num_binds = 0;
	list_for_each_entry(bind, &bind_lookup->list_bind, list) {
		l3proto = bind_lookup_get_l3proto(bind->family);
		l4proto = bind_lookup_get_l4proto(bind->proto);

		bind_lookup->bind_nums[l3proto][l4proto]++;
		num_binds++;
	}

	if (num_binds == 0)
		return;

	bind_lookup->binds = (const struct kz_bind const **) kzalloc(sizeof(struct kz_bind *) * num_binds, GFP_KERNEL);
	num_binds = 0;
	for (l3proto = KZ_BIND_L3PROTO_IPV4; l3proto < KZ_BIND_L3PROTO_COUNT; l3proto++) {
		for (l4proto = KZ_BIND_L4PROTO_TCP; l4proto < KZ_BIND_L4PROTO_COUNT; l4proto++) {
			bind_lookup->binds_by_type[l3proto][l4proto] = &bind_lookup->binds[num_binds];
			num_binds += bind_lookup->bind_nums[l3proto][l4proto];
		}
	}

	list_for_each_entry(bind, &bind_lookup->list_bind, list) {
		l3proto = bind_lookup_get_l3proto(bind->family);
		l4proto = bind_lookup_get_l4proto(bind->proto);

		bind_lookup->binds_by_type[l3proto][l4proto][filled_bind_nums[l3proto][l4proto]++] = bind;
	}
}

static void
bind_lookup_free_rcu(struct rcu_head *rcu_head)
{
	struct kz_bind_lookup *bind_lookup = container_of(rcu_head, struct kz_bind_lookup, rcu);

	bind_lookup_destroy(bind_lookup);
}

static inline void
instance_bind_lookup_swap(struct kz_instance *instance, struct kz_bind_lookup *new_bind_lookup)
{
	struct kz_bind_lookup *old_bind_lookup;

	rcu_read_lock();
	old_bind_lookup = rcu_dereference(instance->bind_lookup);
	if (new_bind_lookup != old_bind_lookup) {
		rcu_assign_pointer(instance->bind_lookup, new_bind_lookup);
		call_rcu(&old_bind_lookup->rcu, bind_lookup_free_rcu);
	}
	rcu_read_unlock();
}

/* !!! must be called with the instance mutex held !!! */
void
kz_instance_remove_bind(struct kz_instance *instance, const netlink_port_t pid_to_remove, const struct kz_transaction const *tr)
{
	struct kz_bind_lookup *bind_lookup;
	const struct kz_bind const *orig_bind;
	struct kz_bind *new_bind;
	struct kz_operation *io, *po;

	bind_lookup = bind_lookup_new();

	list_for_each_entry(orig_bind, &instance->bind_lookup->list_bind, list) {
		bool skip = (!tr || (tr->flags & KZF_TRANSACTION_FLUSH_BIND)) &&
			    orig_bind->peer_pid == pid_to_remove;
		if (!skip) {
			new_bind = kz_bind_clone(orig_bind);
			list_add(&new_bind->list, &bind_lookup->list_bind);
			kz_bind_debug(new_bind, "bind from old bind list added");
		}
	}

	if (tr)
		list_for_each_entry_safe(io, po, &tr->op, list) {
			if (io->type == KZNL_OP_BIND) {
				new_bind = (struct kz_bind *) (io->data);
				list_del(&io->list);
				list_add(&new_bind->list, &bind_lookup->list_bind);
				kz_bind_debug(new_bind, "bind from transaction added");
			}
		}

	bind_lookup_build(bind_lookup);
	instance_bind_lookup_swap(instance, bind_lookup);
}
EXPORT_SYMBOL_GPL(kz_instance_remove_bind);

/* Bind lookup */

static inline unsigned int
bind_lookup_hash_v4(__be32 saddr, __be16 sport, __be32 daddr, __be16 dport)
{
	/* FIXME: seed */
	return jhash_3words(saddr, daddr, (sport << 16) + dport, 0);
}

const struct kz_bind * const
kz_instance_bind_lookup_v4(const struct kz_instance const *instance, u8 l4proto,
			__be32 saddr, __be16 sport,
			__be32 daddr, __be16 dport)
{
	unsigned int bind_num;
	unsigned int lookup_bind_num;
	enum kz_bind_l4proto bind_l4proto = bind_lookup_get_l4proto(l4proto);
	const struct kz_bind const *bind;

	kz_debug("lookup bind; l4proto='%d', saddr='%pI4', sport='%d', daddr='%pI4', dport='%d'\n", l4proto, &saddr, htons(sport), &daddr, htons(dport));

	bind_num = instance->bind_lookup->bind_nums[KZ_BIND_L3PROTO_IPV4][bind_l4proto];
	if (bind_num == 0) {
		kz_debug("no potential bind found;\n");
		return NULL;
	}

	lookup_bind_num = bind_lookup_hash_v4(saddr, sport, daddr, dport) % bind_num;
	kz_debug("potential bind found; bind_num='%d', selected_bind_num='%d'\n", bind_num, lookup_bind_num);

	bind = instance->bind_lookup->binds_by_type[KZ_BIND_L3PROTO_IPV4][bind_l4proto][lookup_bind_num];

	kz_bind_debug(bind, "bind found");

	return bind;

}
EXPORT_SYMBOL(kz_instance_bind_lookup_v4);

static inline unsigned int
bind_lookup_hash_v6(const struct in6_addr const *saddr, __be16 sport, const struct in6_addr const *daddr, __be16 dport)
{
	/* FIXME: seed */
	return jhash_3words(jhash2(saddr->s6_addr32, ARRAY_SIZE(saddr->s6_addr32), 0),
			    jhash2(daddr->s6_addr32, ARRAY_SIZE(daddr->s6_addr32), 0),
			    (sport << 16) + dport, 0);
}

const struct kz_bind * const
kz_instance_bind_lookup_v6(const struct kz_instance const *instance, u8 l4proto,
			   const struct in6_addr const *saddr, __be16 sport,
			   const struct in6_addr const *daddr, __be16 dport)
{
	unsigned int bind_num;
	unsigned int lookup_bind_num;
	enum kz_bind_l4proto bind_l4proto = bind_lookup_get_l4proto(l4proto);
	const struct kz_bind const *bind;

	kz_debug("lookup bind; l4proto='%d', saddr='%pI6', sport='%d', daddr='%pI6', dport='%d'\n", l4proto, saddr, htons(sport), daddr, htons(dport));

	bind_num = instance->bind_lookup->bind_nums[KZ_BIND_L3PROTO_IPV6][bind_l4proto];
	if (bind_num == 0) {
		kz_debug("no potential bind found;\n");
		return NULL;
	}

	lookup_bind_num = bind_lookup_hash_v6(saddr, sport, daddr, dport) % bind_num;
	kz_debug("potential bind found; bind_num='%d', selected_bind_num='%d'\n", bind_num, lookup_bind_num);

	bind = instance->bind_lookup->binds_by_type[KZ_BIND_L3PROTO_IPV6][bind_l4proto][lookup_bind_num];

	kz_bind_debug(bind, "bind found");

	return bind;
}
EXPORT_SYMBOL_GPL(kz_instance_bind_lookup_v6);

/***********************************************************
 * NAT rule lookup
 ***********************************************************/

/* FIXME: this is _heavily_ dependent on TCP and UDP port numbers
 * being mapped to the same offset in the ip_nat_range structure */
static inline int
nat_in_range(const NAT_RANGE_TYPE *r,
	 const __be32 addr, const __be16 port,
	 const u_int8_t proto)
{
	/* log messages: the IP addresses are in host-endian format due to usage of "<" and ">" relations */
	kz_debug("comparing range; flags='%x', start_ip='%pI4', end_ip='%pI4', start_port='%u', end_port='%u'\n",
		 r->flags,
	         kz_nat_range_get_min_ip(r),
	         kz_nat_range_get_max_ip(r),
	         ntohs(*kz_nat_range_get_min_port(r)),
	         ntohs(*kz_nat_range_get_max_port(r)));
	kz_debug("with packet; proto='%d', ip='%pI4', port='%u'\n",
		 proto, &addr, ntohs(port));

	if ((proto != IPPROTO_TCP) && (proto != IPPROTO_UDP))
		return 0;

	if (r->flags & IP_NAT_RANGE_MAP_IPS) {
		if ((*kz_nat_range_get_min_ip(r) && ntohl(addr) < ntohl(*kz_nat_range_get_min_ip(r))) ||
		    (*kz_nat_range_get_max_ip(r) && ntohl(addr) > ntohl(*kz_nat_range_get_max_ip(r))))
			return 0;
	}

	if (r->flags & IP_NAT_RANGE_PROTO_SPECIFIED) {
		if ((*kz_nat_range_get_min_port(r) && ntohs(port) < ntohs(*kz_nat_range_get_min_port(r))) ||
		    (*kz_nat_range_get_max_port(r) && ntohs(port) > ntohs(*kz_nat_range_get_max_port(r))))
			return 0;
	}

	kz_debug("match\n");

	return 1;
}

const NAT_RANGE_TYPE *
kz_service_nat_lookup(const struct list_head * const head,
		      const __be32 saddr, const __be32 daddr,
		      const __be16 sport, const __be16 dport,
		  const u_int8_t proto)
{
	struct kz_service_nat_entry *i;

	kz_debug("proto='%u', src='%pI4:%u', dst='%pI4:%u'\n",
		 proto, &saddr, ntohs(sport), &daddr, ntohs(dport));

	list_for_each_entry(i, head, list) {
		/* source range _must_ match, destination either matches or
		 * the destination range is empty in the rule */
		if (nat_in_range(&i->src, saddr, sport, proto) &&
		    (((*kz_nat_range_get_min_ip(&i->dst) == 0) && (*kz_nat_range_get_max_ip(&i->dst) == 0)) ||
		    nat_in_range(&i->dst, daddr, dport, proto))) {
			return &i->map;
		}
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(kz_service_nat_lookup);

/***********************************************************
 * Session lookup
 ***********************************************************/

/* NOTE: ports are passed, but legal only if protocol have them! */
void
kz_lookup_session(const struct kz_config *cfg,
		  const struct kz_reqids *reqids,
		  const struct net_device *in,
		  u_int8_t l3proto,
		  const union nf_inet_addr * const saddr, const union nf_inet_addr * const daddr,
		  u_int8_t l4proto, u_int16_t sport, u_int16_t dport,
		  struct kz_dispatcher **dispatcher,
		  struct kz_zone **clientzone, struct kz_zone **serverzone,
		  struct kz_service **service, int reply)
{
	struct kz_dispatcher *dpt = NULL;
	struct kz_zone *czone = NULL, *szone = NULL;
	struct kz_service *svc = NULL;
	const struct kz_head_z * const zones = &cfg->zones;

	switch (l3proto) {
	case NFPROTO_IPV4:
		kz_debug("in='%s', l3proto='%u', l4proto='%u', src='%pI4:%u', dst='%pI4:%u'\n",
			 in ? in->name : "(NULL)", l3proto, l4proto, &saddr->in, sport, &daddr->in, dport);
		break;
	case NFPROTO_IPV6:
		kz_debug("in='%s', l3proto='%u', l4proto='%u', src='%pI6:%u', dst='%pI6:%u'\n",
			 in ? in->name : "(NULL)", l3proto, l4proto, &saddr->in6, sport, &daddr->in6, dport);
		break;
	default:
		BUG();
		break;
	}

	/* look up src/dst zone */
	switch (l3proto) {
	case NFPROTO_IPV4:
		czone = kz_head_zone_ipv4_lookup(zones, reply ? &daddr->in : &saddr->in);
		szone = kz_head_zone_ipv4_lookup(zones, reply ? &saddr->in : &daddr->in);
		break;
	case NFPROTO_IPV6:
		czone = kz_head_zone_ipv6_lookup(zones, reply ? &daddr->in6 : &saddr->in6);
		szone = kz_head_zone_ipv6_lookup(zones, reply ? &saddr->in6 : &daddr->in6);
		break;
	default:
		BUG();
		break;
	}

	if (czone != NULL) {
		kz_debug("found client zone; name='%s'\n", czone->name);
	}
	if (szone != NULL) {
		kz_debug("found server zone; name='%s'\n", szone->name);
	}

	/* evaluate n-dimensional rules */
	svc = kz_ndim_lookup(cfg, reqids, in, l3proto, saddr, daddr, l4proto, sport, dport, czone, szone, &dpt);

	*dispatcher = dpt;
	*clientzone = czone;
	*serverzone = szone;
	*service = svc;
}
EXPORT_SYMBOL_GPL(kz_lookup_session);
