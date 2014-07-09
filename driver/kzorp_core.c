/*
 * KZorp core
 *
 * Copyright (C) 2006-2010, BalaBit IT Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

/* TODO:
 *   - service NAT list should be stored in an array instead of a linked list
 *   - do we need the _add/_remove functions?
 */

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/workqueue.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif

#include <net/ip.h>
#include <net/ipv6.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_acct.h>

#include "kzorp.h"
#include "kzorp_netlink.h"

static const char *const kz_log_null = "(NULL)";

#define LOG_RATELIMIT_MSG_COST 50

extern int sysctl_kzorp_log_ratelimit_msg_cost;
extern int sysctl_kzorp_log_ratelimit_burst;

/***********************************************************
 * Instances
 ***********************************************************/

DEFINE_MUTEX(kz_instance_mutex);
struct list_head kz_instances;


/* instance 0 is the "global" instance, so it must be the first instance created */
static unsigned int instance_id_cnt = 0;

static void __init
instance_init(void)
{
	INIT_LIST_HEAD(&kz_instances);
}

static void __exit 
instance_cleanup(void)
{
	struct kz_instance *i, *s;
	list_for_each_entry_safe(i, s, &kz_instances, list) {
		list_del(&i->list);
		kfree(i);
	}
}

/* !!! must be called with the instance mutex held !!! */
struct kz_instance *
kz_instance_lookup_nocheck(const char *name)
{
	struct kz_instance *i;

	kz_debug("name='%s'\n", name);

	list_for_each_entry(i, &kz_instances, list) {
		if (strcmp(i->name, name) == 0)
			return i;
	}

	return NULL;
}

/* !!! must be called with the instance mutex held !!! */
struct kz_instance *
kz_instance_lookup(const char *name)
{
	struct kz_instance *i;

	kz_debug("name='%s'", name);

	list_for_each_entry(i, &kz_instances, list) {
		if (!(i->flags & KZF_INSTANCE_DELETED) &&
		    (strcmp(i->name, name) == 0))
			return i;
	}

	return NULL;
}

/* !!! must be called with the instance mutex held !!! */
struct kz_instance *
kz_instance_lookup_id(const unsigned int id)
{
	struct kz_instance *i;

	kz_debug("id='%u'\n", id);

	list_for_each_entry(i, &kz_instances, list) {
		if (!(i->flags & KZF_INSTANCE_DELETED) &&
		    (i->id == id))
			return i;
	}

	return NULL;
}

/***********************************************************
 * Per-instance bind address lists
 ***********************************************************/

struct kz_bind *
kz_bind_new(void)
{
	struct kz_bind *bind;

	bind = kzalloc(sizeof(struct kz_bind), GFP_KERNEL);
	if (bind == NULL)
		return NULL;

	INIT_LIST_HEAD(&bind->list);

	return bind;
}

struct kz_bind *
kz_bind_clone(const struct kz_bind const *_bind)
{
	struct kz_bind *bind;

	bind = kz_bind_new();
	if (bind == NULL)
		return NULL;

	bind->peer_pid = _bind->peer_pid;
	bind->family = _bind->family;
	bind->proto = _bind->proto;
	bind->addr = _bind->addr;
	bind->port = _bind->port;

	return bind;
}

void
kz_bind_destroy(struct kz_bind *bind)
{
	kfree(bind);
}

/* !!! must be called with the instance mutex held !!! */
struct kz_instance *
kz_instance_create(const char *name, const unsigned int len, const netlink_port_t peer_pid)
{
	struct kz_instance *i;

	kz_debug("name='%s', pid='%d'\n", name, peer_pid);

	/* check if we already have a deleted instance with this name */
	i = kz_instance_lookup_nocheck(name);
	if (i != NULL) {
		/* caller should check for existing instances */
		BUG_ON(!(i->flags & KZF_INSTANCE_DELETED));
		i->flags &= ~KZF_INSTANCE_DELETED;
		return i;
	}

	/* limit check */
	if (instance_id_cnt >= INSTANCE_MAX_NUM)
		return NULL;

	/* allocate memory for the structure + name + terminating 0 */
	i = kzalloc(sizeof(*i) + len + 1, GFP_KERNEL);
	if (i == NULL)
		return NULL;

	i->id = instance_id_cnt++;
	i->peer_pid = peer_pid;
	/* terminating zero comes from kzalloc() */
	memcpy(i->name, name, len);
	i->bind_lookup = kzalloc(sizeof(struct kz_bind_lookup), GFP_KERNEL);
	INIT_LIST_HEAD(&i->bind_lookup->list_bind);
	list_add(&i->list, &kz_instances);

	kz_debug("instance created; name='%s', id='%d'\n", name, i->id);

	return i;
}

/* !!! must be called with the instance mutex held !!! */
void
kz_instance_delete(struct kz_instance * const i)
{
	kz_debug("name='%s'\n", i->name);

	i->flags |= KZF_INSTANCE_DELETED;
}

/***********************************************************
 * Utility functions
 ***********************************************************/

char *
kz_name_dup(const char * const name)
{
	char *n;
	unsigned int len;

	if (name == NULL)
		return NULL;

	len = strlen(name);
	n = kmalloc(len + 1, GFP_KERNEL);
	if (n == NULL)
		return NULL;

	memcpy(n, name, len);
	n[len] = '\0';

	return n;
}

/***********************************************************
 * Config
 ***********************************************************/

/* content shall stay semantically 'empty', properly inited for work,
   only generation may change after module init!  */
static struct kz_config static_config =
{
	.zones = {.head = LIST_HEAD_INIT(static_config.zones.head)}, 
	.services = {.head = LIST_HEAD_INIT(static_config.services.head)}, 
	.dispatchers = {.head = LIST_HEAD_INIT(static_config.dispatchers.head)}, 
	.generation = 1,
	.cookie = 0UL
};

static void
kz_config_init(struct kz_config *cfg)
{
	cfg->cookie = 0;
	cfg->generation = 0;
	INIT_LIST_HEAD(&cfg->zones.head);
	INIT_LIST_HEAD(&cfg->services.head);
	INIT_LIST_HEAD(&cfg->dispatchers.head);
	kz_head_zone_init(&cfg->zones);
	kz_head_dispatcher_init(&cfg->dispatchers);
}

static int __init
static_cfg_init(void)
{
	int res = 0;
	kz_config_init(&static_config);
	static_config.generation = 1;

	res = kz_head_zone_build(&static_config.zones);
	if (res == 0)
		res = kz_head_dispatcher_build(&static_config.dispatchers);
	return res;
}

static void __exit
static_cfg_cleanup(void)
{
	kz_head_dispatcher_destroy(&static_config.dispatchers);
	kz_head_zone_destroy(&static_config.zones);
}

struct kz_config *kz_config_rcu = &static_config;

struct kz_config *kz_config_new(void)
{
	struct kz_config *cfg = kzalloc(sizeof(struct kz_config), GFP_KERNEL);
	if (cfg)
		kz_config_init(cfg);
	return cfg;
}

void kz_config_destroy(struct kz_config * cfg)
{
	if (cfg != NULL) {
		kz_head_destroy_zone(&cfg->zones);
		kz_head_destroy_service(&cfg->services);
		kz_head_destroy_dispatcher(&cfg->dispatchers);
		kfree(cfg);
	}
}

static void
kz_config_list_free_rcu(struct rcu_head *rcu_head)
{
	struct kz_config *cfg = container_of(rcu_head, struct kz_config, rcu);
	if (cfg != &static_config)
		kz_config_destroy(cfg);
}

void
kz_config_swap(struct kz_config * new_cfg)
{
	struct kz_config * old_cfg;
	rcu_read_lock();
	old_cfg = rcu_dereference(kz_config_rcu);
	if (new_cfg != old_cfg) {
		new_cfg->generation = old_cfg->generation + 1;
		rcu_assign_pointer(kz_config_rcu, new_cfg);
		if (old_cfg != &static_config)
			call_rcu(&old_cfg->rcu, kz_config_list_free_rcu);
	}
	rcu_read_unlock();
}

/***********************************************************
 * Lookup
 ***********************************************************/


void nfct_kzorp_lookup_rcu(struct nf_conntrack_kzorp * kzorp,
	enum ip_conntrack_info ctinfo,
	const struct sk_buff *skb,
	const struct net_device * const in,
	const u8 l3proto,
	const struct kz_config **p_cfg)
{
	struct kz_zone *czone = NULL;
	struct kz_zone *szone = NULL;
	struct kz_dispatcher *dpt = NULL;
	struct kz_service *svc = NULL;
	struct {
		u16 src;
		u16 dst;
	} __attribute__((packed)) *ports, _ports = { .src = 0, .dst = 0 };
	const struct kz_config * loc_cfg;
	u8 l4proto;
	union nf_inet_addr *saddr, *daddr;
        struct kz_reqids reqids;
	int sp_idx;

	ports = &_ports;

	if (p_cfg == NULL)
		p_cfg = &loc_cfg;

	*p_cfg = rcu_dereference(kz_config_rcu);

	BUG_ON(*p_cfg == NULL);
	kzorp->generation = (*p_cfg)->generation;
	
	switch (l3proto) {
	case NFPROTO_IPV4:
	{
		const struct iphdr * const iph = ip_hdr(skb);

		l4proto = iph->protocol;
		saddr = (union nf_inet_addr *) &iph->saddr;
		daddr = (union nf_inet_addr *) &iph->daddr;

		if ((l4proto == IPPROTO_TCP) || (l4proto == IPPROTO_UDP)) {
			ports = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(_ports), &_ports);
			if (unlikely(ports == NULL))
				goto done;
		}
		kz_debug("kzorp lookup for packet: protocol='%u', src='%pI4:%u', dst='%pI4:%u'\n",
			 iph->protocol, &iph->saddr, ntohs(ports->src), &iph->daddr, ntohs(ports->dst));
	}
		break;
	case NFPROTO_IPV6:
	{
		const struct ipv6hdr * const iph = ipv6_hdr(skb);
		int thoff;
		u8 tproto = iph->nexthdr;

		/* find transport header */
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0) )
		__be16 frag_offp;
		thoff = ipv6_skip_exthdr(skb, sizeof(*iph), &tproto, &frag_offp);
#else
		thoff = ipv6_skip_exthdr(skb, sizeof(*iph), &tproto);
#endif
		if (unlikely(thoff < 0))
			goto done;

		l4proto = tproto;
		saddr = (union nf_inet_addr *) &iph->saddr;
		daddr = (union nf_inet_addr *) &iph->daddr;

		if ((l4proto == IPPROTO_TCP) || (l4proto == IPPROTO_UDP)) {
			/* get info from transport header */
			ports = skb_header_pointer(skb, thoff, sizeof(_ports), &_ports);
			if (unlikely(ports == NULL))
				goto done;
		}

		kz_debug("kzorp lookup for packet: protocol='%u', src='%pI6:%u', dst='%pI6:%u'\n", l4proto,
			 &iph->saddr, ntohs(ports->src), &iph->daddr, ntohs(ports->dst));
	}
		break;
	default:
		BUG();
		break;
	}

	/* copy IPSEC reqids from secpath to our own structure */
	if (skb->sp != NULL) {
		reqids.len = skb->sp->len;
		for (sp_idx = 0; sp_idx  < reqids.len; sp_idx++)
			reqids.vec[sp_idx] = skb->sp->xvec[sp_idx]->props.reqid;
	} else {
		reqids.len = 0;
	}

	kz_lookup_session(*p_cfg, &reqids, in, l3proto,
			  saddr, daddr,
			  l4proto, ntohs(ports->src), ntohs(ports->dst),
			  &dpt, &czone, &szone, &svc,
			  (ctinfo >= IP_CT_IS_REPLY));

done:
#define REPLACE_PTR(name, type) \
	if (kzorp->name != name) { \
		if (kzorp->name) \
			kz_##type##_put(kzorp->name); \
		kzorp->name = name ? kz_##type##_get(name) : NULL; \
	}
	
	REPLACE_PTR(czone, zone);
	REPLACE_PTR(szone, zone);
	REPLACE_PTR(dpt, dispatcher);
	REPLACE_PTR(svc, service);

#undef REPLACE_PTR

	kz_debug("kzorp lookup result; dpt='%s', client_zone='%s', server_zone='%s', svc='%s'\n",
		 kzorp->dpt ? kzorp->dpt->name : kz_log_null,
		 kzorp->czone ? kzorp->czone->name : kz_log_null,
		 kzorp->szone ? kzorp->szone->name : kz_log_null,
		 kzorp->svc ? kzorp->svc->name : kz_log_null);

	return;
}
EXPORT_SYMBOL_GPL(nfct_kzorp_lookup_rcu);


const struct nf_conntrack_kzorp * nfct_kzorp_cached_lookup_rcu(
	struct nf_conn *ct,
	enum ip_conntrack_info ctinfo,
	const struct sk_buff *skb,
	const struct net_device * const in,
	const u8 l3proto,
	const struct kz_config **p_cfg)
{
	struct nf_conntrack_kzorp *kzorp;
	const struct kz_config * loc_cfg;

	if (p_cfg == NULL)
		p_cfg = &loc_cfg;

	*p_cfg = rcu_dereference(kz_config_rcu);

	kzorp = kz_extension_find(ct);

	if (!kzorp) { /* no kzorp yet, add a fresh one */
		/* no kzorp extension, we need to try and add it only
		 * if the conntrack is not yet confirmed */
		if (unlikely(nf_ct_is_confirmed(ct))) {
			switch (l3proto) {
			case NFPROTO_IPV4:
			{
				const struct iphdr * const iph = ip_hdr(skb);
				kz_debug("can't add kzorp to ct for packet: src='%pI4', dst='%pI4'\n",
					 &iph->saddr, &iph->daddr);
			}
				break;
			case NFPROTO_IPV6:
			{
				const struct ipv6hdr * const iph = ipv6_hdr(skb);
				kz_debug("can't add kzorp to ct for packet: src='%pI6', dst='%pI6'\n",
					 &iph->saddr, &iph->daddr);
			}
				break;
			default:
				BUG();
			}
			return NULL;
		}

		kzorp = kz_extension_create(ct);
		if (unlikely(!kzorp)) {
			kz_debug("allocation failed creating kzorp\n");
			return NULL;
		}
		/* implicit:  kzorp->sid = 0; */
		nfct_kzorp_lookup_rcu(kzorp, ctinfo, skb, in, l3proto, p_cfg);
		return kzorp;
	}
	
	/* use existing kzorp, make sure it is okay */

	if (unlikely(!kz_generation_valid(*p_cfg, kzorp->generation))) {
		nfct_kzorp_lookup_rcu(kzorp, ctinfo, skb, in, l3proto, p_cfg);
	}

	return kzorp;
}
EXPORT_SYMBOL_GPL(nfct_kzorp_cached_lookup_rcu);

/***********************************************************
 * Zones
 ***********************************************************/

#define ZONE_SERVICE_ALLOC_THRESHOLD 8
struct kz_zone *
kz_zone_new(void)
{
	struct kz_zone *zone;

	zone = kzalloc(sizeof(struct kz_zone), GFP_KERNEL);
	if (zone == NULL)
		return NULL;

	atomic_set(&zone->refcnt, 1);
	zone->depth = 1;

	return zone;
}

void
kz_zone_destroy(struct kz_zone *zone)
{
       if (zone->admin_parent)
	       kz_zone_put(zone->admin_parent);
       /* unique_name may be the same pointer as name! */
       if (zone->unique_name != zone->name)
	       kfree(zone->unique_name);
       if (zone->name)
	       kfree(zone->name);
       kfree(zone);
}
EXPORT_SYMBOL_GPL(kz_zone_destroy);

struct kz_zone *
__kz_zone_lookup_name(const struct list_head * const head, const char *name)
{
	struct kz_zone *i;

	BUG_ON(!name);

	list_for_each_entry(i, head, list) {
		if (strcmp(i->unique_name, name) == 0)
			return i;
	}

	return NULL;
}

struct kz_zone *
kz_zone_lookup_name(const struct kz_config *cfg, const char *name)
{
	return __kz_zone_lookup_name(&cfg->zones.head, name);
}

struct kz_zone *
kz_zone_clone(const struct kz_zone * const o)
{
	struct kz_zone *zone;


	zone = kz_zone_new();
	if (zone == NULL)
		return NULL;

	zone->flags = o->flags;
	zone->family = o->family;
	zone->addr = o->addr;
	zone->mask = o->mask;
	zone->depth = o->depth;

	zone->name = kz_name_dup(o->name);
	if (zone->name == NULL)
		goto error_put;

	if (o->name == o->unique_name) {
		zone->unique_name = zone->name;
	} else {
		/* unique name is different */
		zone->unique_name = kz_name_dup(o->unique_name);
		if (zone->unique_name == NULL)
			goto error_put;
	}

	if (o->admin_parent != NULL)
		zone->admin_parent = kz_zone_get(o->admin_parent);

	return zone;

error_put:
	kz_zone_put(zone);

	return NULL;
}

void
kz_head_destroy_zone(struct kz_head_z *head)
{
	struct kz_zone *i, *p;

	/* destroy lookup data structures */
	kz_head_zone_destroy(head);

	list_for_each_entry_safe(i, p, &head->head, list) {
		list_del(&i->list);
		kz_zone_put(i);
	}
}

/***********************************************************
 * Services
 ***********************************************************/

static atomic_t service_id_cnt;

struct kz_service *
kz_service_new(void)
{
	struct kz_service *service;

	service = kzalloc(sizeof(struct kz_service), GFP_KERNEL);
	if (service == NULL)
		return NULL;

	atomic_set(&service->refcnt, 1);
	atomic_set(&service->session_cnt, 0);

	service->id = atomic_inc_return(&service_id_cnt);

	INIT_LIST_HEAD(&service->a.fwd.snat);
	INIT_LIST_HEAD(&service->a.fwd.dnat);

	return service;
}

void
kz_service_destroy(struct kz_service *service)
{
	struct kz_service_nat_entry *i, *s;

	if (service->name)
		kfree(service->name);

	if (service->type == KZ_SERVICE_FORWARD) {
		/* free NAT entries */
		list_for_each_entry_safe(i, s, &service->a.fwd.snat, list) {
			list_del(&i->list);
			kfree(i);
		}
		list_for_each_entry_safe(i, s, &service->a.fwd.dnat, list) {
			list_del(&i->list);
			kfree(i);
		}
	}

	kfree(service);
}

struct kz_service *
__kz_service_lookup_name(const struct list_head * const head, const char *name)
{
	struct kz_service *i;

	BUG_ON(!name);

	list_for_each_entry(i, head, list) {
		if (strcmp(i->name, name) == 0)
			return i;
	}

	return NULL;
}

struct kz_service *
kz_service_lookup_name(const struct kz_config *cfg, const char *name)
{
	return __kz_service_lookup_name(&cfg->services.head, name);
}
EXPORT_SYMBOL_GPL(kz_service_lookup_name);

int
kz_service_add_nat_entry(struct list_head *head, NAT_RANGE_TYPE *src,
			 NAT_RANGE_TYPE *dst, NAT_RANGE_TYPE *map)
{
	struct kz_service_nat_entry *entry;

	BUG_ON(!src);
	BUG_ON(!map);

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (entry == NULL)
		return -ENOMEM;

	entry->src = *src;
	if (dst != NULL)
		entry->dst = *dst;
	entry->map = *map;

	list_add_tail(&entry->list, head);

	return 0;
}

static int
service_clone_nat_list(const struct list_head * const src, struct list_head *dst)
{
	struct kz_service_nat_entry *i;
	int res = 0;

	list_for_each_entry(i, src, list) {
		res = kz_service_add_nat_entry(dst, &i->src,
					    *kz_nat_range_get_min_ip(&i->dst) ? &i->dst : NULL,
					    &i->map);
		if (res < 0)
			break;
	}

	return res;
}

struct kz_service *
kz_service_clone(const struct kz_service * const o)
{
	struct kz_service *svc;

	svc = kz_service_new();
	if (svc == NULL)
		return NULL;

	svc->instance_id = o->instance_id;
	svc->flags = o->flags;
	svc->type = o->type;
	svc->a = o->a;
	svc->name = kz_name_dup(o->name);
	if (svc->name == NULL)
		goto error_put;
	if (svc->type == KZ_SERVICE_FORWARD) {
		INIT_LIST_HEAD(&svc->a.fwd.snat);
		if (service_clone_nat_list(&o->a.fwd.snat, &svc->a.fwd.snat) < 0)
			goto error_put;
		INIT_LIST_HEAD(&svc->a.fwd.dnat);
		if (service_clone_nat_list(&o->a.fwd.dnat, &svc->a.fwd.dnat) < 0)
			goto error_put;
	}

	return svc;

error_put:
	kz_service_put(svc);

	return NULL;
}

int
kz_service_lock(struct kz_service * const service)
{
	/* lock service session counter */
	set_bit(KZ_SERVICE_CNT_LOCKED_BIT, (unsigned long *)&service->flags);
	return atomic_read(&service->session_cnt);
}

void
kz_service_unlock(struct kz_service * const service)
{
	clear_bit(KZ_SERVICE_CNT_LOCKED_BIT, (unsigned long *)&service->flags);
}

void
kz_head_destroy_service(struct kz_head_s *head)
{
	struct kz_service *i, *p;

	list_for_each_entry_safe(i, p, &head->head, list) {
		list_del(&i->list);
		kz_service_put(i);
	}
}

/***********************************************************
 * Dispatchers
 ***********************************************************/

static struct workqueue_struct *vfree_queue;

#define DISPATCHER_CSS_ALLOC_THRESHOLD 8

static int __init
dpt_init(void)
{
	vfree_queue = create_workqueue("kzorp_vfree_queue");
	if (vfree_queue == NULL) {
		return -ENOMEM;
	}
	return 0;
}

static void
dpt_cleanup(void)
{
	flush_workqueue(vfree_queue);
	destroy_workqueue(vfree_queue);
}

void*
kz_big_alloc(size_t size, enum KZ_ALLOC_TYPE *alloc_type)
{
	void * ret = kzalloc(size, GFP_KERNEL | __GFP_NOWARN);
	*alloc_type = KZALLOC;

	if (!ret) {
		ret = __vmalloc(size, GFP_KERNEL | __GFP_ZERO, PAGE_KERNEL);
		*alloc_type = VMALLOC;
	}

	return ret;
}

static void
vfree_wq_function(struct work_struct *work)
{
	const kz_vfree_work_t *w = (kz_vfree_work_t *) work;

	vfree(w->p);
	kfree(w);
}

void
kz_big_free(void *ptr, enum KZ_ALLOC_TYPE alloc_type)
{
	switch (alloc_type) {
	case KZALLOC: {
			kzfree(ptr);
			break;
		}
	case VMALLOC: {
			int res;
			kz_vfree_work_t *w = kzalloc(sizeof(kz_vfree_work_t), GFP_KERNEL);
			INIT_WORK((struct work_struct *) w, vfree_wq_function);
			w->p = ptr;
			res = queue_work(vfree_queue, (struct work_struct *)w);
			BUG_ON(!res);
			break;
		}
	}
}

/**
 * kz_dispatcher_alloc_rule_array - allocate rule array for N-dim rules
 * @dispatcher: the dispatcher to allocate the array for
 * @alloc_rules: the number of rules to allocate memory for
 *
 * This function tries to allocate the rule array using kzalloc(). If
 * that fails (because we're over the maximum memory allocatable by
 * the slab allocator) we retry the allocation using vmalloc().
 *
 * kz_dispatcher_alloc_rule_array() is always called in user
 * context. For freeing the vmalloc()-ed memory block we have to
 * allocate a work_queue structure, too, so that we don't have to
 * allocate memory when we're trying to free the array.
 *
 * Returns: 0 on success,
 *          -ENOMEM if memory allocation fails
 */
int
kz_dispatcher_alloc_rule_array(struct kz_dispatcher *dispatcher, size_t alloc_rules)
{
	const size_t rule_size = sizeof(struct kz_dispatcher_n_dimension_rule) * alloc_rules;

	dispatcher->rule = kz_big_alloc(rule_size, &dispatcher->rule_allocator);

	dispatcher->num_rule = 0;
	dispatcher->alloc_rule = alloc_rules;

	return 0;
}

/**
 * kz_dispatcher_free_rule_array - free rule array in dispatcher structure
 * @dispatcher: dispatcher to clean up
 *
 * Frees the rule array in the dispatcher structure. This is tricky
 * because the array may have been allocated using vmalloc() and in
 * that case we have to defer vfree()-ing the memory to a work queue
 * thread (so that it happens in user context).
 */
static void
kz_dispatcher_free_rule_array(struct kz_dispatcher *dispatcher)
{
	if (dispatcher->rule != NULL) {
		kz_big_free(dispatcher->rule, dispatcher->rule_allocator);
	}

	dispatcher->num_rule = dispatcher->alloc_rule = 0;
	dispatcher->rule = NULL;
}

struct kz_dispatcher *
kz_dispatcher_new(void)
{
	struct kz_dispatcher *dispatcher;

	dispatcher = kzalloc(sizeof(struct kz_dispatcher), GFP_KERNEL);
	if (dispatcher == NULL)
		return NULL;

	atomic_set(&dispatcher->refcnt, 1);

	return dispatcher;
}

static void
kz_rule_destroy(struct kz_dispatcher_n_dimension_rule *rule)
{
	int j;

	if (rule == NULL)
		return;

	for (j = 0; j < rule->num_src_zone; j++)
		kz_zone_put(rule->src_zone[j]);
	for (j = 0; j < rule->num_dst_zone; j++)
		kz_zone_put(rule->dst_zone[j]);

	kz_service_put(rule->service);

	kfree(rule->src_in_subnet);
	kfree(rule->dst_in_subnet);
	kfree(rule->src_in6_subnet);
	kfree(rule->dst_in6_subnet);
	kfree(rule->ifname);
	kfree(rule->ifgroup);
	kfree(rule->src_port);
	kfree(rule->dst_port);
	kfree(rule->src_zone);
	kfree(rule->dst_zone);
	kfree(rule->proto);
	kfree(rule->dst_ifname);
	kfree(rule->dst_ifgroup);
	kfree(rule->reqid);

	memset(rule, 0, sizeof(*rule));
}

void
kz_dispatcher_destroy(struct kz_dispatcher *dispatcher)
{
	int i;

	if (dispatcher->name)
		kfree(dispatcher->name);

	if (dispatcher->rule != NULL) {
		/* drop rule references */
		for (i = 0; i < dispatcher->num_rule; i++)
			kz_rule_destroy(&dispatcher->rule[i]);

		kz_dispatcher_free_rule_array(dispatcher);
	}

	kfree(dispatcher);
}

struct kz_dispatcher *
kz_dispatcher_lookup_name(const struct kz_config *cfg, const char *name)
{
	struct kz_dispatcher *i;

	BUG_ON(!name);

	list_for_each_entry(i, &cfg->dispatchers.head, list) {
		if (strcmp(i->name, name) == 0)
			return i;
	}

	return NULL;
}

#define kz_alloc_rule_dimension(dim_name, dst_name, src_name, error_label) \
	if (src_name->alloc_##dim_name) { \
		dst_name->dim_name = kzalloc(sizeof(*dst_name->dim_name) * src_name->alloc_##dim_name, GFP_KERNEL); \
		if (dst_name->dim_name == NULL) { \
			res = -ENOMEM; \
			goto error_label; \
		} \
	} else { \
		dst_name->dim_name = NULL; \
	} \
	dst_name->alloc_##dim_name = src_name->alloc_##dim_name;

int
kz_dispatcher_add_rule(struct kz_dispatcher *d, struct kz_service *service,
		       const struct kz_dispatcher_n_dimension_rule * const rule_params)
{
	int res = 0;
	struct kz_dispatcher_n_dimension_rule *rule = NULL;
	int64_t last_id = -1L;

	if (d->num_rule + 1 > d->alloc_rule) {
		kz_err("each rule has already been added to this dispatcher; num_rule='%d'\n",
		       d->alloc_rule);
		res = -EINVAL;
		goto error;
	}

	/* check that the ID of the rule to be added is larger than
	 * the ID of the last rule */
	if (d->num_rule > 0)
		last_id = d->rule[d->num_rule - 1].id;

	if (rule_params->id <= last_id) {
		kz_err("rule id is not larger than the id of the last rule; id='%u', last_id='%lld'\n", rule_params->id, last_id);
		res = -EINVAL;
		goto error;
	}

	rule = &d->rule[d->num_rule];
	rule->id = rule_params->id;
	rule->service = kz_service_get(service);
	rule->dispatcher = d;

	kz_alloc_rule_dimension(src_in_subnet, rule, rule_params, error_free_dimensions);
	kz_alloc_rule_dimension(dst_in_subnet, rule, rule_params, error_free_dimensions);
	kz_alloc_rule_dimension(src_in6_subnet, rule, rule_params, error_free_dimensions);
	kz_alloc_rule_dimension(dst_in6_subnet, rule, rule_params, error_free_dimensions);
	kz_alloc_rule_dimension(ifname, rule, rule_params, error_free_dimensions);
	kz_alloc_rule_dimension(ifgroup, rule, rule_params, error_free_dimensions);
	kz_alloc_rule_dimension(src_port, rule, rule_params, error_free_dimensions);
	kz_alloc_rule_dimension(dst_port, rule, rule_params, error_free_dimensions);
	kz_alloc_rule_dimension(src_zone, rule, rule_params, error_free_dimensions);
	kz_alloc_rule_dimension(dst_zone, rule, rule_params, error_free_dimensions);
	kz_alloc_rule_dimension(proto, rule, rule_params, error_free_dimensions);
	kz_alloc_rule_dimension(dst_ifname, rule, rule_params, error_free_dimensions);
	kz_alloc_rule_dimension(dst_ifgroup, rule, rule_params, error_free_dimensions);
	kz_alloc_rule_dimension(reqid, rule, rule_params, error_free_dimensions);

	d->num_rule++;

	return 0;

error_free_dimensions:
	kz_rule_destroy(rule);

error:
	return res;
}

#define kz_dispatcher_append_rule_entry(entry_name)			\
	if (rule_entry_params->has_##entry_name) {			\
		if (rule->num_##entry_name + 1 > rule->alloc_##entry_name) { \
			kz_err("each " #entry_name " has already been added to the rule; alloc_" #entry_name "='%d'", \
			       rule->num_##entry_name);			\
			res = -ENOMEM;					\
			goto error;					\
		}							\
		rule->entry_name[rule->num_##entry_name] = rule_entry_params->entry_name; \
	}

#define kz_dispatcher_append_rule_entry_portrange(entry_name)		\
	if (rule_entry_params->has_##entry_name) {			\
		if (rule->num_##entry_name + 1 > rule->alloc_##entry_name) { \
			kz_err("each " #entry_name " has already been added to the rule; alloc_" #entry_name "='%d'", \
			       rule->num_##entry_name);			\
			res = -ENOMEM;					\
			goto error;					\
		}							\
		rule->entry_name[rule->num_##entry_name].from = rule_entry_params->entry_name.from; \
		rule->entry_name[rule->num_##entry_name].to = rule_entry_params->entry_name.to; \
	}

#define kz_dispatcher_append_rule_entry_subnet(entry_name)		\
	if (rule_entry_params->has_##entry_name) {			\
		if (rule->num_##entry_name + 1 > rule->alloc_##entry_name) { \
			kz_err("each " #entry_name " has already been added to the rule; alloc_" #entry_name "='%d'", \
			       rule->num_##entry_name);			\
			res = -ENOMEM;					\
			goto error;					\
		}							\
		rule->entry_name[rule->num_##entry_name].addr = rule_entry_params->entry_name.addr; \
		rule->entry_name[rule->num_##entry_name].mask = rule_entry_params->entry_name.mask; \
	}

#define kz_dispatcher_append_rule_entry_ifname(entry_name) \
	if (rule_entry_params->has_##entry_name) { \
		if (rule->num_##entry_name + 1 > rule->alloc_##entry_name) { \
			kz_err("each " #entry_name " has already been added to the rule; alloc_" #entry_name "='%d'", \
			       rule->num_##entry_name); \
			res = -ENOMEM; \
			goto error; \
		} \
		memcpy(rule->entry_name[rule->num_##entry_name], rule_entry_params->entry_name, IFNAMSIZ); \
	}


#define kz_dispatcher_inc_rule_entry_num(entry_name) \
	if (rule_entry_params->has_##entry_name) { \
		rule->num_##entry_name++; \
	}

int
kz_dispatcher_add_rule_entry(struct kz_dispatcher_n_dimension_rule *rule,
			     const struct kz_dispatcher_n_dimension_rule_entry_params * const rule_entry_params)
{
	int res = 0;
	struct kz_zone *zone;

	kz_dispatcher_append_rule_entry_ifname(ifname);
	kz_dispatcher_append_rule_entry(ifgroup);
	kz_dispatcher_append_rule_entry_subnet(src_in_subnet);
	kz_dispatcher_append_rule_entry_subnet(dst_in_subnet);
	kz_dispatcher_append_rule_entry_subnet(src_in6_subnet);
	kz_dispatcher_append_rule_entry_subnet(dst_in6_subnet);
	kz_dispatcher_append_rule_entry_portrange(src_port);
	kz_dispatcher_append_rule_entry_portrange(dst_port);
	kz_dispatcher_append_rule_entry(src_zone);
	kz_dispatcher_append_rule_entry(dst_zone);
	kz_dispatcher_append_rule_entry(proto);
	kz_dispatcher_append_rule_entry_ifname(dst_ifname);
	kz_dispatcher_append_rule_entry(dst_ifgroup);
	kz_dispatcher_append_rule_entry(reqid);

	// no error has occured
	if (rule_entry_params->has_src_zone) {
		zone = rule->src_zone[rule->num_src_zone];
		if (zone != NULL)
			kz_zone_get(zone);
	}

	if (rule_entry_params->has_dst_zone) {
		zone = rule->dst_zone[rule->num_dst_zone];
		if (zone != NULL)
			kz_zone_get(zone);
	}

	kz_dispatcher_inc_rule_entry_num(ifname);
	kz_dispatcher_inc_rule_entry_num(ifgroup);
	kz_dispatcher_inc_rule_entry_num(src_in_subnet);
	kz_dispatcher_inc_rule_entry_num(dst_in_subnet);
	kz_dispatcher_inc_rule_entry_num(src_in6_subnet);
	kz_dispatcher_inc_rule_entry_num(dst_in6_subnet);
	kz_dispatcher_inc_rule_entry_num(src_port);
	kz_dispatcher_inc_rule_entry_num(dst_port);
	kz_dispatcher_inc_rule_entry_num(src_zone);
	kz_dispatcher_inc_rule_entry_num(dst_zone);
	kz_dispatcher_inc_rule_entry_num(proto);
	kz_dispatcher_inc_rule_entry_num(dst_ifname);
	kz_dispatcher_inc_rule_entry_num(dst_ifgroup);
	kz_dispatcher_inc_rule_entry_num(reqid);
error:
	return res;
}

static void
kz_rule_arr_relink_zones(u_int32_t * size, struct kz_zone **arr, const struct list_head * zonelist)
{
	u_int32_t i, put;
	
	if (*size == 0)
		return;

	for (i = 0, put = 0; i < *size; ++i)
	{
		struct kz_zone * const in = arr[i];
		struct kz_zone * out = __kz_zone_lookup_name(zonelist, in->unique_name);

		if (out == NULL) { /* just drop */
			kz_zone_put(in);
			continue;
		}
		if (in != out) {
			kz_zone_get(out);
			kz_zone_put(in);
		}
		arr[put++] = out;
	}
	*size = put;
}

static void
kz_rule_relink_zones(struct kz_dispatcher_n_dimension_rule *r, const struct list_head * zonelist)
{
	kz_rule_arr_relink_zones(&r->num_src_zone, r->src_zone, zonelist);
	kz_rule_arr_relink_zones(&r->num_dst_zone, r->dst_zone, zonelist);
}

#define kz_clone_rule_dimension(dim_name, dst_name, src_name) \
	dst_name->num_##dim_name = src_name->num_##dim_name; \
	memcpy(dst_name->dim_name, src_name->dim_name, \
	       dst_name->alloc_##dim_name * sizeof(*dst_name->dim_name))


int
kz_rule_copy(struct kz_dispatcher_n_dimension_rule *dst,
	     const struct kz_dispatcher_n_dimension_rule * const src)
{
	int res = 0;
	int i;

	dst->id = src->id;
	dst->service = kz_service_get(src->service);
	dst->dispatcher = NULL;

	kz_alloc_rule_dimension(src_in_subnet, dst, src, error);
	kz_alloc_rule_dimension(dst_in_subnet, dst, src, error);
	kz_alloc_rule_dimension(src_in6_subnet, dst, src, error);
	kz_alloc_rule_dimension(dst_in6_subnet, dst, src, error);
	kz_alloc_rule_dimension(ifname, dst, src, error);
	kz_alloc_rule_dimension(ifgroup, dst, src, error);
	kz_alloc_rule_dimension(src_port, dst, src, error);
	kz_alloc_rule_dimension(dst_port, dst, src, error);
	kz_alloc_rule_dimension(src_zone, dst, src, error);
	kz_alloc_rule_dimension(dst_zone, dst, src, error);
	kz_alloc_rule_dimension(proto, dst, src, error);
	kz_alloc_rule_dimension(dst_ifname, dst, src, error);
	kz_alloc_rule_dimension(dst_ifgroup, dst, src, error);
	kz_alloc_rule_dimension(reqid, dst, src, error);

	kz_clone_rule_dimension(src_in_subnet, dst, src);
	kz_clone_rule_dimension(dst_in_subnet, dst, src);
	kz_clone_rule_dimension(src_in6_subnet, dst, src);
	kz_clone_rule_dimension(dst_in6_subnet, dst, src);
	kz_clone_rule_dimension(ifname, dst, src);
	kz_clone_rule_dimension(ifgroup, dst, src);
	kz_clone_rule_dimension(src_port, dst, src);
	kz_clone_rule_dimension(dst_port, dst, src);
	kz_clone_rule_dimension(src_zone, dst, src);
	kz_clone_rule_dimension(dst_zone, dst, src);
	kz_clone_rule_dimension(proto, dst, src);
	kz_clone_rule_dimension(dst_ifname, dst, src);
	kz_clone_rule_dimension(dst_ifgroup, dst, src);
	kz_clone_rule_dimension(reqid, dst, src);

	for (i = 0; i < dst->num_src_zone; i++)
		dst->src_zone[i] = kz_zone_get(dst->src_zone[i]);
	for (i = 0; i < dst->num_dst_zone; i++)
		dst->dst_zone[i] = kz_zone_get(dst->dst_zone[i]);

	return 0;

error:
	kz_rule_destroy(dst);

	return res;
}

int
kz_dispatcher_copy_rules(struct kz_dispatcher *dst,
			 const struct kz_dispatcher * const src)
{
	unsigned int i = 0, j;
	int res = 0;

	dst->alloc_rule = src->alloc_rule;

	if (dst->alloc_rule == 0) {
		dst->rule = NULL;
		dst->num_rule = 0;
	} else {
		res = kz_dispatcher_alloc_rule_array(dst, src->alloc_rule);
		if (res < 0)
			return -ENOMEM;


		for (i = 0; i < src->num_rule; i++) {
			res = kz_rule_copy(&dst->rule[i], &src->rule[i]);
			if (res < 0)
				goto error;

			dst->rule[i].dispatcher = dst;
			dst->num_rule = i + 1;
		}
	}

	kz_debug("cloned rules; dst_num_rules='%u', dst_alloc_rules='%u', src_num_rules='%u', src_alloc_rules='%u'\n",
		 dst->num_rule, dst->alloc_rule, src->num_rule, src->alloc_rule);

	return 0;

error:
	if (dst->rule) {
		for (j = 0; j < dst->num_rule; j++)
			kz_rule_destroy(&dst->rule[j]);

		kz_dispatcher_free_rule_array(dst);
	}

	return res;
}

struct kz_dispatcher *
kz_dispatcher_clone_pure(const struct kz_dispatcher * const o)
{
	struct kz_dispatcher *dpt;

	dpt = kz_dispatcher_new();
	if (dpt == NULL)
		return NULL;

	dpt->instance = o->instance;
	dpt->name = kz_name_dup(o->name);
	if (dpt->name == NULL)
		goto error_put;

	return dpt;

error_put:
	kz_dispatcher_put(dpt);

	return NULL;
}

struct kz_dispatcher *
kz_dispatcher_clone(const struct kz_dispatcher * const o)
{
	struct kz_dispatcher *dpt;

	dpt = kz_dispatcher_clone_pure(o);
	if (dpt == NULL)
		return NULL;

	if (kz_dispatcher_copy_rules(dpt, o) < 0)
		goto error_put;

	return dpt;

error_put:
	kz_dispatcher_put(dpt);

	return NULL;
}

/* all zone links must point into the passed lists, remove those not found */
static void
kz_dispatcher_relink_n_dim(struct kz_dispatcher *d, const struct list_head * zonelist, const struct list_head * servicelist)
{
	unsigned int i, put;
	bool drop = 0;
	for (i = 0; i < d->num_rule; ++i) {
		struct kz_dispatcher_n_dimension_rule *rule = &d->rule[i];
		struct kz_service *service = __kz_service_lookup_name(servicelist, rule->service->name);
		if (service == NULL) {
			kz_err("Dropping rule with missing service; dispatcher='%s', rule_id='%u', service='%s'\n",
			       d->name, rule->id, rule->service->name);
			kz_rule_destroy(rule);
			drop = 1;
			continue;
		}
		if (service != rule->service) {
			kz_service_put(rule->service);
			rule->service = kz_service_get(service);
		}
		kz_rule_relink_zones(rule, zonelist);
	}
	if (!drop)
		return;
	/* sweep dropped rules */
	for (i = 0, put = 0; i < d->num_rule; ++i) {
		if (d->rule[i].service != NULL)
			d->rule[put++] = d->rule[i];
	}
	d->num_rule = put;
}

void
kz_dispatcher_relink(struct kz_dispatcher *d, const struct list_head * zonelist, const struct list_head * servicelist)
{
	kz_dispatcher_relink_n_dim(d, zonelist, servicelist);
	kz_debug("re-linked n-dim dispatcher; name='%s', num_rules='%u'\n", d->name, d->num_rule);
}

void
kz_head_destroy_dispatcher(struct kz_head_d *head)
{
	struct kz_dispatcher *i, *p;

	/* destroy lookup data structures */
	kz_head_dispatcher_destroy(head);

	list_for_each_entry_safe(i, p, &head->head, list) {
		list_del(&i->list);
		kz_dispatcher_put(i);
	}
}

/***********************************************************
 * sysctl interface
 ***********************************************************/

#ifdef CONFIG_SYSCTL
static ctl_table kzorp_table[] = {
	{
		.procname	= "log_ratelimit_msg_cost",
		.data		= &sysctl_kzorp_log_ratelimit_msg_cost,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_ms_jiffies
	},
	{
		.procname	= "log_ratelimit_burst",
		.data		= &sysctl_kzorp_log_ratelimit_burst,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{ }
};

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0) )
static struct ctl_path kzorp_sysctl_path[] = {
	{ .procname = "net", },
	{ .procname = "netfilter", },
	{ .procname = "kzorp", },
	{ }
};
#endif

static struct ctl_table_header * kzorp_sysctl_header;
#endif /* CONFIG_SYSCTL */

#ifdef CONFIG_KZORP_PROC_FS
static unsigned int
seq_print_counters(struct seq_file *s,
		   const struct nf_conn *ct,
		   enum ip_conntrack_dir dir)
{
	struct nf_conn_counter *acct;

	acct = nf_conn_acct_find(ct);
	if (!acct)
		return 0;

#define counter2long(x) ((unsigned long long)x.counter)
	return seq_printf(s, "packets=%llu bytes=%llu ",
				counter2long(acct[dir].packets),
				counter2long(acct[dir].bytes));
}

struct kz_iter_state {
	struct seq_net_private p;
	unsigned int bucket;
};

static struct hlist_nulls_node *kz_get_first(struct seq_file *seq)
{
	struct net *net = seq_file_net(seq);
	struct kz_iter_state *st = seq->private;
	struct hlist_nulls_node *n;

	for (st->bucket = 0;
	     st->bucket < net->ct.htable_size;
	     st->bucket++) {
		n = rcu_dereference(net->ct.hash[st->bucket].first);
		if (!is_a_nulls(n))
			return n;
	}
	return NULL;
}

static struct hlist_nulls_node *kz_get_next(struct seq_file *seq, struct hlist_nulls_node *head)
{
	struct net *net = seq_file_net(seq);
	struct kz_iter_state *st = seq->private;

	head = rcu_dereference(head->next);
	while (is_a_nulls(head)) {
		if (likely(get_nulls_value(head) == st->bucket)) {
			if (++st->bucket >= net->ct.htable_size)
				return NULL;
		}
		head = rcu_dereference(net->ct.hash[st->bucket].first);
	}
	return head;
}

static struct hlist_nulls_node *kz_get_idx(struct seq_file *seq, loff_t pos)
{
	struct hlist_nulls_node *head = kz_get_first(seq);

	if (head)
		while (pos && (head = kz_get_next(seq, head)))
			pos--;
	return pos ? NULL : head;
}

static void *kz_seq_start(struct seq_file *seq, loff_t *pos)
	__acquires(RCU)
{
	rcu_read_lock();
	return kz_get_idx(seq, *pos);
}

static void *kz_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	(*pos)++;
	return kz_get_next(s, v);
}

static void kz_seq_stop(struct seq_file *s, void *v)
	__releases(RCU)
{
	rcu_read_unlock();
}

/* return 0 on success, 1 in case of error */
static int kz_seq_show(struct seq_file *s, void *v)
{
	const struct nf_conntrack_tuple_hash *hash = v;
	struct nf_conn *conntrack = nf_ct_tuplehash_to_ctrack(hash);
	const struct nf_conntrack_kzorp *kzorp = kz_extension_find(conntrack);
	struct nf_conntrack_l3proto *l3proto;
	struct nf_conntrack_l4proto *l4proto;
	struct kz_dispatcher *dpt = NULL;
	struct kz_zone *czone = NULL, *szone = NULL;
	struct kz_service *svc = NULL;
	struct kz_instance *ins = NULL;
	int ret = 0;

	NF_CT_ASSERT(conntrack);

	if (unlikely(!atomic_inc_not_zero(&conntrack->ct_general.use)))
		return 0;

	/* we only want to print DIR_ORIGINAL */
	if (NF_CT_DIRECTION(hash))
		goto release;

	/* we onyl want to print forwarded sessions */
	if (!kzorp || !kzorp->czone || !kzorp->szone || !kzorp->dpt || !kzorp->svc)
		goto release;

	szone = kzorp->szone;
	czone = kzorp->czone;
	dpt   = kzorp->dpt;
	svc   = kzorp->svc;

	if (svc->type != KZ_SERVICE_FORWARD)
		goto release;

	ins = kz_instance_lookup_id(svc->instance_id);

	if (!ins)
		goto release;

	l3proto = __nf_ct_l3proto_find(conntrack->tuplehash[IP_CT_DIR_ORIGINAL]
				       .tuple.src.l3num);

	NF_CT_ASSERT(l3proto);
	l4proto = __nf_ct_l4proto_find(conntrack->tuplehash[IP_CT_DIR_ORIGINAL]
				   .tuple.src.l3num,
				   conntrack->tuplehash[IP_CT_DIR_ORIGINAL]
				   .tuple.dst.protonum);
	NF_CT_ASSERT(l4proto);

	ret = -ENOSPC;
	if (seq_printf(s, "instance=%-8s sid=%lu dpt=%-8s svc=%-8s czone=%-8s "
		       "szone=%-8s ", ins->name, kzorp->sid,
		       dpt->name, svc->name, czone->name, szone->name) != 0)
		goto release;

	if (seq_printf(s, "%-8s %u %-8s %u %ld ",
		       l3proto->name,
		       conntrack->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num,
		       l4proto->name,
		       conntrack->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum,
		       timer_pending(&conntrack->timeout)
		       ? (long)(conntrack->timeout.expires - jiffies)/HZ : 0) != 0)
		goto release;

	if (l4proto->print_conntrack && l4proto->print_conntrack(s, conntrack))
		goto release;

	if (print_tuple(s, &conntrack->tuplehash[IP_CT_DIR_ORIGINAL].tuple,
			l3proto, l4proto))
		goto release;

	if (seq_print_counters(s, conntrack, IP_CT_DIR_ORIGINAL))
		goto release;

	if (!(test_bit(IPS_SEEN_REPLY_BIT, &conntrack->status)))
		if (seq_printf(s, "[UNREPLIED] "))
			goto release;

	if (print_tuple(s, &conntrack->tuplehash[IP_CT_DIR_REPLY].tuple,
			l3proto, l4proto))
		goto release;

	if (seq_print_counters(s, conntrack, IP_CT_DIR_REPLY))
		goto release;

	if (test_bit(IPS_ASSURED_BIT, &conntrack->status))
		if (seq_printf(s, "[ASSURED] "))
			goto release;

#if defined(CONFIG_NF_CONNTRACK_MARK)
	if (seq_printf(s, "mark=%u ", conntrack->mark))
		goto release;
#endif

#ifdef CONFIG_NF_CONNTRACK_SECMARK
	if (seq_printf(s, "secmark=%u ", conntrack->secmark))
		goto release;
#endif

	if (seq_printf(s, "use=%u\n", atomic_read(&conntrack->ct_general.use)))
		goto release;

	ret = 0;
release:
	nf_ct_put(conntrack);
	return ret;
}

static struct seq_operations kz_seq_ops = {
	.start = kz_seq_start,
	.next  = kz_seq_next,
	.stop  = kz_seq_stop,
	.show  = kz_seq_show
};

static int kz_open(struct inode *inode, struct file *file)
{
	return seq_open_net(inode, file, &kz_seq_ops,
			sizeof(struct kz_iter_state));
}

static const struct file_operations kz_file_ops = {
	.owner   = THIS_MODULE,
	.open    = kz_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_net,
};
#endif /* CONFIG_PROC_FS */


/***********************************************************
 * Rate limit
 ***********************************************************/

#define LOG_RATELIMIT_MSG_COST 50
#define LOG_RATELIMIT_BURST    50

/*
 * printk rate limiting, lifted from the networking subsystem.
 *
 * This enforces a rate limit: not more than one kernel message
 * every printk_ratelimit_jiffies to make a denial-of-service
 * attack impossible.
 */
static int __log_ratelimit(int ratelimit_msg_cost, int ratelimit_burst)
{
	static DEFINE_SPINLOCK(ratelimit_lock);
	static unsigned long toks = LOG_RATELIMIT_MSG_COST * HZ * LOG_RATELIMIT_BURST / 1000;
	static unsigned long last_msg;
	static int missed;
	unsigned long flags;
	unsigned long now = jiffies;

	spin_lock_irqsave(&ratelimit_lock, flags);
	toks += now - last_msg;
	last_msg = now;

	if (toks > (ratelimit_burst * ratelimit_msg_cost))
		toks = ratelimit_burst * ratelimit_msg_cost;

	if (toks >= ratelimit_msg_cost) {
		int lost = missed;

		missed = 0;
		toks -= ratelimit_msg_cost;
		spin_unlock_irqrestore(&ratelimit_lock, flags);

		if (lost)
			printk(KERN_WARNING "kzorp: %d messages suppressed.\n", lost);

		return 1;
	}

	missed++;
	spin_unlock_irqrestore(&ratelimit_lock, flags);

	return 0;
}

/* minimum time in jiffies between messages */
int sysctl_kzorp_log_ratelimit_msg_cost;

/* number of messages we send before ratelimiting */
int sysctl_kzorp_log_ratelimit_burst = LOG_RATELIMIT_BURST;

int kz_log_ratelimit(void)
{
	return __log_ratelimit(sysctl_kzorp_log_ratelimit_msg_cost,
			       sysctl_kzorp_log_ratelimit_burst);
}
EXPORT_SYMBOL_GPL(kz_log_ratelimit);

/***********************************************************
 * Conntrack extension
 ***********************************************************/

void
kz_destroy_kzorp(struct nf_conntrack_kzorp *kzorp)
{
	if (kzorp->czone != NULL)
		kz_zone_put(kzorp->czone);
	if (kzorp->szone != NULL)
		kz_zone_put(kzorp->szone);
	if (kzorp->dpt != NULL)
		kz_dispatcher_put(kzorp->dpt);
	if (kzorp->svc != NULL)
		kz_service_put(kzorp->svc);
}

EXPORT_SYMBOL_GPL(kz_destroy_kzorp);

/***********************************************************
 * Initialization
 ***********************************************************/

int __init kzorp_core_init(void)
{
	int res = -ENOMEM;
	struct kz_instance *global;
#ifdef CONFIG_KZORP_PROC_FS
	struct proc_dir_entry *proc;
#endif

	sysctl_kzorp_log_ratelimit_msg_cost = msecs_to_jiffies(LOG_RATELIMIT_MSG_COST);

	atomic_set(&service_id_cnt, 1);
	instance_init();
	
	res = static_cfg_init();
	if (res < 0)
		goto cleanup;

	res = dpt_init();
	if (res < 0)
		goto cleanup;

	res = kz_lookup_init();
	if (res < 0)
		goto cleanup_dpt;

	/* create global instance */
	LOCK_INSTANCES();
	global = kz_instance_create(KZ_INSTANCE_GLOBAL, KZ_INSTANCE_GLOBAL_STRLEN, 0);
	if (global == NULL) {
		UNLOCK_INSTANCES();
		printk(KERN_ERR "kzorp: failed to create global instance\n");
		res = -ENOMEM;
		goto cleanup_lookup;
	}
	UNLOCK_INSTANCES();

	res = kz_extension_init();
	if (res < 0) {
		kz_err("unable to init conntrack extension\n");
		goto cleanup_global_instance;
	}
#ifdef CONFIG_SYSCTL
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0) )
	kzorp_sysctl_header = register_net_sysctl(&init_net, "net/netfilter/kzorp", kzorp_table);
#else
	kzorp_sysctl_header = register_sysctl_paths(kzorp_sysctl_path, kzorp_table);
#endif
	if (!kzorp_sysctl_header) {
		printk(KERN_ERR "nf_kzorp: can't register to sysctl.\n");
		res = -EINVAL;
		goto cleanup_ctx;
	}
#endif

#ifdef CONFIG_KZORP_PROC_FS
	proc = proc_create("nf_kzorp", 0440, init_net.proc_net, &kz_file_ops);
	if (!proc) {
		res = -EINVAL;
		goto cleanup_sysctl;
	}
#endif

	res = kz_sockopt_init();
	if (res < 0)
		goto cleanup_proc;

	res = kz_netlink_init();
	if (res < 0)
		goto cleanup_sockopt;

	return res;

cleanup_sockopt:
	kz_sockopt_cleanup();

cleanup_proc:
#ifdef CONFIG_KZORP_PROC_FS
	remove_proc_entry("nf_kzorp", init_net.proc_net);
#endif

#ifdef CONFIG_KZORP_PROC_FS
cleanup_sysctl:
#endif

#if CONFIG_SYSCTL
	unregister_sysctl_table(kzorp_sysctl_header);
#endif

cleanup_ctx:
	kz_extension_cleanup();

cleanup_global_instance:
	kz_instance_delete(global);

cleanup_lookup:
	kz_lookup_cleanup();

cleanup_dpt:
	dpt_cleanup();

cleanup:
	static_cfg_cleanup();
	return res;
}

static void __exit kzorp_core_fini(void)
{
	struct kz_instance *global;

	kz_netlink_cleanup();

	kz_sockopt_cleanup();

#ifdef CONFIG_KZORP_PROC_FS
	remove_proc_entry("nf_kzorp", init_net.proc_net);
#endif
#ifdef CONFIG_SYSCTL
	unregister_sysctl_table(kzorp_sysctl_header);
#endif
	kz_extension_fini();

	kz_config_swap(&static_config);

	LOCK_INSTANCES();
	global = kz_instance_lookup(KZ_INSTANCE_GLOBAL);
	if (global) {
		kz_instance_delete(global);
	}
	instance_cleanup();
	UNLOCK_INSTANCES();

	kz_lookup_cleanup();

	dpt_cleanup();

	/* last things last! */
	rcu_barrier() ;
	static_cfg_cleanup();
}

MODULE_DESCRIPTION("kzorp core");
MODULE_AUTHOR("Krisztian Kovacs <hidden@balabit.com>");
MODULE_LICENSE("GPL");

module_init(kzorp_core_init);
module_exit(kzorp_core_fini);
