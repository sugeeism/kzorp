/*
 * KZorp data structures
 *
 * Copyright (C) 2006-2010, BalaBit IT Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#ifndef _KZORP_H
#define _KZORP_H

#include <asm/atomic.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/netfilter_ipv4.h>
#include <linux/in.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <linux/netfilter/kzorp_netlink.h>
#include <net/xfrm.h>
#include <linux/if.h>
#include <linux/netdevice.h>

#include <net/netfilter/kzorp_compat.h>
#include <net/netfilter/kzorp_internal.h>

#define KZ_MAJOR_VERSION  4
#define KZ_COMPAT_VERSION 1

enum KZ_ALLOC_TYPE
{
	KZALLOC,
	VMALLOC
};

void *kz_big_alloc(size_t size, enum KZ_ALLOC_TYPE *alloc_type);
void kz_big_free(void *ptr, enum KZ_ALLOC_TYPE alloc_type);

/***********************************************************
 * Core data structures
 ***********************************************************/

typedef unsigned int kz_generation_t; /* integral with suitable size */
typedef __be32 netlink_port_t;

struct nf_conntrack_kzorp {
	unsigned int ct_zone;
	struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];
	void (*timerfunc_save)(unsigned long);
	unsigned long sid;
	/*  "lookup data" from here to end */
	kz_generation_t generation; /* config version */
	struct kz_zone *czone;		/* client zone */
	struct kz_zone *szone;		/* server zone */
	struct kz_dispatcher *dpt;	/* dispatcher */
	struct kz_service *svc;		/* service */
};

#define NF_CT_EXT_KZ_TYPE struct nf_conntrack_kzorp

enum kzf_instance_flags {
	KZF_INSTANCE_DELETED = 1 << 0,
	KZF_INSTANCE_TRANS   = 1 << 1,
};

struct kz_bind {
	struct list_head list;
	union nf_inet_addr addr;
	netlink_port_t peer_pid;
	sa_family_t family;
	__u16 port;
	__u8 proto;
};

enum kz_bind_l3proto {
	KZ_BIND_L3PROTO_IPV4,
	KZ_BIND_L3PROTO_IPV6,
	KZ_BIND_L3PROTO_COUNT
};

enum kz_bind_l4proto {
	KZ_BIND_L4PROTO_TCP,
	KZ_BIND_L4PROTO_UDP,
	KZ_BIND_L4PROTO_COUNT
};

struct kz_bind_lookup {
	struct rcu_head rcu;
	struct list_head list_bind;

	/* cache of binds by l3 and l4 proto */

	/*
	 * The binds and binds_by_type look something like this:
	 *
	 *	 +-------------+-------------+-------------+-------------+-------------+-------------+-------------+-------------+
	 *	 |  Bind 1     |  Bind 2     |	...	   |  Bind X	 |  Bind X + 1 | ...	     |	Bind Y	   | ...	 |
	 *	 |  (IPv4/TCP) |  (IPv4/TCP) |		   |  (IPv4/UDP) |  (IPv6/TCP) |	     |	(IPv6/UDP) |		 |
	 *	 +-------------+-------------+-------------+------/------+-----/-------+-------------+------/------+-------------+
	 *	       |                                  /-------     /-------		        /-----------
	 *	       |                          /-------      /------		    /-----------
	 *	       |                  /-------	/-------        /-----------
	 *       +-----+-------+-------------+-------------+-------------+
	 *       | IPv4/TCP    | IPv4/UDP    | IPv6/TCP    | IPv6/UDP    |
	 *       +-------------+-------------+-------------+-------------+
	 */

	/* array of pointers to all bind structures, ordered by l3proto and l4proto */
	const struct kz_bind const **binds;
	/* array of pointers to the appropriate element of the binds array */
	const struct kz_bind const **binds_by_type[KZ_BIND_L3PROTO_COUNT][KZ_BIND_L4PROTO_COUNT];
	unsigned int bind_nums[KZ_BIND_L3PROTO_COUNT][KZ_BIND_L4PROTO_COUNT];
};

struct kz_instance {
	struct list_head list;
	struct kz_bind_lookup *bind_lookup;
	unsigned int id;
	unsigned int flags;
	netlink_port_t peer_pid;
	char name[0];
};

enum kzf_transaction_flags {
	KZF_TRANSACTION_FLUSH_ZONES		= 1 << 0,
	KZF_TRANSACTION_FLUSH_SERVICES		= 1 << 1,
	KZF_TRANSACTION_FLUSH_DISPATCHERS	= 1 << 2,
	KZF_TRANSACTION_FLUSH_BIND		= 1 << 3,
};

struct kz_transaction {
	unsigned int instance_id;
	netlink_port_t peer_pid;
	unsigned int flags;
	u_int64_t cookie;
	const struct kz_config * cfg;
	struct list_head op;
};

enum kznl_op_data_type {
	KZNL_OP_ZONE,
	KZNL_OP_SERVICE,
	KZNL_OP_DISPATCHER,
	KZNL_OP_BIND,
};

struct kz_operation {
	struct list_head list;
	enum kznl_op_data_type type;
	void *data;
	void (*data_destroy)(void *);
};

struct kz_port_range {
	u_int16_t from;
	u_int16_t to;
};

struct kz_in_subnet {
	struct in_addr addr;
	struct in_addr mask;
};

struct kz_in6_subnet {
	struct in6_addr addr;
	struct in6_addr mask;
};

struct kz_dispatcher_n_dimension_rule_entry_params {
	u_int32_t rule_id;

#define DECLARE_RULE_ENTRY_PARAM(DIM_NAME, _, TYPE, ...) \
	bool has_##DIM_NAME; \
	TYPE DIM_NAME

	KZORP_DIM_LIST(DECLARE_RULE_ENTRY_PARAM, ;);

#undef DECLARE_RULE_ENTRY_PARAM
};

struct kz_dispatcher_n_dimension_rule {
	u_int32_t id;

	struct kz_service *service;
	struct kz_dispatcher *dispatcher;

#define DECLARE_RULE_ENTRY(DIM_NAME, _, TYPE, ...) \
	u_int32_t alloc_##DIM_NAME; \
	u_int32_t num_##DIM_NAME; \
	TYPE *DIM_NAME

	KZORP_DIM_LIST(DECLARE_RULE_ENTRY, ;);

#undef DECLARE_RULE_ENTRY
};

struct kz_reqids {
  u32 vec[XFRM_MAX_DEPTH];
  int len;
};

struct kz_query {
	sa_family_t src_addr_family;
	union nf_inet_addr src_addr;
	sa_family_t dst_addr_family;
	union nf_inet_addr dst_addr;
	u_int16_t src_port;
	u_int16_t dst_port;
	char ifname[IFNAMSIZ];
        struct kz_reqids reqids;
	u_int8_t proto;
};

typedef struct {
	struct work_struct my_work;
	void *p;
} kz_vfree_work_t;

struct kz_dispatcher {
	struct list_head list;
	atomic_t refcnt;
	struct kz_instance *instance;

	unsigned int alloc_rule;
	unsigned int num_rule;
	struct kz_dispatcher_n_dimension_rule *rule;
	enum KZ_ALLOC_TYPE rule_allocator;

	char *name;
};

struct kz_service_nat_entry {
	struct list_head list;
	NAT_RANGE_TYPE src;
	NAT_RANGE_TYPE dst;
	NAT_RANGE_TYPE map;
};

struct kz_service_info_fwd {
	struct list_head snat;
	struct list_head dnat;

	sa_family_t router_dst_addr_family;
	union nf_inet_addr router_dst_addr;
	__be16 router_dst_port;
};

struct kz_service_info_deny {
	enum kz_service_ipv4_deny_method ipv4_reject_method;
	enum kz_service_ipv6_deny_method ipv6_reject_method;
};

#define KZ_SERVICE_CNT_LOCKED_BIT 16

enum kzf_service_internal_flags {
	KZF_SERVICE_CNT_LOCKED = 1 << KZ_SERVICE_CNT_LOCKED_BIT,
};

struct kz_service {
	struct list_head list;
	atomic_t refcnt;
	unsigned int id;
	unsigned int instance_id;
	unsigned int flags;
	atomic_t session_cnt;
	enum kz_service_type type;
	union {
		struct kz_service_info_fwd fwd;
		struct kz_service_info_deny deny;
	} a;
	char *name;
};

enum kzf_zone_internal_flags {
	KZF_ZONE_HAS_RANGE = 1 << 16,
};

struct kz_zone {
	struct list_head list;
	struct hlist_node hlist;
	atomic_t refcnt;
	unsigned int flags;
	/* static lookup helper data */
	int depth;
	unsigned int index;
	/* range */
	sa_family_t family;
	union nf_inet_addr addr;
	union nf_inet_addr mask;

	/* NOTE: name and unique_name can be the same, in this case
	 * KZorp tries to save some memory and just set unique_name to
	 * the same pointer as name. Because of this, we have to be
	 * extra careful when cloning and freeing zone structures. On
	 * the other hand, we can rely on the names not being the same
	 * if the pointers differ -- this saves us a few strcmp()
	 * calls here and there. */
	char *name;
	char *unique_name;

	struct kz_zone *admin_parent;
};

/***********************************************************
 * Lookup data structures
 ***********************************************************/

#define DISPATCHER_INET_HASH_SIZE 256

#define KZ_ZONE_HASH_SIZE 32
#define KZ_ZONE_MAX 16384
#define KZ_ZONE_BF_SIZE (KZ_ZONE_MAX / 8)

struct kz_lookup_ipv6_node;

struct kz_zone_lookup {
	struct hlist_head hash[33][KZ_ZONE_HASH_SIZE];
	struct kz_lookup_ipv6_node *root;
};

/* config holder for zones */
struct kz_head_z {
	struct list_head head;
	/* lookup data structures */
	struct kz_zone_lookup luzone;
};

/* config holder for dispatchers */
struct kz_head_d {
	struct list_head head;
	/* lookup data structures */
	struct kz_rule_lookup_data *lookup_data;
	enum KZ_ALLOC_TYPE lookup_data_allocator;
};

/* config holder for services */
struct kz_head_s {
	struct list_head head;
	/* no lookup data for now */
};

/* config holder for instances */
struct kz_head_i {
	struct list_head head;
	/* no lookup data for now */
};

/* full config of kzorp
   we have one global instance with rcu protection
   functions may access it vis usual cru API

   CONVENTION: if passed in as function parameter,
   the caller ensures the content is stable!
*/
struct kz_config {
	struct rcu_head rcu;
	struct kz_head_z zones;
	struct kz_head_s services;
	struct kz_head_d dispatchers;
	struct kz_head_i instances;
	u_int64_t cookie;
	kz_generation_t generation;
};

/***********************************************************
 * Shared data
 ***********************************************************/

#define INSTANCE_MAX_NUM 256

extern struct mutex kz_instance_mutex;
extern struct list_head kz_instances;

/* NOTE: shared for nfnetlink transactions in nfnetlink module */
#define LOCK_INSTANCES(...) do {mutex_lock(&kz_instance_mutex);} while (0)
#define UNLOCK_INSTANCES(...) do {mutex_unlock(&kz_instance_mutex);} while (0)
/* we share mutex of instances in core -- no point to use multiples */
#define LOCK_TRANSACTIONS LOCK_INSTANCES
#define UNLOCK_TRANSACTIONS UNLOCK_INSTANCES

#define KZ_KFREE(p) do {if (p) {kfree(p); p = NULL;} } while (0)

/* rcu-protected pointer; can never be NULL
   the generation in the structure is unique in module lifetime
*/
extern struct kz_config *kz_config_rcu;

/* installs the new version, schedules rcu-free on the old one 
   generation is handled internally
*/
void kz_config_swap(struct kz_config * new_cfg);

struct kz_config *kz_config_new(void);
void kz_config_destroy(struct kz_config * cfg);

static inline kz_generation_t
kz_generation_get(const struct kz_config *cfg) {
	return cfg ? cfg->generation : 0;
}

static inline int
kz_generation_valid(const struct kz_config *cfg, kz_generation_t generation) {
	return (generation == kz_generation_get(cfg));
}

/***********************************************************
 * Core functions
 ***********************************************************/

extern char *kz_name_dup(const char * const name);

extern void kz_head_destroy_zone(struct kz_head_z *h);
extern void kz_head_destroy_service(struct kz_head_s *h);
extern void kz_head_destroy_dispatcher(struct kz_head_d *h);

struct kz_bind * kz_bind_new(void);
struct kz_bind * kz_bind_clone(const struct kz_bind const *_bind);
void kz_bind_destroy(struct kz_bind *bind);

const struct kz_bind * const
kz_instance_bind_lookup_v4(const struct kz_instance const *instance, u8 l4proto,
			   __be32 saddr, __be16 sport,
			   __be32 daddr, __be16 dport);

const struct kz_bind * const
kz_instance_bind_lookup_v6(const struct kz_instance const *instance, u8 l4proto,
			   const struct in6_addr const *saddr, __be16 sport,
			   const struct in6_addr const *daddr, __be16 dport);
void kz_instance_remove_bind(struct kz_instance *instance, const netlink_port_t pid_to_remove, const struct kz_transaction const *tr);

extern struct kz_instance *kz_instance_lookup_nocheck(const char *name);
extern struct kz_instance *kz_instance_lookup(const char *name);
extern struct kz_instance *kz_instance_lookup_id(const unsigned int id);
extern struct kz_instance *kz_instance_create(const char *name, const unsigned int len, const netlink_port_t peer_pid);

extern struct kz_zone *kz_zone_new(void);
extern void kz_zone_destroy(struct kz_zone *zone);
extern struct kz_zone *__kz_zone_lookup_name(const struct list_head * const head, const char *name);
extern struct kz_zone *kz_zone_lookup_name(const struct kz_config *cfg, const char *name);

extern struct kz_zone *kz_zone_clone(const struct kz_zone * const zone);

static inline struct kz_zone *kz_zone_get(struct kz_zone *zone)
{
	atomic_inc(&zone->refcnt);
	return zone;
}

static inline void kz_zone_put(struct kz_zone *zone)
{
	if (atomic_dec_and_test(&zone->refcnt))
		kz_zone_destroy(zone);
}

extern struct kz_service *kz_service_new(void);
extern void service_destroy(struct kz_service *service);
extern void kz_service_destroy(struct kz_service *service);
extern struct kz_service *__kz_service_lookup_name(const struct list_head * const head,
						   const char *name);
extern struct kz_service *kz_service_lookup_name(const struct kz_config *cfg, const char *name);
extern int kz_service_add_nat_entry(struct list_head *head, NAT_RANGE_TYPE *src,
				    NAT_RANGE_TYPE *dst, NAT_RANGE_TYPE *map);
extern struct kz_service *kz_service_clone(const struct kz_service * const o);
extern int kz_service_lock(struct kz_service * const service);
extern void kz_service_unlock(struct kz_service * const service);

static inline struct kz_service *kz_service_get(struct kz_service *service)
{
	atomic_inc(&service->refcnt);
	return service;
}

static inline void kz_service_put(struct kz_service *service)
{
	if (atomic_dec_and_test(&service->refcnt))
		kz_service_destroy(service);
}

extern int kz_rule_copy(struct kz_dispatcher_n_dimension_rule *dst,
			const struct kz_dispatcher_n_dimension_rule * const src);

extern struct kz_dispatcher *kz_dispatcher_new(void);
extern void kz_dispatcher_destroy(struct kz_dispatcher *);
extern struct kz_dispatcher *kz_dispatcher_lookup_name(const struct kz_config *cfg, const char *name);
extern int kz_dispatcher_add_css(struct kz_dispatcher *d, struct kz_zone *client,
				 struct kz_zone *server, struct kz_service *service);
extern int kz_dispatcher_add_rule(struct kz_dispatcher *d, struct kz_service *service,
				  const struct kz_dispatcher_n_dimension_rule * const rule_params);
extern int kz_dispatcher_add_rule_entry(struct kz_dispatcher_n_dimension_rule *rule,
					const struct kz_dispatcher_n_dimension_rule_entry_params * const rule_entry_params);
extern int kz_dispatcher_alloc_rule_array(struct kz_dispatcher *dispatcher, size_t alloc_rules);
extern int kz_dispatcher_copy_rules(struct kz_dispatcher *dst, const struct kz_dispatcher * const src);
extern struct kz_dispatcher *kz_dispatcher_clone(const struct kz_dispatcher * const o);
extern struct kz_dispatcher *kz_dispatcher_clone_pure(const struct kz_dispatcher * const o);
extern void kz_dispatcher_relink(struct kz_dispatcher *d, const struct list_head * zonelist, const struct list_head * servicelist);

static inline struct kz_dispatcher *
kz_dispatcher_get(struct kz_dispatcher *dispatcher)
{
	atomic_inc(&dispatcher->refcnt);
	return dispatcher;
}

static inline void
kz_dispatcher_put(struct kz_dispatcher *dispatcher)
{
	if (atomic_dec_and_test(&dispatcher->refcnt))
		kz_dispatcher_destroy(dispatcher);
}

int kz_log_ratelimit(void);

/***********************************************************
 * Conntrack structure extension
 ***********************************************************/


/* returns consolidated kzorp lookup info; caches it in ct, and uses 
   the cache if valid;
   returns NULL only if it's not possible to add kzorp extension to ct
   rcu_dereferenced config is stored in p_cfg
  call under rcu_read_lock() even if p_cfg==NULL!

   the returned structure is placed in ct, and destroy will happen
   when ct gets destroyed
*/

extern const struct nf_conntrack_kzorp * nfct_kzorp_cached_lookup_rcu(
	struct nf_conn *ct,
	enum ip_conntrack_info ctinfo,
	const struct sk_buff *skb,
	const struct net_device * const in,
	u8 l3proto,
	const struct kz_config **p_cfg);

/* fills kzorp structure with lookup data
   rcu_dereferenced config is stored in p_cfg
   call under rcu_read_lock() even if p_cfg==NULL!
   leaves non-lookup fields untouched!
   pointers in the passed structure must be valid/NULL,
   as they are released while the new ones addrefed

   make sure to call kz_destroy_kzorp on pkzorp eventually
*/
extern void nfct_kzorp_lookup_rcu(struct nf_conntrack_kzorp * pkzorp,
	enum ip_conntrack_info ctinfo,
	const struct sk_buff *skb,
	const struct net_device * const in,
	const u8 l3proto,
	const struct kz_config **p_cfg);

/* unreferences stuff inside
*/
extern void kz_destroy_kzorp(struct nf_conntrack_kzorp *kzorp);

/***********************************************************
 * Hook functions
 ***********************************************************/

extern int kz_hooks_init(void);
extern void kz_hooks_cleanup(void);

/***********************************************************
 * Cache functions
 ***********************************************************/

extern int kz_extension_init(void);
extern void kz_extension_cleanup(void);
extern void kz_extension_fini(void);
extern struct nf_conntrack_kzorp *kz_extension_create(struct nf_conn *ct);
/* handle kzorp extension in conntrack record
   an earlier version had the kzorp structure directly in nf_conn
   we changed that to use the extension API and add only on request
   this makes it possible to use kzorp as a dkms module.

   FIXME: check/test the below sentences
   The downside is that extensions can not be added after certain point
   (basicly, it must happen at the start of a session, not at second
    or a further packet...). 
   If the kzorp extension can't be added, we still can do zone/svc
   lookup on the fly -- only losing the cache. 
   The other thing we lose is the session id assignment.
   
   So a proper ruleset that wants to use those facilities shall make
   sure to have have the first packet meet KZORP related lookup.
   
*/

extern struct nf_conntrack_kzorp *kz_extension_find(struct nf_conn *ct);

/***********************************************************
 * Lookup functions
 ***********************************************************/

extern int kz_lookup_init(void);
extern void kz_lookup_cleanup(void);

extern void kz_head_dispatcher_init(struct kz_head_d *h);
extern int kz_head_dispatcher_build(struct kz_head_d *h);
extern void kz_head_dispatcher_destroy(struct kz_head_d *h);

extern void kz_head_zone_init(struct kz_head_z *h);
extern int kz_head_zone_build(struct kz_head_z *h);
extern void kz_head_zone_destroy(struct kz_head_z *h);
extern struct kz_zone *kz_head_zone_ipv4_lookup(const struct kz_head_z *h, const struct in_addr * const addr);

extern const NAT_RANGE_TYPE *kz_service_nat_lookup(const struct list_head * const head,
						    const __be32 saddr, const __be32 daddr,
						    const __be16 sport, const __be16 dport,
						    const u_int8_t proto);

extern void kz_lookup_session(const struct kz_config *cfg,
			      const struct kz_reqids *reqids,
			      const struct net_device *in,
			      u_int8_t l3proto,
			      const union nf_inet_addr * const saddr, const union nf_inet_addr * const daddr,
			      u_int8_t l4proto, u_int16_t sport, u_int16_t dport,
			      struct kz_dispatcher **dispatcher,
			      struct kz_zone **clientzone, struct kz_zone **serverzone,
			      struct kz_service **service, int reply);

/***********************************************************
 * Netlink functions
 ***********************************************************/

extern int kz_nfnetlink_init(void);
extern void kz_nfnetlink_cleanup(void);


/***********************************************************
 * Logging
 ***********************************************************/

#define kz_debug(format, args...) pr_debug("%s: " format, __FUNCTION__, ##args)
#define kz_err(format, args...) pr_err("kzorp:%s: " format, __FUNCTION__, ##args)

#define kz_bind_debug(bind, msg) \
{ \
	switch (bind->family) { \
	case NFPROTO_IPV4: \
		kz_debug("%s; address='%pI4', port='%d', proto='%d' pid='%d'\n", msg, &bind->addr.in, bind->port, bind->proto, bind->peer_pid); \
		break; \
	case NFPROTO_IPV6: \
		kz_debug("%s; address='%pI6', port='%d', proto='%d' pid='%d'\n", msg, &bind->addr.in6, bind->port, bind->proto, bind->peer_pid); \
		break; \
	default: \
		BUG(); \
	} \
}

/* Bitfield */
enum {
	KZL_NONE		= 0,    /* supress log message */
	KZL_NORMAL		= 1,
	KZL_DROPPED_PACKETS	= 2,	/* silently dropped packets */
	KZL_PACKET_INFO		= 4,	/* source and destination */
	KZL_LOOKUP		= 8,	/* Main parts used by lookup_session */
	KZL_POINTERS		= 16,	/*service etc. pointers (debug) */
	KZL_FUNC_DEBUG		= 32,	/* function startup, control path  */
	KZL_FUNC_EXTRA_DEBUG    = 64,   /* basically same as KZL_FUNC_DEBUG, lots of log */
};
#endif

/***********************************************************
 * getsockopt() interface
 ***********************************************************/

extern int kz_sockopt_init(void);
extern void kz_sockopt_cleanup(void);

/***********************************************************
 * Netlink interface
 ***********************************************************/

extern int kz_netlink_init(void);
extern void kz_netlink_cleanup(void);
